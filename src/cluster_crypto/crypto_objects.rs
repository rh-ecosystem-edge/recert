use super::{
    certificate::{self, Certificate},
    json_crawl::Hint,
    jwt,
    keys::{PrivateKey, PublicKey},
    locations::Location,
    symmetric_key::SymmetricKey,
};
use crate::rules;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bytes::Bytes;
use p256::SecretKey;
use pkcs1::DecodeRsaPrivateKey;
use std::{
    io::Write,
    process::{Command, Stdio},
};
use x509_certificate::InMemorySigningKeyPair;

pub(crate) enum CryptoObject {
    PrivateKey(PrivateKey, PublicKey),
    PublicKey(PublicKey),
    Certificate(Certificate),
    Jwt(jwt::Jwt),
    SymmetricKey(SymmetricKey),
}

impl From<(PrivateKey, PublicKey)> for CryptoObject {
    fn from(keys: (PrivateKey, PublicKey)) -> Self {
        let (private_key, public_key) = keys;
        CryptoObject::PrivateKey(private_key, public_key)
    }
}

impl From<PublicKey> for CryptoObject {
    fn from(public_key: PublicKey) -> Self {
        CryptoObject::PublicKey(public_key)
    }
}

impl From<certificate::Certificate> for CryptoObject {
    fn from(certificate: certificate::Certificate) -> Self {
        CryptoObject::Certificate(certificate)
    }
}

impl From<jwt::Jwt> for CryptoObject {
    fn from(jwt: jwt::Jwt) -> Self {
        CryptoObject::Jwt(jwt)
    }
}

impl From<SymmetricKey> for CryptoObject {
    fn from(key: SymmetricKey) -> Self {
        CryptoObject::SymmetricKey(key)
    }
}

pub(crate) struct DiscoveredCryptoObect {
    pub(crate) crypto_object: CryptoObject,
    pub(crate) location: Location,
}

impl DiscoveredCryptoObect {
    pub(crate) fn new(crypto_object: CryptoObject, location: Location) -> Self {
        Self { crypto_object, location }
    }
}

pub(crate) fn process_unknown_value(value: Bytes, location: &Location, hint: Hint) -> Result<Vec<DiscoveredCryptoObect>> {
    let crypto_objects_when_processed_as_string = match String::from_utf8(value.clone().to_vec()) {
        Ok(string) => process_unknown_string(&string, location).context("processing as string")?,
        _ => vec![],
    };

    match crypto_objects_when_processed_as_string.len() {
        0 => (),
        _ => return Ok(crypto_objects_when_processed_as_string),
    };

    let crypto_objects_when_processed_as_binary = process_unknown_binary(value, location, hint)?;

    Ok(crypto_objects_when_processed_as_binary)
}

fn process_unknown_binary(value: Bytes, location: &Location, hint: Hint) -> Result<Vec<DiscoveredCryptoObect>> {
    match hint {
        Hint::SymmetricKey => (),
        _ => return Ok(vec![]),
    }

    Ok(if let Some(symmetric_key) = process_symmetric_key(&value, location)? {
        vec![symmetric_key]
    } else {
        vec![]
    })
}

fn process_unknown_string(value: &str, location: &Location) -> Result<Vec<DiscoveredCryptoObect>> {
    let pem_bundle_objects = process_pem_bundle(value, location).context("processing pem bundle");

    // We intentionally ignore errors from processing PEM bundles because that function easily
    // trips up from values that kinda look like PEM (e.g. a serialized install config yaml
    // embedded in a configmap entry that contains an additionalTrustBundle PEM, which is
    // inherently external, so we don't care about it)
    match pem_bundle_objects {
        Ok(objects) => {
            if !objects.is_empty() {
                return Ok(objects);
            }
        }
        Err(err) => log::warn!("ignoring error from processing pem-looking text at location {}: {}", location, err),
    };

    // If we didn't find any PEM objects, try to process the value as a JWT
    if let Some(jwt) = process_jwt(value, location)? {
        Ok(vec![jwt])
    } else {
        Ok(vec![])
    }
}

pub(crate) fn process_symmetric_key(value: &Bytes, location: &Location) -> Result<Option<DiscoveredCryptoObect>> {
    // For now we only consider sequences of 32 bytes to be symmetric keys
    if value.len() != 32 {
        return Ok(None);
    }

    Ok(Some(DiscoveredCryptoObect::new(
        CryptoObject::from(SymmetricKey::new(value.clone())),
        location.with_symmetric_key()?,
    )))
}

/// Given a value taken from a YAML field, check if it looks like a JWT and record it in the
/// appropriate data structures.
pub(crate) fn process_jwt(value: &str, location: &Location) -> Result<Option<DiscoveredCryptoObect>> {
    // Need a cheap way to detect jwts that doesn't involve parsing them because we run this
    // against every secret/configmap data entry
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Ok(None);
    }

    let header = parts[0];
    let payload = parts[1];
    let signature = parts[2];

    if URL_SAFE_NO_PAD.decode(header.as_bytes()).is_err() {
        return Ok(None);
    }
    if URL_SAFE_NO_PAD.decode(payload.as_bytes()).is_err() {
        return Ok(None);
    }
    if URL_SAFE_NO_PAD.decode(signature.as_bytes()).is_err() {
        return Ok(None);
    }

    Ok(Some(DiscoveredCryptoObect::new(
        jwt::Jwt::new(value.to_string()).into(),
        location.with_jwt()?,
    )))
}

/// Given a PEM bundle, scan it for cryptographic keys and certificates and record them in the
/// appropriate data structures.
pub(crate) fn process_pem_bundle(value: &str, location: &Location) -> Result<Vec<DiscoveredCryptoObect>> {
    let pems = pem::parse_many(value).context("parsing pem")?;

    pems.iter()
        .enumerate()
        .map(|(pem_index, pem)| process_single_pem(pem).with_context(|| format!("processing pem at index {} in the bundle", pem_index)))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .enumerate()
        .filter(|(_, crypto_object)| crypto_object.is_some())
        .map(|(pem_index, crypto_object)| (pem_index, crypto_object.unwrap()))
        .map(|(pem_index, crypto_object)| {
            Ok(DiscoveredCryptoObect::new(
                crypto_object,
                location.with_pem_bundle_index(pem_index.try_into()?)?,
            ))
        })
        .collect::<Result<Vec<_>>>()
}

/// Given a single PEM, scan it for cryptographic keys and certificates and record them in the
/// appropriate data structures.
pub(crate) fn process_single_pem(pem: &pem::Pem) -> Result<Option<CryptoObject>> {
    match pem.tag() {
        "CERTIFICATE" => process_pem_cert(pem).context("processing pem cert"),
        "TRUSTED CERTIFICATE" => process_pem_cert(pem).context("processing trusted pem cert"), // TODO: we'll have to save it back as TRUSTED
        "RSA PRIVATE KEY" => process_pem_rsa_private_key(pem).context("processing pem rsa private key"),
        "EC PRIVATE KEY" => process_pem_ec_private_key(pem).context("processing pem ec private key"),
        "PRIVATE KEY" => process_pem_private_key(pem).context("processing pem private key"),
        "PUBLIC KEY" => bail!("private pkcs8 unsupported"),
        "RSA PUBLIC KEY" => Ok(process_pem_public_key(pem)),
        "ENTITLEMENT DATA" | "RSA SIGNATURE" => Ok(None),
        _ => bail!("unknown pem tag {}", pem.tag()),
    }
}

fn process_pem_private_key(pem: &pem::Pem) -> Result<Option<CryptoObject>> {
    let pair = InMemorySigningKeyPair::from_pkcs8_der(pem.contents())?;

    Ok(match pair {
        InMemorySigningKeyPair::Ecdsa(_, _, _) => bail!("private ecdsa pkcs8 unsupported"),
        InMemorySigningKeyPair::Ed25519(_) => bail!("private ed25519 pkcs8 unsupported"),
        InMemorySigningKeyPair::Rsa(_, bytes) => {
            let rsa_private_key = rsa::RsaPrivateKey::from_pkcs1_der(&bytes)?;

            let private_part = PrivateKey::Rsa(rsa_private_key);
            let public_part = PublicKey::try_from(&private_part)?;

            Some((private_part, public_part).into())
        }
    })
}

pub(crate) fn process_pem_public_key(pem: &pem::Pem) -> Option<CryptoObject> {
    Some(PublicKey::from_rsa_bytes(&bytes::Bytes::copy_from_slice(pem.contents())).into())
}

/// Given an RSA private key PEM, record it in the appropriate data structures.
pub(crate) fn process_pem_rsa_private_key(pem: &pem::Pem) -> Result<Option<CryptoObject>> {
    let rsa_private_key = rsa::RsaPrivateKey::from_pkcs1_pem(&pem.to_string())?;

    let private_part = PrivateKey::Rsa(rsa_private_key);
    let public_part = PublicKey::try_from(&private_part)?;

    Ok(Some((private_part, public_part).into()))
}

/// Given an EC private key PEM, record it in the appropriate data structures.
pub(crate) fn process_pem_ec_private_key(pem: &pem::Pem) -> Result<Option<CryptoObject>> {
    // First convert to pkcs#8 by shelling out to openssl pkcs8 -topk8 -nocrypt:
    let mut command = Command::new("openssl")
        .arg("pkcs8")
        .arg("-topk8")
        .arg("-nocrypt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    command
        .stdin
        .take()
        .context("failed to take openssl stdin pipe")?
        .write_all(pem.to_string().as_bytes())?;

    let output = command.wait_with_output()?;
    let pem = pem::parse(output.stdout)?;

    let key = pem.to_string().parse::<SecretKey>()?;
    let public_key = key.public_key();

    let private_part = PrivateKey::Ec(Bytes::copy_from_slice(pem.contents()));
    let public_part = PublicKey::Ec(Bytes::copy_from_slice(public_key.to_string().as_bytes()));

    Ok(Some((private_part, public_part).into()))
}

/// Given a certificate PEM, record it in the appropriate data structures.
pub(crate) fn process_pem_cert(pem: &pem::Pem) -> Result<Option<CryptoObject>> {
    let x509_certificate = &x509_certificate::CapturedX509Certificate::from_der(pem.contents()).context("parsing DER")?;

    let hashable_cert = certificate::Certificate::try_from(x509_certificate).context("parsing cert")?;

    if rules::EXTERNAL_CERTS.read().unwrap().contains(&hashable_cert.subject) {
        return Ok(None);
    }

    match hashable_cert.cert.key_algorithm().context("failed to get cert key algorithm")? {
        x509_certificate::KeyAlgorithm::Rsa => {}
        x509_certificate::KeyAlgorithm::Ecdsa(_) => {}
        x509_certificate::KeyAlgorithm::Ed25519 => {
            bail!("ed25519 certs unsupported");
        }
    }

    Ok(Some(CryptoObject::from(hashable_cert)))
}
