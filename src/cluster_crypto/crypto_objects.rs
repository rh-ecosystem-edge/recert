use super::{
    certificate::{self, Certificate},
    jwt,
    keys::{PrivateKey, PublicKey},
    locations::Location,
    scanning::ExternalCerts,
};
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

#[allow(clippy::large_enum_variant)]
pub(crate) enum CryptoObject {
    PrivateKey(PrivateKey, PublicKey),
    PublicKey(PublicKey),
    Certificate(Certificate),
    Jwt(jwt::Jwt),
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

pub(crate) struct DiscoveredCryptoObect {
    pub(crate) crypto_object: CryptoObject,
    pub(crate) location: Location,
}

impl DiscoveredCryptoObect {
    pub(crate) fn new(crypto_object: CryptoObject, location: Location) -> Self {
        Self { crypto_object, location }
    }
}

/// Given a value taken from a YAML field or the entire contents of a file, scan it for
/// cryptographic keys and certificates and record them in the appropriate data structures.
pub(crate) fn process_unknown_value(
    value: String,
    location: &Location,
    external_certs: &ExternalCerts,
) -> Result<Vec<DiscoveredCryptoObect>> {
    let pem_bundle_objects = process_pem_bundle(&value, location, external_certs).context("processing pem bundle");

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
    if let Some(jwt) = process_jwt(&value, location)? {
        Ok(vec![jwt])
    } else {
        Ok(vec![])
    }
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

    let jwt = jwt::Jwt { str: value.to_string() };

    let location = location.with_jwt()?;

    Ok(Some(DiscoveredCryptoObect::new(jwt.into(), location)))
}

/// Given a PEM bundle, scan it for cryptographic keys and certificates and record them in the
/// appropriate data structures.
pub(crate) fn process_pem_bundle(value: &str, location: &Location, external_certs: &ExternalCerts) -> Result<Vec<DiscoveredCryptoObect>> {
    let pems = pem::parse_many(value).context("parsing pem")?;

    #[allow(clippy::unwrap_used)] // The filter ensures that unwrap will never panic. We can't use
    // a filter_map because we want to maintain the index of the pem in the bundle.
    pems.iter()
        .enumerate()
        .map(|(pem_index, pem)| {
            process_single_pem(pem, external_certs).with_context(|| format!("processing pem at index {} in the bundle", pem_index))
        })
        .collect::<Result<Vec<_>>>()
        .context("error processing PEM")?
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
pub(crate) fn process_single_pem(pem: &pem::Pem, external_certs: &ExternalCerts) -> Result<Option<CryptoObject>> {
    match pem.tag() {
        "CERTIFICATE" => process_pem_cert(pem, external_certs).context("processing pem cert"),
        "TRUSTED CERTIFICATE" => process_pem_cert(pem, external_certs).context("processing trusted pem cert"), // TODO: we'll have to save it back as TRUSTED
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
        InMemorySigningKeyPair::Ecdsa(_, _, pkcs8_der) => {
            let pubkey_pem = super::crypto_utils::pubkey_pem_from_pkcs8_der(&pkcs8_der).context("extracting EC public key")?;

            let private_part = PrivateKey::Ec(Bytes::from(pkcs8_der));
            let public_part = PublicKey::Ec(pubkey_pem.into());

            Some((private_part, public_part).into())
        }
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
pub(crate) fn process_pem_cert(pem: &pem::Pem, external_certs: &ExternalCerts) -> Result<Option<CryptoObject>> {
    let x509_certificate = &x509_certificate::CapturedX509Certificate::from_der(pem.contents()).context("parsing DER")?;

    let hashable_cert = certificate::Certificate::try_from(x509_certificate).context("parsing cert")?;

    if external_certs.has_cert(&hashable_cert).context("has external cert")? {
        log::trace!("ignoring external cert {}", hashable_cert.subject);
        return Ok(None);
    } else {
        log::trace!("not ignoring internal cert {}", hashable_cert.subject);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_ec_pkcs8_pem(curve: &str) -> Vec<u8> {
        let ecparam = Command::new("openssl")
            .args(["ecparam", "-name", curve, "-genkey", "-noout"])
            .output()
            .expect("failed to run openssl ecparam");
        assert!(ecparam.status.success(), "ecparam failed");

        let mut child = Command::new("openssl")
            .args(["pkcs8", "-topk8", "-nocrypt"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn openssl pkcs8");

        child.stdin.take().unwrap().write_all(&ecparam.stdout).unwrap();

        let output = child.wait_with_output().expect("pkcs8 conversion failed");
        assert!(
            output.status.success(),
            "pkcs8 conversion failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn assert_ec_private_key_round_trips(curve: &str) {
        let pkcs8_pem_bytes = generate_ec_pkcs8_pem(curve);
        let parsed = pem::parse(&pkcs8_pem_bytes).expect("failed to parse PEM");
        assert_eq!(parsed.tag(), "PRIVATE KEY");

        let result = process_pem_private_key(&parsed).expect("process_pem_private_key failed");
        let crypto_obj = result.expect("expected Some(CryptoObject)");

        match crypto_obj {
            CryptoObject::PrivateKey(private_key, public_key) => {
                match &private_key {
                    PrivateKey::Ec(bytes) => {
                        assert_eq!(bytes.as_ref(), parsed.contents(), "stored bytes should be PKCS#8 DER");
                    }
                    _ => panic!("expected PrivateKey::Ec"),
                }

                let priv_pem = private_key.pem().expect("PrivateKey::pem() should succeed");
                assert_eq!(
                    priv_pem.tag(),
                    "PRIVATE KEY",
                    "PKCS#8 DER must use PRIVATE KEY tag, not EC PRIVATE KEY"
                );
                assert_eq!(priv_pem.contents(), parsed.contents(), "round-tripped DER should match original");

                match &public_key {
                    PublicKey::Ec(pem_bytes) => {
                        let pub_pem = pem::parse(pem_bytes.as_ref()).expect("public key should be valid PEM");
                        assert_eq!(pub_pem.tag(), "PUBLIC KEY");
                    }
                    _ => panic!("expected PublicKey::Ec"),
                }
            }
            _ => panic!("expected CryptoObject::PrivateKey"),
        }
    }

    #[test]
    fn test_process_pem_private_key_ecdsa_p256_pkcs8() {
        assert_ec_private_key_round_trips("prime256v1");
    }

    #[test]
    fn test_process_pem_private_key_ecdsa_p384_pkcs8() {
        assert_ec_private_key_round_trips("secp384r1");
    }

    #[test]
    fn test_process_pem_private_key_rsa_pkcs8_still_works() {
        let output = Command::new("openssl")
            .args(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"])
            .output()
            .expect("failed to generate RSA key");
        assert!(output.status.success());

        let parsed = pem::parse(&output.stdout).expect("failed to parse PEM");
        assert_eq!(parsed.tag(), "PRIVATE KEY");

        let result = process_pem_private_key(&parsed).expect("process_pem_private_key failed");
        let crypto_obj = result.expect("expected Some(CryptoObject)");

        match crypto_obj {
            CryptoObject::PrivateKey(private_key, _) => {
                assert!(matches!(private_key, PrivateKey::Rsa(_)), "expected PrivateKey::Rsa");
            }
            _ => panic!("expected CryptoObject::PrivateKey"),
        }
    }

    #[test]
    fn test_process_pem_ec_private_key_sec1_p256() {
        let output = Command::new("openssl")
            .args(["ecparam", "-name", "prime256v1", "-genkey", "-noout"])
            .output()
            .expect("failed to generate EC key");
        assert!(output.status.success());

        let parsed = pem::parse(&output.stdout).expect("failed to parse PEM");
        assert_eq!(parsed.tag(), "EC PRIVATE KEY");

        let result = process_pem_ec_private_key(&parsed).expect("process_pem_ec_private_key failed");
        let crypto_obj = result.expect("expected Some(CryptoObject)");

        match crypto_obj {
            CryptoObject::PrivateKey(private_key, public_key) => {
                assert!(matches!(private_key, PrivateKey::Ec(_)), "expected PrivateKey::Ec");
                match &public_key {
                    PublicKey::Ec(pem_bytes) => {
                        let pub_pem = pem::parse(pem_bytes.as_ref()).expect("public key should be valid PEM");
                        assert_eq!(pub_pem.tag(), "PUBLIC KEY");
                    }
                    _ => panic!("expected PublicKey::Ec"),
                }
            }
            _ => panic!("expected CryptoObject::PrivateKey"),
        }
    }

    #[test]
    fn test_ec_pkcs8_full_round_trip() {
        let pkcs8_pem_bytes = generate_ec_pkcs8_pem("prime256v1");
        let parsed = pem::parse(&pkcs8_pem_bytes).expect("failed to parse PEM");

        let result = process_pem_private_key(&parsed).expect("process_pem_private_key failed");
        let crypto_obj = result.expect("expected Some(CryptoObject)");

        match crypto_obj {
            CryptoObject::PrivateKey(private_key, _) => {
                let output_pem = private_key.pem().expect("pem() failed");
                let external_certs = super::super::scanning::ExternalCerts::empty();
                let reparsed = process_single_pem(&output_pem, &external_certs).expect("re-parse failed");
                let reparsed = reparsed.expect("expected Some on re-parse");
                match reparsed {
                    CryptoObject::PrivateKey(re_key, _) => {
                        assert!(matches!(re_key, PrivateKey::Ec(_)), "re-parsed key should be PrivateKey::Ec");
                    }
                    _ => panic!("expected CryptoObject::PrivateKey on re-parse"),
                }
            }
            _ => panic!("expected CryptoObject::PrivateKey"),
        }
    }

    #[test]
    fn test_ec_serialize_uses_correct_pem_tag() {
        let pkcs8_pem_bytes = generate_ec_pkcs8_pem("prime256v1");
        let parsed = pem::parse(&pkcs8_pem_bytes).expect("failed to parse PEM");

        let result = process_pem_private_key(&parsed).expect("process_pem_private_key failed");
        let crypto_obj = result.expect("expected Some(CryptoObject)");

        match crypto_obj {
            CryptoObject::PrivateKey(private_key, _) => {
                let serialized = serde_json::to_string(&private_key).expect("serialize failed");
                assert!(
                    serialized.contains("BEGIN PRIVATE KEY"),
                    "serialized EC key should use PRIVATE KEY tag"
                );
                assert!(
                    !serialized.contains("BEGIN EC PRIVATE KEY"),
                    "serialized EC key must not use EC PRIVATE KEY tag"
                );
            }
            _ => panic!("expected CryptoObject::PrivateKey"),
        }
    }

    #[test]
    fn test_process_pem_private_key_corrupted_pkcs8() {
        let garbage = pem::Pem::new("PRIVATE KEY", vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let result = process_pem_private_key(&garbage);
        assert!(result.is_err(), "corrupted PKCS#8 DER should produce an error");
    }
}
