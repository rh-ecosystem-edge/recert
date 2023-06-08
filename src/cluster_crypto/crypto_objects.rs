use super::{
    certificate::{self, Certificate},
    jwt,
    keys::{PrivateKey, PublicKey},
    locations::Location,
};
use crate::rules;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bytes::Bytes;
use p256::SecretKey;
use pkcs1::DecodeRsaPrivateKey;
use std::{
    io::Write,
    process::{Command, Stdio},
};

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

/// Given a value taken from a YAML field, scan it for cryptographic keys and certificates and
/// record them in the appropriate data structures.
pub(crate) fn process_yaml_value(value: String, location: &Location) -> Vec<DiscoveredCryptoObect> {
    let pem_bundle_objects = process_pem_bundle(&value, location);
    if pem_bundle_objects.len() > 0 {
        return pem_bundle_objects;
    }

    if let Some(jwt) = process_jwt(&value, location) {
        vec![jwt]
    } else {
        vec![]
    }
}

/// Given a value taken from a YAML field, check if it looks like a JWT and record it in the
/// appropriate data structures.
pub(crate) fn process_jwt(value: &str, location: &Location) -> Option<DiscoveredCryptoObect> {
    // Need a cheap way to detect jwts that doesn't involve parsing them because we run this
    // against every secret/configmap data entry
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return None;
    }

    let header = parts[0];
    let payload = parts[1];
    let signature = parts[2];

    if let Err(_) = URL_SAFE_NO_PAD.decode(header.as_bytes()) {
        return None;
    }
    if let Err(_) = URL_SAFE_NO_PAD.decode(payload.as_bytes()) {
        return None;
    }
    if let Err(_) = URL_SAFE_NO_PAD.decode(signature.as_bytes()) {
        return None;
    }

    let jwt = jwt::Jwt { str: value.to_string() };

    let location = location.with_jwt();

    Some(DiscoveredCryptoObect::new(jwt.into(), location))
}

/// Given a PEM bundle, scan it for cryptographic keys and certificates and record them in the
/// appropriate data structures.
pub(crate) fn process_pem_bundle(value: &str, location: &Location) -> Vec<DiscoveredCryptoObect> {
    let pems = pem::parse_many(value).unwrap();

    pems.iter()
        .map(process_single_pem)
        .enumerate()
        .filter(|(_, crypto_object)| crypto_object.is_some())
        .map(|(i, crypto_object)| (i, crypto_object.unwrap()))
        .map(|(i, crypto_object)| DiscoveredCryptoObect::new(crypto_object, location.with_pem_bundle_index(i.try_into().unwrap())))
        .collect()
}

/// Given a single PEM, scan it for cryptographic keys and certificates and record them in the
/// appropriate data structures.
pub(crate) fn process_single_pem(pem: &pem::Pem) -> Option<CryptoObject> {
    match pem.tag() {
        "CERTIFICATE" => process_pem_cert(pem),
        "RSA PRIVATE KEY" => process_pem_rsa_private_key(pem),
        "EC PRIVATE KEY" => process_pem_ec_private_key(pem),
        "PRIVATE KEY" => {
            panic!("private pkcs8 unsupported");
        }
        "PUBLIC KEY" => {
            panic!("public pkcs8 unsupported");
        }
        "RSA PUBLIC KEY" => process_pem_public_key(pem),
        "ENTITLEMENT DATA" | "RSA SIGNATURE" => None,
        _ => {
            panic!("unknown pem tag {}", pem.tag());
        }
    }
}

pub(crate) fn process_pem_public_key(pem: &pem::Pem) -> Option<CryptoObject> {
    Some(PublicKey::from_rsa_bytes(&bytes::Bytes::copy_from_slice(pem.contents())).into())
}

/// Given an RSA private key PEM, record it in the appropriate data structures.
pub(crate) fn process_pem_rsa_private_key(pem: &pem::Pem) -> Option<CryptoObject> {
    let rsa_private_key = rsa::RsaPrivateKey::from_pkcs1_pem(&pem.to_string()).unwrap();

    let private_part = PrivateKey::Rsa(rsa_private_key);
    let public_part = PublicKey::from(&private_part);

    Some((private_part, public_part).into())
}

/// Given an EC private key PEM, record it in the appropriate data structures.
pub(crate) fn process_pem_ec_private_key(pem: &pem::Pem) -> Option<CryptoObject> {
    // First convert to pkcs#8 by shelling out to openssl pkcs8 -topk8 -nocrypt:
    let mut command = Command::new("openssl")
        .arg("pkcs8")
        .arg("-topk8")
        .arg("-nocrypt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    command.stdin.take().unwrap().write_all(pem.to_string().as_bytes()).unwrap();

    let output = command.wait_with_output().unwrap();
    let pem = pem::parse(output.stdout).unwrap();

    let key = pem.to_string().parse::<SecretKey>().unwrap();
    let public_key = key.public_key();

    let private_part = PrivateKey::Ec(Bytes::copy_from_slice(pem.contents()));
    let public_part = PublicKey::Ec(Bytes::copy_from_slice(public_key.to_string().as_bytes()));

    Some((private_part, public_part).into())
}

/// Given a certificate PEM, record it in the appropriate data structures.
pub(crate) fn process_pem_cert(pem: &pem::Pem) -> Option<CryptoObject> {
    let x509_certificate = &x509_certificate::CapturedX509Certificate::from_der(pem.contents()).unwrap();
    let hashable_cert = certificate::Certificate::from(x509_certificate.clone());

    if rules::EXTERNAL_CERTS.contains(&hashable_cert.subject) {
        return None;
    }

    match hashable_cert.original.key_algorithm().unwrap() {
        x509_certificate::KeyAlgorithm::Rsa => {}
        x509_certificate::KeyAlgorithm::Ecdsa(_) => {}
        x509_certificate::KeyAlgorithm::Ed25519 => {
            panic!("ed25519 unsupported");
        }
    }

    Some(CryptoObject::from(hashable_cert))
}

