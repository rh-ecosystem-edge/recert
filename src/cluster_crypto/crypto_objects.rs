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
        "PUBLIC KEY" => process_pem_spki_public_key(pem).context("processing SPKI public key"),
        "RSA PUBLIC KEY" => Ok(process_pem_public_key(pem)),
        "ENTITLEMENT DATA" | "RSA SIGNATURE" => Ok(None),
        _ => bail!("unknown pem tag {}", pem.tag()),
    }
}

fn process_pem_private_key(pem: &pem::Pem) -> Result<Option<CryptoObject>> {
    let pkcs8_der = pem.contents().to_vec();
    let pair = super::crypto_utils::signing_key_pair_from_pkcs8_der(&pkcs8_der)?;

    Ok(match pair {
        InMemorySigningKeyPair::Ecdsa(_, _, ecdsa_pkcs8_der) => {
            let pubkey_pem = super::crypto_utils::pubkey_pem_from_pkcs8_der(&ecdsa_pkcs8_der).context("extracting EC public key")?;

            let private_part = PrivateKey::Ec(Bytes::from(ecdsa_pkcs8_der));
            let public_part = PublicKey::Ec(pubkey_pem.into());

            Some((private_part, public_part).into())
        }
        InMemorySigningKeyPair::Ed25519(_) => {
            let private_part = PrivateKey::Ed25519(Bytes::from(pkcs8_der));
            let public_part = PublicKey::try_from(&private_part)?;

            Some((private_part, public_part).into())
        }
        InMemorySigningKeyPair::Rsa(_, bytes) => {
            let rsa_private_key = rsa::RsaPrivateKey::from_pkcs1_der(&bytes)?;

            let private_part = PrivateKey::Rsa(rsa_private_key);
            let public_part = PublicKey::try_from(&private_part)?;

            Some((private_part, public_part).into())
        }
    })
}

fn process_pem_spki_public_key(pem: &pem::Pem) -> Result<Option<CryptoObject>> {
    let pem_bytes = pem.to_string();
    let spki_der = pem.contents();

    let ec_oid = simple_asn1::oid!(1, 2, 840, 10045, 2, 1);
    let ed25519_oid = simple_asn1::oid!(1, 3, 101, 112);

    let blocks = simple_asn1::from_der(spki_der).context("parsing SPKI DER")?;
    let top = blocks.into_iter().next().context("empty ASN.1")?;

    if let simple_asn1::ASN1Block::Sequence(_, items) = top {
        if let Some(simple_asn1::ASN1Block::Sequence(_, alg_items)) = items.first() {
            if let Some(simple_asn1::ASN1Block::ObjectIdentifier(_, alg_oid)) = alg_items.first() {
                if *alg_oid == ec_oid {
                    return Ok(Some(PublicKey::Ec(Bytes::from(pem_bytes.into_bytes())).into()));
                } else if *alg_oid == ed25519_oid {
                    return Ok(Some(PublicKey::Ed25519(Bytes::from(pem_bytes.into_bytes())).into()));
                }
            }
        }
    }

    bail!("unsupported PUBLIC KEY algorithm in SPKI")
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
    let pkcs8_pem = pem::parse(output.stdout)?;
    let pkcs8_der = pkcs8_pem.contents();

    let pubkey_pem = super::crypto_utils::pubkey_pem_from_pkcs8_der(pkcs8_der).context("extracting EC public key")?;

    let private_part = PrivateKey::Ec(Bytes::copy_from_slice(pkcs8_der));
    let public_part = PublicKey::Ec(pubkey_pem.into());

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
        x509_certificate::KeyAlgorithm::Ed25519 => {}
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
    fn test_process_pem_private_key_ed25519_pkcs8() {
        let output = Command::new("openssl")
            .args(["genpkey", "-algorithm", "Ed25519"])
            .output()
            .expect("failed to generate Ed25519 key");
        assert!(output.status.success(), "openssl genpkey Ed25519 failed");

        let parsed = pem::parse(&output.stdout).expect("failed to parse PEM");
        assert_eq!(parsed.tag(), "PRIVATE KEY");

        let result = process_pem_private_key(&parsed).expect("process_pem_private_key failed");
        let crypto_obj = result.expect("expected Some(CryptoObject)");

        match crypto_obj {
            CryptoObject::PrivateKey(private_key, public_key) => {
                match &private_key {
                    PrivateKey::Ed25519(bytes) => {
                        assert_eq!(bytes.as_ref(), parsed.contents(), "stored bytes should be PKCS#8 DER");
                    }
                    _ => panic!("expected PrivateKey::Ed25519"),
                }
                match &public_key {
                    PublicKey::Ed25519(pem_bytes) => {
                        let pub_pem = pem::parse(pem_bytes.as_ref()).expect("public key should be valid PEM");
                        assert_eq!(pub_pem.tag(), "PUBLIC KEY");
                    }
                    _ => panic!("expected PublicKey::Ed25519"),
                }
            }
            _ => panic!("expected CryptoObject::PrivateKey"),
        }
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

    fn generate_ed25519_self_signed_cert() -> Vec<u8> {
        let key_output = Command::new("openssl")
            .args(["genpkey", "-algorithm", "Ed25519"])
            .output()
            .expect("failed to generate Ed25519 key");
        assert!(key_output.status.success());

        let mut key_file = tempfile::NamedTempFile::new().unwrap();
        key_file.write_all(&key_output.stdout).unwrap();

        let cert_output = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-key",
                key_file.path().to_str().unwrap(),
                "-subj",
                "/CN=ed25519-test",
                "-days",
                "1",
            ])
            .output()
            .expect("failed to generate self-signed Ed25519 cert");
        assert!(
            cert_output.status.success(),
            "openssl req failed: {}",
            String::from_utf8_lossy(&cert_output.stderr)
        );
        cert_output.stdout
    }

    #[test]
    fn test_process_pem_cert_ed25519() {
        let cert_pem = generate_ed25519_self_signed_cert();
        let parsed = pem::parse(&cert_pem).expect("failed to parse cert PEM");
        assert_eq!(parsed.tag(), "CERTIFICATE");

        let result = process_pem_cert(&parsed, &super::super::scanning::ExternalCerts::empty());
        assert!(result.is_ok(), "process_pem_cert should accept Ed25519 certs: {:?}", result.err());
        assert!(result.unwrap().is_some(), "should return Some(CryptoObject)");
    }

    #[test]
    fn test_certificate_try_from_ed25519() {
        let cert_pem = generate_ed25519_self_signed_cert();
        let parsed = pem::parse(&cert_pem).expect("failed to parse cert PEM");
        let x509 = x509_certificate::CapturedX509Certificate::from_der(parsed.contents()).expect("failed to parse DER");

        let cert = certificate::Certificate::try_from(&x509);
        assert!(cert.is_ok(), "Certificate::try_from should work for Ed25519: {:?}", cert.err());

        let cert = cert.unwrap();
        assert!(matches!(cert.public_key, PublicKey::Ed25519(_)), "expected PublicKey::Ed25519");
    }

    #[test]
    fn test_ed25519_private_key_pem_round_trip() {
        let output = Command::new("openssl")
            .args(["genpkey", "-algorithm", "Ed25519"])
            .output()
            .expect("failed to generate Ed25519 key");
        assert!(output.status.success());

        let parsed = pem::parse(&output.stdout).expect("failed to parse PEM");
        let result = process_pem_private_key(&parsed).expect("process failed");
        let crypto_obj = result.expect("expected Some");

        match crypto_obj {
            CryptoObject::PrivateKey(private_key, public_key) => {
                let priv_pem = private_key.pem().expect("PrivateKey::pem() should succeed");
                assert_eq!(priv_pem.tag(), "PRIVATE KEY");
                assert_eq!(priv_pem.contents(), parsed.contents());

                let pub_pem = public_key.pem().expect("PublicKey::pem() should succeed");
                assert_eq!(pub_pem.tag(), "PUBLIC KEY");
            }
            _ => panic!("expected CryptoObject::PrivateKey"),
        }
    }

    #[test]
    fn test_process_pem_private_key_corrupted_der() {
        let garbage = pem::Pem::new("PRIVATE KEY", vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let result = process_pem_private_key(&garbage);
        assert!(result.is_err(), "corrupted DER should produce an error");
    }

    #[test]
    fn test_ed25519_resign_produces_valid_cert() {
        use super::super::crypto_utils::fix_ed25519_alg_id;
        use bcder::encode::Values;
        use x509_certificate::{rfc5280, InMemorySigningKeyPair, KeyAlgorithm, Sign, Signer, X509Certificate};

        let cert_pem = generate_ed25519_self_signed_cert();
        let parsed = pem::parse(&cert_pem).expect("failed to parse cert PEM");
        let x509 = x509_certificate::CapturedX509Certificate::from_der(parsed.contents()).expect("failed to parse DER");

        let certificate: &rfc5280::Certificate = x509.as_ref();
        let mut tbs_certificate = certificate.tbs_certificate.clone();

        let (new_key, _doc) = InMemorySigningKeyPair::generate_random(KeyAlgorithm::Ed25519).expect("failed to generate Ed25519 key");

        tbs_certificate.subject_public_key_info = rfc5280::SubjectPublicKeyInfo {
            algorithm: KeyAlgorithm::from(&new_key).into(),
            subject_public_key: bcder::BitString::new(0, bytes::Bytes::copy_from_slice(&new_key.public_key_data())),
        };

        let signature_algorithm: rfc5280::AlgorithmIdentifier = new_key.signature_algorithm().expect("sig alg").into();
        tbs_certificate.signature = signature_algorithm.clone();

        let mut tbs_der = Vec::<u8>::new();
        tbs_certificate
            .encode_ref()
            .write_encoded(bcder::Mode::Der, &mut tbs_der)
            .expect("failed to encode TBS");
        let tbs_der = fix_ed25519_alg_id(&tbs_der);

        let signature = new_key.try_sign(&tbs_der).expect("signing failed");

        let cert = rfc5280::Certificate {
            tbs_certificate,
            signature_algorithm,
            signature: bcder::BitString::new(0, bytes::Bytes::copy_from_slice(signature.as_ref())),
        };

        let cert_der = fix_ed25519_alg_id(&X509Certificate::from(cert).encode_der().expect("encode_der"));
        let new_cert = x509_certificate::CapturedX509Certificate::from_der(cert_der).expect("from_der");

        let new_cert_pem = new_cert.encode_pem();
        let mut child = Command::new("openssl")
            .args(["x509", "-pubkey", "-noout"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn openssl");

        use std::io::Write;
        child.stdin.take().unwrap().write_all(new_cert_pem.as_bytes()).unwrap();
        let output = child.wait_with_output().expect("failed to wait");

        assert!(
            output.status.success(),
            "openssl should be able to parse re-signed Ed25519 cert. stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn test_try_from_in_memory_signing_key_pair_bails_on_ed25519() {
        let output = Command::new("openssl")
            .args(["genpkey", "-algorithm", "Ed25519"])
            .output()
            .expect("failed to generate Ed25519 key");
        assert!(output.status.success());

        let parsed = pem::parse(&output.stdout).expect("failed to parse PEM");
        let pair = crate::cluster_crypto::crypto_utils::signing_key_pair_from_pkcs8_der(parsed.contents()).expect("failed to parse key");

        let result = PrivateKey::try_from(&pair);
        assert!(result.is_err(), "TryFrom should bail for Ed25519");
        assert!(
            result.unwrap_err().to_string().contains("Ed25519"),
            "error message should mention Ed25519"
        );
    }

    fn generate_ed25519_pkcs8_pem() -> Vec<u8> {
        let output = Command::new("openssl")
            .args(["genpkey", "-algorithm", "Ed25519"])
            .output()
            .expect("failed to generate Ed25519 key");
        assert!(output.status.success(), "openssl genpkey Ed25519 failed");
        output.stdout
    }

    fn generate_ed25519_key_pair() -> (PrivateKey, PublicKey) {
        let pem_bytes = generate_ed25519_pkcs8_pem();
        let parsed = pem::parse(&pem_bytes).expect("failed to parse PEM");
        let result = process_pem_private_key(&parsed).expect("process failed").expect("expected Some");
        match result {
            CryptoObject::PrivateKey(private_key, public_key) => (private_key, public_key),
            _ => panic!("expected CryptoObject::PrivateKey"),
        }
    }

    fn assert_is_ec_public_key_pem(public_key: &PublicKey) {
        match public_key {
            PublicKey::Ec(pem_bytes) => {
                let pub_pem = pem::parse(pem_bytes.as_ref()).expect("public key should be valid PEM");
                assert_eq!(pub_pem.tag(), "PUBLIC KEY");
            }
            _ => panic!("expected PublicKey::Ec"),
        }
    }

    fn assert_public_key_from_ec_private_key(curve: &str) {
        let pkcs8_pem_bytes = generate_ec_pkcs8_pem(curve);
        let parsed = pem::parse(&pkcs8_pem_bytes).expect("failed to parse PEM");
        let private_key = PrivateKey::Ec(bytes::Bytes::copy_from_slice(parsed.contents()));

        let public_key = PublicKey::try_from(&private_key).expect("PublicKey::try_from should succeed");
        assert_is_ec_public_key_pem(&public_key);
    }

    fn generate_ec_sec1_pem(curve: &str) -> Vec<u8> {
        let output = Command::new("openssl")
            .args(["ecparam", "-name", curve, "-genkey", "-noout"])
            .output()
            .expect("failed to generate EC key");
        assert!(output.status.success());
        output.stdout
    }

    fn assert_sec1_ec_key_round_trips(curve: &str) {
        let sec1_pem_bytes = generate_ec_sec1_pem(curve);
        let parsed = pem::parse(&sec1_pem_bytes).expect("failed to parse PEM");
        assert_eq!(parsed.tag(), "EC PRIVATE KEY");

        let result = process_pem_ec_private_key(&parsed).expect("process_pem_ec_private_key failed");
        let crypto_obj = result.expect("expected Some(CryptoObject)");

        match crypto_obj {
            CryptoObject::PrivateKey(private_key, public_key) => {
                match &private_key {
                    PrivateKey::Ec(bytes) => {
                        assert_ne!(bytes.as_ref(), parsed.contents(), "stored bytes should differ from SEC1 input");
                        InMemorySigningKeyPair::from_pkcs8_der(bytes.as_ref()).expect("stored bytes should be valid PKCS#8 DER");
                    }
                    _ => panic!("expected PrivateKey::Ec"),
                }
                assert_is_ec_public_key_pem(&public_key);
            }
            _ => panic!("expected CryptoObject::PrivateKey"),
        }
    }

    #[test]
    fn test_public_key_from_ec_p256_private_key() {
        assert_public_key_from_ec_private_key("prime256v1");
    }

    #[test]
    fn test_public_key_from_ec_p384_private_key() {
        assert_public_key_from_ec_private_key("secp384r1");
    }

    #[test]
    fn test_public_key_from_ed25519_private_key() {
        let (private_key, _) = generate_ed25519_key_pair();
        let public_key = PublicKey::try_from(&private_key).expect("PublicKey::try_from should succeed for Ed25519");
        assert!(matches!(public_key, PublicKey::Ed25519(_)), "expected PublicKey::Ed25519");
    }

    #[test]
    fn test_ed25519_private_key_serialize() {
        let (private_key, _) = generate_ed25519_key_pair();
        let serialized = serde_json::to_string(&private_key).expect("serialize should succeed");
        assert!(
            serialized.contains("PRIVATE KEY"),
            "serialized Ed25519 key should contain PRIVATE KEY tag"
        );
        assert!(!serialized.contains("EC PRIVATE KEY"), "should not contain EC PRIVATE KEY tag");
    }

    #[test]
    fn test_process_pem_ec_private_key_sec1_p256() {
        assert_sec1_ec_key_round_trips("prime256v1");
    }

    #[test]
    fn test_process_pem_ec_private_key_sec1_p384() {
        assert_sec1_ec_key_round_trips("secp384r1");
    }

    #[test]
    fn test_process_pem_ec_private_key_corrupted_sec1() {
        let garbage = pem::Pem::new("EC PRIVATE KEY", vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let result = process_pem_ec_private_key(&garbage);
        assert!(result.is_err(), "corrupted SEC1 DER should produce an error");
    }

    #[test]
    fn test_process_pem_bundle_mixed_ec_rsa() {
        let ec_pem_bytes = generate_ec_pkcs8_pem("prime256v1");
        let rsa_output = Command::new("openssl")
            .args(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"])
            .output()
            .expect("failed to generate RSA key");
        assert!(rsa_output.status.success());

        let mut bundle = String::from_utf8(ec_pem_bytes).expect("EC PEM not UTF-8");
        bundle.push_str(&String::from_utf8(rsa_output.stdout).expect("RSA PEM not UTF-8"));

        let pems = pem::parse_many(&bundle).expect("failed to parse bundle");
        assert_eq!(pems.len(), 2);

        let mut found_ec = false;
        let mut found_rsa = false;
        for p in &pems {
            let result = process_single_pem(p, &super::super::scanning::ExternalCerts::empty())
                .expect("process_single_pem failed")
                .expect("expected Some");
            match result {
                CryptoObject::PrivateKey(PrivateKey::Ec(_), _) => found_ec = true,
                CryptoObject::PrivateKey(PrivateKey::Rsa(_), _) => found_rsa = true,
                _ => panic!("unexpected CryptoObject variant"),
            }
        }
        assert!(found_ec, "should find EC key in bundle");
        assert!(found_rsa, "should find RSA key in bundle");
    }
}
