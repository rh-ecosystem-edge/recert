use crate::cluster_crypto::{crypto_utils::SigningKey, keys::PublicKey};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as base64_url, Engine as _};
use std::{io::Write, process::Command};
use x509_certificate::InMemorySigningKeyPair;

pub(crate) fn verify(jwt: &str, public_key: &PublicKey) -> Result<bool> {
    if let PublicKey::Ec(_) = public_key {
        return Ok(false);
    };

    let pub_pem = public_key.pem()?.to_string();

    let parts = jwt.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        bail!("jwt not 3 parts");
    }

    let header_decoded = base64_url.decode(parts[0].as_bytes())?;
    let signature_decoded = base64_url.decode(parts[2].as_bytes())?;

    let header_payload = format!("{}.{}", parts[0], parts[1]);

    let header_json = serde_json::from_slice::<serde_json::Value>(&header_decoded)?;

    let alg = header_json
        .get("alg")
        .context("jwt missing alg")?
        .as_str()
        .context("alg not string")?;

    if alg != "RS256" {
        log::warn!("unsupported alg {}", alg);
        return Ok(false);
    }

    let mut cert_file = tempfile::NamedTempFile::new()?;
    cert_file.write_all(pub_pem.as_bytes())?;
    cert_file.flush()?;

    let mut signature_file = tempfile::NamedTempFile::new()?;
    signature_file.write_all(signature_decoded.as_slice())?;
    signature_file.flush()?;

    let mut header_payload_file = tempfile::NamedTempFile::new()?;
    header_payload_file.write_all(header_payload.as_bytes())?;
    header_payload_file.flush()?;

    let output = Command::new("openssl")
        .arg("dgst")
        .arg("-sha256")
        .arg("-verify")
        .arg(cert_file.path())
        .arg("-signature")
        .arg(signature_file.path())
        .arg(header_payload_file.path())
        .output()?;

    Ok(output.status.success())
}

pub(crate) fn resign(jwt: &str, private_key: &SigningKey) -> Result<String> {
    let parts = jwt.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Ok(jwt.to_string());
    }

    let header_decoded = base64_url.decode(parts[0].as_bytes())?;
    let payload = parts[1]; // No need to decode this, we're just passing it through

    let mut header_json = serde_json::from_slice::<serde_json::Value>(&header_decoded)?;

    let alg = header_json
        .get("alg")
        .context("jwt missing alg")?
        .as_str()
        .context("alg not string")?;

    if alg != "RS256" {
        bail!("unsupported alg {}", alg);
    }

    let (jwt_key_id, private_pem_bytes) = match &private_key.in_memory_signing_key_pair {
        InMemorySigningKeyPair::Ecdsa(_, _, _) => {
            bail!("ecdsa unsupported");
        }
        InMemorySigningKeyPair::Ed25519(_) => {
            bail!("ed unsupported");
        }
        InMemorySigningKeyPair::Rsa(_rsa_key_pair, _bytes) => (
            private_key.jwt_key_id().context("calculating key id")?,
            private_key.pkcs8_pem.clone(),
        ),
    };

    header_json
        .as_object_mut()
        .context("headern not objecT")?
        .insert("kid".to_string(), serde_json::Value::String(jwt_key_id));

    let header_json = serde_json::to_string(&header_json)?;

    let header_payload = format!("{}.{}", base64_url.encode(header_json.as_bytes()), payload);

    let mut header_payload_file = tempfile::NamedTempFile::new()?;
    header_payload_file.write_all(header_payload.as_bytes())?;
    header_payload_file.flush()?;

    let mut pem_file = tempfile::NamedTempFile::new()?;
    pem_file.write_all(private_pem_bytes.as_slice())?;

    let output = Command::new("openssl")
        .arg("dgst")
        .arg("-sha256")
        .arg("-sign")
        .arg(pem_file.path())
        .arg(header_payload_file.path())
        .output()?;

    Ok(format!("{}.{}", header_payload, base64_url.encode(output.stdout)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_crypto::crypto_utils::{generate_rsa_key, SigningKey};
    use crate::cluster_crypto::keys::{PrivateKey, PublicKey};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as b64;

    fn unsigned_rs256_jwt() -> String {
        let header = b64.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = b64.encode(br#"{"sub":"test"}"#);
        format!("{}.{}.AA", header, payload)
    }

    fn rsa_signing_key() -> &'static SigningKey {
        static KEY: std::sync::OnceLock<SigningKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| generate_rsa_key(2048).unwrap())
    }

    fn dummy_rsa_public_key() -> PublicKey {
        PublicKey::Rsa(bytes::Bytes::from_static(b"not-a-real-key"))
    }

    fn rsa_public_key() -> PublicKey {
        let private_key = PrivateKey::try_from(&rsa_signing_key().in_memory_signing_key_pair).unwrap();
        PublicKey::try_from(&private_key).unwrap()
    }

    #[test]
    fn test_verify_rejects_non_three_part_jwt() {
        assert!(verify("not-a-jwt", &dummy_rsa_public_key()).is_err());
    }

    #[test]
    fn test_verify_ec_public_key_returns_false() {
        let public_key = PublicKey::Ec(bytes::Bytes::from_static(
            b"-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----",
        ));
        assert!(!verify("a.b.c", &public_key).unwrap());
    }

    #[test]
    fn test_verify_unsupported_alg_returns_false() {
        let header = b64.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let jwt = format!("{}.{}.AA", header, b64.encode(br#"{"sub":"test"}"#));
        assert!(!verify(&jwt, &dummy_rsa_public_key()).unwrap());
    }

    #[test]
    fn test_resign_passthrough_when_not_three_parts() {
        assert_eq!(resign("not-a-jwt", rsa_signing_key()).unwrap(), "not-a-jwt");
    }

    #[test]
    fn test_resign_rejects_non_rs256() {
        let header = b64.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let jwt = format!("{}.{}.AA", header, b64.encode(br#"{"sub":"test"}"#));
        assert!(resign(&jwt, rsa_signing_key()).unwrap_err().to_string().contains("unsupported alg"));
    }

    #[test]
    fn test_verify_missing_alg_errors() {
        let header = b64.encode(br#"{"typ":"JWT"}"#);
        let jwt = format!("{}.{}.AA", header, b64.encode(br#"{"sub":"test"}"#));
        assert!(verify(&jwt, &dummy_rsa_public_key())
            .unwrap_err()
            .to_string()
            .contains("jwt missing alg"));
    }

    #[test]
    fn test_resign_rejects_ecdsa_key() {
        let key = crate::cluster_crypto::crypto_utils::generate_ec_key(x509_certificate::EcdsaCurve::Secp256r1).unwrap();
        assert!(resign(&unsigned_rs256_jwt(), &key)
            .unwrap_err()
            .to_string()
            .contains("ecdsa unsupported"));
    }

    #[test]
    fn test_resign_and_verify_rs256_roundtrip() {
        let key = rsa_signing_key();
        let jwt = unsigned_rs256_jwt();
        let resigned = resign(&jwt, key).unwrap();
        let parts: Vec<_> = resigned.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header: serde_json::Value = serde_json::from_slice(&b64.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert!(header.get("kid").and_then(|v| v.as_str()).is_some());
        assert!(verify(&resigned, &rsa_public_key()).unwrap());
    }
}
