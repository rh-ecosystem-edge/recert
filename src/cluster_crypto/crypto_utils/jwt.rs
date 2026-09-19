use crate::cluster_crypto::{crypto_utils::SigningKey, keys::PublicKey};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as base64_url, Engine as _};
use std::{io::Write, process::Command};

pub(crate) fn verify(jwt: &str, public_key: &PublicKey) -> Result<bool> {
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

    let mut cert_file = tempfile::NamedTempFile::new()?;
    cert_file.write_all(pub_pem.as_bytes())?;
    cert_file.flush()?;

    let mut signature_file = tempfile::NamedTempFile::new()?;
    signature_file.write_all(signature_decoded.as_slice())?;
    signature_file.flush()?;

    let mut header_payload_file = tempfile::NamedTempFile::new()?;
    header_payload_file.write_all(header_payload.as_bytes())?;
    header_payload_file.flush()?;

    let output = match alg {
        "RS256" => Command::new("openssl")
            .args([
                "dgst",
                "-sha256",
                "-verify",
                cert_file.path().to_str().context("cert path")?,
                "-signature",
                signature_file.path().to_str().context("sig path")?,
                header_payload_file.path().to_str().context("data path")?,
            ])
            .output()?,
        "ES256" => Command::new("openssl")
            .args([
                "dgst",
                "-sha256",
                "-verify",
                cert_file.path().to_str().context("cert path")?,
                "-signature",
                signature_file.path().to_str().context("sig path")?,
                header_payload_file.path().to_str().context("data path")?,
            ])
            .output()?,
        "ES384" => Command::new("openssl")
            .args([
                "dgst",
                "-sha384",
                "-verify",
                cert_file.path().to_str().context("cert path")?,
                "-signature",
                signature_file.path().to_str().context("sig path")?,
                header_payload_file.path().to_str().context("data path")?,
            ])
            .output()?,
        "EdDSA" => Command::new("openssl")
            .args([
                "pkeyutl",
                "-verify",
                "-inkey",
                cert_file.path().to_str().context("cert path")?,
                "-pubin",
                "-rawin",
                "-in",
                header_payload_file.path().to_str().context("data path")?,
                "-sigfile",
                signature_file.path().to_str().context("sig path")?,
            ])
            .output()?,
        _ => {
            log::warn!("unsupported JWT alg {}", alg);
            return Ok(false);
        }
    };

    Ok(output.status.success())
}

pub(crate) fn resign(jwt: &str, private_key: &SigningKey) -> Result<String> {
    let parts = jwt.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Ok(jwt.to_string());
    }

    let header_decoded = base64_url.decode(parts[0].as_bytes())?;
    let payload = parts[1];

    let mut header_json = serde_json::from_slice::<serde_json::Value>(&header_decoded)?;

    let new_alg = private_key.jwt_alg().context("determining JWT algorithm")?;

    let jwt_key_id = private_key.jwt_key_id().context("calculating key id")?;

    let header_obj = header_json.as_object_mut().context("header not object")?;
    header_obj.insert("alg".to_string(), serde_json::Value::String(new_alg.to_string()));
    header_obj.insert("kid".to_string(), serde_json::Value::String(jwt_key_id));

    let header_json = serde_json::to_string(&header_json)?;

    let header_payload = format!("{}.{}", base64_url.encode(header_json.as_bytes()), payload);

    let mut header_payload_file = tempfile::NamedTempFile::new()?;
    header_payload_file.write_all(header_payload.as_bytes())?;
    header_payload_file.flush()?;

    let mut pem_file = tempfile::NamedTempFile::new()?;
    pem_file.write_all(private_key.pkcs8_pem.as_slice())?;
    pem_file.flush()?;

    let output = match new_alg {
        "RS256" | "ES256" => Command::new("openssl")
            .args([
                "dgst",
                "-sha256",
                "-sign",
                pem_file.path().to_str().context("pem path")?,
                header_payload_file.path().to_str().context("data path")?,
            ])
            .output()?,
        "ES384" => Command::new("openssl")
            .args([
                "dgst",
                "-sha384",
                "-sign",
                pem_file.path().to_str().context("pem path")?,
                header_payload_file.path().to_str().context("data path")?,
            ])
            .output()?,
        "EdDSA" => Command::new("openssl")
            .args([
                "pkeyutl",
                "-sign",
                "-inkey",
                pem_file.path().to_str().context("pem path")?,
                "-rawin",
                "-in",
                header_payload_file.path().to_str().context("data path")?,
            ])
            .output()?,
        _ => bail!("unsupported JWT algorithm {}", new_alg),
    };

    if !output.status.success() {
        bail!("JWT signing failed: {}", String::from_utf8_lossy(&output.stderr));
    }

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
    fn test_verify_ec_public_key_bad_signature_returns_false() {
        let key = crate::cluster_crypto::crypto_utils::generate_ec_key(x509_certificate::EcdsaCurve::Secp256r1).unwrap();
        let private_key = key.to_private_key().unwrap();
        let public_key = PublicKey::try_from(&private_key).unwrap();

        // Well-formed ES256 JWT with a valid base64 signature that does not match the key.
        let header = b64.encode(br#"{"alg":"ES256","typ":"JWT"}"#);
        let payload = b64.encode(br#"{"sub":"test"}"#);
        let jwt = format!("{}.{}.AA", header, payload);
        assert!(!verify(&jwt, &public_key).unwrap());
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
    fn test_resign_overwrites_hs256_alg_with_key_alg() {
        // resign replaces the incoming alg with the signing key's algorithm.
        let header = b64.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let jwt = format!("{}.{}.AA", header, b64.encode(br#"{"sub":"test"}"#));
        let resigned = resign(&jwt, rsa_signing_key()).unwrap();
        let parts: Vec<_> = resigned.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header: serde_json::Value = serde_json::from_slice(&b64.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert!(header.get("kid").and_then(|v| v.as_str()).is_some());
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
    fn test_resign_and_verify_es256_roundtrip() {
        let key = crate::cluster_crypto::crypto_utils::generate_ec_key(x509_certificate::EcdsaCurve::Secp256r1).unwrap();
        let resigned = resign(&unsigned_rs256_jwt(), &key).unwrap();
        let parts: Vec<_> = resigned.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header: serde_json::Value = serde_json::from_slice(&b64.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert!(header.get("kid").and_then(|v| v.as_str()).is_some());

        let private_key = key.to_private_key().unwrap();
        let public_key = PublicKey::try_from(&private_key).unwrap();
        assert!(verify(&resigned, &public_key).unwrap());
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
