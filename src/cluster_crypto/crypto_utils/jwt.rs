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
