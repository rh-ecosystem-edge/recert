use crate::cluster_crypto::{crypto_utils::SigningKey, keys::PublicKey};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as base64_url, Engine as _};
use std::{io::Write, process::Command};

/// The `openssl dgst` digest flag for JWT algorithms that are signed over a digest. EdDSA signs the
/// raw message and is handled separately via `openssl pkeyutl`.
fn digest_for_alg(alg: &str) -> Option<&'static str> {
    match alg {
        "RS256" | "ES256" => Some("-sha256"),
        "ES384" => Some("-sha384"),
        _ => None,
    }
}

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

    let cert_path = cert_file.path().to_str().context("cert path")?;
    let sig_path = signature_file.path().to_str().context("sig path")?;
    let data_path = header_payload_file.path().to_str().context("data path")?;

    let mut command = Command::new("openssl");
    match alg {
        "EdDSA" => command.args([
            "pkeyutl", "-verify", "-inkey", cert_path, "-pubin", "-rawin", "-in", data_path, "-sigfile", sig_path,
        ]),
        _ => match digest_for_alg(alg) {
            Some(digest) => command.args(["dgst", digest, "-verify", cert_path, "-signature", sig_path, data_path]),
            None => {
                log::warn!("unsupported JWT alg {}", alg);
                return Ok(false);
            }
        },
    };
    let output = command.output()?;

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

    let pem_path = pem_file.path().to_str().context("pem path")?;
    let data_path = header_payload_file.path().to_str().context("data path")?;

    let mut command = Command::new("openssl");
    match new_alg {
        "EdDSA" => command.args(["pkeyutl", "-sign", "-inkey", pem_path, "-rawin", "-in", data_path]),
        _ => match digest_for_alg(new_alg) {
            Some(digest) => command.args(["dgst", digest, "-sign", pem_path, data_path]),
            None => bail!("unsupported JWT algorithm {}", new_alg),
        },
    };
    let output = command.output()?;

    if !output.status.success() {
        bail!("JWT signing failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(format!("{}.{}", header_payload, base64_url.encode(output.stdout)))
}
