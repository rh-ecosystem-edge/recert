use crate::cluster_crypto::{
    crypto_utils::{self, SigningKey},
    keys::PublicKey,
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as base64_url, Engine as _};
use std::{io::Write, process::Command};
use x509_certificate::InMemorySigningKeyPair;

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

    if alg != "RS256" {
        bail!("unsupported alg {}", alg);
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

    let (kid, pem_bytes) = match &private_key.in_memory_signing_key_pair {
        InMemorySigningKeyPair::Ecdsa(_, _, _) => {
            bail!("ecdsa unsupported");
        }
        InMemorySigningKeyPair::Ed25519(_) => {
            bail!("ed unsupported");
        }
        InMemorySigningKeyPair::Rsa(_rsa_key_pair, bytes) => (
            base64_url.encode(crypto_utils::sha256(bytes).context("calculating kid")?),
            private_key.pkcs8_pem.clone(),
        ),
    };

    header_json
        .as_object_mut()
        .context("headern not objecT")?
        .insert("kid".to_string(), serde_json::Value::String(kid));

    let header_json = serde_json::to_string(&header_json)?;

    let header_payload = format!("{}.{}", base64_url.encode(header_json.as_bytes()), payload);

    let mut header_payload_file = tempfile::NamedTempFile::new()?;
    header_payload_file.write_all(header_payload.as_bytes())?;
    header_payload_file.flush()?;

    let mut pem_file = tempfile::NamedTempFile::new()?;
    pem_file.write_all(pem_bytes.as_slice())?;

    let output = Command::new("openssl")
        .arg("dgst")
        .arg("-sha256")
        .arg("-sign")
        .arg(pem_file.path())
        .arg(header_payload_file.path())
        .output()?;

    Ok(format!("{}.{}", header_payload, base64_url.encode(output.stdout)))
}
