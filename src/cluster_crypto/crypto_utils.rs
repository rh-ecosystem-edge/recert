use super::certificate;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use bcder::{encode::Values, Mode};
use pkcs1::DecodeRsaPrivateKey;
use rsa::{self, pkcs8::EncodePrivateKey, RsaPrivateKey};
use serde::ser::SerializeStruct;
use std::io::Write;
use std::path::Path;
use std::process::Command as StdCommand;
use std::process::Stdio;
use tokio::process::Command;
use x509_certificate::{rfc5280, EcdsaCurve, InMemorySigningKeyPair};

pub(crate) mod jwt;

pub(crate) struct SigningKey {
    pub in_memory_signing_key_pair: InMemorySigningKeyPair,
    pub pkcs8_pem: Vec<u8>,
}

impl Clone for SigningKey {
    fn clone(&self) -> Self {
        Self {
            in_memory_signing_key_pair: InMemorySigningKeyPair::from_pkcs8_pem(&self.pkcs8_pem).unwrap(),
            pkcs8_pem: self.pkcs8_pem.clone(),
        }
    }
}

impl serde::Serialize for SigningKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut st = serializer.serialize_struct("SigningKey", 2)?;
        st.serialize_field("pkcs8_pem", &base64_standard.encode(&self.pkcs8_pem))?;
        st.end()
    }
}

/// Shell out to openssl to verify that a certificate is signed by a given signing certificate. We
/// use this when our certificate lib doesn't support the signature algorithm used by the
/// certificates.
pub(crate) fn openssl_is_signed(potential_signer: &certificate::Certificate, signee: &certificate::Certificate) -> Result<bool> {
    // TODO: This condition is a hack. We should trust the openssl command we run further down to
    // tell us this, but we don't because currently the way this openssl command works, if you pass
    // it the same cert in both arguments, even when said cert is not self-signed, openssl would
    // give it a green light and say it's valid. So we do this hack to avoid pretending
    // certificates are their own signer when they're not. This is a hack because it's possible
    // that a certificate is not self-signed and has the same issuer and subject and it would pass
    // here undetected. This is not a big deal in our use case because these certs are all coming
    // from our trusted installer/operators.
    if potential_signer == signee && !potential_signer.cert.subject_is_issuer() {
        return Ok(false);
    }

    let mut signing_cert_file = tempfile::NamedTempFile::new()?;
    signing_cert_file.write_all(potential_signer.cert.encode_pem().as_bytes())?;
    let mut signed_cert_file = tempfile::NamedTempFile::new()?;
    signed_cert_file.write_all(signee.cert.encode_pem().as_bytes())?;
    let mut openssl_verify_command = std::process::Command::new("openssl");
    openssl_verify_command
        .arg("verify")
        .arg("-no_check_time")
        .arg("-no-CAfile")
        .arg("-no-CApath")
        .arg("-partial_chain")
        .arg("-trusted")
        .arg(signing_cert_file.path())
        .arg(signed_cert_file.path());
    let openssl_verify_output = openssl_verify_command.output()?;
    Ok(openssl_verify_output.status.success())
}

pub(crate) async fn generate_rsa_key_async(key_size: usize) -> Result<SigningKey> {
    let pkcs8_pem = Command::new("openssl")
        .args(["genrsa", &key_size.to_string()])
        .output()
        .await
        .context("openssl genrsa")?
        .stdout
        .to_vec();

    let in_memory_signing_key_pair = InMemorySigningKeyPair::from_pkcs8_pem(&pkcs8_pem).context("pair from der")?;

    Ok(SigningKey {
        in_memory_signing_key_pair,
        pkcs8_pem,
    })
}

pub(crate) fn generate_rsa_key(key_size: usize) -> Result<SigningKey> {
    let pkcs8_pem = StdCommand::new("openssl")
        .args(["genrsa", &key_size.to_string()])
        .output()
        .context("openssl genrsa")?
        .stdout;

    let key_pair = InMemorySigningKeyPair::from_pkcs8_pem(&pkcs8_pem).context("pair from der")?;

    Ok(SigningKey {
        in_memory_signing_key_pair: key_pair,
        pkcs8_pem,
    })
}

pub(crate) fn generate_ec_key(ec_curve: EcdsaCurve) -> Result<SigningKey> {
    let gen_sec1_ec = StdCommand::new("openssl")
        .args([
            "ecparam",
            "-name",
            match ec_curve {
                EcdsaCurve::Secp256r1 => "prime256v1",
                EcdsaCurve::Secp384r1 => "secp384r1",
            },
            "-genkey",
            "-noout",
            "-outform",
            "DER",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .context("openssl ecdsa")?;

    let pkcs8_pem_data = StdCommand::new("openssl")
        .args(["pkcs8", "-topk8", "-nocrypt", "-inform", "DER"])
        .stdin(gen_sec1_ec.stdout.unwrap())
        .output()
        .context("openssl pkcs8")?
        .stdout;

    let key_pair = InMemorySigningKeyPair::from_pkcs8_pem(&pkcs8_pem_data).context("pair from der")?;

    Ok(SigningKey {
        in_memory_signing_key_pair: key_pair,
        pkcs8_pem: pkcs8_pem_data,
    })
}

pub(crate) fn key_from_pkcs8_file(path: &Path) -> Result<SigningKey> {
    let pkcs8_pem_data = std::fs::read_to_string(path).context("reading private key file")?;
    let in_memory_signing_key_pair = InMemorySigningKeyPair::from_pkcs8_pem(&pkcs8_pem_data).context("pair from der");

    Ok(SigningKey {
        in_memory_signing_key_pair: in_memory_signing_key_pair?,
        pkcs8_pem: pkcs8_pem_data.into(),
    })
}

pub(crate) fn rsa_key_from_pkcs1_file(path: &Path) -> Result<SigningKey> {
    let rsa_private_key = RsaPrivateKey::from_pkcs1_pem(std::fs::read_to_string(path).context("reading private key file")?.as_str())
        .context("private from pem")?;
    let pkcs8_pem_data: Vec<u8> = rsa_private_key
        .to_pkcs8_pem(pkcs1::LineEnding::LF)
        .context("private to pkcs8 pem")?
        .as_bytes()
        .into();
    let in_memory_signing_key_pair = InMemorySigningKeyPair::from_pkcs8_pem(&pkcs8_pem_data).context("pair from der")?;

    Ok(SigningKey {
        in_memory_signing_key_pair,
        pkcs8_pem: pkcs8_pem_data,
    })
}

pub(crate) fn key_from_file(path: &Path) -> Result<SigningKey> {
    let parsed_pem = pem::parse(std::fs::read(path).context("reading private key file")?).context("parsing private key file")?;
    let pem_tag = parsed_pem.tag();

    match pem_tag {
        "RSA PRIVATE KEY" => rsa_key_from_pkcs1_file(path),
        "EC PRIVATE KEY" => bail!("loading non PKCS#8 EC private keys is not yet supported"),
        "PRIVATE KEY" => key_from_pkcs8_file(path),
        _ => bail!("unknown private key format"),
    }
}

pub(crate) fn encode_tbs_cert_to_der(tbs_certificate: &rfc5280::TbsCertificate) -> Result<Vec<u8>> {
    let mut tbs_der = Vec::<u8>::new();
    tbs_certificate.encode_ref().write_encoded(Mode::Der, &mut tbs_der)?;
    Ok(tbs_der)
}

pub(crate) fn sign(signing_key: &SigningKey, tbs_der: &[u8]) -> Result<Vec<u8>> {
    let mut temp_file = tempfile::NamedTempFile::new()?;
    temp_file.write_all(tbs_der)?;

    let mut command = StdCommand::new("openssl")
        .args([
            "dgst",
            "-sha256",
            "-sign",
            "/dev/stdin",
            temp_file.path().to_str().context("getting temp file path")?,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("openssl dgst")?;

    command
        .stdin
        .take()
        .context("getting openssl dgst stdin")?
        .write_all(signing_key.pkcs8_pem.as_slice())
        .context("writing to openssl dgst stdin")?;

    Ok(command.wait_with_output().context("waiting for openssl dgst")?.stdout)
}

pub(crate) fn sha256(data: &[u8]) -> Result<Vec<u8>> {
    // We don't use native Rust sha256 libraries on purpose, because FIPS compliance is a
    // requirement for us, and we don't know if the native libraries are FIPS compliant.

    let mut command = StdCommand::new("openssl")
        .args(["dgst", "-sha256", "-binary"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("openssl dgst")?;

    command
        .stdin
        .take()
        .context("getting openssl dgst stdin")?
        .write_all(data)
        .context("writing to openssl dgst stdin")?;

    Ok(command.wait_with_output().context("waiting for openssl dgst")?.stdout)
}
