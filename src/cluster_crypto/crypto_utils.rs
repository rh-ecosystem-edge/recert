use super::certificate;
use super::{distributed_jwt, keys};
use anyhow::{bail, Context, Result};
use bcder::{encode::Values, Mode};
use jwt_simple::prelude::RSAPublicKeyLike;
use pkcs1::DecodeRsaPrivateKey;
use rsa::{self, pkcs8::EncodePrivateKey, RsaPrivateKey};
use serde_json::{Map, Value};
use std::io::Write;
use std::process::Stdio;
use std::{path::PathBuf, process::Command as StdCommand};
use tokio::process::Command;
use x509_certificate::{rfc5280, EcdsaCurve, InMemorySigningKeyPair};

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

pub(crate) fn verify_jwt(
    public_key: &keys::PublicKey,
    distributed_jwt: &distributed_jwt::DistributedJwt,
) -> Result<jwt_simple::prelude::JWTClaims<Map<String, Value>>, jwt_simple::Error> {
    match &public_key {
        keys::PublicKey::Rsa(bytes) => jwt_simple::prelude::RS256PublicKey::from_der(bytes)?,
        keys::PublicKey::Ec(_) => bail!("EC public keys are not supported"),
    }
    .verify_token::<Map<String, Value>>(&distributed_jwt.jwt.str, None)
}

pub(crate) async fn generate_rsa_key_async(key_size: usize) -> Result<InMemorySigningKeyPair> {
    let private_key_parsed_pem = &pem::parse(
        Command::new("openssl")
            .args(["genrsa", &key_size.to_string()])
            .output()
            .await
            .context("openssl genrsa")?
            .stdout,
    )
    .context("private from pem")?;

    let key_pair = InMemorySigningKeyPair::from_pkcs8_der(private_key_parsed_pem.contents()).context("pair from der")?;
    Ok(key_pair)
}

pub(crate) fn generate_rsa_key(key_size: usize) -> Result<InMemorySigningKeyPair> {
    let key_pair = InMemorySigningKeyPair::from_pkcs8_pem(
        StdCommand::new("openssl")
            .args(["genrsa", &key_size.to_string()])
            .output()
            .context("openssl genrsa")?
            .stdout,
    )
    .context("pair from der")?;

    Ok(key_pair)
}

pub(crate) fn generate_ec_key(ec_curve: EcdsaCurve) -> Result<InMemorySigningKeyPair> {
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

    let pkcs8_der_data = StdCommand::new("openssl")
        .args(["pkcs8", "-topk8", "-nocrypt", "-inform", "DER", "-outform", "DER"])
        .stdin(gen_sec1_ec.stdout.unwrap())
        .output()
        .context("openssl pkcs8")?
        .stdout;

    let key_pair = InMemorySigningKeyPair::from_pkcs8_der(pkcs8_der_data).context("pair from der")?;

    Ok(key_pair)
}

pub(crate) fn key_from_pkcs8_file(path: &PathBuf) -> Result<InMemorySigningKeyPair> {
    InMemorySigningKeyPair::from_pkcs8_pem(std::fs::read_to_string(path).context("reading private key file")?.as_str())
        .context("pair from der")
}

pub(crate) fn rsa_key_from_pkcs1_file(path: &PathBuf) -> Result<InMemorySigningKeyPair> {
    let rsa_private_key = RsaPrivateKey::from_pkcs1_pem(std::fs::read_to_string(path).context("reading private key file")?.as_str())
        .context("private from pem")?;
    let rsa_pkcs8_der_bytes: Vec<u8> = rsa_private_key.to_pkcs8_der().context("private to der")?.as_bytes().into();
    let key_pair = InMemorySigningKeyPair::from_pkcs8_der(rsa_pkcs8_der_bytes).context("pair from der")?;
    Ok(key_pair)
}

pub(crate) fn key_from_file(path: &PathBuf) -> Result<InMemorySigningKeyPair> {
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
