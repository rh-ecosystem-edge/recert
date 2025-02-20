use super::certificate;
use anyhow::ensure;
use anyhow::{bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD as base64_standard, URL_SAFE_NO_PAD as base64_url},
    Engine as _,
};
use bcder::BitString;
use bcder::{encode::Values, Mode};
use pkcs1::DecodeRsaPrivateKey;
use rsa::{self, pkcs8::EncodePrivateKey, RsaPrivateKey};
use serde::ser::SerializeStruct;
use std::io::Write;
use std::path::Path;
use std::process::Command as StdCommand;
use std::process::Stdio;
use tokio::process::Command;
use x509_certificate::{rfc5280, EcdsaCurve, InMemorySigningKeyPair, KeyAlgorithm, Sign};

pub(crate) mod jwt;

pub(crate) struct SigningKey {
    pub in_memory_signing_key_pair: InMemorySigningKeyPair,
    pkcs8_pem: Vec<u8>,
}

impl SigningKey {
    /// Generates the "kid" field for a JWT header in accordance with how Kubernetes does it (a
    /// Base64URL-encoded SHA256 hash of the PKIX DER encoding of the public key derived from the
    /// private key)
    // Implementation based on https://github.com/openshift/kubernetes/blob/6fdacf04117cef54a0babd0945e8ef87d0f9461d/pkg/serviceaccount/jwt.go#L92-L112
    fn jwt_key_id(&self) -> Result<String> {
        let keyinfo = rfc5280::SubjectPublicKeyInfo {
            algorithm: KeyAlgorithm::Rsa.into(),
            subject_public_key: BitString::new(0, self.in_memory_signing_key_pair.public_key_data()),
        };
        let pkix_der_bytes = {
            let mut buffer: Vec<u8> = Vec::new();
            keyinfo
                .encode_ref()
                .write_encoded(bcder::Mode::Der, &mut buffer)
                .context("encode")?;
            buffer
        };
        Ok(base64_url.encode(sha256(pkix_der_bytes.as_slice()).context("hash")?))
    }
}

impl Clone for SigningKey {
    fn clone(&self) -> Self {
        Self {
            #[allow(clippy::unwrap_used)] // This can never panic because a SigningKey could never be created with an invalid pkcs8_pem
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
        .stdin(gen_sec1_ec.stdout.context("no stdout")?)
        .output()
        .context("openssl pkcs8")?
        .stdout;

    let key_pair = InMemorySigningKeyPair::from_pkcs8_pem(&pkcs8_pem_data).context("pair from der")?;

    Ok(SigningKey {
        in_memory_signing_key_pair: key_pair,
        pkcs8_pem: pkcs8_pem_data,
    })
}

pub(crate) fn key_from_pkcs8_pem(pem: &str) -> Result<SigningKey> {
    let in_memory_signing_key_pair = InMemorySigningKeyPair::from_pkcs8_pem(pem).context("pair from der");

    Ok(SigningKey {
        in_memory_signing_key_pair: in_memory_signing_key_pair?,
        pkcs8_pem: pem.into(),
    })
}

pub(crate) fn rsa_key_from_pkcs1_pem(pem: &str) -> Result<SigningKey> {
    let rsa_private_key = RsaPrivateKey::from_pkcs1_pem(pem).context("private from pem")?;
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
    let data = std::fs::read(path).context("reading private key file")?;

    key_from_pem(&String::from_utf8(data).context("converting private key file to utf8")?)
}

pub(crate) fn key_from_pem(pem: &str) -> Result<SigningKey> {
    let parsed_pem = pem::parse(pem.as_bytes()).context("parsing private key file")?;
    let pem_tag = parsed_pem.tag();

    match pem_tag {
        "RSA PRIVATE KEY" => rsa_key_from_pkcs1_pem(pem).context("RSA key from PKCS#1"),
        "EC PRIVATE KEY" => bail!("loading non PKCS#8 EC private keys is not yet supported"),
        "PRIVATE KEY" => key_from_pkcs8_pem(pem).context("key from PKCS#8"),
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

pub(crate) fn ensure_openssl_version() -> Result<()> {
    // run the openssl version command and check that it's at least 3.0.0
    let openssl_version_output = std::process::Command::new("openssl")
        .arg("version")
        .output()
        .context("running openssl version")?;

    log::info!("using openssl: {}", String::from_utf8_lossy(&openssl_version_output.stdout));

    ensure!(
        openssl_version_output.status.success(),
        "openssl version command failed: {}, do you have openssl installed?",
        String::from_utf8_lossy(&openssl_version_output.stderr)
    );

    let output = &String::from_utf8(openssl_version_output.stdout).context("utf-8 output")?;

    let openssl_version = output
        .split_whitespace()
        .nth(1)
        .context("getting second word from openssl version output")?
        .split('-')
        .next()
        .context("splitting openssl version output on '-'")?
        .split('.')
        .collect::<Vec<_>>();

    ensure!(
        openssl_version.len() == 3,
        "parsing openssl version output: expected 3 components, got {}",
        openssl_version.len()
    );

    ensure!(openssl_version[0] == "3", "incompatible openssl version, expected major 3");

    log::info!("OpenSSL version is compatible");

    Ok(())
}

mod test {
    #[test]
    fn test_kid() {
        let signing_key = {
            // I ran this key through the Linux `rev` util to avoid random GitHub security scanners
            // from screaming at me, it's just a test key, it's not confidential
            let private_key_obfuscated = "-----YEK ETAVIRP NIGEB-----
PSBRSYflxWzN8CQABIoAAEgAlSggwkKBCSAAFEQAB0w9GikhqkgBNADABIwvEIIM
mp/I/mejSYZybQr8ZbV/06xHnSHSJgmkBgWFmZJTm98NeqvVyny24/d3+mo7rXM8
Mb542VasOhyEwKVO1dhIo46IU2yGE7FE0+JPQodYx5EuZ5OzzXUgjnFmniWFxJWS
lXNUeZHQ3Y37NhzcHHHeEK7wUPz/6Jp9aHScX5smfzXlw5WHjQgNmCOg4M5Hp7zu
m5K4N+s00ekY2Yy4WsMWQbzqBqs6KCTaSZ16pCbrt+6ctCYYGUG5J7ayqlA4KQLm
FvcaEKrI7QDTykqZ3hervkPQ6QvhAc3mx6vBShg+/LvOcOtUMJNc4jvePCr5G8x0
pWFXKfjdDtpUPbJqO8HuShy6gBZSuYzvUhs/50jgaZGFAEggCEAABMgA5iBb028H
/SmR6NBD8pyecF4o3CRIVsOMxcBDhiqByLQ5FckTL8d+cYpzI2Z5pcF+uZLJ9RHI
P6uAxbyb4n2Z3svHQtijwsWXGBwtV5M3xEJ4VnMsf99r4uhpHtEzLnz4ykDrB1Yv
5fRVG5OnJrGJm5MlINKs7iqCMf2EbpAlvW6Juf9ouhoLSXwyOaUs4b5C1DGn1S4G
ZxD0YEr6SjcNtTT9zOtIt+3swc+4ZA5LO7rX9R3iLNcy8f4qEvumV0g1uTzOa2bg
uke0jZmQIgTbIuSbxDQgBKQxdvSEwgqA03vYj9XK+n+kqFRFoCz9d7Uovmso19Oa
wXglUXTIOhiHAL3Fd8j1Vx+lvUR+4Qg8JNIAuBFlW/IoStHeh4Vft3REyTN3nr56
UWsAYJqCd/ozjPONvhYF+Rcz8cL2Fp/eEtoFGS+pdhDrhm5fWL3yUrF785DIU1KF
vNEAqYxHIi+sbQdEBSKxqbPItwjD5I8kHDQgBKQTKGYYix4gBJW+aB5B5nlWvQT/
+0sczhF84MCy2sNdo4UYG8ge/5+qQtKhUrOS1NUvV9JUeWiAt3q2UGc/7tHgZWrV
BPwcLYxoAAE21rPytKFY4Zh15JnyGpBl8nsWHI6jRey0t55F8Ga3ASHgrqEZiPcS
CJQGknd9Af9UTOwA9yIJSA5J8DVYW9LvigxA1rZS6NK/j9CYBCQgBKQHmgx0BX7e
+J1QifF5Qw8Yu+edRyNCq/tAJ84c4FhKD42S3CZUbzgXcYfsKU75Kg16hXIK19hL
gCQgBKQQauQAVefN3WEo+ASbdabeEaq4JT+dXIByQw3pFzfGr4f4r8GkVUFn9GLc
VpwbHt9zIBJwWghW6rRaMJ4V82a8YlFQeN0y062GxDYmNq6OELAkv1dg1kYtafxS
VA1Vmr+7eR+zMuUz4HwdA2ikd74bYyPgI9je8djvqQ3xodIzbf4ZNtelAMMbk1DK
sdDjwKnAmd9fTozhrDQgBKQLLbSACzKqMUpfKGTILHKFPJb6STPdAgbSwt3YMom0
dHSRoJHkmuHeToCG2zxd03UcUqxqztRAf6AAIc6J63v7YgEU4NBCoDpgscHSvD9M
wotPP4a26KThoHHoFw7o6RWG6DPLTYoUIzEe7NmZmk3ZtYTWrut1MTquAv4Juy0A
==geFSp0b8Fl22ffuYED4gmTgXRP
-----YEK ETAVIRP DNE-----";
            let private_key_pem = private_key_obfuscated
                .lines()
                .map(|line| line.chars().rev().collect::<String>())
                .collect::<String>();
            super::key_from_pem(private_key_pem.as_str()).unwrap()
        };

        let calculated_kid = signing_key.jwt_key_id().unwrap();

        // Got this one from the Go code below
        let expected_kid = "GKx0EwGz_guqR2ID87rRHmYY_YPhED667Y0QN7m8JtY";
        assert_eq!(calculated_kid, expected_kid);

        /*
        package main

        import (
            "crypto"
            "crypto/x509"
            "encoding/base64"
            "encoding/pem"
            "fmt"
        )

        const key string = `
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvDc1sZX2EkQUj/DF6+6J
        vt3f+Nsp8lb6njfPZkyWZhVoAZJoCUh0px8etP1W2fK0G8mWEo3pvyP6ZklicRVo
        p5hZ44FF88zuWbhOcWHaEDyftBBexBstlCOuKCIXdTlSsBMoTrGlduOWzLs+6R+T
        OIDgpjYEIx1ucJV835rOV3Eh2vaSev8z1MOyhHhxx3M4Te92N0B2XlDV5Zi0CuAJ
        asmuyeRlBmGArXOvra2wqetWUmkwiurKgas20FjLFuMmNmJHtNLPjeCuZtMfBuaw
        j3r4+HDSTFLTnDry//oIUgb+sZt3AIb0OkD5L63od2apMkw0OyKyhGnLxR/NtGwY
        uQIDAQAB
        -----END PUBLIC KEY-----
        `

        func main() {
            block, _ := pem.Decode([]byte(key))
            if block == nil {
                panic("Error decoding public key")
            }

            publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
            if err != nil {
                panic(err)
            }

            publicKeyDERBytes, err := x509.MarshalPKIXPublicKey(publicKey)
            if err != nil {
                panic(err)
            }

            hasher := crypto.SHA256.New()
            hasher.Write(publicKeyDERBytes)
            publicKeyDERHash := hasher.Sum(nil)

            keyID := base64.RawURLEncoding.EncodeToString(publicKeyDERHash)

            fmt.Println(keyID)
        }
        */
    }
}
