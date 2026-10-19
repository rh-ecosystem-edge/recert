use super::algorithms::{EcdsaCurve, KeyAlgorithm};
use super::keys::PrivateKey;
use anyhow::ensure;
use anyhow::{bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD as base64_standard, URL_SAFE_NO_PAD as base64_url},
    Engine as _,
};
use der::{Decode, Encode};
use pkcs1::DecodeRsaPrivateKey;
use rsa::{self, pkcs8::EncodePrivateKey, RsaPrivateKey};
use serde::ser::SerializeStruct;
use std::io::Write;
use std::path::Path;
use std::process::Command as StdCommand;
use std::process::Stdio;
use tokio::process::Command;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

pub(crate) mod cert_signers;
pub(crate) mod jwt;

/// Identifies the key algorithm of a PKCS#8 private key. This is pure ASN.1 decoding, no
/// cryptographic operations are performed.
pub(crate) fn pkcs8_key_algorithm(der: &[u8]) -> Result<KeyAlgorithm> {
    let key = pkcs8::PrivateKeyInfo::from_der(der).context("decoding PKCS#8 DER")?;
    KeyAlgorithm::from_algorithm_identifier(&key.algorithm).context("identifying PKCS#8 key algorithm")
}

const OPENSSL_PUBOUT_DER_ARGS: [&str; 6] = ["pkey", "-inform", "PEM", "-pubout", "-outform", "DER"];

fn openssl_spki_der_from_pkcs8_pem(pkcs8_pem: &[u8]) -> Result<Vec<u8>> {
    let mut child = StdCommand::new("openssl")
        .args(OPENSSL_PUBOUT_DER_ARGS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning openssl pkey")?;

    child
        .stdin
        .take()
        .context("failed to take openssl stdin pipe")?
        .write_all(pkcs8_pem)?;

    let output = child.wait_with_output().context("waiting for openssl pkey")?;
    ensure!(
        output.status.success(),
        "openssl pkey -pubout failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    Ok(output.stdout)
}

async fn openssl_spki_der_from_pkcs8_pem_async(pkcs8_pem: &[u8]) -> Result<Vec<u8>> {
    use tokio::io::AsyncWriteExt;

    let mut child = Command::new("openssl")
        .args(OPENSSL_PUBOUT_DER_ARGS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning openssl pkey")?;

    let mut stdin = child.stdin.take().context("failed to take openssl stdin pipe")?;
    stdin.write_all(pkcs8_pem).await?;
    drop(stdin);

    let output = child.wait_with_output().await.context("waiting for openssl pkey")?;
    ensure!(
        output.status.success(),
        "openssl pkey -pubout failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    Ok(output.stdout)
}

/// A private key we can sign with. All cryptographic operations (generation, public key
/// derivation, signing) are delegated to openssl, we only keep the PKCS#8 PEM along with some
/// metadata extracted from it.
#[derive(Clone)]
pub(crate) struct SigningKey {
    key_algorithm: KeyAlgorithm,
    /// As derived by openssl
    public_key_info: SubjectPublicKeyInfoOwned,
    pkcs8_pem: Vec<u8>,
}

impl SigningKey {
    /// Parses the PEM and re-encodes it so that openssl (which is stricter than the pem crate
    /// about formatting) can always read it
    fn normalize_pkcs8_pem(pkcs8_pem: &[u8]) -> Result<(KeyAlgorithm, Vec<u8>)> {
        let parsed_pem = pem::parse(pkcs8_pem).context("parsing PKCS#8 PEM")?;
        ensure!(parsed_pem.tag() == "PRIVATE KEY", "expected PKCS#8 PEM, got {}", parsed_pem.tag());
        let key_algorithm = pkcs8_key_algorithm(parsed_pem.contents())?;
        let normalized_pem = pem::encode_config(&parsed_pem, pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF));
        Ok((key_algorithm, normalized_pem.into_bytes()))
    }

    fn from_pkcs8_pem(pkcs8_pem: Vec<u8>) -> Result<Self> {
        let (key_algorithm, pkcs8_pem) = Self::normalize_pkcs8_pem(&pkcs8_pem)?;
        let spki_der = openssl_spki_der_from_pkcs8_pem(&pkcs8_pem)?;

        Ok(Self {
            key_algorithm,
            public_key_info: SubjectPublicKeyInfoOwned::from_der(&spki_der).context("decoding openssl SPKI")?,
            pkcs8_pem,
        })
    }

    async fn from_pkcs8_pem_async(pkcs8_pem: Vec<u8>) -> Result<Self> {
        let (key_algorithm, pkcs8_pem) = Self::normalize_pkcs8_pem(&pkcs8_pem)?;
        let spki_der = openssl_spki_der_from_pkcs8_pem_async(&pkcs8_pem).await?;

        Ok(Self {
            key_algorithm,
            public_key_info: SubjectPublicKeyInfoOwned::from_der(&spki_der).context("decoding openssl SPKI")?,
            pkcs8_pem,
        })
    }

    #[cfg(test)]
    pub(crate) fn key_algorithm(&self) -> KeyAlgorithm {
        self.key_algorithm
    }

    pub(crate) fn public_key_info(&self) -> &SubjectPublicKeyInfoOwned {
        &self.public_key_info
    }

    /// The signature algorithm `sign` uses for this key
    pub(crate) fn signature_algorithm(&self) -> AlgorithmIdentifierOwned {
        self.key_algorithm.signature_algorithm()
    }

    /// Generates the "kid" field for a JWT header in accordance with how Kubernetes does it (a
    /// Base64URL-encoded SHA256 hash of the PKIX DER encoding of the public key derived from the
    /// private key)
    // Implementation based on https://github.com/openshift/kubernetes/blob/6fdacf04117cef54a0babd0945e8ef87d0f9461d/pkg/serviceaccount/jwt.go#L92-L112
    pub(crate) fn jwt_key_id(&self) -> Result<String> {
        let pkix_der_bytes = self.public_key_info.to_der().context("encoding public key")?;
        Ok(base64_url.encode(sha256(pkix_der_bytes.as_slice()).context("hash")?))
    }

    pub(crate) fn jwt_alg(&self) -> Result<&'static str> {
        Ok(match self.key_algorithm {
            KeyAlgorithm::Rsa => "RS256",
            KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1) => "ES256",
            KeyAlgorithm::Ecdsa(EcdsaCurve::Secp384r1) => "ES384",
            KeyAlgorithm::Ed25519 => "EdDSA",
        })
    }

    pub(crate) fn to_private_key(&self) -> Result<PrivateKey> {
        let parsed = pem::parse(&self.pkcs8_pem).context("parsing pkcs8 pem")?;
        PrivateKey::from_pkcs8_der(parsed.contents())
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

pub(crate) async fn generate_rsa_key_async(key_size: usize) -> Result<SigningKey> {
    let pkcs8_pem = Command::new("openssl")
        .args(["genrsa", &key_size.to_string()])
        .output()
        .await
        .context("openssl genrsa")?
        .stdout
        .to_vec();

    SigningKey::from_pkcs8_pem_async(pkcs8_pem).await
}

pub(crate) fn generate_rsa_key(key_size: usize) -> Result<SigningKey> {
    let pkcs8_pem = StdCommand::new("openssl")
        .args(["genrsa", &key_size.to_string()])
        .output()
        .context("openssl genrsa")?
        .stdout;

    SigningKey::from_pkcs8_pem(pkcs8_pem)
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

    SigningKey::from_pkcs8_pem(pkcs8_pem_data)
}

pub(crate) fn generate_ed25519_key() -> Result<SigningKey> {
    let output = StdCommand::new("openssl")
        .args(["genpkey", "-algorithm", "Ed25519"])
        .output()
        .context("openssl genpkey Ed25519")?;

    ensure!(
        output.status.success(),
        "openssl genpkey Ed25519 failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let pem = String::from_utf8(output.stdout).context("openssl genpkey output not valid UTF-8")?;
    key_from_pkcs8_pem(&pem)
}

pub(crate) fn key_from_pkcs8_pem(pem: &str) -> Result<SigningKey> {
    SigningKey::from_pkcs8_pem(pem.into())
}

pub(crate) fn rsa_key_from_pkcs1_pem(pem: &str) -> Result<SigningKey> {
    let rsa_private_key = RsaPrivateKey::from_pkcs1_pem(pem).context("private from pem")?;
    let pkcs8_pem_data: Vec<u8> = rsa_private_key
        .to_pkcs8_pem(pkcs1::LineEnding::LF)
        .context("private to pkcs8 pem")?
        .as_bytes()
        .into();

    SigningKey::from_pkcs8_pem(pkcs8_pem_data)
}

pub(crate) fn key_from_file(path: &Path) -> Result<SigningKey> {
    let data = std::fs::read(path).context("reading private key file")?;

    key_from_pem(&String::from_utf8(data).context("converting private key file to utf8")?)
}

pub(crate) fn pubkey_pem_from_pkcs8_der(pkcs8_der: &[u8]) -> Result<Vec<u8>> {
    let mut child = StdCommand::new("openssl")
        .args(["pkey", "-inform", "DER", "-pubout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning openssl pkey")?;

    child
        .stdin
        .take()
        .context("failed to take openssl stdin pipe")?
        .write_all(pkcs8_der)?;

    let output = child.wait_with_output().context("waiting for openssl pkey")?;
    ensure!(
        output.status.success(),
        "openssl pkey -pubout failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    Ok(output.stdout)
}

fn ec_curve(key_algorithm: KeyAlgorithm) -> Result<EcdsaCurve> {
    match key_algorithm {
        KeyAlgorithm::Ecdsa(curve) => Ok(curve),
        key_algorithm => bail!("expected an EC key, got {key_algorithm:?}"),
    }
}

pub(crate) fn ec_curve_from_pkcs8_der(pkcs8_der: &[u8]) -> Result<EcdsaCurve> {
    ec_curve(pkcs8_key_algorithm(pkcs8_der)?)
}

pub(crate) fn ec_curve_from_public_key_der(spki_der: &[u8]) -> Result<EcdsaCurve> {
    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der).context("decoding SPKI DER")?;
    ec_curve(KeyAlgorithm::from_algorithm_identifier(&spki.algorithm)?)
}

fn openssl_stdin_text(args: &[&str], input: &[u8], failure_label: &'static str) -> Result<String> {
    let mut child = StdCommand::new("openssl")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning openssl {failure_label}"))?;

    child.stdin.take().context("failed to take openssl stdin pipe")?.write_all(input)?;

    let output = child
        .wait_with_output()
        .with_context(|| format!("waiting for openssl {failure_label}"))?;
    ensure!(
        output.status.success(),
        "openssl {failure_label} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).with_context(|| format!("openssl {failure_label} output not valid UTF-8"))
}

pub(crate) fn ec_sec1_to_pkcs8_pem(sec1_pem: &str) -> Result<String> {
    openssl_stdin_text(&["pkcs8", "-topk8", "-nocrypt"], sec1_pem.as_bytes(), "pkcs8 -topk8")
}

pub(crate) fn pkcs8_der_to_sec1_pem(pkcs8_der: &[u8]) -> Result<String> {
    openssl_stdin_text(&["pkey", "-traditional", "-inform", "DER"], pkcs8_der, "pkey -traditional")
}

pub(crate) fn key_from_pem(pem: &str) -> Result<SigningKey> {
    let parsed_pem = pem::parse(pem.as_bytes()).context("parsing private key file")?;
    let pem_tag = parsed_pem.tag();

    match pem_tag {
        "RSA PRIVATE KEY" => rsa_key_from_pkcs1_pem(pem).context("RSA key from PKCS#1"),
        "EC PRIVATE KEY" => ec_sec1_to_pkcs8_pem(pem)
            .and_then(|pkcs8| key_from_pkcs8_pem(&pkcs8))
            .context("EC key from SEC1"),
        "PRIVATE KEY" => key_from_pkcs8_pem(pem).context("key from PKCS#8"),
        _ => bail!("unknown private key format"),
    }
}

pub(crate) fn sign(signing_key: &SigningKey, tbs_der: &[u8]) -> Result<Vec<u8>> {
    let mut temp_file = tempfile::NamedTempFile::new()?;
    temp_file.write_all(tbs_der)?;

    let temp_path = temp_file.path().to_str().context("getting temp file path")?;

    let args: Vec<&str> = match signing_key.key_algorithm {
        KeyAlgorithm::Ed25519 => vec!["pkeyutl", "-sign", "-inkey", "/dev/stdin", "-rawin", "-in", temp_path],
        KeyAlgorithm::Ecdsa(curve) => {
            let digest = match curve {
                EcdsaCurve::Secp256r1 => "-sha256",
                EcdsaCurve::Secp384r1 => "-sha384",
            };
            vec!["dgst", digest, "-sign", "/dev/stdin", temp_path]
        }
        KeyAlgorithm::Rsa => vec!["dgst", "-sha256", "-sign", "/dev/stdin", temp_path],
    };

    let mut command = StdCommand::new("openssl")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning openssl sign")?;

    command
        .stdin
        .take()
        .context("getting openssl stdin")?
        .write_all(signing_key.pkcs8_pem.as_slice())
        .context("writing to openssl stdin")?;

    let output = command.wait_with_output().context("waiting for openssl sign")?;
    ensure!(
        output.status.success(),
        "openssl sign failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    Ok(output.stdout)
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

#[cfg(test)]
mod test {
    #[allow(unused_imports)]
    use std::io::Write;

    use crate::cluster_crypto::test_utils::{generate_ed25519_pkcs8_pem, skip_if_fips};

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

    fn generate_ec_sec1_pem(curve: &str) -> String {
        let output = std::process::Command::new("openssl")
            .args(["ecparam", "-name", curve, "-genkey", "-noout"])
            .output()
            .expect("failed to generate EC key");
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    }

    fn sign_and_verify(signing_key: &super::SigningKey, verify_digest: &str) -> bool {
        let data = b"test data to sign for verification";
        let signature = super::sign(signing_key, data).expect("sign should succeed");
        assert!(!signature.is_empty());

        let pkcs8_der = pem::parse(&signing_key.pkcs8_pem).unwrap();
        let pubkey_pem = super::pubkey_pem_from_pkcs8_der(pkcs8_der.contents()).unwrap();

        let mut pub_file = tempfile::NamedTempFile::new().unwrap();
        pub_file.write_all(&pubkey_pem).unwrap();

        let mut sig_file = tempfile::NamedTempFile::new().unwrap();
        sig_file.write_all(&signature).unwrap();

        let mut data_file = tempfile::NamedTempFile::new().unwrap();
        data_file.write_all(data).unwrap();

        std::process::Command::new("openssl")
            .args([
                "dgst",
                verify_digest,
                "-verify",
                pub_file.path().to_str().unwrap(),
                "-signature",
                sig_file.path().to_str().unwrap(),
                data_file.path().to_str().unwrap(),
            ])
            .output()
            .expect("openssl verify failed")
            .status
            .success()
    }

    fn assert_key_from_pem_ec_sec1(curve: &str) {
        let sec1_pem = generate_ec_sec1_pem(curve);
        assert!(sec1_pem.contains("BEGIN EC PRIVATE KEY"));

        let signing_key = super::key_from_pem(&sec1_pem).expect("key_from_pem should accept SEC1 EC keys");
        assert!(signing_key.pkcs8_pem.starts_with(b"-----BEGIN PRIVATE KEY-----"));
    }

    fn assert_key_from_pem_ec_pkcs8(curve: &str) {
        let sec1_pem = generate_ec_sec1_pem(curve);
        let pkcs8_pem = super::ec_sec1_to_pkcs8_pem(&sec1_pem).expect("conversion failed");
        assert!(pkcs8_pem.contains("BEGIN PRIVATE KEY"));

        let signing_key = super::key_from_pem(&pkcs8_pem).expect("key_from_pem should accept PKCS#8 EC keys");
        assert!(signing_key.pkcs8_pem.starts_with(b"-----BEGIN PRIVATE KEY-----"));
    }

    fn assert_ec_sec1_to_pkcs8_pem_direct(curve: &str) {
        let sec1_pem = generate_ec_sec1_pem(curve);
        let pkcs8_pem = super::ec_sec1_to_pkcs8_pem(&sec1_pem).expect("ec_sec1_to_pkcs8_pem failed");
        assert!(pkcs8_pem.contains("BEGIN PRIVATE KEY"));
        assert!(!pkcs8_pem.contains("BEGIN EC PRIVATE KEY"));
    }

    fn assert_pkcs8_der_to_sec1_pem_direct(curve: &str) {
        let sec1_pem = generate_ec_sec1_pem(curve);
        let pkcs8_pem = super::ec_sec1_to_pkcs8_pem(&sec1_pem).expect("ec_sec1_to_pkcs8_pem failed");
        let pkcs8_der = pem::parse(pkcs8_pem).expect("converted PKCS#8 should parse").contents().to_vec();
        let round_trip = super::pkcs8_der_to_sec1_pem(&pkcs8_der).expect("pkcs8_der_to_sec1_pem failed");
        assert!(round_trip.contains("BEGIN EC PRIVATE KEY"));
        assert!(!round_trip.contains("BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn test_key_from_pem_ec_sec1() {
        assert_key_from_pem_ec_sec1("prime256v1");
    }

    #[test]
    fn test_key_from_pem_ed25519_pkcs8() {
        skip_if_fips!("Ed25519");

        let pem_str = String::from_utf8(generate_ed25519_pkcs8_pem()).unwrap();
        assert!(pem_str.contains("BEGIN PRIVATE KEY"));

        let signing_key = super::key_from_pem(&pem_str).expect("key_from_pem should accept Ed25519 PKCS#8 keys");
        assert!(signing_key.pkcs8_pem.starts_with(b"-----BEGIN PRIVATE KEY-----"));
        assert_eq!(signing_key.key_algorithm(), super::KeyAlgorithm::Ed25519);
    }

    #[test]
    fn test_generate_ed25519_key() {
        skip_if_fips!("Ed25519");

        let signing_key = super::generate_ed25519_key().expect("generate_ed25519_key should succeed");
        assert_eq!(signing_key.key_algorithm(), super::KeyAlgorithm::Ed25519);
        assert_eq!(public_key_data(&signing_key).len(), 32, "Ed25519 public key should be 32 bytes");
    }

    #[test]
    fn test_sign_ed25519() {
        skip_if_fips!("Ed25519");

        let signing_key = super::generate_ed25519_key().expect("generate_ed25519_key failed");
        let data = b"test data to sign";

        let signature = super::sign(&signing_key, data).expect("sign should succeed for Ed25519");
        assert!(!signature.is_empty(), "signature should not be empty");
        assert_eq!(signature.len(), 64, "Ed25519 signature should be 64 bytes");

        // Verify the signature using openssl
        let mut key_file = tempfile::NamedTempFile::new().unwrap();
        key_file.write_all(&signing_key.pkcs8_pem).unwrap();

        let mut sig_file = tempfile::NamedTempFile::new().unwrap();
        sig_file.write_all(&signature).unwrap();

        let mut data_file = tempfile::NamedTempFile::new().unwrap();
        data_file.write_all(data).unwrap();

        let verify_output = std::process::Command::new("openssl")
            .args([
                "pkeyutl",
                "-verify",
                "-inkey",
                key_file.path().to_str().unwrap(),
                "-rawin",
                "-in",
                data_file.path().to_str().unwrap(),
                "-sigfile",
                sig_file.path().to_str().unwrap(),
            ])
            .output()
            .expect("openssl pkeyutl -verify failed");

        assert!(
            verify_output.status.success(),
            "signature verification failed: {}",
            String::from_utf8_lossy(&verify_output.stderr)
        );
    }

    #[test]
    fn test_try_from_signing_key_ed25519() {
        skip_if_fips!("Ed25519");

        let signing_key = super::generate_ed25519_key().expect("generate_ed25519_key failed");
        let private_key = signing_key.to_private_key().expect("to_private_key should succeed for Ed25519");
        assert!(matches!(private_key, super::PrivateKey::Ed25519(_)), "expected PrivateKey::Ed25519");
    }

    #[test]
    fn test_try_from_signing_key_rsa() {
        let signing_key = super::generate_rsa_key(2048).expect("generate_rsa_key failed");
        let private_key = signing_key.to_private_key().expect("to_private_key should succeed for RSA");
        assert!(matches!(private_key, super::PrivateKey::Rsa(_)), "expected PrivateKey::Rsa");
    }

    #[test]
    fn test_sign_rsa() {
        let signing_key = super::generate_rsa_key(2048).expect("generate_rsa_key failed");
        assert!(sign_and_verify(&signing_key, "-sha256"), "RSA signature verification failed");
    }

    #[test]
    fn test_key_from_pem_unknown_tag() {
        let fake_pem = "-----BEGIN DSA PRIVATE KEY-----\nZmFrZQ==\n-----END DSA PRIVATE KEY-----\n";
        let result = super::key_from_pem(fake_pem);
        let err = result.err().expect("should fail for unknown PEM tag");
        assert!(
            err.to_string().contains("unknown private key format"),
            "should report unknown format"
        );
    }

    #[test]
    fn test_key_from_pkcs8_pem_garbage() {
        let garbage = pem::Pem::new("PRIVATE KEY", vec![0xDE, 0xAD]).to_string();
        let result = super::key_from_pkcs8_pem(&garbage);
        assert!(result.is_err(), "garbage DER should fail");
    }

    /// The contents of the subjectPublicKey BIT STRING
    fn public_key_data(signing_key: &super::SigningKey) -> Vec<u8> {
        signing_key.public_key_info().subject_public_key.raw_bytes().to_vec()
    }

    fn assert_public_key_data_matches_openssl(signing_key: &super::SigningKey) {
        use der::Encode;

        let pkcs8_der = pem::parse(&signing_key.pkcs8_pem).unwrap();
        let pubkey_pem = super::pubkey_pem_from_pkcs8_der(pkcs8_der.contents()).unwrap();
        let spki_der = pem::parse(pubkey_pem).unwrap();
        assert_eq!(
            signing_key.public_key_info().to_der().unwrap(),
            spki_der.contents(),
            "public key should re-encode exactly like openssl encodes it"
        );
        assert_eq!(
            super::KeyAlgorithm::from_algorithm_identifier(&signing_key.public_key_info().algorithm).unwrap(),
            signing_key.key_algorithm(),
            "SPKI algorithm should match the private key algorithm"
        );
    }

    #[test]
    fn test_public_key_data_rsa() {
        let signing_key = super::generate_rsa_key(2048).unwrap();
        assert_eq!(signing_key.key_algorithm(), super::KeyAlgorithm::Rsa);
        assert_public_key_data_matches_openssl(&signing_key);

        // For RSA, the subjectPublicKey is the PKCS#1 RSAPublicKey, which the rsa crate should
        // agree with
        use pkcs1::EncodeRsaPublicKey;
        let super::PrivateKey::Rsa(rsa_private_key) = signing_key.to_private_key().unwrap() else {
            panic!("expected RSA private key");
        };
        assert_eq!(
            public_key_data(&signing_key),
            rsa_private_key.to_public_key().to_pkcs1_der().unwrap().as_bytes()
        );
    }

    #[tokio::test]
    async fn test_public_key_data_rsa_async() {
        let signing_key = super::generate_rsa_key_async(2048).await.unwrap();
        assert_eq!(signing_key.key_algorithm(), super::KeyAlgorithm::Rsa);
        assert_public_key_data_matches_openssl(&signing_key);
    }

    #[test]
    fn test_public_key_data_ec() {
        for curve in [super::EcdsaCurve::Secp256r1, super::EcdsaCurve::Secp384r1] {
            let signing_key = super::generate_ec_key(curve).unwrap();
            assert_eq!(signing_key.key_algorithm(), super::KeyAlgorithm::Ecdsa(curve));
            assert_eq!(
                public_key_data(&signing_key)[0],
                0x04,
                "EC public key should be an uncompressed point"
            );
            assert_public_key_data_matches_openssl(&signing_key);
        }
    }

    #[test]
    fn test_public_key_data_ed25519() {
        skip_if_fips!("Ed25519");

        let signing_key = super::generate_ed25519_key().unwrap();
        assert_public_key_data_matches_openssl(&signing_key);
    }

    #[test]
    fn test_jwt_alg() {
        assert_eq!(super::generate_rsa_key(2048).unwrap().jwt_alg().unwrap(), "RS256");
        assert_eq!(
            super::generate_ec_key(super::EcdsaCurve::Secp256r1).unwrap().jwt_alg().unwrap(),
            "ES256"
        );
        assert_eq!(
            super::generate_ec_key(super::EcdsaCurve::Secp384r1).unwrap().jwt_alg().unwrap(),
            "ES384"
        );

        skip_if_fips!("Ed25519");
        assert_eq!(super::generate_ed25519_key().unwrap().jwt_alg().unwrap(), "EdDSA");
    }

    #[test]
    fn test_signing_key_clone_ed25519() {
        skip_if_fips!("Ed25519");

        let key = super::generate_ed25519_key().expect("generate failed");
        let cloned = key.clone();
        assert_eq!(cloned.key_algorithm(), super::KeyAlgorithm::Ed25519, "cloned key should be Ed25519");

        let signature = super::sign(&cloned, b"clone test data").expect("sign with clone should succeed");
        assert_eq!(signature.len(), 64, "Ed25519 signature should be 64 bytes");
    }

    #[test]
    fn test_try_from_signing_key_ec() {
        let signing_key = super::generate_ec_key(super::EcdsaCurve::Secp256r1).expect("generate_ec_key failed");
        let private_key = signing_key.to_private_key().expect("to_private_key should succeed for EC");
        assert!(matches!(private_key, super::PrivateKey::Ec { .. }), "expected PrivateKey::Ec");
    }

    #[test]
    fn test_key_from_pem_ec_sec1_p384() {
        assert_key_from_pem_ec_sec1("secp384r1");
    }

    #[test]
    fn test_key_from_pem_ec_pkcs8_p256() {
        assert_key_from_pem_ec_pkcs8("prime256v1");
    }

    #[test]
    fn test_key_from_pem_ec_pkcs8_p384() {
        assert_key_from_pem_ec_pkcs8("secp384r1");
    }

    #[test]
    fn test_sign_ec_p256() {
        let key = super::key_from_pem(&generate_ec_sec1_pem("prime256v1")).unwrap();
        assert!(sign_and_verify(&key, "-sha256"));
    }

    #[test]
    fn test_sign_ec_p384() {
        let key = super::key_from_pem(&generate_ec_sec1_pem("secp384r1")).unwrap();
        assert!(sign_and_verify(&key, "-sha384"));
    }

    #[test]
    fn test_sign_ec_p384_fails_sha256_verify() {
        let key = super::key_from_pem(&generate_ec_sec1_pem("secp384r1")).unwrap();
        assert!(!sign_and_verify(&key, "-sha256"), "P-384 signature must NOT verify under SHA-256");
    }

    #[test]
    fn test_ec_sec1_to_pkcs8_pem_p256() {
        assert_ec_sec1_to_pkcs8_pem_direct("prime256v1");
    }

    #[test]
    fn test_ec_sec1_to_pkcs8_pem_p384() {
        assert_ec_sec1_to_pkcs8_pem_direct("secp384r1");
    }

    #[test]
    fn test_ec_sec1_to_pkcs8_pem_garbage() {
        let result = super::ec_sec1_to_pkcs8_pem("not a valid PEM");
        assert!(result.is_err(), "garbage input should produce an error");
    }

    #[test]
    fn test_pkcs8_der_to_sec1_pem_p256() {
        assert_pkcs8_der_to_sec1_pem_direct("prime256v1");
    }

    #[test]
    fn test_pkcs8_der_to_sec1_pem_p384() {
        assert_pkcs8_der_to_sec1_pem_direct("secp384r1");
    }

    #[test]
    fn test_pkcs8_der_to_sec1_pem_garbage() {
        let result = super::pkcs8_der_to_sec1_pem(b"not a valid PEM");
        assert!(result.is_err(), "garbage input should produce an error");
    }

    #[test]
    fn test_pubkey_pem_from_pkcs8_der_garbage() {
        let result = super::pubkey_pem_from_pkcs8_der(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(result.is_err(), "garbage DER should produce an error");
    }
}
