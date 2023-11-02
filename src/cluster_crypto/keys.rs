use super::REDACT_SECRETS;
use anyhow::{bail, Context, Error, Result};
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use bytes::Bytes;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, LineEnding};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use rsa::RsaPrivateKey;
use serde::Serialize;
use std::{
    self,
    fmt::Formatter,
    io::Write,
    process::{Command, Stdio},
    sync::atomic::Ordering::Relaxed,
};
use x509_certificate::InMemorySigningKeyPair;

#[derive(Hash, Eq, PartialEq, Clone)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum PrivateKey {
    Rsa(RsaPrivateKey),
    Ec(Bytes),
}

impl Serialize for PrivateKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if REDACT_SECRETS.load(Relaxed) {
            return serializer.serialize_str("<redacted>");
        }

        match self {
            Self::Rsa(rsa_private_key) => serializer.serialize_str(
                &base64_standard.encode(
                    &rsa_private_key
                        .to_pkcs8_pem(LineEnding::LF)
                        .unwrap_or("failed to serialize RSA private key".to_string().into()),
                ),
            ),
            Self::Ec(ec_bytes) => serializer.serialize_str(&pem::Pem::new("EC PRIVATE KEY", ec_bytes.as_ref()).to_string()),
        }
    }
}

impl TryFrom<&InMemorySigningKeyPair> for PrivateKey {
    type Error = Error;

    fn try_from(value: &InMemorySigningKeyPair) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            InMemorySigningKeyPair::Ecdsa(_, _, vec) => PrivateKey::Ec(Bytes::copy_from_slice(vec.as_ref())),
            InMemorySigningKeyPair::Ed25519(_) => todo!(),
            InMemorySigningKeyPair::Rsa(_, vec) => {
                let rsa_private_key = RsaPrivateKey::from_pkcs1_der(vec.as_ref()).context(format!(
                    "converting in memory pair to RSA PrivateKey {:?}",
                    Bytes::copy_from_slice(vec.as_ref())
                ))?;
                PrivateKey::Rsa(rsa_private_key)
            }
        })
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa(_) => write!(f, "<rsa_priv>"),
            Self::Ec(_) => write!(f, "<ec_priv>"),
        }
    }
}

impl PrivateKey {
    pub(crate) fn pem(&self) -> Result<pem::Pem> {
        Ok(match &self {
            PrivateKey::Rsa(rsa_private_key) => pem::Pem::new("RSA PRIVATE KEY", rsa_private_key.to_pkcs1_der()?.as_bytes()),
            PrivateKey::Ec(ec_bytes) => pem::Pem::new("EC PRIVATE KEY", ec_bytes.as_ref()),
        })
    }
}

#[derive(Hash, Eq, PartialEq, Clone)]
pub(crate) enum PublicKey {
    Rsa(Bytes),
    Ec(Bytes),
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(
            &base64_standard.encode(
                self.pem()
                    .context("converting to PEM")
                    .map_err(serde::ser::Error::custom)?
                    .to_string(),
            ),
        )
    }
}

impl TryFrom<&PrivateKey> for PublicKey {
    type Error = Error;

    fn try_from(priv_key: &PrivateKey) -> Result<Self> {
        Ok(match priv_key {
            PrivateKey::Rsa(private_key) => PublicKey::from_rsa_bytes(&bytes::Bytes::copy_from_slice(
                private_key.to_public_key().to_public_key_der()?.as_bytes(),
            )),
            PrivateKey::Ec(ec_bytes) => {
                let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, ec_bytes, &ring::rand::SystemRandom::new())
                    .ok()
                    .context("failed to make pair from pkcs8")?;
                PublicKey::Ec(Bytes::copy_from_slice(pair.public_key().as_ref()))
            }
        })
    }
}

impl From<Bytes> for PublicKey {
    fn from(value: Bytes) -> Self {
        PublicKey::from_rsa_bytes(&value)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa(der_bytes) => write!(f, "<rsa_pub: {}>", base64_standard.encode(der_bytes.as_ref())),
            Self::Ec(x) => write!(f, "<ec_pub: {:?}>", x),
        }
    }
}

impl PublicKey {
    pub(crate) fn from_rsa_bytes(der_bytes: &Bytes) -> PublicKey {
        PublicKey::Rsa(der_bytes.clone())
    }

    pub(crate) fn from_ec_cert_bytes(cert_bytes: &Bytes) -> Result<PublicKey> {
        // Need to shell out to openssl
        let mut command = Command::new("openssl")
            .arg("x509")
            .arg("-pubkey")
            .arg("-noout")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .context("running openssl")?;

        command
            .stdin
            .take()
            .context("failed to get openssl stdin pipe")?
            .write_all(cert_bytes)?;

        let output = command.wait_with_output().context("waiting for openssl output")?;
        if !output.status.success() {
            bail!("openssl failed: {}", String::from_utf8_lossy(&output.stderr));
        }

        Ok(PublicKey::Ec(output.stdout.into()))
    }

    pub(crate) fn pem(&self) -> Result<pem::Pem> {
        Ok(match &self {
            PublicKey::Rsa(rsa_der_bytes) => pem::Pem::new("RSA PUBLIC KEY", rsa_der_bytes.as_ref()),
            PublicKey::Ec(pem_bytes) => pem::parse(pem_bytes).context("ec bytes as pem").context("bytes as PEM")?,
        })
    }
}
