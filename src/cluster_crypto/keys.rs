use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use bytes::Bytes;
use p256::pkcs8::EncodePublicKey;
use pkcs1::EncodeRsaPrivateKey;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use rsa::RsaPrivateKey;
use std::{
    self,
    fmt::Formatter,
    io::Write,
    process::{Command, Stdio},
};

#[derive(Hash, Eq, PartialEq, Clone)]
pub(crate) enum PrivateKey {
    Rsa(RsaPrivateKey),
    Ec(Bytes),
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

impl TryFrom<&PrivateKey> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(priv_key: &PrivateKey) -> Result<Self> {
        Ok(match priv_key {
            PrivateKey::Rsa(private_key) => PublicKey::from_rsa_bytes(&bytes::Bytes::copy_from_slice(
                private_key.to_public_key().to_public_key_der()?.as_bytes(),
            )),
            PrivateKey::Ec(ec_bytes) => {
                let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, ec_bytes)
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
            .spawn()?;

        command
            .stdin
            .take()
            .context("failed to get openssl stdin pipe")?
            .write_all(cert_bytes)?;

        let output = command.wait_with_output()?;
        if !output.status.success() {
            return Err(anyhow::anyhow!("openssl failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        Ok(PublicKey::Ec(output.stdout.into()))
    }

    pub(crate) fn pem(&self) -> pem::Pem {
        match &self {
            PublicKey::Rsa(rsa_der_bytes) => pem::Pem::new("RSA PUBLIC KEY", rsa_der_bytes.as_ref()),
            PublicKey::Ec(_) => todo!("Unsupported"),
        }
    }
}
