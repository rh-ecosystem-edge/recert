use super::REDACT_SECRETS;
use anyhow::{bail, Context, Error, Result};
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use bytes::Bytes;
use pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, LineEnding};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::RsaPrivateKey;
use serde::Serialize;
use std::{
    self,
    fmt::Formatter,
    hash::{Hash, Hasher},
    io::Write,
    process::{Command, Stdio},
    sync::atomic::Ordering::Relaxed,
};
use x509_certificate::InMemorySigningKeyPair;

/// PEM form an ECDSA private key was found in. PKCS#8 DER is what we store and use for key
/// operations; this only controls how the key is written back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EcEncoding {
    Sec1,
    Pkcs8,
}

/// An ECDSA private key. Always stored as PKCS#8 DER internally; `encoding` controls how it is
/// written back and is not part of key identity.
#[derive(Clone, Debug)]
pub(crate) struct EcPrivateKey {
    pkcs8_der: Bytes,
    encoding: EcEncoding,
}

impl PartialEq for EcPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.pkcs8_der == other.pkcs8_der
    }
}

impl Eq for EcPrivateKey {}

impl Hash for EcPrivateKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pkcs8_der.hash(state);
    }
}

impl EcPrivateKey {
    pub(crate) fn from_pkcs8_der(der: Bytes) -> Self {
        Self {
            pkcs8_der: der,
            encoding: EcEncoding::Pkcs8,
        }
    }

    pub(crate) fn from_sec1_pem(pem: &pem::Pem) -> Result<Self> {
        let pkcs8_pem_str = super::crypto_utils::ec_sec1_to_pkcs8_pem(&pem.to_string()).context("converting SEC1 to PKCS#8")?;
        let pkcs8_pem = pem::parse(pkcs8_pem_str).context("parsing converted PKCS#8 PEM")?;
        Ok(Self {
            pkcs8_der: Bytes::copy_from_slice(pkcs8_pem.contents()),
            encoding: EcEncoding::Sec1,
        })
    }

    pub(crate) fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8_der
    }

    pub(crate) fn pem(&self) -> Result<pem::Pem> {
        match self.encoding {
            EcEncoding::Pkcs8 => Ok(pem::Pem::new("PRIVATE KEY", self.pkcs8_der.as_ref())),
            EcEncoding::Sec1 => {
                let sec1_pem = super::crypto_utils::pkcs8_der_to_sec1_pem(&self.pkcs8_der).context("converting PKCS#8 to SEC1")?;
                pem::parse(sec1_pem).context("parsing SEC1 PEM")
            }
        }
    }
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum PrivateKey {
    Rsa(RsaPrivateKey),
    Ec(EcPrivateKey),
    Ed25519(Bytes),
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Rsa(left), Self::Rsa(right)) => left == right,
            (Self::Ec(left), Self::Ec(right)) => left == right,
            (Self::Ed25519(left), Self::Ed25519(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for PrivateKey {}

impl Hash for PrivateKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Self::Rsa(key) => key.hash(state),
            Self::Ec(ec) => ec.hash(state),
            Self::Ed25519(bytes) => bytes.hash(state),
        }
    }
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
                    rsa_private_key
                        .to_pkcs8_pem(LineEnding::LF)
                        .unwrap_or("failed to serialize RSA private key".to_string().into()),
                ),
            ),
            Self::Ec(ec) => serializer.serialize_str(&ec.pem().map_err(serde::ser::Error::custom)?.to_string()),
            Self::Ed25519(bytes) => serializer.serialize_str(&pem::Pem::new("PRIVATE KEY", bytes.as_ref()).to_string()),
        }
    }
}

impl TryFrom<&InMemorySigningKeyPair> for PrivateKey {
    type Error = Error;

    fn try_from(value: &InMemorySigningKeyPair) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            InMemorySigningKeyPair::Ecdsa(_, _, vec) => PrivateKey::Ec(EcPrivateKey::from_pkcs8_der(Bytes::copy_from_slice(vec.as_ref()))),
            // Ed25519 doesn't expose raw key bytes in the enum variant, so we construct
            // PrivateKey::Ed25519 from the PKCS#8 PEM via TryFrom<&SigningKey> instead.
            InMemorySigningKeyPair::Ed25519(_) => bail!("Ed25519 private key extraction unsupported from this type"),
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
            Self::Ed25519(_) => write!(f, "<ed25519_priv>"),
        }
    }
}

impl PrivateKey {
    /// Copy output encoding from `original` onto `self`. No-op unless both keys are EC.
    pub(crate) fn with_encoding_of(mut self, original: &PrivateKey) -> Self {
        if let (PrivateKey::Ec(new_ec), PrivateKey::Ec(orig_ec)) = (&mut self, original) {
            new_ec.encoding = orig_ec.encoding;
        }
        self
    }

    pub(crate) fn pem(&self) -> Result<pem::Pem> {
        match &self {
            PrivateKey::Rsa(rsa_private_key) => Ok(pem::Pem::new("RSA PRIVATE KEY", rsa_private_key.to_pkcs1_der()?.as_bytes())),
            PrivateKey::Ec(ec) => ec.pem(),
            PrivateKey::Ed25519(bytes) => Ok(pem::Pem::new("PRIVATE KEY", bytes.as_ref())),
        }
    }
}

#[derive(Hash, Eq, PartialEq, Clone)]
pub(crate) enum PublicKey {
    Rsa(Bytes),
    Ec(Bytes),
    Ed25519(Bytes),
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
            PrivateKey::Ec(ec) => PublicKey::Ec(super::crypto_utils::pubkey_pem_from_pkcs8_der(ec.pkcs8_der())?.into()),
            PrivateKey::Ed25519(pkcs8_der) => PublicKey::Ed25519(super::crypto_utils::pubkey_pem_from_pkcs8_der(pkcs8_der)?.into()),
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
            Self::Ed25519(x) => write!(f, "<ed25519_pub: {:?}>", x),
        }
    }
}

impl PublicKey {
    pub(crate) fn from_rsa_bytes(der_bytes: &Bytes) -> PublicKey {
        PublicKey::Rsa(der_bytes.clone())
    }

    fn pubkey_pem_from_cert_pem(cert_bytes: &Bytes) -> Result<Bytes> {
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

        Ok(output.stdout.into())
    }

    pub(crate) fn from_cert_bytes(cert_bytes: &Bytes, algo: &x509_certificate::KeyAlgorithm) -> Result<PublicKey> {
        let pem = Self::pubkey_pem_from_cert_pem(cert_bytes)?;
        Ok(match algo {
            x509_certificate::KeyAlgorithm::Ecdsa(_) => PublicKey::Ec(pem),
            x509_certificate::KeyAlgorithm::Ed25519 => PublicKey::Ed25519(pem),
            x509_certificate::KeyAlgorithm::Rsa => bail!("use from_rsa_bytes for RSA keys"),
        })
    }

    pub(crate) fn pem(&self) -> Result<pem::Pem> {
        Ok(match &self {
            PublicKey::Rsa(rsa_der_bytes) => pem::Pem::new("RSA PUBLIC KEY", rsa_der_bytes.as_ref()),
            PublicKey::Ec(pem_bytes) | PublicKey::Ed25519(pem_bytes) => {
                pem::parse(pem_bytes).context(format!("bytes to pem {:?}", pem_bytes))?
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_crypto::test_utils::{generate_ec_pkcs8_pem, generate_ed25519_pkcs8_pem};
    use std::io::Write;
    use std::process::{Command, Stdio};

    #[test]
    fn test_ec_encoding_is_not_part_of_key_identity() {
        let pkcs8_pem_bytes = generate_ec_pkcs8_pem("prime256v1");
        let parsed = pem::parse(&pkcs8_pem_bytes).expect("failed to parse PEM");
        let der = bytes::Bytes::copy_from_slice(parsed.contents());

        let sec1 = PrivateKey::Ec(EcPrivateKey {
            pkcs8_der: der.clone(),
            encoding: EcEncoding::Sec1,
        });
        let pkcs8 = PrivateKey::Ec(EcPrivateKey {
            pkcs8_der: der,
            encoding: EcEncoding::Pkcs8,
        });

        assert_eq!(sec1, pkcs8, "same PKCS#8 DER should compare equal regardless of output encoding");

        let mut sec1_hasher = std::collections::hash_map::DefaultHasher::new();
        let mut pkcs8_hasher = std::collections::hash_map::DefaultHasher::new();
        sec1.hash(&mut sec1_hasher);
        pkcs8.hash(&mut pkcs8_hasher);
        assert_eq!(sec1_hasher.finish(), pkcs8_hasher.finish(), "encoding must not affect the key hash");
    }

    #[test]
    fn test_with_encoding_of_copies_sec1_onto_generated_key() {
        let pkcs8_pem_bytes = generate_ec_pkcs8_pem("prime256v1");
        let parsed = pem::parse(&pkcs8_pem_bytes).expect("failed to parse PEM");
        let der = bytes::Bytes::copy_from_slice(parsed.contents());

        let original = PrivateKey::Ec(EcPrivateKey {
            pkcs8_der: der.clone(),
            encoding: EcEncoding::Sec1,
        });
        let generated = PrivateKey::Ec(EcPrivateKey {
            pkcs8_der: der,
            encoding: EcEncoding::Pkcs8,
        });

        let copied = generated.with_encoding_of(&original);
        assert_eq!(copied.pem().expect("pem() failed").tag(), "EC PRIVATE KEY");
    }

    #[test]
    fn test_with_encoding_of_ignores_non_ec_original() {
        let pkcs8_pem_bytes = generate_ec_pkcs8_pem("prime256v1");
        let parsed = pem::parse(&pkcs8_pem_bytes).expect("failed to parse PEM");
        let generated = PrivateKey::Ec(EcPrivateKey::from_pkcs8_der(bytes::Bytes::copy_from_slice(parsed.contents())));

        let ed25519_bytes = generate_ed25519_pkcs8_pem();
        let ed25519_pem = pem::parse(&ed25519_bytes).expect("failed to parse PEM");
        let ed25519 = PrivateKey::Ed25519(bytes::Bytes::copy_from_slice(ed25519_pem.contents()));

        let copied = generated.with_encoding_of(&ed25519);
        assert_eq!(
            copied.pem().expect("pem() failed").tag(),
            "PRIVATE KEY",
            "should stay PKCS#8 when original is not EC"
        );
    }
}
