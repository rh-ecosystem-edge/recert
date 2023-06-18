use super::keys::PublicKey;
use anyhow::{Context, Result};
use p256::pkcs8::EncodePublicKey;
use std::hash::{Hash, Hasher};
use x509_certificate::{self, CapturedX509Certificate};

#[derive(Clone, Debug)]
pub(crate) struct Certificate {
    pub(crate) issuer: String,
    pub(crate) subject: String,
    pub(crate) public_key: PublicKey,
    pub(crate) original: CapturedX509Certificate,
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.issuer == other.issuer && self.subject == other.subject && self.public_key == other.public_key
    }
}

impl Eq for Certificate {}

impl Hash for Certificate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.issuer.hash(state);
        self.subject.hash(state);
        self.public_key.hash(state);
    }
}

impl TryFrom<CapturedX509Certificate> for Certificate {
    type Error = anyhow::Error;

    fn try_from(cert: CapturedX509Certificate) -> Result<Self> {
        Ok(Certificate {
            issuer: cert.issuer_name().user_friendly_str().unwrap_or("undecodable".to_string()),
            subject: cert.subject_name().user_friendly_str().unwrap_or("undecodable".to_string()),
            public_key: match cert.key_algorithm().context("failed to get cert key algorithm")? {
                x509_certificate::KeyAlgorithm::Rsa => PublicKey::from_rsa_bytes(&bytes::Bytes::copy_from_slice(
                    &bytes::Bytes::copy_from_slice(&cert.to_public_key_der().context("parsing public key")?.as_bytes()),
                )),
                x509_certificate::KeyAlgorithm::Ecdsa(_) => {
                    PublicKey::from_ec_cert_bytes(&bytes::Bytes::copy_from_slice(cert.encode_pem().as_bytes()))
                }
                x509_certificate::KeyAlgorithm::Ed25519 => panic!("ed25519 not supported"),
            },
            original: cert,
        })
    }
}
