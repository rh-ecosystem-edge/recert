use super::keys::PublicKey;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use bcder::Oid;
use der::Decode;
use p256::pkcs8::EncodePublicKey;
use serde::{ser::SerializeStruct, Serialize};
use std::hash::{Hash, Hasher};
use x509_cert::ext::pkix::name::GeneralName::DnsName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_certificate::{self, rfc5280, CapturedX509Certificate};

pub(crate) const SUBJECT_ALTERNATIVE_NAME_OID: [u8; 3] = [85, 29, 17];
pub(crate) const SUBJECT_KEY_IDENTIFIER_OID: [u8; 3] = [85, 29, 14];
pub(crate) const AUTHORITY_KEY_IDENTIFIER_OID: [u8; 3] = [85, 29, 35];

#[derive(Clone, Debug)]
pub(crate) struct Certificate {
    pub(crate) issuer: String,
    pub(crate) subject: String,
    pub(crate) sans: Vec<String>,
    pub(crate) public_key: PublicKey,
    pub(crate) cert: CapturedX509Certificate,
}

fn time_string(asn1time: &x509_certificate::asn1time::Time) -> String {
    match asn1time {
        x509_certificate::asn1time::Time::UtcTime(time) => time.to_string(),
        x509_certificate::asn1time::Time::GeneralTime(time) => time.to_string(),
    }
}

impl Serialize for Certificate {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut struct_serializer = serializer.serialize_struct("Certificate", 4)?;
        struct_serializer.serialize_field("issuer", &self.issuer)?;
        struct_serializer.serialize_field("subject", &self.subject)?;

        let cert: &x509_certificate::X509Certificate = &self.cert;
        let certificate: &x509_certificate::rfc5280::Certificate = cert.as_ref();
        struct_serializer.serialize_field("validity_start", &time_string(&certificate.tbs_certificate.validity.not_before))?;
        struct_serializer.serialize_field("validity_end", &time_string(&certificate.tbs_certificate.validity.not_after))?;
        struct_serializer.serialize_field("sans", &self.sans)?;

        struct_serializer.serialize_field("pem", &base64_standard.encode(self.cert.encode_pem()))?;
        struct_serializer.end()
    }
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

impl TryFrom<&CapturedX509Certificate> for Certificate {
    type Error = anyhow::Error;

    fn try_from(cert: &CapturedX509Certificate) -> Result<Self> {
        Ok(Certificate {
            issuer: cert.issuer_name().user_friendly_str().unwrap_or("undecodable".to_string()),
            subject: cert.subject_name().user_friendly_str().unwrap_or("undecodable".to_string()),
            public_key: match cert.key_algorithm().context("failed to get cert key algorithm")? {
                x509_certificate::KeyAlgorithm::Rsa => PublicKey::from_rsa_bytes(&bytes::Bytes::copy_from_slice(
                    cert.to_public_key_der().context("parsing public key")?.as_bytes(),
                )),
                x509_certificate::KeyAlgorithm::Ecdsa(_) => {
                    PublicKey::from_ec_cert_bytes(&bytes::Bytes::copy_from_slice(cert.encode_pem().as_bytes()))
                        .context("converting EC key bytes")?
                }
                x509_certificate::KeyAlgorithm::Ed25519 => bail!("ed25519 not supported"),
            },
            cert: cert.clone(),
            sans: {
                let certificate: &rfc5280::Certificate = cert.as_ref();
                if let Some(extensions) = &certificate.tbs_certificate.extensions {
                    extensions
                        .iter()
                        .filter(|ext| ext.id == Oid(&SUBJECT_ALTERNATIVE_NAME_OID))
                        .map(|ext| -> Result<Vec<String>> {
                            Ok(SubjectAltName::from_der(ext.value.as_slice().context("empty SAN extension")?)?
                                .0
                                .iter()
                                .filter_map(|san| -> Option<String> {
                                    let value: Option<String> = match san {
                                        DnsName(name) => Some(name.to_string()),
                                        _ => None,
                                    };

                                    value
                                })
                                .collect::<Vec<String>>())
                        })
                        .collect::<Result<Vec<Vec<String>>>>()
                        .context("mutating cert CN/SAN extensions")?
                        .into_iter()
                        .flatten()
                        .collect::<Vec<String>>()
                } else {
                    vec![]
                }
            },
        })
    }
}
