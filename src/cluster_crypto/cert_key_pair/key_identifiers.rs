use anyhow::{bail, ensure, Context, Result};
use bcder::Oid;
use der::{asn1::OctetString, Decode, Encode};
use num_bigint::Sign;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use simple_asn1::ASN1Block;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier};
use x509_certificate::{
    rfc5280,
    KeyAlgorithm::{self, Ecdsa},
};

use crate::cluster_crypto::certificate::{AUTHORITY_KEY_IDENTIFIER_OID, SUBJECT_KEY_IDENTIFIER_OID};

#[derive(PartialEq, Eq)]
pub(crate) struct HashableKeyID(pub(crate) OctetString);

impl std::hash::Hash for HashableKeyID {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        for byte in self.0.as_bytes() {
            byte.hash(state);
        }
    }
}

#[derive(PartialEq, Eq, Hash)]
pub(crate) struct HashableSerialNumber(pub(crate) Vec<u8>);

#[derive(EnumIter, Copy, Clone, Debug)]
pub(crate) enum SubjectKeyIdentifierMethod {
    /// Subject key identifier calculated according to method (1) in RFC 7083:
    /// https://datatracker.ietf.org/doc/html/rfc7093#section-2. Recent versions of golang
    /// (probably 1.25 - see https://github.com/golang/go/issues/71746) use it and consequently
    /// OCP.
    ///
    /// It applies for all key types, as it doesn't decode the DER formatted key, it looks at the
    /// raw asn.1 BIT STRING
    RFC7093,

    /// Subject key identifier calculated according to method (1) in RFC 5280:
    /// https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2 This is the old default
    /// method used by openssl and golang (golang since June 2020).
    ///
    /// It applies for all key types, as it doesn't decode the DER formatted key, it looks at the
    /// raw asn.1 BIT STRING
    RFC5280,

    /// Key identifier calculated according to the newKeyPairWithHash method
    /// from OCP's library-go:
    ///
    /// https://github.com/openshift/library-go/blob/bf4ec512c632fc58304927448bac6c34d744d882/pkg/crypto/crypto.go#L976-L985
    ///
    /// It only applies for RSA keys. It takes the SHA1 hash of the public key modulus ("N")
    /// encoded as big-endian big num byte slice.
    LibraryGoSha1,
}

fn calculate_skid(tbs_certificate: &rfc5280::TbsCertificate, method: SubjectKeyIdentifierMethod) -> Result<SubjectKeyIdentifier> {
    match method {
        SubjectKeyIdentifierMethod::RFC5280 => {
            let mut hasher = Sha1::new();
            hasher.update(tbs_certificate.subject_public_key_info.subject_public_key.octet_bytes());
            let skid = hasher.finalize();
            let new_skid_extension = SubjectKeyIdentifier(x509_cert::der::asn1::OctetString::new(&*skid)?);

            Ok(new_skid_extension)
        }
        SubjectKeyIdentifierMethod::RFC7093 => {
            let mut hasher = Sha256::new();
            hasher.update(tbs_certificate.subject_public_key_info.subject_public_key.octet_bytes());
            let skid = hasher.finalize().as_slice()[0..20].to_vec();
            let new_skid_extension = SubjectKeyIdentifier(x509_cert::der::asn1::OctetString::new(&*skid)?);
            Ok(new_skid_extension)
        }
        SubjectKeyIdentifierMethod::LibraryGoSha1 => {
            match KeyAlgorithm::try_from(&tbs_certificate.subject_public_key_info.algorithm)
                .ok()
                .context("failed to get cert key algorithm")?
            {
                x509_certificate::KeyAlgorithm::Rsa => {
                    let mut hasher = Sha1::new();

                    let key_bytes = &tbs_certificate.subject_public_key_info.subject_public_key.octet_bytes();
                    let asn1_blocks = simple_asn1::from_der(key_bytes).context("parsing public key as DER")?;

                    for asn1_block in asn1_blocks {
                        match asn1_block {
                            ASN1Block::Sequence(_, blocks) => {
                                if blocks.len() != 2 {
                                    bail!("RSA keys should only have modulus and exponent")
                                }

                                match &blocks[0] {
                                    ASN1Block::Integer(_, modulus) => {
                                        let (sign, bytes) = modulus.to_bytes_be();
                                        match sign {
                                            Sign::Plus => {}
                                            _ => bail!("invalid modulus sign"),
                                        };

                                        ensure!(!bytes.is_empty(), "modulus is zero {:?}", key_bytes);

                                        hasher.update(&bytes);
                                    }
                                    _ => bail!("unexpected block type"),
                                };

                                // exponent is ignored in this method
                            }
                            _ => bail!("unexpected block type"),
                        }
                    }

                    let skid = hasher.finalize();
                    let new_skid_extension = SubjectKeyIdentifier(x509_cert::der::asn1::OctetString::new(&*skid)?);

                    Ok(new_skid_extension)
                }
                Ecdsa(_) => bail!("LibraryGoSha1 not supported for ecdsa keys"),
                x509_certificate::KeyAlgorithm::Ed25519 => bail!("ed25519 not supported"),
            }
        }
    }
}

pub(crate) fn get_skid(tbs_certificate: &rfc5280::TbsCertificate) -> Result<Option<SubjectKeyIdentifier>> {
    Ok(if let Some(all_extensions) = &tbs_certificate.extensions {
        let skid_extensions = all_extensions
            .iter()
            .filter(|ext| ext.id == Oid(&SUBJECT_KEY_IDENTIFIER_OID))
            .collect::<Vec<_>>();

        if skid_extensions.is_empty() {
            return Ok(None);
        }

        ensure!(
            skid_extensions.len() == 1,
            "multiple ({}) SKID extensions found",
            skid_extensions.len()
        );

        Some(
            SubjectKeyIdentifier::from_der(skid_extensions[0].value.as_slice().context("SKID has slice")?)
                .context("Creating SKID from DER")?,
        )
    } else {
        None
    })
}

pub(crate) fn get_akid(tbs_certificate: &rfc5280::TbsCertificate) -> Result<Option<AuthorityKeyIdentifier>> {
    Ok(if let Some(all_extensions) = &tbs_certificate.extensions {
        let akid_extensions = all_extensions
            .iter()
            .filter(|ext| ext.id == Oid(&AUTHORITY_KEY_IDENTIFIER_OID))
            .collect::<Vec<_>>();

        if akid_extensions.is_empty() {
            return Ok(None);
        }

        ensure!(
            akid_extensions.len() == 1,
            "multiple ({}) AKID extensions found",
            akid_extensions.len()
        );

        Some(
            AuthorityKeyIdentifier::from_der(akid_extensions[0].value.as_slice().context("AKID has slice")?)
                .context("creating AKID from DER")?,
        )
    } else {
        None
    })
}

/// Given a certificate, return the key identifier method that was used to generate the SKID
/// extension.
///
/// We find the method by using brute force through all methods until we have a match. If the cert
/// doesn't have any SKID extension, we return None. But if it has one, and we can't find a method
/// match, we return an error.
pub(crate) fn get_cert_skid_method(
    tbs_certificate: &mut rfc5280::TbsCertificate,
    skid: &SubjectKeyIdentifier,
) -> Result<SubjectKeyIdentifierMethod> {
    for candidate_skid_method in SubjectKeyIdentifierMethod::iter() {
        let method_predicted_skid = calculate_skid(tbs_certificate, candidate_skid_method).context("calculating SKID")?;

        if method_predicted_skid == *skid {
            return Ok(candidate_skid_method);
        }
    }

    bail!("failed to find matching SKID method");
}

/// Given a certificate and the SKID method, calculate the SKID extension and set it in the
/// certificate.
pub(crate) fn calculate_and_set_skid(
    tbs_certificate: &mut rfc5280::TbsCertificate,
    method: SubjectKeyIdentifierMethod,
) -> Result<SubjectKeyIdentifier> {
    let new_skid_extension = calculate_skid(tbs_certificate, method).context("calculating skid")?;

    tbs_certificate
        .extensions
        .as_mut()
        .context("no extensions found")?
        .iter_mut()
        .filter(|ext| ext.id == Oid(&SUBJECT_KEY_IDENTIFIER_OID))
        .map(|ext| {
            ext.value = bcder::OctetString::new(bytes::Bytes::copy_from_slice(
                new_skid_extension.to_der().context("converting to DER")?.as_slice(),
            ));
            Ok(())
        })
        .collect::<Result<Vec<()>>>()
        .context("setting skid")?;
    Ok(new_skid_extension)
}

/// Modify the certificate to set the AKID extension.
pub(crate) fn set_akid(tbs_certificate: &mut rfc5280::TbsCertificate, akid: AuthorityKeyIdentifier) -> Result<()> {
    tbs_certificate
        .extensions
        .as_mut()
        .context("no extensions found")?
        .iter_mut()
        .filter(|ext| ext.id == Oid(&AUTHORITY_KEY_IDENTIFIER_OID))
        .map(|ext| {
            ext.value = bcder::OctetString::new(bytes::Bytes::copy_from_slice(
                akid.to_der().context("converting to DER")?.as_slice(),
            ));
            Ok(())
        })
        .collect::<Result<Vec<()>>>()
        .context("setting akid")?;
    Ok(())
}
