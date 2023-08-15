use super::SUBJECT_KEY_IDENTIFIER_OID;
use anyhow::{bail, Context, Result};
use bcder::{OctetString, Oid};
use der::{Decode, Encode};
use sha1::{Digest, Sha1};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_certificate::{
    rfc5280,
    KeyAlgorithm::{self, Ecdsa},
};

#[derive(EnumIter, Copy, Clone, Debug)]
pub(crate) enum SubjectKeyIdentifierMethod {
    /// Subject key identifier calculated according to method (1) in RFC 5280:
    /// https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2 This is the default method
    /// used by openssl and golang (golang since June 2020).
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

pub(crate) fn calculate_skid(
    tbs_certificate: &rfc5280::TbsCertificate,
    method: SubjectKeyIdentifierMethod,
) -> Result<SubjectKeyIdentifier> {
    match method {
        SubjectKeyIdentifierMethod::RFC5280 => {
            let mut hasher = Sha1::new();
            hasher.update(tbs_certificate.subject_public_key_info.subject_public_key.octet_bytes());
            let skid = hasher.finalize();
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

                    let asn1_blocks = simple_asn1::from_der(&tbs_certificate.subject_public_key_info.subject_public_key.octet_bytes())
                        .context("parsing public key as DER")?;

                    for asn1_block in asn1_blocks {
                        match asn1_block {
                            simple_asn1::ASN1Block::Sequence(_, blocks) => {
                                if blocks.len() != 2 {
                                    bail!("RSA keys should only have modulus and exponent")
                                }

                                match &blocks[0] {
                                    simple_asn1::ASN1Block::Integer(_, modulus) => {
                                        let (sign, bytes) = modulus.to_bytes_be();
                                        match sign {
                                            num_bigint::Sign::Plus => {}
                                            _ => bail!("invalid modulus sign"),
                                        };

                                        if bytes.len() == 0 {
                                            bail!("modulus is zero")
                                        }

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

/// Given a certificate, return the key identifier method that was used to generate the SKID
/// extension.
///
/// This is used to determine how to generate the SKID extension when regenerating the certificate.
pub(crate) fn get_cert_key_skid_method(tbs_certificate: &mut rfc5280::TbsCertificate) -> Option<Result<SubjectKeyIdentifierMethod>> {
    if let Some(all_extensions) = &mut tbs_certificate.extensions {
        let skid_extensions = all_extensions
            .iter_mut()
            .filter(|ext| ext.id == Oid(&SUBJECT_KEY_IDENTIFIER_OID))
            .collect::<Vec<_>>();

        if skid_extensions.len() == 0 {
            return None;
        }

        if skid_extensions.len() > 1 {
            return Some(Err(anyhow::anyhow!("multiple SKID extensions found")));
        }

        let skid_slice = match (&skid_extensions[0]).value.as_slice() {
            Some(slice) => slice,
            None => return Some(Err(anyhow::anyhow!("SKID extension not octet string"))),
        };

        let parsed_skid_extension = match SubjectKeyIdentifier::from_der(skid_slice) {
            Ok(parsed_extension) => parsed_extension,
            Err(_) => return Some(Err(anyhow::anyhow!("failed to parse SKID extension"))),
        };

        for candidate_skid_method in SubjectKeyIdentifierMethod::iter() {
            let method_predicted_skid = calculate_skid(tbs_certificate, candidate_skid_method);

            match method_predicted_skid {
                Ok(method_predicted_skid) => {
                    if method_predicted_skid == parsed_skid_extension {
                        return Some(Ok(candidate_skid_method));
                    }
                }
                Err(_) => continue,
            }
        }
    } else {
        return None;
    }

    Some(Err(anyhow::anyhow!("failed to find matching SKID method")))
}

pub(crate) fn fix_skid(tbs_certificate: &mut rfc5280::TbsCertificate, method: SubjectKeyIdentifierMethod) -> Result<()> {
    let new_skid_extension = calculate_skid(tbs_certificate, method)?;

    if let Some(extensions) = &mut tbs_certificate.extensions {
        extensions
            .iter_mut()
            .filter(|ext| ext.id == Oid(&SUBJECT_KEY_IDENTIFIER_OID))
            .map(|ext| {
                ext.value = OctetString::new(bytes::Bytes::copy_from_slice(
                    new_skid_extension
                        .to_der()
                        .context("failed to generate SAN extension")
                        .ok()
                        .context("failed to generate SAN extension")?
                        .as_slice(),
                ));
                Ok(())
            })
            .collect::<Result<Vec<()>>>()
            .context("fixing skid")?;
    }
    Ok(())
}
