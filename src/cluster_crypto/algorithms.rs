//! The key and signature algorithms recert supports, and how they're identified in ASN.1
//! structures (certificates, SubjectPublicKeyInfo, PKCS#8)

use anyhow::{bail, Context, Result};
use der::{asn1::ObjectIdentifier, Any};
use x509_cert::spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned};

pub(crate) const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
pub(crate) const SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
pub(crate) const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
pub(crate) const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
pub(crate) const ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
pub(crate) const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
pub(crate) const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
pub(crate) const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum EcdsaCurve {
    Secp256r1,
    Secp384r1,
}

impl EcdsaCurve {
    pub(crate) fn from_oid(oid: &ObjectIdentifier) -> Result<Self> {
        Ok(match *oid {
            SECP256R1 => EcdsaCurve::Secp256r1,
            SECP384R1 => EcdsaCurve::Secp384r1,
            _ => bail!("unsupported EC curve {oid}"),
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum KeyAlgorithm {
    Rsa,
    Ecdsa(EcdsaCurve),
    Ed25519,
}

impl KeyAlgorithm {
    /// Identifies the key algorithm from the AlgorithmIdentifier of a SubjectPublicKeyInfo or a
    /// PKCS#8 PrivateKeyInfo
    pub(crate) fn from_algorithm_identifier<Params: Into<Any> + Clone>(algorithm_identifier: &AlgorithmIdentifier<Params>) -> Result<Self> {
        Ok(match algorithm_identifier.oid {
            RSA_ENCRYPTION => KeyAlgorithm::Rsa,
            EC_PUBLIC_KEY => {
                let curve = algorithm_identifier
                    .parameters
                    .clone()
                    .context("EC key algorithm is missing the curve parameter")?
                    .into()
                    .decode_as::<ObjectIdentifier>()
                    .context("decoding EC curve")?;
                KeyAlgorithm::Ecdsa(EcdsaCurve::from_oid(&curve)?)
            }
            ED25519 => KeyAlgorithm::Ed25519,
            oid => bail!("unsupported key algorithm {oid}"),
        })
    }

    /// The AlgorithmIdentifier of the signatures recert makes with keys of this algorithm.
    /// Parameters are as required by RFC 4055 (RSA, NULL), RFC 5758 (ECDSA, absent) and RFC 8410
    /// (Ed25519, absent).
    pub(crate) fn signature_algorithm(self) -> AlgorithmIdentifierOwned {
        match self {
            KeyAlgorithm::Rsa => AlgorithmIdentifierOwned {
                oid: SHA256_WITH_RSA_ENCRYPTION,
                parameters: Some(Any::null()),
            },
            KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1) => AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256,
                parameters: None,
            },
            KeyAlgorithm::Ecdsa(EcdsaCurve::Secp384r1) => AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA384,
                parameters: None,
            },
            KeyAlgorithm::Ed25519 => AlgorithmIdentifierOwned {
                oid: ED25519,
                parameters: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{Decode, Encode};
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    fn spki_algorithm(spki_der_hex: &str) -> Result<KeyAlgorithm> {
        let spki = SubjectPublicKeyInfoOwned::from_der(&hex::decode(spki_der_hex).unwrap()).unwrap();
        KeyAlgorithm::from_algorithm_identifier(&spki.algorithm)
    }

    #[test]
    fn test_key_algorithm_from_spki() {
        // Ed25519 key from RFC 8410 section 10.1
        assert_eq!(
            spki_algorithm("302a300506032b657003210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1").unwrap(),
            KeyAlgorithm::Ed25519
        );

        let ec_spki = |curve: ObjectIdentifier| {
            SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid: EC_PUBLIC_KEY,
                    parameters: Some(Any::from(&curve)),
                },
                subject_public_key: der::asn1::BitString::from_bytes(&[4]).unwrap(),
            }
            .to_der()
            .map(hex::encode)
            .unwrap()
        };
        assert_eq!(
            spki_algorithm(&ec_spki(SECP256R1)).unwrap(),
            KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1)
        );
        assert_eq!(
            spki_algorithm(&ec_spki(SECP384R1)).unwrap(),
            KeyAlgorithm::Ecdsa(EcdsaCurve::Secp384r1)
        );
        // secp521r1 isn't supported
        assert!(spki_algorithm(&ec_spki(ObjectIdentifier::new_unwrap("1.3.132.0.35"))).is_err());
    }

    #[test]
    fn test_signature_algorithm_encoding() {
        let encoded = |key_algorithm: KeyAlgorithm| hex::encode(key_algorithm.signature_algorithm().to_der().unwrap());
        assert_eq!(encoded(KeyAlgorithm::Rsa), "300d06092a864886f70d01010b0500");
        assert_eq!(encoded(KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1)), "300a06082a8648ce3d040302");
        assert_eq!(encoded(KeyAlgorithm::Ecdsa(EcdsaCurve::Secp384r1)), "300a06082a8648ce3d040303");
        assert_eq!(encoded(KeyAlgorithm::Ed25519), "300506032b6570");
    }
}
