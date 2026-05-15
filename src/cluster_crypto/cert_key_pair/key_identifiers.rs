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

#[derive(EnumIter, Copy, Clone, Debug, PartialEq, Eq)]
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

    /// Key identifier calculated according to the SubjectKeyIDFromPublicKey method
    /// from OCP's library-go:
    ///
    /// https://github.com/openshift/library-go/blob/fa6e3d17eb261352330139c7a4d9cf79f9191d64/pkg/crypto/keygen.go#L102-L118
    ///
    /// It takes the first 160 bits of the SHA-256 hash of the raw key material:
    /// - RSA: pub.N.Bytes() (bare modulus, no ASN.1 framing)
    /// - ECDSA: pub.ECDH().Bytes() (uncompressed EC point)
    LibraryGoSha256,
}

fn rsa_modulus_bytes(tbs_certificate: &rfc5280::TbsCertificate) -> Result<Vec<u8>> {
    let key_bytes = tbs_certificate.subject_public_key_info.subject_public_key.octet_bytes();
    let asn1_blocks = simple_asn1::from_der(&key_bytes).context("parsing public key as DER")?;

    let asn1_block = asn1_blocks.into_iter().next().context("empty ASN.1 blocks")?;
    match asn1_block {
        ASN1Block::Sequence(_, blocks) => {
            ensure!(blocks.len() == 2, "RSA keys should only have modulus and exponent");
            match &blocks[0] {
                ASN1Block::Integer(_, modulus) => {
                    let (sign, bytes) = modulus.to_bytes_be();
                    ensure!(sign == Sign::Plus, "invalid modulus sign");
                    ensure!(!bytes.is_empty(), "modulus is zero");
                    Ok(bytes)
                }
                _ => bail!("unexpected block type for modulus"),
            }
        }
        _ => bail!("unexpected top-level block type"),
    }
}

fn make_skid(bytes: &[u8]) -> Result<SubjectKeyIdentifier> {
    Ok(SubjectKeyIdentifier(x509_cert::der::asn1::OctetString::new(bytes)?))
}

fn calculate_skid(tbs_certificate: &rfc5280::TbsCertificate, method: SubjectKeyIdentifierMethod) -> Result<SubjectKeyIdentifier> {
    let spk_bytes = || tbs_certificate.subject_public_key_info.subject_public_key.octet_bytes();

    match method {
        SubjectKeyIdentifierMethod::RFC5280 => make_skid(&Sha1::digest(spk_bytes())),
        SubjectKeyIdentifierMethod::RFC7093 => make_skid(&Sha256::digest(spk_bytes())[..20]),
        SubjectKeyIdentifierMethod::LibraryGoSha1 => {
            let algo = KeyAlgorithm::try_from(&tbs_certificate.subject_public_key_info.algorithm)
                .ok()
                .context("failed to get cert key algorithm")?;
            match algo {
                x509_certificate::KeyAlgorithm::Rsa => make_skid(&Sha1::digest(rsa_modulus_bytes(tbs_certificate)?)),
                Ecdsa(_) => bail!("LibraryGoSha1 not supported for ecdsa keys"),
                x509_certificate::KeyAlgorithm::Ed25519 => bail!("ed25519 not supported"),
            }
        }
        SubjectKeyIdentifierMethod::LibraryGoSha256 => {
            let algo = KeyAlgorithm::try_from(&tbs_certificate.subject_public_key_info.algorithm)
                .ok()
                .context("failed to get cert key algorithm")?;
            match algo {
                x509_certificate::KeyAlgorithm::Rsa => make_skid(&Sha256::digest(rsa_modulus_bytes(tbs_certificate)?)[..20]),
                // library-go's ECDSA SKID is identical to RFC7093 (both SHA-256 the
                // uncompressed EC point), so the brute-force detection in
                // get_cert_skid_method will always match RFC7093 first for EC certs.
                Ecdsa(_) => bail!("LibraryGoSha256 for ECDSA is identical to RFC7093, should not reach here"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use x509_certificate::{CapturedX509Certificate, X509Certificate};

    fn tbs_from_pem(pem: &str) -> rfc5280::TbsCertificate {
        let cert = CapturedX509Certificate::from_pem(pem).unwrap();
        let x509: &X509Certificate = &cert;
        let certificate: &rfc5280::Certificate = x509.as_ref();
        certificate.tbs_certificate.clone()
    }

    fn assert_skid_method(pem: &str, expected_method: SubjectKeyIdentifierMethod) {
        let mut tbs = tbs_from_pem(pem);
        let skid = get_skid(&tbs).unwrap().expect("cert should have SKID");
        let method = get_cert_skid_method(&mut tbs, &skid).unwrap();
        assert_eq!(method, expected_method);
    }

    fn assert_skid_roundtrip(pem: &str, expected_method: SubjectKeyIdentifierMethod) {
        let tbs = tbs_from_pem(pem);
        let skid = get_skid(&tbs).unwrap().expect("cert should have SKID");
        let calculated = calculate_skid(&tbs, expected_method).unwrap();
        assert_eq!(skid, calculated);
    }

    // All test certs below are real-world certificates from an OCP SNO cluster,
    // extracted from a recert summary YAML. The SKID method classification was
    // verified using the Python script at testdata/classify.py.

    // RSA, CN=aggregator-signer OU=openshift — SKID via SHA1(subjectPublicKey BIT STRING)
    const RSA_RFC5280: &str = include_str!("testdata/rsa_rfc5280.pem");
    // RSA, CN=ingress-operator@1778264075 — SKID via SHA256(subjectPublicKey BIT STRING)[:20]
    const RSA_RFC7093: &str = include_str!("testdata/rsa_rfc7093.pem");
    // RSA, CN=openshift-service-serving-signer@1778263995 — SKID via SHA1(RSA modulus)
    const RSA_LIBRARY_GO_SHA1: &str = include_str!("testdata/rsa_library_go_sha1.pem");
    // RSA, CN=openshift-cluster-monitoring@1778264477 — SKID via SHA256(RSA modulus)[:20]
    const RSA_LIBRARY_GO_SHA256: &str = include_str!("testdata/rsa_library_go_sha256.pem");
    // EC (P-256), CN=olm-selfsigned-5bb81b5ed486756c — SKID via SHA256(subjectPublicKey BIT STRING)[:20]
    const EC_RFC7093: &str = include_str!("testdata/ec_rfc7093.pem");

    #[test]
    fn test_rsa_rfc5280_detection() {
        assert_skid_method(RSA_RFC5280, SubjectKeyIdentifierMethod::RFC5280);
    }

    #[test]
    fn test_rsa_rfc5280_roundtrip() {
        assert_skid_roundtrip(RSA_RFC5280, SubjectKeyIdentifierMethod::RFC5280);
    }

    #[test]
    fn test_rsa_rfc7093_detection() {
        assert_skid_method(RSA_RFC7093, SubjectKeyIdentifierMethod::RFC7093);
    }

    #[test]
    fn test_rsa_rfc7093_roundtrip() {
        assert_skid_roundtrip(RSA_RFC7093, SubjectKeyIdentifierMethod::RFC7093);
    }

    #[test]
    fn test_rsa_library_go_sha1_detection() {
        assert_skid_method(RSA_LIBRARY_GO_SHA1, SubjectKeyIdentifierMethod::LibraryGoSha1);
    }

    #[test]
    fn test_rsa_library_go_sha1_roundtrip() {
        assert_skid_roundtrip(RSA_LIBRARY_GO_SHA1, SubjectKeyIdentifierMethod::LibraryGoSha1);
    }

    #[test]
    fn test_rsa_library_go_sha256_detection() {
        assert_skid_method(RSA_LIBRARY_GO_SHA256, SubjectKeyIdentifierMethod::LibraryGoSha256);
    }

    #[test]
    fn test_rsa_library_go_sha256_roundtrip() {
        assert_skid_roundtrip(RSA_LIBRARY_GO_SHA256, SubjectKeyIdentifierMethod::LibraryGoSha256);
    }

    #[test]
    fn test_ec_rfc7093_detection() {
        assert_skid_method(EC_RFC7093, SubjectKeyIdentifierMethod::RFC7093);
    }

    #[test]
    fn test_ec_rfc7093_roundtrip() {
        assert_skid_roundtrip(EC_RFC7093, SubjectKeyIdentifierMethod::RFC7093);
    }

    #[test]
    /// The point of this test is to ensure that all the PEM files in our testdata directory are
    /// valid and self-signed. Not because it matters for the test but because those certs are
    /// practically binary blobs that we don't generate, so it's good practice to at-least make
    /// them hard to tamper with. Of course someone could remove this test but that would look
    /// suspicious. Probably overkill.
    fn test_all_testdata_pems_are_self_signed() {
        fn collect_pems(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    collect_pems(&path, out);
                } else if path.extension().and_then(|e| e.to_str()) == Some("pem") {
                    out.push(path);
                }
            }
        }

        let testdata = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cluster_crypto/cert_key_pair/testdata");

        let mut pems = Vec::new();
        collect_pems(&testdata, &mut pems);
        assert!(!pems.is_empty(), "no PEM files found in {}", testdata.display());

        for path in &pems {
            let pem = std::fs::read(path).unwrap();
            let cert = CapturedX509Certificate::from_pem(&pem).unwrap();
            cert.verify_signed_by_certificate(&cert).unwrap_or_else(|e| {
                panic!("{}: not self-signed: {e}", path.display());
            });
        }
    }
}
