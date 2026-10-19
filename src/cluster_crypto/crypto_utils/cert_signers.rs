//! Figures out which certificates signed which other certificates.
//!
//! We only care about the cryptographic relationship (does the public key of cert A verify the
//! signature of cert B), not about whether B is a valid cert, so names, validity, extensions, etc.
//! are all ignored. A relationship we miss is a cert we fail to regenerate properly, so nothing is
//! ever skipped based on such metadata.
//!
//! For FIPS compliance the signature checks are done by openssl. Spawning openssl for every
//! (signer, signee) pair would mean tens of thousands of processes in a typical cluster, so
//! instead we run a single `openssl verify` per distinct public key, which checks all signees at
//! once against synthetic trust anchors carrying that public key.
//!
//! `openssl verify` builds and validates chains rather than just checking signatures, so the
//! anchors are crafted such that the only thing that can fail is the signee's signature check:
//! - Their subject is the signee's issuer, and their serial and issuer match the signee's AKID
//!   authorityCertSerialNumber / authorityCertIssuer (if any), as openssl requires those to match
//!   before it considers a cert to be an issuer candidate.
//! - They have no SKID, so openssl doesn't compare it with the signee's AKID keyIdentifier.
//! - They're CAs that are allowed to sign certs.
//! - `-partial_chain` makes openssl trust them as-is, without checking their own (bogus) signature.
//!
//! Combined with disabling time checks, security level checks and unknown critical extension
//! checks, every signee either verifies, which means it was signed by that key, or fails with
//! X509_V_ERR_CERT_SIGNATURE_FAILURE, which means it wasn't. Anything else is an error, so that we
//! never silently miss a signer.

use anyhow::{bail, ensure, Context, Result};
use der::{
    asn1::{BitString, ObjectIdentifier, OctetString, UtcTime},
    oid::AssociatedOid,
    Decode, Encode,
};
use std::{
    collections::{BTreeMap, HashMap},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use x509_cert::{
    ext::{
        pkix::{name::GeneralName, AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages},
        Extension,
    },
    name::Name,
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::{Time, Validity},
    Certificate, TbsCertificate, Version,
};

const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const ED448: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.113");
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

const SHA1_SIGNATURE_ALGORITHMS: [ObjectIdentifier; 4] = [
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5"), // sha1WithRSAEncryption
    ObjectIdentifier::new_unwrap("1.3.14.3.2.29"),        // sha1WithRSASignature (legacy OIW)
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.1"),    // ecdsa-with-SHA1
    ObjectIdentifier::new_unwrap("1.2.840.10040.4.3"),    // dsa-with-sha1
];

/// A self-signed ecdsa-with-SHA1 cert, used to find out whether openssl is able to verify SHA-1
/// signatures in the environment we're running in (e.g. it can't in FIPS mode)
const SHA1_SIGNATURE_PROBE_PEM: &str = include_str!("sha1_signature_probe.pem");

/// X509_V_ERR_CERT_SIGNATURE_FAILURE
const OPENSSL_SIGNATURE_FAILURE: u32 = 7;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum KeyType {
    Rsa,
    Ec,
    Ed25519,
    Ed448,
    Unknown,
}

impl KeyType {
    fn of_public_key(spki: &SubjectPublicKeyInfoOwned) -> Self {
        match spki.algorithm.oid {
            RSA_ENCRYPTION | RSASSA_PSS => KeyType::Rsa,
            EC_PUBLIC_KEY => KeyType::Ec,
            ED25519 => KeyType::Ed25519,
            ED448 => KeyType::Ed448,
            _ => KeyType::Unknown,
        }
    }

    /// The type of key that could have produced a signature made with the given algorithm
    fn of_signature_algorithm(signature_algorithm: &ObjectIdentifier) -> Self {
        let oid = signature_algorithm.to_string();
        if oid.starts_with("1.2.840.113549.1.1.") || oid == "1.3.14.3.2.29" {
            KeyType::Rsa
        } else if oid.starts_with("1.2.840.10045.4.") {
            KeyType::Ec
        } else if *signature_algorithm == ED25519 {
            KeyType::Ed25519
        } else if *signature_algorithm == ED448 {
            KeyType::Ed448
        } else {
            KeyType::Unknown
        }
    }

    /// Whether a key of this type could have produced a signature that requires a `required` key.
    /// When we don't know, we let openssl decide.
    fn could_have_signed(self, required: KeyType) -> bool {
        self == KeyType::Unknown || required == KeyType::Unknown || self == required
    }
}

/// What a synthetic trust anchor needs to look like in order for openssl to consider it as the
/// issuer of a signee
struct AnchorTemplate {
    subject: Name,
    issuer: Name,
    serial_number: SerialNumber,
}

impl AnchorTemplate {
    fn for_signee(signee: &TbsCertificate) -> Result<Self> {
        let mut template = AnchorTemplate {
            subject: signee.issuer.clone(),
            issuer: signee.issuer.clone(),
            serial_number: SerialNumber::from(1u32),
        };

        if let Some((_, akid)) = signee.get::<AuthorityKeyIdentifier>().context("parsing authority key identifier")? {
            if let Some(serial_number) = akid.authority_cert_serial_number {
                template.serial_number = serial_number;
            }
            // openssl only looks at the first directory name
            if let Some(issuer) = akid.authority_cert_issuer.iter().flatten().find_map(|name| match name {
                GeneralName::DirectoryName(name) => Some(name.clone()),
                _ => None,
            }) {
                template.issuer = issuer;
            }
        }

        Ok(template)
    }

    fn dedup_key(&self) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        Ok((self.subject.to_der()?, self.issuer.to_der()?, self.serial_number.to_der()?))
    }

    fn to_anchor_der(&self, public_key: &SubjectPublicKeyInfoOwned) -> Result<Vec<u8>> {
        // The anchor's own signature is never checked, so its algorithm and value don't matter
        let signature_algorithm = AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA256,
            parameters: None,
        };

        let tbs_certificate = TbsCertificate {
            version: Version::V3,
            serial_number: self.serial_number.clone(),
            signature: signature_algorithm.clone(),
            issuer: self.issuer.clone(),
            validity: Validity {
                not_before: Time::UtcTime(UtcTime::from_unix_duration(Duration::ZERO)?),
                not_after: Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(2_500_000_000))?),
            },
            subject: self.subject.clone(),
            subject_public_key_info: public_key.clone(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![
                Extension {
                    extn_id: BasicConstraints::OID,
                    critical: true,
                    extn_value: OctetString::new(
                        BasicConstraints {
                            ca: true,
                            path_len_constraint: None,
                        }
                        .to_der()?,
                    )?,
                },
                Extension {
                    extn_id: KeyUsage::OID,
                    critical: true,
                    extn_value: OctetString::new(KeyUsage(KeyUsages::KeyCertSign.into()).to_der()?)?,
                },
            ]),
        };

        Ok(Certificate {
            tbs_certificate,
            signature_algorithm,
            signature: BitString::from_bytes(&[0])?,
        }
        .to_der()?)
    }
}

struct Signee<'a> {
    der: &'a [u8],
    required_key_type: KeyType,
    anchor_template: AnchorTemplate,
}

impl<'a> Signee<'a> {
    fn parse(der: &'a [u8]) -> Result<(Self, bool)> {
        let cert = Certificate::from_der(der).context("parsing certificate")?;
        let signature_algorithm = cert.signature_algorithm.oid;

        // openssl considers these self-signed (without checking the signature) and refuses to look
        // for an issuer, so we can't use the trust anchor trick for them
        ensure!(
            cert.tbs_certificate.subject != cert.tbs_certificate.issuer,
            "finding the signers of self-issued certs is not supported"
        );

        Ok((
            Signee {
                der,
                required_key_type: KeyType::of_signature_algorithm(&signature_algorithm),
                anchor_template: AnchorTemplate::for_signee(&cert.tbs_certificate)?,
            },
            SHA1_SIGNATURE_ALGORITHMS.contains(&signature_algorithm),
        ))
    }
}

/// For every signee, finds all candidates whose public key verifies the signee's signature, and
/// returns their indices (in ascending order). Both candidates and signees are DER encoded certs.
pub(crate) fn find_signers(candidates: &[impl AsRef<[u8]>], signees: &[impl AsRef<[u8]>]) -> Result<Vec<Vec<usize>>> {
    let mut any_sha1_signee = false;
    let signees = signees
        .iter()
        .enumerate()
        .map(|(i, der)| {
            let (signee, is_sha1) = Signee::parse(der.as_ref()).with_context(|| format!("signee #{i}"))?;
            any_sha1_signee |= is_sha1;
            Ok(signee)
        })
        .collect::<Result<Vec<_>>>()?;

    if any_sha1_signee {
        ensure_sha1_signatures_verifiable()?;
    }

    // Many certs share the same key (e.g. CA certs re-issued with the same key), we only need to
    // check each key once
    let mut candidates_by_public_key: BTreeMap<Vec<u8>, (SubjectPublicKeyInfoOwned, Vec<usize>)> = BTreeMap::new();
    for (i, der) in candidates.iter().enumerate() {
        let spki = Certificate::from_der(der.as_ref())
            .with_context(|| format!("parsing candidate #{i}"))?
            .tbs_certificate
            .subject_public_key_info;
        candidates_by_public_key
            .entry(spki.to_der()?)
            .or_insert_with(|| (spki, Vec::new()))
            .1
            .push(i);
    }
    let public_keys = candidates_by_public_key.into_values().collect::<Vec<_>>();

    let signed_by_public_key = parallel_map(&public_keys, |(public_key, _)| signees_signed_by(public_key, &signees))?;

    let mut signers = vec![Vec::new(); signees.len()];
    for ((_, candidate_indices), signed) in public_keys.iter().zip(signed_by_public_key) {
        for signee_index in signed {
            signers[signee_index].extend(candidate_indices);
        }
    }
    signers.iter_mut().for_each(|signers| signers.sort_unstable());

    Ok(signers)
}

/// Returns the indices of all signees whose signature is verified by the given public key
fn signees_signed_by(public_key: &SubjectPublicKeyInfoOwned, signees: &[Signee]) -> Result<Vec<usize>> {
    let key_type = KeyType::of_public_key(public_key);

    // A key can't produce signatures of an algorithm meant for a different type of key (and
    // openssl doesn't even get to checking the signature in that case, so we have to filter these
    // out ourselves)
    let checked_signees = (0..signees.len())
        .filter(|&i| key_type.could_have_signed(signees[i].required_key_type))
        .collect::<Vec<_>>();

    if checked_signees.is_empty() {
        return Ok(vec![]);
    }

    let mut anchors = BTreeMap::new();
    for &i in &checked_signees {
        let template = &signees[i].anchor_template;
        anchors.entry(template.dedup_key()?).or_insert(template);
    }

    let dir = tempfile::tempdir()?;
    let mut anchors_pem = String::new();
    for template in anchors.values() {
        anchors_pem.push_str(&pem::encode(&pem::Pem::new("CERTIFICATE", template.to_anchor_der(public_key)?)));
    }
    std::fs::write(dir.path().join("anchors.pem"), anchors_pem)?;

    let signee_file = |i: usize| format!("{i}.pem");
    for &i in &checked_signees {
        std::fs::write(
            dir.path().join(signee_file(i)),
            pem::encode(&pem::Pem::new("CERTIFICATE", signees[i].der)),
        )?;
    }

    let output = Command::new("openssl")
        .current_dir(dir.path())
        // RHEL / Fedora's crypto policies reject SHA-1 signatures by default
        .env("OPENSSL_ENABLE_SHA1_SIGNATURES", "1")
        .args([
            "verify",
            "-no_check_time",
            "-auth_level",
            "0",
            "-ignore_critical",
            "-no-CAfile",
            "-no-CApath",
            "-no-CAstore",
            "-partial_chain",
            "-trusted",
            "anchors.pem",
        ])
        .args(checked_signees.iter().map(|&i| signee_file(i)))
        .output()
        .context("running openssl verify")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let results = parse_verify_output(&stdout, &stderr).with_context(|| format!("parsing openssl verify output: {stderr}"))?;

    let mut signed = vec![];
    for &i in &checked_signees {
        match results.get(&signee_file(i)) {
            Some(VerifyResult::Ok) => signed.push(i),
            Some(VerifyResult::Failed(errors)) if errors.iter().all(|&error| error == (OPENSSL_SIGNATURE_FAILURE, 0)) && !errors.is_empty() => {}
            Some(VerifyResult::Failed(errors)) => bail!(
                "openssl verify failed signee #{i} for a reason other than a signature mismatch ({errors:?}), so we can't tell if it was signed by this key: {stderr}"
            ),
            None => bail!("openssl verify didn't report a result for signee #{i}: {stdout} {stderr}"),
        }
    }

    Ok(signed)
}

#[derive(Debug, PartialEq)]
enum VerifyResult {
    Ok,
    /// The (error code, depth) pairs openssl reported
    Failed(Vec<(u32, u32)>),
}

fn parse_verify_output(stdout: &str, stderr: &str) -> Result<HashMap<String, VerifyResult>> {
    let mut results = HashMap::new();

    for line in stdout.lines() {
        if let Some(file) = line.strip_suffix(": OK") {
            results.insert(file.to_string(), VerifyResult::Ok);
        }
    }

    // For every failed cert, openssl first prints the errors it encountered (as
    // "error <code> at <depth> depth lookup: <description>") and then
    // "error <file>: verification failed"
    let mut errors = vec![];
    for line in stderr.lines() {
        let Some(line) = line.strip_prefix("error ") else {
            continue;
        };

        if let Some(file) = line.strip_suffix(": verification failed") {
            ensure!(
                results
                    .insert(file.to_string(), VerifyResult::Failed(std::mem::take(&mut errors)))
                    .is_none(),
                "multiple results for {file}"
            );
        } else if let Some((code, rest)) = line.split_once(" at ") {
            if let Some((depth, _)) = rest.split_once(" depth lookup: ") {
                errors.push((code.parse()?, depth.parse()?));
            }
        }
    }

    Ok(results)
}

fn ensure_sha1_signatures_verifiable() -> Result<()> {
    let mut probe = tempfile::NamedTempFile::new()?;
    std::io::Write::write_all(&mut probe, SHA1_SIGNATURE_PROBE_PEM.as_bytes())?;
    let probe_path = probe.path().to_str().context("non-utf8 temp path")?;

    let output = Command::new("openssl")
        .env("OPENSSL_ENABLE_SHA1_SIGNATURES", "1")
        .args([
            "verify",
            "-check_ss_sig",
            "-no_check_time",
            "-auth_level",
            "0",
            "-no-CApath",
            "-no-CAstore",
            "-CAfile",
            probe_path,
            probe_path,
        ])
        .output()
        .context("running openssl verify")?;

    ensure!(
        output.status.success(),
        "found SHA-1 signed certificates, but openssl can't verify SHA-1 signatures in this environment (FIPS mode?), so we can't tell which certificates signed them: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    Ok(())
}

/// Like `items.iter().map(f).collect()`, but runs on all CPUs
fn parallel_map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> Result<R> + Sync) -> Result<Vec<R>> {
    let next = AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(items.len());

    let mut results = std::thread::scope(|scope| {
        let workers = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    let mut results = vec![];
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= items.len() {
                            break results;
                        }
                        results.push((i, f(&items[i])));
                    }
                })
            })
            .collect::<Vec<_>>();

        workers
            .into_iter()
            .flat_map(|worker| worker.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic)))
            .collect::<Vec<_>>()
    });

    results.sort_unstable_by_key(|(i, _)| *i);
    results.into_iter().map(|(_, result)| result).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_crypto::test_utils::{openssl_fips_mode, skip_if_fips};

    const SHA1_CA_PEM: &str = include_str!("testdata/sha1_ca.pem");
    /// Signed by SHA1_CA_PEM with ecdsa-with-SHA1
    const SHA1_LEAF_PEM: &str = include_str!("testdata/sha1_leaf.pem");

    struct TestDir(tempfile::TempDir);

    impl TestDir {
        fn new() -> Self {
            TestDir(tempfile::tempdir().unwrap())
        }

        fn path(&self, name: &str) -> String {
            self.0.path().join(name).to_str().unwrap().to_string()
        }

        fn openssl(&self, args: &[&str]) {
            let output = Command::new("openssl")
                .current_dir(self.0.path())
                .env("OPENSSL_ENABLE_SHA1_SIGNATURES", "1")
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "openssl {:?}: {}",
                args,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        fn key(&self, name: &str, algorithm: &[&str]) {
            self.openssl(&[&["genpkey", "-out", &format!("{name}.key")], algorithm].concat());
        }

        fn ec_key(&self, name: &str) {
            self.key(name, &["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1"]);
        }

        fn self_signed(&self, name: &str, key: &str, subject: &str, extra: &[&str]) {
            self.openssl(
                &[
                    &[
                        "req",
                        "-x509",
                        "-key",
                        &format!("{key}.key"),
                        "-out",
                        &format!("{name}.pem"),
                        "-subj",
                        subject,
                        "-days",
                        "1",
                    ],
                    extra,
                ]
                .concat(),
            );
        }

        /// Issues a cert for a new EC key, signed by `ca_key` with `ca` as the issuer cert
        fn issue(&self, name: &str, ca: &str, ca_key: &str, extra: &[&str]) {
            self.ec_key(name);
            self.openssl(&[
                "req",
                "-new",
                "-key",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.csr"),
                "-subj",
                &format!("/CN={name}"),
            ]);
            self.openssl(
                &[
                    &[
                        "x509",
                        "-req",
                        "-in",
                        &format!("{name}.csr"),
                        "-CA",
                        &format!("{ca}.pem"),
                        "-CAkey",
                        &format!("{ca_key}.key"),
                        "-out",
                        &format!("{name}.pem"),
                        "-days",
                        "1",
                    ],
                    extra,
                ]
                .concat(),
            );
        }

        fn ext_file(&self, name: &str, contents: &str) -> String {
            std::fs::write(self.path(name), contents).unwrap();
            self.path(name)
        }

        fn der(&self, name: &str) -> Vec<u8> {
            pem::parse(std::fs::read(self.path(&format!("{name}.pem"))).unwrap())
                .unwrap()
                .contents()
                .to_vec()
        }

        /// Runs find_signers with all given certs as candidates, returning the names of the
        /// signers of each signee
        fn signers(&self, candidates: &[&str], signees: &[&str]) -> Vec<Vec<String>> {
            let candidate_ders = candidates.iter().map(|name| self.der(name)).collect::<Vec<_>>();
            let signee_ders = signees.iter().map(|name| self.der(name)).collect::<Vec<_>>();
            find_signers(&candidate_ders, &signee_ders)
                .unwrap()
                .into_iter()
                .map(|signers| signers.into_iter().map(|i| candidates[i].to_string()).collect())
                .collect()
        }
    }

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn test_find_signers_by_key_only() {
        let dir = TestDir::new();
        dir.ec_key("ca");
        dir.self_signed("ca", "ca", "/CN=ca", &[]);
        // Same subject but a different key, like a rotated CA
        dir.ec_key("rotated");
        dir.self_signed("rotated", "rotated", "/CN=ca", &[]);
        // Same key but a different subject
        dir.self_signed("renamed", "ca", "/CN=renamed", &[]);
        dir.issue("leaf", "ca", "ca", &[]);
        // Signed by the CA key, but with an issuer name that doesn't match the CA cert's subject
        dir.issue("misnamed", "renamed", "ca", &[]);
        dir.issue("rotated_leaf", "rotated", "rotated", &[]);

        let candidates = ["ca", "rotated", "renamed", "leaf", "misnamed", "rotated_leaf"];
        assert_eq!(
            dir.signers(&candidates, &["leaf", "misnamed", "rotated_leaf"]),
            vec![names(&["ca", "renamed"]), names(&["ca", "renamed"]), names(&["rotated"])]
        );
    }

    #[test]
    fn test_find_signers_self_issued() {
        let dir = TestDir::new();
        dir.ec_key("ca");
        dir.self_signed("ca", "ca", "/CN=ca", &[]);

        let error = find_signers(&[dir.der("ca")], &[dir.der("ca")]).unwrap_err();
        assert!(format!("{error:#}").contains("self-issued"), "{error:#}");
    }

    #[test]
    fn test_find_signers_mixed_key_types() {
        let dir = TestDir::new();
        dir.key("rsa", &["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]);
        dir.self_signed("rsa", "rsa", "/CN=ca", &[]);
        dir.ec_key("ec");
        dir.self_signed("ec", "ec", "/CN=ca", &[]);
        dir.key("ec384", &["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:secp384r1"]);
        dir.self_signed("ec384", "ec384", "/CN=ca", &[]);
        dir.issue("rsa_leaf", "rsa", "rsa", &[]);
        dir.issue("rsa_pss_leaf", "rsa", "rsa", &["-sigopt", "rsa_padding_mode:pss"]);
        dir.issue("ec_leaf", "ec", "ec", &[]);
        dir.issue("ec384_leaf", "ec384", "ec384", &[]);

        let mut candidates = vec!["rsa", "ec", "ec384", "rsa_leaf", "ec_leaf"];
        let mut signees = vec!["rsa_leaf", "rsa_pss_leaf", "ec_leaf", "ec384_leaf"];
        let mut expected = vec![names(&["rsa"]), names(&["rsa"]), names(&["ec"]), names(&["ec384"])];

        if openssl_fips_mode() {
            eprintln!("skipping Ed25519 part of the test, Ed25519 is not available in FIPS mode");
        } else {
            dir.key("ed25519", &["-algorithm", "Ed25519"]);
            dir.self_signed("ed25519", "ed25519", "/CN=ca", &[]);
            dir.issue("ed25519_leaf", "ed25519", "ed25519", &[]);
            candidates.push("ed25519");
            signees.push("ed25519_leaf");
            expected.push(names(&["ed25519"]));
        }

        assert_eq!(dir.signers(&candidates, &signees), expected);
    }

    #[test]
    fn test_find_signers_authority_key_identifier() {
        let dir = TestDir::new();
        dir.ec_key("ca");
        // A SKID that isn't derived from the key, so it doesn't match a re-issued CA cert's
        dir.self_signed(
            "ca",
            "ca",
            "/CN=ca",
            &["-set_serial", "1234", "-addext", "subjectKeyIdentifier=0102030405"],
        );
        dir.self_signed("reissued", "ca", "/CN=ca", &["-set_serial", "5678"]);
        // AKID with keyid, issuer and serial of the CA cert
        let leaf_ext = dir.ext_file("leaf.cnf", "authorityKeyIdentifier=keyid:always,issuer:always\n");
        dir.issue("leaf", "ca", "ca", &["-extfile", &leaf_ext]);

        assert_eq!(dir.signers(&["reissued", "ca"], &["leaf"]), vec![names(&["reissued", "ca"])]);
    }

    #[test]
    fn test_find_signers_ignores_policy() {
        let dir = TestDir::new();
        dir.ec_key("ca");
        dir.self_signed("ca", "ca", "/CN=ca", &[]);
        let critical_ext = dir.ext_file("critical.cnf", "1.2.3.4=critical,ASN1:NULL\n");
        dir.issue("unknown_critical_ext", "ca", "ca", &["-extfile", &critical_ext]);
        // A leaf "issued" by another leaf, which isn't a CA
        dir.issue("leaf", "ca", "ca", &[]);
        dir.issue("issued_by_leaf", "leaf", "leaf", &[]);

        assert_eq!(
            dir.signers(&["ca", "leaf"], &["unknown_critical_ext", "issued_by_leaf"]),
            vec![names(&["ca"]), names(&["leaf"])]
        );
    }

    #[test]
    fn test_find_signers_sha1() {
        let ca = pem::parse(SHA1_CA_PEM).unwrap().contents().to_vec();
        let leaf = pem::parse(SHA1_LEAF_PEM).unwrap().contents().to_vec();

        let result = find_signers(&[ca], &[leaf]);

        if openssl_fips_mode() {
            // We must not silently miss the signer just because we can't verify the signature
            let error = result.unwrap_err();
            assert!(format!("{error:#}").contains("can't verify SHA-1 signatures"), "{error:#}");
        } else {
            assert_eq!(result.unwrap(), vec![vec![0]]);
        }
    }

    #[test]
    fn test_find_signers_sha1_generated() {
        skip_if_fips!("SHA-1 signing");

        let dir = TestDir::new();
        dir.key("rsa", &["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]);
        dir.self_signed("rsa", "rsa", "/CN=ca", &[]);
        dir.issue("rsa_sha1", "rsa", "rsa", &["-sha1"]);
        dir.ec_key("ec");
        dir.self_signed("ec", "ec", "/CN=ca", &[]);
        dir.issue("ec_sha1", "ec", "ec", &["-sha1"]);

        assert_eq!(
            dir.signers(&["rsa", "ec"], &["rsa_sha1", "ec_sha1"]),
            vec![names(&["rsa"]), names(&["ec"])]
        );
    }

    #[test]
    fn test_find_signers_garbage() {
        assert!(find_signers(&[b"garbage".to_vec()], &[] as &[Vec<u8>]).is_err());
        assert!(find_signers(&[] as &[Vec<u8>], &[b"garbage".to_vec()]).is_err());
    }

    #[test]
    fn test_find_signers_empty() {
        assert_eq!(
            find_signers(&[] as &[Vec<u8>], &[] as &[Vec<u8>]).unwrap(),
            Vec::<Vec<usize>>::new()
        );
    }

    #[test]
    fn test_parse_verify_output() {
        let stdout = "0.pem: OK\n2.pem: OK\n";
        let stderr = "CN=leaf\n\
            error 7 at 0 depth lookup: certificate signature failure\n\
            error 1.pem: verification failed\n\
            00C3D2DCB37F0000:error:0800009C:elliptic curve routines:ossl_ecdsa_simple_verify_sig:bad signature:crypto/ec/ecdsa_ossl.c:488:\n\
            CN=other\n\
            error 20 at 0 depth lookup: unable to get local issuer certificate\n\
            error 3.pem: verification failed\n";

        assert_eq!(
            parse_verify_output(stdout, stderr).unwrap(),
            HashMap::from([
                ("0.pem".to_string(), VerifyResult::Ok),
                ("1.pem".to_string(), VerifyResult::Failed(vec![(7, 0)])),
                ("2.pem".to_string(), VerifyResult::Ok),
                ("3.pem".to_string(), VerifyResult::Failed(vec![(20, 0)])),
            ])
        );
    }

    #[test]
    fn test_sha1_signature_probe() {
        let probe = Certificate::from_der(pem::parse(SHA1_SIGNATURE_PROBE_PEM).unwrap().contents()).unwrap();
        assert!(SHA1_SIGNATURE_ALGORITHMS.contains(&probe.signature_algorithm.oid));

        // Detecting that SHA-1 signatures can't be verified in FIPS mode is the point of the probe
        assert_eq!(ensure_sha1_signatures_verifiable().is_ok(), !openssl_fips_mode());
    }
}
