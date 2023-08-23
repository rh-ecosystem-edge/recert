use self::key_identifiers::{HashableKeyID, HashableSerialNumber};

use super::{
    certificate::Certificate,
    crypto_utils::encode_tbs_cert_to_der,
    distributed_cert::DistributedCert,
    distributed_private_key::DistributedPrivateKey,
    distributed_public_key::DistributedPublicKey,
    keys::PrivateKey,
    locations::{FileContentLocation, FileLocation, K8sLocation, Location},
    pem_utils,
    signee::Signee,
};
use crate::{
    cluster_crypto::{crypto_utils::rsa_key_from_file, locations::LocationValueType},
    cnsanreplace::CnSanReplaceRules,
    file_utils::{get_filesystem_yaml, recreate_yaml_at_location_with_new_pem},
    k8s_etcd::{get_etcd_yaml, InMemoryK8sEtcd},
    rsa_key_pool::RsaKeyPool,
    use_key::{self, UseKeyRules},
};
use anyhow::{bail, Context, Result};
use bcder::BitString;
use bytes::Bytes;
use fn_error_context::context;
use rsa::{signature::Signer, RsaPrivateKey};
use std::{cell::RefCell, collections::HashMap, fmt::Display, rc::Rc};
use tokio::{self, io::AsyncReadExt};
use x509_cert::{ext::pkix::SubjectKeyIdentifier, serial_number::SerialNumber};
use x509_certificate::{
    rfc5280::{self, AlgorithmIdentifier, CertificateSerialNumber},
    CapturedX509Certificate, InMemorySigningKeyPair, KeyAlgorithm, Sign, X509Certificate,
};

mod cert_mutations;
mod key_identifiers;

const SUBJECT_ALTERNATIVE_NAME_OID: [u8; 3] = [85, 29, 17];
const SUBJECT_KEY_IDENTIFIER_OID: [u8; 3] = [85, 29, 14];
const AUTHORITY_KEY_IDENTIFIER_OID: [u8; 3] = [85, 29, 35];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CertKeyPair {
    pub(crate) distributed_private_key: Option<Rc<RefCell<DistributedPrivateKey>>>,
    pub(crate) distributed_cert: Rc<RefCell<DistributedCert>>,

    /// The signer is the cert that signed this cert. If this is a self-signed cert, then this will
    /// be None
    pub(crate) signer: Option<Rc<RefCell<CertKeyPair>>>,
    /// The signees are the certs or jwts that this cert has signed
    pub(crate) signees: Vec<Signee>,
    /// Sometimes cert public keys also appear on their own, outside the cert, so we need to track
    /// them
    pub(crate) associated_public_key: Option<Rc<RefCell<DistributedPublicKey>>>,
    pub(crate) regenerated: bool,
}

pub(crate) type SkidEdits = HashMap<key_identifiers::HashableKeyID, SubjectKeyIdentifier>;
pub(crate) type SerialNumberEdits = HashMap<key_identifiers::HashableSerialNumber, CertificateSerialNumber>;

impl CertKeyPair {
    pub(crate) fn num_parents(&self) -> usize {
        if let Some(signer) = self.signer.as_ref() {
            1 + signer.borrow().num_parents()
        } else {
            0
        }
    }

    pub(crate) fn regenerate(
        &mut self,
        sign_with: Option<&InMemorySigningKeyPair>,
        rsa_key_pool: &mut RsaKeyPool,
        cn_san_replace_rules: &CnSanReplaceRules,
        use_key_rules: &UseKeyRules,
        skid_edits: &mut SkidEdits,
        serial_number_edits: &mut SerialNumberEdits,
    ) -> Result<()> {
        let (new_cert_subject_key_pair, rsa_private_key, new_cert) = self.re_sign_cert(
            sign_with,
            rsa_key_pool,
            cn_san_replace_rules,
            use_key_rules,
            skid_edits,
            serial_number_edits,
        )?;

        (*self.distributed_cert).borrow_mut().certificate = Certificate::try_from(new_cert)?;

        for signee in &mut self.signees {
            signee.regenerate(
                &(*self.distributed_cert).borrow().certificate.public_key,
                Some(&new_cert_subject_key_pair),
                rsa_key_pool,
                cn_san_replace_rules,
                use_key_rules,
                Some(skid_edits),
                Some(serial_number_edits),
            )?;
        }

        if let Some(associated_public_key) = &mut self.associated_public_key {
            (*associated_public_key)
                .borrow_mut()
                .regenerate(&PrivateKey::Rsa(rsa_private_key.clone()))?;
        }

        // This condition exists because not all certs originally had a private key associated with
        // them (e.g. some private keys are discarded during install time), so we want to save the
        // regenerated private key only in case there was one there to begin with. Otherwise we
        // just discard it just like it was discarded during install time.
        if let Some(distributed_private_key) = &mut self.distributed_private_key {
            (**distributed_private_key).borrow_mut().key = PrivateKey::Rsa(rsa_private_key)
        }

        self.regenerated = true;

        Ok(())
    }

    /// Re-signs the certificate with the given signing key. If the signing key is None, then the
    /// certificate will be self-signed.
    ///
    /// Returns the signing keys, the new certificate, and if the certificate had a subject iden
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    #[context["re-signing cert with subject {}", self.distributed_cert.borrow().certificate.subject]]
    pub(crate) fn re_sign_cert(
        &mut self,
        sign_with: Option<&InMemorySigningKeyPair>,
        rsa_key_pool: &mut RsaKeyPool,
        cn_san_rules: &CnSanReplaceRules,
        use_key_rules: &use_key::UseKeyRules,
        skid_edits: &mut SkidEdits,
        serial_number_edits: &mut SerialNumberEdits,
    ) -> Result<(InMemorySigningKeyPair, RsaPrivateKey, CapturedX509Certificate)> {
        // Clone the to-be-signed part of the certificate from the original certificate
        let cert: &X509Certificate = &(*self.distributed_cert).borrow().certificate.original;
        let certificate: &rfc5280::Certificate = cert.as_ref();
        let mut tbs_certificate = certificate.tbs_certificate.clone();

        let skid = key_identifiers::get_skid(&tbs_certificate)?;

        // Check which method was used to calculate the SKID. We call this early because
        // determining the method relies on the cert keys before they're regenerated
        let skid_method = if let Some(skid) = &skid {
            Some(key_identifiers::get_cert_skid_method(&mut tbs_certificate, skid)?)
        } else {
            None
        };

        let (self_new_rsa_private_key, self_new_key_pair) = if let Some(use_key_path) = use_key_rules
            .key_file(tbs_certificate.subject.clone())
            .context("getting use key file from cert")?
        {
            println!("Using key from file: {:?} because CN rules match", use_key_path);
            rsa_key_from_file(&use_key_path).context("getting rsa key from file")?
        } else {
            // TODO: Find a less hacky way to get the key size. It's ugly but if we get this wrong, the
            // only thing that happens is that we don't get to enjoy the pool's cache or we generate a
            // key too large
            let rsa_key_size = tbs_certificate.subject_public_key_info.subject_public_key.bit_len() - 112;

            // Generate a new RSA key for this cert
            rsa_key_pool.get(rsa_key_size).context("getting rsa key")?
        };

        // Replace just the public key info in the to-be-signed part with the newly generated RSA
        // key
        tbs_certificate.subject_public_key_info = rfc5280::SubjectPublicKeyInfo {
            algorithm: KeyAlgorithm::from(&self_new_key_pair).into(),
            subject_public_key: BitString::new(0, self_new_key_pair.public_key_data()),
        };

        // If we weren't given a key to sign with, we use the new key we just generated
        // as this is a root (self-signed) certificate
        let signing_key = if let Some(key_pair) = &sign_with {
            key_pair
        } else {
            &self_new_key_pair
        };

        // TODO: No need to change the signature algorithm once we know how to re-sign ECDSA,
        // we're only forced to change this because we make all certs RSA
        let signature_algorithm: AlgorithmIdentifier = signing_key.signature_algorithm()?.into();
        tbs_certificate.signature = signature_algorithm.clone();

        // Fix SKID
        if let Some(skid_method) = skid_method {
            if let Some(skid) = skid {
                let new_skid = key_identifiers::calculate_and_set_skid(&mut tbs_certificate, skid_method)?;

                let insert_result = skid_edits.insert(key_identifiers::HashableKeyID(skid.0), new_skid.clone());

                if let Some(old_skid) = insert_result {
                    bail!("duplicate SKID found: {:?} and {:?}", old_skid, new_skid);
                }
            } else {
                bail!("should never happen");
            }
        }

        // This must happen after the SKID is calculated because for self-signed certs, the SKID is
        // equal to the AKID and so the skid_edits map must be populated with our own SKID before
        // fix_akid looks it up
        let akid = key_identifiers::get_akid(&tbs_certificate).context("getting akid")?;
        if let Some(mut akid) = akid {
            fix_akid(&mut akid, skid_edits, serial_number_edits)?;

            key_identifiers::set_akid(&mut tbs_certificate, akid).context("setting akid")?;
        }

        // regenerate serial number
        let serial_number = tbs_certificate.serial_number.clone();
        let new_serial_number = serial_number.clone(); // TODO: Generate new serial number

        let insert_result = serial_number_edits.insert(
            key_identifiers::HashableSerialNumber(serial_number.into_bytes().into()),
            new_serial_number.clone(),
        );

        if let Some(old_serial_number) = insert_result {
            bail!("duplicate serial number found: {:?} and {:?}", old_serial_number, new_serial_number);
        }

        // Perform all requested mutations on the certificate
        cert_mutations::mutate_cert(&mut tbs_certificate, cn_san_rules).context("mutating cert")?;

        // The to-be-signed ceritifcate, encoded to DER, is the bytes we sign
        let tbs_der = encode_tbs_cert_to_der(&tbs_certificate)?;

        // Generate the actual signature
        let signature = signing_key.try_sign(&tbs_der)?;

        // Create a full certificate by combining the to-be-signed part with the signature itself
        let cert = rfc5280::Certificate {
            tbs_certificate,
            signature_algorithm,
            signature: BitString::new(0, Bytes::copy_from_slice(signature.as_ref())),
        };

        // Encode the entire cert as DER and reload it into a CapturedX509Certificate which is the
        // type we use in our structs
        let cert = CapturedX509Certificate::from_der(X509Certificate::from(cert).encode_der()?)?;

        Ok((self_new_key_pair, self_new_rsa_private_key, cert))
    }

    pub(crate) async fn commit_to_etcd_and_disk(&self, etcd_client: &InMemoryK8sEtcd) -> Result<()> {
        self.commit_pair_certificate(etcd_client).await?;
        self.commit_pair_key(etcd_client).await
    }

    pub(crate) async fn commit_pair_certificate(&self, etcd_client: &InMemoryK8sEtcd) -> Result<()> {
        let locations = (*self.distributed_cert).borrow().locations.0.clone();

        for location in locations {
            match location {
                Location::K8s(k8slocation) => {
                    self.commit_k8s_cert(etcd_client, &k8slocation).await?;
                }
                Location::Filesystem(filelocation) => {
                    self.commit_filesystem_cert(&filelocation).await?;
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn commit_k8s_cert(&self, etcd_client: &InMemoryK8sEtcd, k8slocation: &K8sLocation) -> Result<()> {
        let resource = get_etcd_yaml(etcd_client, &k8slocation.resource_location).await?;

        let cert_pem = pem::parse((*self.distributed_cert).borrow().certificate.original.encode_pem())?;

        etcd_client
            .put(
                &k8slocation.resource_location.as_etcd_key(),
                recreate_yaml_at_location_with_new_pem(
                    resource,
                    &k8slocation.yaml_location,
                    &cert_pem,
                    crate::file_utils::RecreateYamlEncoding::Json,
                )?
                .as_bytes()
                .to_vec(),
            )
            .await;

        Ok(())
    }

    #[allow(clippy::await_holding_refcell_ref)]
    pub(crate) async fn commit_pair_key(&self, etcd_client: &InMemoryK8sEtcd) -> Result<()> {
        if let Some(private_key) = &self.distributed_private_key {
            (*private_key).borrow_mut().commit_to_etcd_and_disk(etcd_client).await?;
        }

        Ok(())
    }

    pub(crate) async fn commit_filesystem_cert(&self, filelocation: &FileLocation) -> Result<()> {
        let mut file = tokio::fs::File::open(&filelocation.path).await?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).await?;

        let newpem = pem::parse((*self.distributed_cert).borrow().certificate.original.encode_pem())?;

        Ok(tokio::fs::write(
            &filelocation.path,
            match &filelocation.content_location {
                FileContentLocation::Raw(location_value_type) => match &location_value_type {
                    LocationValueType::Pem(pem_location_info) => pem_utils::pem_bundle_replace_pem_at_index(
                        String::from_utf8(contents)?,
                        pem_location_info.pem_bundle_index,
                        &newpem,
                    )?,
                    _ => {
                        bail!("Cannot replace PEM in non-PEM file");
                    }
                },
                FileContentLocation::Yaml(yaml_location) => {
                    let resource = get_filesystem_yaml(filelocation).await?;
                    recreate_yaml_at_location_with_new_pem(
                        resource,
                        yaml_location,
                        &newpem,
                        if filelocation.path.ends_with("currentconfig") {
                            crate::file_utils::RecreateYamlEncoding::Json
                        } else {
                            crate::file_utils::RecreateYamlEncoding::Yaml
                        },
                    )?
                }
            },
        )
        .await?)
    }
}

fn fix_akid(
    akid: &mut x509_cert::ext::pkix::AuthorityKeyIdentifier,
    skids: &mut SkidEdits,
    serial_numbers: &mut SerialNumberEdits,
) -> Result<(), anyhow::Error> {
    if let Some(key_identifier) = &akid.key_identifier {
        let matching_skid = skids
            .get(&HashableKeyID(key_identifier.clone()))
            .context("could not find matching akid key identifier in chain")?;

        akid.key_identifier = Some(matching_skid.0.clone());
    }

    if let Some(serial_number) = &akid.authority_cert_serial_number {
        let matching_sn = serial_numbers
            .get(&HashableSerialNumber(serial_number.as_bytes().into()))
            .context("could not find matching akid serial number in chain")?;

        akid.authority_cert_serial_number = Some(SerialNumber::new(&matching_sn.clone().into_bytes())?);
    }

    Ok(())
}

impl Display for CertKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for _ in 0..self.num_parents() {
            write!(f, "-")?;
        }

        if self.num_parents() > 0 {
            write!(f, " ")?;
        }

        write!(
            f,
            "Cert {:03} locations {}, ",
            (*self.distributed_cert).borrow().locations.0.len(),
            // "<>",
            (*self.distributed_cert).borrow().locations,
        )?;
        write!(
            f,
            "{}",
            if let Some(distributed_private_key) = &self.distributed_private_key {
                format!(
                    "priv {:03} locations {}",
                    (*distributed_private_key).borrow().locations.0.len(),
                    (*distributed_private_key).borrow().locations,
                    // "<>",
                )
            } else {
                "NO PRIV".to_string()
            }
        )?;
        write!(f, " | {}", (*self.distributed_cert).borrow().certificate.subject,)?;

        if !self.signees.is_empty() {
            writeln!(f)?;
        }

        for signee in &self.signees {
            writeln!(f, "{}", signee)?;
        }

        if let Some(associated_public_key) = &self.associated_public_key {
            writeln!(f, "* {}", (**associated_public_key).borrow())?;
        }

        Ok(())
    }
}
