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
    cluster_crypto::locations::LocationValueType,
    file_utils::{get_filesystem_yaml, recreate_yaml_at_location_with_new_pem},
    k8s_etcd::{get_etcd_yaml, InMemoryK8sEtcd},
    rsa_key_pool::RsaKeyPool,
};
use anyhow::{bail, Context, Result};
use bcder::BitString;
use bytes::Bytes;
use rsa::{signature::Signer, RsaPrivateKey};
use std::{cell::RefCell, fmt::Display, rc::Rc};
use tokio::{self, io::AsyncReadExt};
use x509_certificate::{
    rfc5280::{self, AlgorithmIdentifier},
    CapturedX509Certificate, InMemorySigningKeyPair, KeyAlgorithm, Sign, X509Certificate,
};

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

impl CertKeyPair {
    pub(crate) fn num_parents(&self) -> usize {
        if let Some(signer) = self.signer.as_ref() {
            1 + signer.borrow().num_parents()
        } else {
            0
        }
    }

    pub(crate) fn regenerate(&mut self, sign_with: Option<&InMemorySigningKeyPair>, rsa_key_pool: &mut RsaKeyPool) -> Result<()> {
        let (new_cert_subject_key_pair, rsa_private_key, new_cert) = self.re_sign_cert(sign_with, rsa_key_pool)?;
        (*self.distributed_cert).borrow_mut().certificate = Certificate::try_from(new_cert)?;

        for signee in &mut self.signees {
            signee.regenerate(
                &(*self.distributed_cert).borrow().certificate.public_key,
                Some(&new_cert_subject_key_pair),
                rsa_key_pool,
            )?;
        }

        if let Some(associated_public_key) = &mut self.associated_public_key {
            (*associated_public_key)
                .borrow_mut()
                .regenerate(&PrivateKey::Rsa(rsa_private_key.clone()))?;
        }

        // This condition exists because not all certs originally had a private key
        // associated with them (e.g. some private keys are discarded during install time),
        // so we only want to write the private key back into the graph incase there was
        // one there to begin with.
        if let Some(distributed_private_key) = &mut self.distributed_private_key {
            (**distributed_private_key).borrow_mut().key = PrivateKey::Rsa(rsa_private_key)
        }

        self.regenerated = true;

        Ok(())
    }

    pub(crate) fn re_sign_cert(
        &mut self,
        sign_with: Option<&InMemorySigningKeyPair>,
        rsa_key_pool: &mut RsaKeyPool,
    ) -> Result<(InMemorySigningKeyPair, RsaPrivateKey, CapturedX509Certificate)> {
        // Generate a new RSA key for this cert
        let (self_new_rsa_private_key, self_new_key_pair) = rsa_key_pool.get().context("rsa key pool empty")?;

        // Copy the to-be-signed part of the certificate from the original certificate
        let cert: &X509Certificate = &(*self.distributed_cert).borrow().certificate.original;
        let certificate: &rfc5280::Certificate = cert.as_ref();
        let mut tbs_certificate = certificate.tbs_certificate.clone();

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
        for location in (*self.distributed_cert).borrow().locations.0.iter() {
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

        etcd_client
            .put(
                &k8slocation.resource_location.as_etcd_key(),
                recreate_yaml_at_location_with_new_pem(
                    resource,
                    &k8slocation.yaml_location,
                    &pem::parse((*self.distributed_cert).borrow().certificate.original.encode_pem())?,
                )?
                .as_bytes()
                .to_vec(),
            )
            .await;

        Ok(())
    }

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
                    recreate_yaml_at_location_with_new_pem(resource, yaml_location, &newpem)?
                }
            },
        )
        .await?)
    }
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

        if self.signees.len() > 0 {
            writeln!(f, "")?;
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
