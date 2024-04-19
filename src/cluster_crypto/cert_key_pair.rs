use self::key_identifiers::{HashableKeyID, HashableSerialNumber};
use super::{
    certificate::Certificate,
    crypto_utils::{self, encode_tbs_cert_to_der, sign, SigningKey},
    distributed_cert::DistributedCert,
    distributed_private_key::DistributedPrivateKey,
    distributed_public_key::DistributedPublicKey,
    keys::PublicKey,
    locations::{FileContentLocation, FileLocation, K8sLocation, Location},
    pem_utils,
    signee::Signee,
};
use crate::{
    cluster_crypto::locations::LocationValueType,
    config::CryptoCustomizations,
    file_utils::{
        add_recert_edited_annotation, commit_file, get_filesystem_yaml, recreate_yaml_at_location_with_new_pem,
        update_auth_certificate_annotations,
    },
    k8s_etcd::{get_etcd_json, InMemoryK8sEtcd},
    rsa_key_pool::RsaKeyPool,
};
use anyhow::{bail, ensure, Context, Result};
use bcder::{BitString, Oid};
use bytes::Bytes;
use fn_error_context::context;
use p256::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use serde::Serialize;
use std::{cell::RefCell, collections::HashMap, rc::Rc};
use tokio::{self, io::AsyncReadExt};
use x509_cert::{ext::pkix::SubjectKeyIdentifier, serial_number::SerialNumber};
use x509_certificate::{
    rfc5280::{self, AlgorithmIdentifier, CertificateSerialNumber},
    CapturedX509Certificate, EcdsaCurve, KeyAlgorithm, Sign, X509Certificate,
};

mod cert_mutations;
mod key_identifiers;

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct CertKeyPair {
    #[serde(rename = "pair_private_key")]
    pub(crate) distributed_private_key: Option<Rc<RefCell<DistributedPrivateKey>>>,
    #[serde(rename = "pair_cert")]
    pub(crate) distributed_cert: Rc<RefCell<DistributedCert>>,

    /// The signer is the cert that signed this cert. If this is a self-signed cert, then this will
    /// be None
    #[serde(skip_serializing)]
    pub(crate) signer: Option<Rc<RefCell<CertKeyPair>>>,
    /// The signees are the certs or jwts that this cert has signed
    pub(crate) signees: Vec<Signee>,
    /// Sometimes cert public keys also appear on their own, outside the cert, so we need to track
    /// them
    pub(crate) associated_public_key: Option<Rc<RefCell<DistributedPublicKey>>>,
}

pub(crate) type SkidEdits = HashMap<key_identifiers::HashableKeyID, SubjectKeyIdentifier>;
pub(crate) type SerialNumberEdits = HashMap<key_identifiers::HashableSerialNumber, CertificateSerialNumber>;

impl CertKeyPair {
    pub(crate) fn regenerate(
        &mut self,
        sign_with: Option<&SigningKey>,
        rsa_key_pool: &mut RsaKeyPool,
        crypto_customizations: &CryptoCustomizations,
        skid_edits: &mut SkidEdits,
        serial_number_edits: &mut SerialNumberEdits,
    ) -> Result<()> {
        let alternative_certificate = crypto_customizations
            .use_cert_rules
            .get_replacement_cert((*self.distributed_cert).borrow_mut().certificate.cert.subject_name())
            .context("evaluating replacement cert")?;

        match alternative_certificate {
            // This is the classic case, user has not provided any replacement cert for this cert,
            // so simply regenerate the cert and all of its children
            None => {
                let (new_cert_subject_signing_key, new_cert) =
                    self.re_sign_cert(sign_with, rsa_key_pool, crypto_customizations, skid_edits, serial_number_edits)?;
                let new_cert = Certificate::try_from(&new_cert)?;
                (*self.distributed_cert).borrow_mut().certificate_regenerated = Some(new_cert.clone());

                for signee in &mut self.signees {
                    signee.regenerate(
                        Some(&new_cert_subject_signing_key),
                        rsa_key_pool,
                        crypto_customizations,
                        Some(skid_edits),
                        Some(serial_number_edits),
                    )?;
                }

                if let Some(associated_public_key) = &mut self.associated_public_key {
                    (*associated_public_key)
                        .borrow_mut()
                        .regenerate((&new_cert_subject_signing_key.in_memory_signing_key_pair).try_into()?)?;
                }

                // This condition exists because not all certs originally had a private key associated with
                // them (e.g. some private keys are discarded during install time), so we want to save the
                // regenerated private key only in case there was one there to begin with. Otherwise we
                // just discard it just like it was discarded during install time.
                if let Some(distributed_private_key) = &mut self.distributed_private_key {
                    (**distributed_private_key).borrow_mut().key_regenerated =
                        Some((&new_cert_subject_signing_key.in_memory_signing_key_pair).try_into()?);
                }
            }
            // User asked us to use their provided cert instead of this one, so we simply replace
            // it. If the cert has any children, we can't continue as we don't have the private
            // key for the user-provided cert to use to regenerate the children, so we error
            // out. We also cannot extend its expiration even if extend_expiration is true.
            Some(replacement_cert) => {
                ensure!(self.signees.is_empty(), "replacement cert cannot be used with signees");

                if let Some(associated_public_key) = &mut self.associated_public_key {
                    (*associated_public_key)
                        .borrow_mut()
                        .regenerate_from_public(&replacement_cert.public_key)?;
                }

                (*self.distributed_cert).borrow_mut().certificate_regenerated = Some(replacement_cert);
            }
        }

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
        sign_with: Option<&SigningKey>,
        rsa_key_pool: &mut RsaKeyPool,
        crypto_customizations: &CryptoCustomizations,
        skid_edits: &mut SkidEdits,
        serial_number_edits: &mut SerialNumberEdits,
    ) -> Result<(SigningKey, CapturedX509Certificate)> {
        // Clone the to-be-signed part of the certificate from the original certificate
        let cert: &X509Certificate = &(*self.distributed_cert).borrow().certificate.cert;
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

        // mkoid 1.2.840.113549.1.1.1
        let rsa_oid: Oid<Bytes> = Oid(Bytes::from_static(&[42, 134, 72, 134, 247, 13, 1, 1, 1]));

        // mkoid 1.2.840.10045.2.1
        let ec_public_key_oid: Oid<Bytes> = Oid(Bytes::from_static(&[42, 134, 72, 206, 61, 2, 1]));

        let self_new_key_pair = if let Some(use_key_rule) = crypto_customizations
            .use_key_rules
            .key_file(tbs_certificate.subject.clone())
            .context("getting use key file for cert")?
        {
            log::info!("{}", use_key_rule);
            use_key_rule.signing_key
        } else if tbs_certificate.subject_public_key_info.algorithm.algorithm == rsa_oid.clone() {
            let rsa_key_size = match &(*self.distributed_cert).borrow().certificate.public_key {
                PublicKey::Rsa(bytes) => rsa::RsaPublicKey::from_public_key_der(bytes)
                    .context("getting rsa key")?
                    .n()
                    .to_radix_le(2)
                    .len(),
                PublicKey::Ec(_) => bail!("key algorithm mismatch"),
            };

            // Draw an new RSA key from the pool for this cert
            rsa_key_pool.get(rsa_key_size).context("getting rsa key")?
        } else if tbs_certificate.subject_public_key_info.algorithm.algorithm == ec_public_key_oid.clone() {
            if let Some(params) = &tbs_certificate.subject_public_key_info.algorithm.parameters {
                let curve_oid = params.decode_oid()?;
                let curve = EcdsaCurve::try_from(&curve_oid)?;

                crypto_utils::generate_ec_key(curve).context("generating ec key")?
            } else {
                bail!("ECDSA key missing parameters");
            }
        } else {
            bail!("unsupported key type");
        };

        // Replace just the public key info in the to-be-signed part with the newly generated RSA
        // key
        tbs_certificate.subject_public_key_info = rfc5280::SubjectPublicKeyInfo {
            algorithm: KeyAlgorithm::from(&self_new_key_pair.in_memory_signing_key_pair).into(),
            subject_public_key: BitString::new(0, self_new_key_pair.in_memory_signing_key_pair.public_key_data()),
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
        let signature_algorithm: AlgorithmIdentifier = signing_key.in_memory_signing_key_pair.signature_algorithm()?.into();
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

        if let Some(_old_serial_number) = insert_result {
            // TODO: This is buggy. Figure out why
            // bail!("duplicate serial number found: {:?} and {:?}", old_serial_number, new_serial_number);
        }

        // Perform all requested mutations on the certificate
        cert_mutations::mutate_cert(
            &mut tbs_certificate,
            &crypto_customizations.cn_san_replace_rules,
            crypto_customizations.extend_expiration,
            crypto_customizations.force_expire,
        )
        .context("mutating cert")?;

        // The to-be-signed certificate, encoded to DER, is the bytes we sign
        let tbs_der = encode_tbs_cert_to_der(&tbs_certificate)?;

        // Generate the actual signature
        let signature = sign(signing_key, &tbs_der).context("signing")?;

        // Create a full certificate by combining the to-be-signed part with the signature itself
        let cert = rfc5280::Certificate {
            tbs_certificate,
            signature_algorithm,
            signature: BitString::new(0, Bytes::copy_from_slice(signature.as_ref())),
        };

        // Encode the entire cert as DER and reload it into a CapturedX509Certificate which is the
        // type we use in our structs
        let cert = CapturedX509Certificate::from_der(X509Certificate::from(cert).encode_der()?)?;

        Ok((self_new_key_pair, cert))
    }

    pub(crate) async fn commit_to_etcd_and_disk(&self, etcd_client: &InMemoryK8sEtcd) -> Result<()> {
        self.commit_pair_certificate(etcd_client).await.context("committing cert")?;
        self.commit_pair_key(etcd_client).await.context("committing key")?;

        Ok(())
    }

    pub(crate) async fn commit_pair_certificate(&self, etcd_client: &InMemoryK8sEtcd) -> Result<()> {
        let locations = (*self.distributed_cert).borrow().locations.0.clone();

        for location in locations {
            self.commit_pair_certificate_at_location(&location, etcd_client)
                .await
                .context(format!("failed to commit certificate to location {:?}", location))?;
        }

        Ok(())
    }

    async fn commit_pair_certificate_at_location(&self, location: &Location, etcd_client: &InMemoryK8sEtcd) -> Result<()> {
        match location {
            Location::K8s(k8slocation) => {
                self.commit_k8s_cert(etcd_client, k8slocation)
                    .await
                    .context("committing cert to k8s")?;
            }
            Location::Filesystem(filelocation) => {
                self.commit_filesystem_cert(filelocation)
                    .await
                    .context("committing cert to filesystem")?;
            }
        };
        Ok(())
    }

    pub(crate) async fn commit_k8s_cert(&self, etcd_client: &InMemoryK8sEtcd, k8slocation: &K8sLocation) -> Result<()> {
        let mut resource = get_etcd_json(etcd_client, &k8slocation.resource_location)
            .await?
            .context("resource disappeared")?;
        add_recert_edited_annotation(&mut resource, &k8slocation.yaml_location)?;

        let cert_pem = pem::parse(
            (*self.distributed_cert)
                .borrow()
                .certificate_regenerated
                .clone()
                .context("certificate was not regenerated")?
                .cert
                .encode_pem(),
        )?;

        let certificate = self
            .distributed_cert
            .borrow()
            .certificate_regenerated
            .clone()
            .context("certificate was not regenerated")?;

        update_auth_certificate_annotations(&mut resource, &certificate)?;

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

        let newpem = pem::parse(
            (*self.distributed_cert)
                .borrow()
                .clone()
                .certificate_regenerated
                .context("certificate was not regenerated")?
                .cert
                .encode_pem(),
        )?;

        commit_file(
            &filelocation.path,
            match &filelocation.content_location {
                FileContentLocation::Raw(location_value_type) => match &location_value_type {
                    LocationValueType::Pem(pem_location_info) => pem_utils::pem_bundle_replace_pem_at_index(
                        &String::from_utf8(contents)?,
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
                        if filelocation.path.ends_with("currentconfig") || filelocation.path.ends_with("mcs-machine-config-content.json") {
                            crate::file_utils::RecreateYamlEncoding::Json
                        } else {
                            crate::file_utils::RecreateYamlEncoding::Yaml
                        },
                    )?
                }
            },
        )
        .await
    }
}

fn fix_akid(
    akid: &mut x509_cert::ext::pkix::AuthorityKeyIdentifier,
    skids: &mut SkidEdits,
    serial_numbers: &mut SerialNumberEdits,
) -> Result<()> {
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
