use super::{
    distributed_public_key::DistributedPublicKey,
    k8s_etcd::get_etcd_json,
    keys::PrivateKey,
    locations::{FileContentLocation, FileLocation, K8sLocation, Location, LocationValueType, Locations},
    pem_utils,
    signee::Signee,
};
use crate::{
    cli::config,
    file_utils::{
        add_recert_edited_annotation, commit_file, get_filesystem_yaml, read_file_to_string, recreate_yaml_at_location_with_new_pem,
    },
    k8s_etcd::InMemoryK8sEtcd,
    rsa_key_pool::RsaKeyPool,
};
use anyhow::{bail, Context, Result};
use pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde::Serialize;
use std::{self, cell::RefCell, path::PathBuf, rc::Rc};

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct DistributedPrivateKey {
    pub(crate) key: PrivateKey,
    pub(crate) key_regenerated: Option<PrivateKey>,
    pub(crate) locations: Locations,
    pub(crate) signees: Vec<Signee>,
    pub(crate) associated_distributed_public_key: Option<Rc<RefCell<DistributedPublicKey>>>,
}

impl DistributedPrivateKey {
    pub(crate) fn regenerate(&mut self, rsa_key_pool: &mut RsaKeyPool, customizations: &config::Customizations) -> Result<()> {
        let num_bits = match &self.key {
            PrivateKey::Rsa(key) => key.n().to_radix_le(2).len(),
            PrivateKey::Ec(_) => bail!("cannot regenerate standalone EC key"),
        };

        let self_new_key_pair = rsa_key_pool.get(num_bits).context("RSA pool empty")?;

        for signee in &mut self.signees {
            signee.regenerate(Some(&self_new_key_pair), rsa_key_pool, customizations, None, None)?;
        }

        let regenerated_private_key: PrivateKey = (&self_new_key_pair.in_memory_signing_key_pair).try_into()?;
        self.key_regenerated = Some(regenerated_private_key.clone());

        if let Some(public_key) = &self.associated_distributed_public_key {
            (*public_key).borrow_mut().regenerate(regenerated_private_key.clone())?;
        }

        Ok(())
    }

    pub(crate) async fn commit_to_etcd_and_disk(&self, etcd_client: &InMemoryK8sEtcd) -> Result<()> {
        for location in self.locations.0.iter() {
            self.commit_at_location(location, etcd_client)
                .await
                .context(format!("failed to commit private key to location {:?}", location))?;
        }

        Ok(())
    }

    async fn commit_at_location(&self, location: &Location, etcd_client: &InMemoryK8sEtcd) -> Result<()> {
        match location {
            Location::K8s(k8slocation) => {
                self.commit_k8s_private_key(etcd_client, k8slocation)
                    .await
                    .context("commit private key to k8s")?;
            }
            Location::Filesystem(filelocation) => {
                self.commit_filesystem_private_key(filelocation)
                    .await
                    .context("commit private key to filesystem")?;
            }
        };
        Ok(())
    }

    async fn commit_k8s_private_key(&self, etcd_client: &InMemoryK8sEtcd, k8slocation: &K8sLocation) -> Result<()> {
        let mut resource = get_etcd_json(etcd_client, &k8slocation.resource_location)
            .await?
            .context("resource disappeared")?;
        add_recert_edited_annotation(&mut resource, &k8slocation.yaml_location)?;

        etcd_client
            .put(
                &k8slocation.resource_location.as_etcd_key(),
                recreate_yaml_at_location_with_new_pem(
                    resource,
                    &k8slocation.yaml_location,
                    &self.key_regenerated.clone().context("key was no regenerated")?.pem()?,
                    crate::file_utils::RecreateYamlEncoding::Json,
                )?
                .as_bytes()
                .to_vec(),
            )
            .await;

        Ok(())
    }

    async fn commit_filesystem_private_key(&self, filelocation: &FileLocation) -> Result<()> {
        let private_key_pem = match &self.key_regenerated.clone().context("key was no regenerated")? {
            PrivateKey::Rsa(rsa_private_key) => pem::Pem::new("RSA PRIVATE KEY", rsa_private_key.to_pkcs1_der()?.as_bytes()),
            PrivateKey::Ec(ec_bytes) => pem::Pem::new("EC PRIVATE KEY", ec_bytes.as_ref()),
        };

        commit_file(
            &filelocation.path,
            match &filelocation.content_location {
                FileContentLocation::Raw(pem_location_info) => match &pem_location_info {
                    LocationValueType::Pem(pem_location_info) => pem_utils::pem_bundle_replace_pem_at_index(
                        String::from_utf8((read_file_to_string(&PathBuf::from(&filelocation.path)).await)?.into_bytes())?,
                        pem_location_info.pem_bundle_index,
                        &private_key_pem,
                    )?,
                    _ => bail!("cannot commit non-PEM to filesystem"),
                },
                FileContentLocation::Yaml(yaml_location) => {
                    let resource = get_filesystem_yaml(filelocation).await?;
                    recreate_yaml_at_location_with_new_pem(
                        resource,
                        yaml_location,
                        &private_key_pem,
                        crate::file_utils::RecreateYamlEncoding::Yaml,
                    )?
                }
            },
        )
        .await?;

        Ok(())
    }
}
