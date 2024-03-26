use anyhow::{bail, ensure, Context, Result};
use p256::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use serde::Serialize;

use super::{
    keys::{PrivateKey, PublicKey},
    locations::{FileContentLocation, FileLocation, K8sLocation, Location, LocationValueType, Locations},
    pem_utils,
};
use crate::{
    file_utils::{
        add_recert_edited_annotation, commit_file, get_filesystem_yaml, read_file_to_string, recreate_yaml_at_location_with_new_pem,
    },
    k8s_etcd::{get_etcd_json, InMemoryK8sEtcd},
    rsa_key_pool::RsaKeyPool,
};
use std::{fmt::Display, path::PathBuf};

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct DistributedPublicKey {
    pub(crate) key: PublicKey,
    pub(crate) key_regenerated: Option<PublicKey>,
    pub(crate) locations: Locations,
    pub(crate) associated: bool,
}

impl Display for DistributedPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Standalone pub {:03} locations {}",
            self.locations.0.len(),
            self.locations,
            // "<>",
        )?;

        Ok(())
    }
}

impl DistributedPublicKey {
    pub(crate) fn regenerate(&mut self, new_private: PrivateKey) -> Result<()> {
        self.key_regenerated = Some(PublicKey::try_from(&new_private)?);

        Ok(())
    }

    /// For when we want to generate a standalone public key that doesn't have any assocation, we
    /// just generate a temproary private key, derive the public key from it and then discard the
    /// private key.
    pub(crate) fn regenerate_no_private(&mut self, rsa_key_pool: &mut RsaKeyPool) -> Result<()> {
        ensure!(
            !self.associated,
            "public keys with an association should only be regenerated indirectly through their association"
        );

        let num_bits = match &self.key {
            PublicKey::Rsa(bytes) => rsa::RsaPublicKey::from_public_key_der(bytes)
                .context("getting rsa key")?
                .n()
                .to_radix_le(2)
                .len(),
            PublicKey::Ec(_) => bail!("key algorithm mismatch"),
        };

        let signing_key = rsa_key_pool.get(num_bits).context("RSA pool empty")?;

        let regenerated_private_key: PrivateKey = (&signing_key.in_memory_signing_key_pair)
            .try_into()
            .context("signing key to private key")?;
        self.key_regenerated = Some((&regenerated_private_key).try_into().context("private to public key")?);

        Ok(())
    }

    pub(crate) fn regenerate_from_public(&mut self, new_public: &PublicKey) -> Result<()> {
        self.key_regenerated = Some(new_public.clone());

        Ok(())
    }

    pub(crate) async fn commit_to_etcd_and_disk(&self, etcd_client: &InMemoryK8sEtcd) -> Result<()> {
        for location in self.locations.0.iter() {
            self.commit_at_location(location, etcd_client)
                .await
                .context(format!("committing public key to location {}", location))?;
        }

        Ok(())
    }

    async fn commit_at_location(&self, location: &Location, etcd_client: &InMemoryK8sEtcd) -> Result<()> {
        match location {
            Location::K8s(k8slocation) => {
                self.commit_k8s_public_key(etcd_client, k8slocation)
                    .await
                    .context("committing to k8s")?;
            }
            Location::Filesystem(filelocation) => {
                self.commit_filesystem_public_key(filelocation)
                    .await
                    .context("committing to filesystem")?;
            }
        };
        Ok(())
    }

    async fn commit_k8s_public_key(&self, etcd_client: &InMemoryK8sEtcd, k8slocation: &K8sLocation) -> Result<()> {
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
                    &self
                        .key_regenerated
                        .clone()
                        .context("key was not regenerated")?
                        .pem()
                        .context("key to pem")?,
                    crate::file_utils::RecreateYamlEncoding::Json,
                )?
                .as_bytes()
                .to_vec(),
            )
            .await;

        Ok(())
    }

    async fn commit_filesystem_public_key(&self, filelocation: &FileLocation) -> Result<()> {
        let public_key_pem = match &self.key_regenerated.clone().context("key was not regenerated")? {
            PublicKey::Rsa(public_key_bytes) => pem::Pem::new("RSA PUBLIC KEY", public_key_bytes.as_ref()),
            PublicKey::Ec(_) => bail!("ECDSA public key not yet supported for filesystem commit"),
        };

        commit_file(
            &filelocation.path,
            match &filelocation.content_location {
                FileContentLocation::Raw(pem_location_info) => match &pem_location_info {
                    LocationValueType::Pem(pem_location_info) => pem_utils::pem_bundle_replace_pem_at_index(
                        &String::from_utf8((read_file_to_string(&PathBuf::from(filelocation.path.clone())).await?).into_bytes())?,
                        pem_location_info.pem_bundle_index,
                        &public_key_pem,
                    )?,
                    _ => bail!("cannot commit non-PEM location to filesystem"),
                },
                FileContentLocation::Yaml(yaml_location) => {
                    let resource = get_filesystem_yaml(filelocation).await?;
                    recreate_yaml_at_location_with_new_pem(
                        resource,
                        yaml_location,
                        &public_key_pem,
                        crate::file_utils::RecreateYamlEncoding::Yaml,
                    )?
                }
            },
        )
        .await?;
        Ok(())
    }
}
