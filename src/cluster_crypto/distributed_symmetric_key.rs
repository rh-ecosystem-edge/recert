use super::{
    crypto_utils,
    locations::{FileContentLocation, FileLocation, K8sLocation, Location, LocationValueType, Locations},
    symmetric_key::SymmetricKey,
};
use crate::{
    file_utils::{commit_file, encode_resource_data_entry},
    k8s_etcd::{get_etcd_json, InMemoryK8sEtcd},
};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::Value;

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct DistributedSymmetricKey {
    pub(crate) symmetric_key: SymmetricKey,
    pub(crate) symmetric_key_regenerated: Option<SymmetricKey>,
    pub(crate) locations: Locations,
}

impl DistributedSymmetricKey {
    pub(crate) fn regenerate(&mut self) -> Result<()> {
        let new_bytes = crypto_utils::get_random_bytes(self.symmetric_key.bytes.len())?;
        self.symmetric_key_regenerated = Some(SymmetricKey::new(new_bytes));

        Ok(())
    }

    pub(crate) async fn commit_to_etcd_and_disk(&self, etcd_client: &InMemoryK8sEtcd) -> Result<()> {
        if let Some(symmetric_key_regenerated) = &self.symmetric_key_regenerated {
            for location in &self.locations.0 {
                Self::commit_at_location(location, symmetric_key_regenerated, etcd_client)
                    .await
                    .context(format!("committing symmetric key to location {}", location))?;
            }
        }

        Ok(())
    }

    async fn commit_to_etcd(
        symmetric_key_regenerated: &SymmetricKey,
        etcd_client: &InMemoryK8sEtcd,
        k8slocation: &K8sLocation,
    ) -> Result<()> {
        let mut resource = get_etcd_json(etcd_client, &k8slocation.resource_location)
            .await?
            .context("resource disappeared")?;
        let value_at_json_pointer = resource
            .pointer_mut(&k8slocation.yaml_location.json_pointer)
            .context("value disappeared")?;

        match &k8slocation.yaml_location.value {
            LocationValueType::SymmetricKey => {
                if let Value::String(value_at_json_pointer) = value_at_json_pointer {
                    *value_at_json_pointer =
                        encode_resource_data_entry(&k8slocation.yaml_location, symmetric_key_regenerated.clone().bytes)
                            .context("encoding resource data entry")?
                            .as_str()
                            .context("encoded value not string")?
                            .to_string();
                } else if let Value::Array(value_at_json_pointer) = value_at_json_pointer {
                    *value_at_json_pointer =
                        encode_resource_data_entry(&k8slocation.yaml_location, symmetric_key_regenerated.clone().bytes)
                            .context("encoding resource data entry")?
                            .as_array()
                            .context("encoded value not array")?
                            .clone();
                } else {
                    bail!("non-string value at json pointer")
                }
            }
            _ => bail!("cannot commit symmetric key to non-symmetric key value type"),
        }

        etcd_client
            .put(
                &k8slocation.resource_location.as_etcd_key(),
                serde_json::to_string(&resource)?.as_bytes().to_vec(),
            )
            .await;

        Ok(())
    }

    async fn commit_to_filesystem(symmetric_key_regenerated: &SymmetricKey, filelocation: &FileLocation) -> Result<()> {
        commit_file(
            &filelocation.path,
            match &filelocation.content_location {
                FileContentLocation::Raw(pem_location_info) => match &pem_location_info {
                    LocationValueType::SymmetricKey => symmetric_key_regenerated.bytes.clone(),
                    _ => bail!("cannot commit symmetric key to non-symmetric key value type"),
                },
                FileContentLocation::Yaml(_) => todo!("filesystem YAML Symmetric keys not implemented"),
            },
        )
        .await?;

        Ok(())
    }

    async fn commit_at_location(
        location: &Location,
        symmetric_key_regenerated: &SymmetricKey,
        etcd_client: &InMemoryK8sEtcd,
    ) -> Result<(), anyhow::Error> {
        match location {
            Location::K8s(k8slocation) => {
                Self::commit_to_etcd(symmetric_key_regenerated, etcd_client, k8slocation)
                    .await
                    .context("committing etcd symmetric key")?;
            }
            Location::Filesystem(filelocation) => {
                Self::commit_to_filesystem(symmetric_key_regenerated, filelocation)
                    .await
                    .context("committing filesystem symmetric key")?;
            }
        };
        Ok(())
    }
}
