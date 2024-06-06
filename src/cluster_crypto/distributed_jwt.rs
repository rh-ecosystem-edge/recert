use super::crypto_utils::jwt;
use super::{
    crypto_utils::SigningKey,
    jwt::Jwt,
    jwt::JwtSigner,
    locations::{FileContentLocation, FileLocation, K8sLocation, Location, LocationValueType, Locations},
};
use crate::{
    file_utils::{commit_file, encode_resource_data_entry},
    k8s_etcd::{get_etcd_json, InMemoryK8sEtcd},
};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::Value;

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct DistributedJwt {
    pub(crate) jwt: Jwt,
    pub(crate) jwt_regenerated: Option<Jwt>,
    pub(crate) locations: Locations,
    #[serde(skip_serializing)]
    pub(crate) signer: JwtSigner,
}

impl DistributedJwt {
    pub(crate) fn regenerate(&mut self, new_signing_key: &SigningKey) -> Result<()> {
        let new_key = match &self.signer {
            JwtSigner::Unknown => bail!("cannot regenerate jwt with unknown signer"),
            JwtSigner::CertKeyPair(_cert_key_pair) => self.resign(new_signing_key)?,
            JwtSigner::PrivateKey(_private_key) => self.resign(new_signing_key)?,
        };
        self.jwt_regenerated = Some(Jwt { str: new_key });

        Ok(())
    }

    fn resign(&self, new_signing_key_pair: &SigningKey) -> Result<String> {
        jwt::resign(&self.jwt.str, new_signing_key_pair).context("resigning jwt")
    }

    pub(crate) async fn commit_to_etcd_and_disk(&self, etcd_client: &InMemoryK8sEtcd) -> Result<()> {
        if let Some(jwt_regenerated) = &self.jwt_regenerated {
            for location in &self.locations.0 {
                Self::commit_at_location(location, jwt_regenerated, etcd_client)
                    .await
                    .context(format!("committing JWT to location {}", location))?;
            }
        }

        Ok(())
    }

    async fn commit_to_etcd(jwt_regenerated: &Jwt, etcd_client: &InMemoryK8sEtcd, k8slocation: &K8sLocation) -> Result<()> {
        let mut resource = get_etcd_json(etcd_client, &k8slocation.resource_location)
            .await?
            .context("resource disappeared")?;
        let value_at_json_pointer = resource
            .pointer_mut(&k8slocation.yaml_location.json_pointer)
            .context("value disappeared")?;

        match &k8slocation.yaml_location.value {
            LocationValueType::Pem(_pem_location_info) => {
                bail!("JWT cannot be in PEM")
            }
            LocationValueType::Jwt => {
                if let Value::String(value_at_json_pointer) = value_at_json_pointer {
                    *value_at_json_pointer = encode_resource_data_entry(&k8slocation.yaml_location, &jwt_regenerated.clone().str)
                        .as_str()
                        .context("encoded value not string")?
                        .to_string();
                } else if let Value::Array(value_at_json_pointer) = value_at_json_pointer {
                    value_at_json_pointer.clone_from(
                        encode_resource_data_entry(&k8slocation.yaml_location, &jwt_regenerated.clone().str)
                            .as_array()
                            .context("encoded value not array")?,
                    );
                } else {
                    bail!("non-string value at json pointer")
                }
            }
            LocationValueType::YetUnknown => bail!("cannot commit unknown value type to etcd"),
        }

        etcd_client
            .put(
                &k8slocation.resource_location.as_etcd_key(),
                serde_json::to_string(&resource)?.as_bytes().to_vec(),
            )
            .await;

        Ok(())
    }

    async fn commit_to_filesystem(jwt_regenerated: &Jwt, filelocation: &FileLocation) -> Result<()> {
        commit_file(
            &filelocation.path,
            match &filelocation.content_location {
                FileContentLocation::Raw(pem_location_info) => match &pem_location_info {
                    LocationValueType::Pem(_) => bail!("JWT cannot be in PEM"),
                    LocationValueType::Jwt => jwt_regenerated.clone().str.clone(),
                    LocationValueType::YetUnknown => bail!("cannot commit unknown value type"),
                },
                FileContentLocation::Yaml(_) => todo!("filesystem YAML JWTs not implemented"),
            },
        )
        .await?;

        Ok(())
    }

    async fn commit_at_location(location: &Location, jwt_regenerated: &Jwt, etcd_client: &InMemoryK8sEtcd) -> Result<()> {
        match location {
            Location::K8s(k8slocation) => {
                Self::commit_to_etcd(jwt_regenerated, etcd_client, k8slocation)
                    .await
                    .context("committing etcd JWT")?;
            }
            Location::Filesystem(filelocation) => {
                Self::commit_to_filesystem(jwt_regenerated, filelocation)
                    .await
                    .context("committing filesystem JWT")?;
            }
        };
        Ok(())
    }
}
