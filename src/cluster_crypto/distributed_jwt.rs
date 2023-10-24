use super::{
    crypto_utils::{verify_jwt, SigningKey},
    jwt::Jwt,
    jwt::JwtSigner,
    keys::PublicKey,
    locations::{FileContentLocation, FileLocation, K8sLocation, Location, LocationValueType, Locations},
};
use crate::{
    file_utils::{commit_file, encode_resource_data_entry},
    k8s_etcd::{get_etcd_json, InMemoryK8sEtcd},
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as base64_url, Engine as _};
use jwt_simple::prelude::RSAKeyPairLike;
use serde::Serialize;
use serde_json::Value;
use sha2::Digest;
use x509_certificate::InMemorySigningKeyPair;

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct DistributedJwt {
    pub(crate) jwt: Jwt,
    pub(crate) jwt_regenerated: Option<Jwt>,
    pub(crate) locations: Locations,
    #[serde(skip_serializing)]
    pub(crate) signer: JwtSigner,
}

impl DistributedJwt {
    pub(crate) fn regenerate(&mut self, original_signing_key: &PublicKey, new_signing_key: &SigningKey) -> Result<()> {
        let new_key = match &self.signer {
            JwtSigner::Unknown => bail!("cannot regenerate jwt with unknown signer"),
            JwtSigner::CertKeyPair(_cert_key_pair) => self.resign(original_signing_key, new_signing_key)?,
            JwtSigner::PrivateKey(_private_key) => self.resign(original_signing_key, new_signing_key)?,
        };
        self.jwt_regenerated = Some(Jwt { str: new_key });

        Ok(())
    }

    fn resign(&self, original_public_key: &PublicKey, new_signing_key_pair: &SigningKey) -> Result<String> {
        match &new_signing_key_pair.in_memory_signing_key_pair {
            InMemorySigningKeyPair::Ecdsa(_, _, _) => {
                bail!("ecdsa unsupported");
            }
            InMemorySigningKeyPair::Ed25519(_) => {
                bail!("ed unsupported");
            }
            InMemorySigningKeyPair::Rsa(_rsa_key_pair, bytes) => {
                let claims = verify_jwt(original_public_key, self)?;

                let mut sha256 = sha2::Sha256::new();
                sha256.update(bytes);
                let kid = base64_url.encode(sha256.finalize());

                Ok(jwt_simple::prelude::RS256KeyPair::from_der(bytes)?
                    .with_key_id(&kid)
                    .sign(claims)?
                    .to_string())
            }
        }
    }

    pub(crate) async fn commit_to_etcd_and_disk(&self, etcd_client: &InMemoryK8sEtcd) -> Result<()> {
        if let Some(jwt_regenerated) = &self.jwt_regenerated {
            for location in &self.locations.0 {
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
                }
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
                    *value_at_json_pointer = encode_resource_data_entry(&k8slocation.yaml_location, &jwt_regenerated.clone().str)
                        .as_array()
                        .context("encoded value not array")?
                        .clone();
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
}
