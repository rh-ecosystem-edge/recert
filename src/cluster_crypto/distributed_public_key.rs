use super::{
    keys::{PrivateKey, PublicKey},
    locations::{FileContentLocation, FileLocation, K8sLocation, Location, LocationValueType, Locations},
    pem_utils,
};
use crate::{
    file_utils::{get_filesystem_yaml, read_file_to_string, recreate_yaml_at_location_with_new_pem},
    k8s_etcd::{get_etcd_yaml, InMemoryK8sEtcd},
};
use std::fmt::Display;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DistributedPublicKey {
    pub(crate) key: PublicKey,
    pub(crate) locations: Locations,
    pub(crate) regenerated: bool,
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
    pub(crate) fn regenerate(&mut self, new_private: &PrivateKey) {
        self.key = new_private.into();
        self.regenerated = true;
    }

    pub(crate) async fn commit_to_etcd_and_disk(&self, etcd_client: &mut InMemoryK8sEtcd) {
        for location in self.locations.0.iter() {
            match location {
                Location::K8s(k8slocation) => {
                    self.commit_k8s_private_key(etcd_client, &k8slocation).await;
                }
                Location::Filesystem(filelocation) => {
                    self.commit_filesystem_private_key(&filelocation).await;
                }
            }
        }
    }

    async fn commit_k8s_private_key(&self, etcd_client: &mut InMemoryK8sEtcd, k8slocation: &K8sLocation) {
        let resource = get_etcd_yaml(etcd_client, &k8slocation.resource_location).await;

        etcd_client
            .put(
                &k8slocation.resource_location.as_etcd_key(),
                recreate_yaml_at_location_with_new_pem(resource, &k8slocation.yaml_location, &self.key.pem())
                    .as_bytes()
                    .to_vec(),
            )
            .await;
    }

    async fn commit_filesystem_private_key(&self, filelocation: &FileLocation) {
        let public_key_pem = match &self.key {
            PublicKey::Rsa(public_key_bytes) => pem::Pem::new("RSA PUBLIC KEY", public_key_bytes.as_ref()),
            PublicKey::Ec(_) => panic!("unsupported"),
        };

        tokio::fs::write(
            &filelocation.path,
            match &filelocation.content_location {
                FileContentLocation::Raw(pem_location_info) => match &pem_location_info {
                    LocationValueType::Pem(pem_location_info) => pem_utils::pem_bundle_replace_pem_at_index(
                        String::from_utf8((read_file_to_string(filelocation.path.clone().into()).await).into_bytes()).unwrap(),
                        pem_location_info.pem_bundle_index,
                        &public_key_pem,
                    ),
                    _ => {
                        panic!("shouldn't happen");
                    }
                },
                FileContentLocation::Yaml(yaml_location) => {
                    let resource = get_filesystem_yaml(filelocation).await;
                    recreate_yaml_at_location_with_new_pem(resource, yaml_location, &public_key_pem)
                }
            },
        )
        .await
        .unwrap();
    }
}
