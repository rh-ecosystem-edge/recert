use super::{
    crypto_utils::generate_rsa_key,
    distributed_public_key::DistributedPublicKey,
    k8s_etcd::get_etcd_yaml,
    keys::{PrivateKey, PublicKey},
    locations::{FileContentLocation, FileLocation, K8sLocation, Location, LocationValueType, Locations},
    pem_utils,
    signee::Signee,
};
use crate::{
    file_utils::{get_filesystem_yaml, read_file_to_string, recreate_yaml_at_location_with_new_pem},
    k8s_etcd::InMemoryK8sEtcd,
};
use pkcs1::EncodeRsaPrivateKey;
use std::{self, cell::RefCell, fmt::Display, rc::Rc};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DistributedPrivateKey {
    pub(crate) key: PrivateKey,
    pub(crate) locations: Locations,
    pub(crate) signees: Vec<Signee>,
    pub(crate) associated_distributed_public_key: Option<Rc<RefCell<DistributedPublicKey>>>,
    pub(crate) regenerated: bool,
}

impl Display for DistributedPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Standalone priv {:03} locations {}",
            self.locations.0.len(),
            self.locations,
            // "<>",
        )?;

        if self.signees.len() > 0 || self.associated_distributed_public_key.is_some() {
            writeln!(f, "")?;
        }

        for signee in &self.signees {
            writeln!(f, "- {}", signee)?;
        }

        if let Some(public_key) = &self.associated_distributed_public_key {
            writeln!(f, "* Associated public key at {}", (*public_key).borrow())?;
        }

        Ok(())
    }
}

impl DistributedPrivateKey {
    pub(crate) fn regenerate(&mut self) {
        let (self_new_rsa_private_key, self_new_key_pair) = generate_rsa_key();

        for signee in &mut self.signees {
            signee.regenerate(&PublicKey::from(&self.key), Some(&self_new_key_pair));
        }

        self.key = PrivateKey::Rsa(self_new_rsa_private_key);
        self.regenerated = true;

        if let Some(public_key) = &self.associated_distributed_public_key {
            (*public_key).borrow_mut().regenerate(&self.key);
        }
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
        let private_key_pem = match &self.key {
            PrivateKey::Rsa(rsa_private_key) => pem::Pem::new("RSA PRIVATE KEY", rsa_private_key.to_pkcs1_der().unwrap().as_bytes()),
            PrivateKey::Ec(ec_bytes) => pem::Pem::new("EC PRIVATE KEY", ec_bytes.as_ref()),
        };

        tokio::fs::write(
            &filelocation.path,
            match &filelocation.content_location {
                FileContentLocation::Raw(pem_location_info) => match &pem_location_info {
                    LocationValueType::Pem(pem_location_info) => pem_utils::pem_bundle_replace_pem_at_index(
                        String::from_utf8((read_file_to_string(filelocation.path.clone().into()).await).into_bytes()).unwrap(),
                        pem_location_info.pem_bundle_index,
                        &private_key_pem,
                    ),
                    _ => {
                        panic!("shouldn't happen");
                    }
                },
                FileContentLocation::Yaml(yaml_location) => {
                    let resource = get_filesystem_yaml(filelocation).await;
                    recreate_yaml_at_location_with_new_pem(resource, yaml_location, &private_key_pem)
                }
            },
        )
        .await
        .unwrap();
    }
}
