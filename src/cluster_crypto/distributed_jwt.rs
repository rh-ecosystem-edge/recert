use super::{
    crypto_utils::verify_jwt,
    jwt::Jwt,
    jwt::JwtSigner,
    keys::PublicKey,
    locations::{FileLocation, K8sLocation, Location, LocationValueType, Locations},
};
use crate::{
    file_utils::encode_resource_data_entry,
    k8s_etcd::{get_etcd_yaml, InMemoryK8sEtcd},
};
use jwt_simple::prelude::RSAKeyPairLike;
use serde_json::Value;
use x509_certificate::InMemorySigningKeyPair;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DistributedJwt {
    pub(crate) jwt: Jwt,
    pub(crate) locations: Locations,
    pub(crate) signer: JwtSigner,
    pub(crate) regenerated: bool,
}

impl DistributedJwt {
    pub(crate) fn regenerate(&mut self, original_signing_key: &PublicKey, new_signing_key: &InMemorySigningKeyPair) {
        let new_key = match &self.signer {
            JwtSigner::Unknown => panic!("Cannot regenerate JWT with unknown signer"),
            JwtSigner::CertKeyPair(_cert_key_pair) => self.resign(original_signing_key, new_signing_key),
            JwtSigner::PrivateKey(_private_key) => self.resign(&original_signing_key, new_signing_key),
        };
        self.jwt.str = new_key;
        self.regenerated = true;
    }

    fn resign(&self, original_public_key: &PublicKey, new_signing_key_pair: &InMemorySigningKeyPair) -> String {
        match verify_jwt(&original_public_key, self) {
            Ok(claims) => match new_signing_key_pair {
                InMemorySigningKeyPair::Ecdsa(_, _, _) => {
                    panic!("Unsupported key type")
                }
                InMemorySigningKeyPair::Ed25519(_) => {
                    panic!("Unsupported key type")
                }
                InMemorySigningKeyPair::Rsa(_rsa_key_pair, bytes) => jwt_simple::prelude::RS256KeyPair::from_der(bytes)
                    .unwrap()
                    .sign(claims)
                    .unwrap()
                    .to_string(),
            },
            Err(_) => panic!("Failed to parse token"),
        }
    }

    pub(crate) async fn commit_to_etcd_and_disk(&self, etcd_client: &mut InMemoryK8sEtcd) {
        for location in &self.locations.0 {
            match location {
                Location::K8s(k8slocation) => {
                    self.commit_to_etcd(etcd_client, &k8slocation).await;
                }
                Location::Filesystem(filelocation) => {
                    self.commit_to_filesystem(&filelocation).await;
                }
            }
        }
    }

    pub(crate) async fn commit_to_etcd(&self, etcd_client: &mut InMemoryK8sEtcd, k8slocation: &K8sLocation) {
        let mut resource = get_etcd_yaml(etcd_client, &k8slocation.resource_location).await;
        if let Some(value_at_json_pointer) = resource.pointer_mut(&k8slocation.yaml_location.json_pointer) {
            if let Value::String(value_at_json_pointer) = value_at_json_pointer {
                match &k8slocation.yaml_location.value {
                    LocationValueType::Pem(_pem_location_info) => {
                        panic!("JWT cannot be in PEM")
                    }
                    LocationValueType::Jwt => {
                        let encoded = encode_resource_data_entry(&k8slocation.yaml_location, &self.jwt.str);

                        *value_at_json_pointer = encoded;
                    }
                    LocationValueType::Unknown => panic!("shouldn't happen"),
                }
            }
        } else {
            panic!("shouldn't happen");
        }

        let newcontents = serde_yaml::to_string(&resource).unwrap();
        etcd_client
            .put(&k8slocation.resource_location.as_etcd_key(), newcontents.as_bytes().to_vec())
            .await;
    }

    pub(crate) async fn commit_to_filesystem(&self, _filelocation: &FileLocation) {
        todo!()
    }
}
