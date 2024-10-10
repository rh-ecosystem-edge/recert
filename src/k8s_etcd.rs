use crate::cluster_crypto::locations::K8sResourceLocation;
use crate::etcd_encoding;
use anyhow::{bail, ensure, Context, Result};
use etcd_client::{Client as EtcdClient, GetOptions};
use futures_util::future::join_all;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

pub(crate) struct EtcdResult {
    pub(crate) key: String,
    pub(crate) value: Vec<u8>,
}

/// An etcd client wrapper backed by an in-memory hashmap. All reads are served from memory, with
/// fallback to actual etcd for misses. All writes are strictly to memory, but supports eventually
/// committing to an actual etcd instance of kubernetes. Values are not stored in the hasmap in
/// native etcd protobuf encoding, but instead are stored as decoded JSONs. Used by recert as a
/// cache to dramatically speed up the process of certificate and key regeneration, as we we don't
/// have to go through etcd for every single edit.
pub(crate) struct InMemoryK8sEtcd {
    pub(crate) etcd_client: Option<Arc<EtcdClient>>,
    etcd_keyvalue_hashmap: Mutex<HashMap<String, Vec<u8>>>,
    edited: Mutex<HashMap<String, Vec<u8>>>,
    deleted_keys: Mutex<HashSet<String>>,
}

impl InMemoryK8sEtcd {
    /// Pass a None etcd_client to disable actual etcd access (dummy mode, empty key list).
    pub(crate) fn new(etcd_client: Option<EtcdClient>) -> Self {
        Self {
            etcd_client: etcd_client.map(Arc::new),
            etcd_keyvalue_hashmap: Mutex::new(HashMap::new()),
            deleted_keys: Mutex::new(HashSet::new()),
            edited: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) async fn commit_to_actual_etcd(&self) -> Result<()> {
        self.commit_hashmap().await?;
        self.commit_deleted_keys().await?;

        Ok(())
    }

    async fn commit_deleted_keys(&self) -> Result<()> {
        let etcd_client = match &self.etcd_client {
            Some(etcd_client) => etcd_client,
            None => return Ok(()),
        };

        join_all(
            self.deleted_keys
                .lock()
                .await
                .iter()
                .map(|key| {
                    let key = key.clone();
                    let etcd_client = Arc::clone(etcd_client);
                    tokio::spawn(async move {
                        loop {
                            let delete_response = etcd_client.kv_client().delete(key.as_bytes(), None).await;

                            if is_too_many_requests_error(&delete_response) {
                                continue;
                            }

                            match delete_response {
                                Ok(_) => break,
                                Err(_) => delete_response.context(format!("during etcd delete {}", key))?,
                            };
                        }

                        anyhow::Ok(())
                    })
                })
                .collect::<Vec<_>>(),
        )
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
        Ok(())
    }

    async fn commit_hashmap(&self) -> Result<()> {
        let etcd_client = match &self.etcd_client {
            Some(etcd_client) => etcd_client,
            None => return Ok(()),
        };

        for (key, value) in self.etcd_keyvalue_hashmap.lock().await.iter() {
            if !self.edited.lock().await.contains_key(key) {
                continue;
            }
            let key = key.clone();
            let value = value.clone();
            let etcd_client = Arc::clone(etcd_client);
            let value = etcd_encoding::encode(value.as_slice()).await.context("encoding value")?;

            etcd_client
                .kv_client()
                .put(key.as_bytes(), value.clone(), None)
                .await
                .context(format!("during etcd put {} {:?}", key, value))?;
        }

        Ok(())
    }

    pub(crate) async fn get(&self, key: String) -> Result<Option<EtcdResult>> {
        let etcd_client = match &self.etcd_client {
            Some(etcd_client) => etcd_client,
            None => bail!("etcd client not configured"),
        };

        let mut result = EtcdResult {
            key: key.to_string(),
            value: vec![],
        };

        {
            let hashmap = self.etcd_keyvalue_hashmap.lock().await;
            if let Some(value) = hashmap.get(&key) {
                result.value.clone_from(value);
                return Ok(Some(result));
            }
        }

        let get_result = etcd_client.kv_client().get(key.clone(), None).await.context("during etcd get")?;

        if let Some(value) = get_result.kvs().first() {
            let raw_etcd_value = value.value();

            let decoded_value = etcd_encoding::decode(raw_etcd_value).await.context("decoding value")?;
            self.etcd_keyvalue_hashmap
                .lock()
                .await
                .insert(key.to_string(), decoded_value.clone());

            result.value = decoded_value;
            return Ok(Some(result));
        };

        Ok(None)
    }

    pub(crate) async fn put(&self, key: &str, value: Vec<u8>) {
        self.etcd_keyvalue_hashmap.lock().await.insert(key.to_string(), value.clone());
        self.deleted_keys.lock().await.remove(key);
        self.edited.lock().await.insert(key.to_string(), value);
    }

    pub(crate) async fn list_keys(&self, resource_kind: &str) -> Result<Vec<String>> {
        let etcd_client = match &self.etcd_client {
            Some(etcd_client) => etcd_client,
            None => return Ok(vec![]),
        };

        let kubernetes_keys = self.get_keys_with_prefix(etcd_client, "/kubernetes.io", resource_kind).await?;
        let openshift_keys = self.get_keys_with_prefix(etcd_client, "/openshift.io", resource_kind).await?;
        let keys: Vec<_> = kubernetes_keys.into_iter().chain(openshift_keys.into_iter()).collect();

        Ok(keys)
    }

    async fn get_keys_with_prefix(&self, etcd_client: &Arc<EtcdClient>, prefix: &str, resource_kind: &str) -> Result<Vec<String>> {
        let etcd_get_options = GetOptions::new().with_prefix().with_limit(0).with_keys_only();
        let keys = etcd_client
            .kv_client()
            .get(format!("{}/{}", prefix, resource_kind), Some(etcd_get_options.clone()))
            .await?;

        keys.kvs()
            .iter()
            .map(|k| Ok(k.key_str()?.to_string()))
            .collect::<Result<Vec<String>>>()
    }

    pub(crate) async fn delete(&self, key: &str) -> Result<()> {
        self.etcd_keyvalue_hashmap.lock().await.remove(key);
        self.deleted_keys.lock().await.insert(key.to_string());
        Ok(())
    }

    pub(crate) async fn update_member(&self, value: String) -> Result<()> {
        let etcd_client = self.etcd_client.as_ref().context("etcd client not configured")?;

        let members_list = etcd_client
            .cluster_client()
            .member_list()
            .await
            .context("listing etcd members list")?;

        let members = members_list.members();

        ensure!(
            members.len() == 1,
            "single-node must have exactly one etcd member, found {}",
            members.len()
        );

        ensure!(
            !etcd_client
                .cluster_client()
                .member_update(members[0].id(), vec![value.clone()])
                .await
                .context("updating etcd member")?
                .members()
                .is_empty(),
            "no members in update response"
        );
        Ok(())
    }

    pub(crate) async fn defragment(&self) -> Result<()> {
        let etcd_client = self.etcd_client.as_ref().context("etcd client not configured")?;
        etcd_client.maintenance_client().defragment().await.context("defragment etcd")?;
        Ok(())
    }
}

fn is_too_many_requests_error(delete_response: &std::prelude::v1::Result<etcd_client::DeleteResponse, etcd_client::Error>) -> bool {
    match delete_response {
        Ok(_) => false,
        Err(err) => match err {
            etcd_client::Error::GRpcStatus(status) => status.message() == "etcdserver: too many requests",
            _ => false,
        },
    }
}

pub(crate) async fn get_etcd_json(client: &InMemoryK8sEtcd, k8slocation: &K8sResourceLocation) -> Result<Option<Value>> {
    let etcd_result = client
        .get(k8slocation.as_etcd_key())
        .await
        .with_context(|| format!("etcd get {}", k8slocation.as_etcd_key()))?;

    Ok(if let Some(etcd_result) = etcd_result {
        Some(serde_json::from_str(&String::from_utf8(etcd_result.value).context("etcd to utf-8")?).context("parsing json")?)
    } else {
        None
    })
}

pub(crate) async fn put_etcd_yaml(client: &InMemoryK8sEtcd, k8slocation: &K8sResourceLocation, value: Value) -> Result<()> {
    client
        .put(&k8slocation.as_etcd_key(), serde_json::to_string(&value)?.as_bytes().into())
        .await;
    Ok(())
}
