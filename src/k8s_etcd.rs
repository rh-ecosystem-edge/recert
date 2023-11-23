use crate::cluster_crypto::locations::K8sResourceLocation;
use crate::etcd_encoding;
use anyhow::{bail, Context, Result};
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
                        etcd_client.kv_client().delete(key.as_bytes(), None).await?;
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
                result.value = value.clone();
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

        let etcd_get_options = GetOptions::new().with_prefix().with_limit(0).with_keys_only();
        let keys = etcd_client
            .kv_client()
            .get(format!("/kubernetes.io/{}", resource_kind), Some(etcd_get_options.clone()))
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
