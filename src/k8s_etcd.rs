use crate::cluster_crypto::locations::K8sResourceLocation;
use anyhow::{bail, Context, Result};
use etcd_client::{Client as EtcdClient, GetOptions};
use futures_util::future::join_all;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Mutex;

pub(crate) struct EtcdResult {
    pub(crate) key: String,
    pub(crate) value: Vec<u8>,
}

/// An etcd client wrapper backed by an in-memory hashmap. All reads are served from memory, with
/// fallback to actual etcd for misses. All writes are strictly to memory, but supports eventually
/// committing to an actual etcd instance of kubernetes, transparently encoding and decoding YAMLs
/// with ouger. Used by recert as a cache to dramatically speed up the process of certificate and
/// key regeneration, as we we don't have to go through ouger and etcd for every single certificate
/// and key access.
pub(crate) struct InMemoryK8sEtcd {
    etcd_client: Arc<EtcdClient>,
    etcd_keyvalue_hashmap: Mutex<HashMap<String, Vec<u8>>>,
    deleted_keys: Mutex<HashSet<String>>,
}

impl InMemoryK8sEtcd {
    pub(crate) fn new(etcd_client: EtcdClient) -> Self {
        Self {
            etcd_client: Arc::new(etcd_client),
            etcd_keyvalue_hashmap: Mutex::new(HashMap::new()),
            deleted_keys: Mutex::new(HashSet::new()),
        }
    }

    pub(crate) async fn commit_to_actual_etcd(&self) -> Result<()> {
        self.commit_hashmap().await?;
        self.commit_deleted_keys().await?;

        Ok(())
    }

    async fn commit_deleted_keys(&self) -> Result<(), anyhow::Error> {
        join_all(
            self.deleted_keys
                .lock()
                .await
                .iter()
                .map(|key| {
                    let key = key.clone();
                    let etcd_client = Arc::clone(&self.etcd_client);
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

    async fn commit_hashmap(&self) -> Result<(), anyhow::Error> {
        for (key, value) in self.etcd_keyvalue_hashmap.lock().await.iter() {
            let key = key.clone();
            let value = value.clone();
            let etcd_client = Arc::clone(&self.etcd_client);
            // TODO: Find a fancier way to detect CRDs
            let value = if key.starts_with("/kubernetes.io/machineconfiguration.openshift.io/machineconfigs/") {
                value.to_vec()
            } else {
                run_ouger("encode", value.as_slice()).await.context("encoding value with ouger")?
            };

            etcd_client.kv_client().put(key.as_bytes(), value, None).await?;
        }

        Ok(())
    }

    pub(crate) async fn get(&self, key: String) -> Result<EtcdResult> {
        let mut result = EtcdResult {
            key: key.to_string(),
            value: vec![],
        };

        {
            let hashmap = self.etcd_keyvalue_hashmap.lock().await;
            if let Some(value) = hashmap.get(&key) {
                result.value = value.clone();
                return Ok(result);
            }
        }

        let get_result = self
            .etcd_client
            .kv_client()
            .get(key.clone(), None)
            .await
            .context("during etcd get")?;
        let raw_etcd_value = get_result.kvs().first().context("key not found")?.value();

        let decoded_value = run_ouger("decode", raw_etcd_value).await.context("decoding value with ouger")?;
        self.etcd_keyvalue_hashmap
            .lock()
            .await
            .insert(key.to_string(), decoded_value.clone());

        result.value = decoded_value;
        Ok(result)
    }

    pub(crate) async fn put(&self, key: &str, value: Vec<u8>) {
        self.etcd_keyvalue_hashmap.lock().await.insert(key.to_string(), value.clone());
        self.deleted_keys.lock().await.remove(key);
    }

    pub(crate) async fn list_keys(&self, resource_kind: &str) -> Result<Vec<String>> {
        let etcd_get_options = GetOptions::new().with_prefix().with_limit(0).with_keys_only();
        let keys = self
            .etcd_client
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

async fn run_ouger(ouger_subcommand: &str, raw_etcd_value: &[u8]) -> Result<Vec<u8>> {
    let mut command = Command::new("ouger")
        .arg(ouger_subcommand)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    command
        .stdin
        .take()
        .context("opening ouger's stdin pipe")?
        .write_all(raw_etcd_value)
        .await
        .context("writing to ouger's stdin pipe")?;

    let result = command.wait_with_output().await.context("waiting for ouger to finish")?;

    if !result.status.success() {
        bail!(
            "ouger {} failed with exit code {} and stderr: {}",
            ouger_subcommand,
            result.status.code().context("checking ouger exit code")?,
            String::from_utf8_lossy(&result.stderr)
        );
    };

    Ok(result.stdout)
}

pub(crate) async fn get_etcd_yaml(client: &InMemoryK8sEtcd, k8slocation: &K8sResourceLocation) -> Result<Value> {
    Ok(serde_yaml::from_str(&String::from_utf8(
        client
            .get(k8slocation.as_etcd_key())
            .await
            .with_context(|| format!("etcd get {}", k8slocation.as_etcd_key()))?
            .value,
    )?)?)
}

pub(crate) async fn put_etcd_yaml(client: &InMemoryK8sEtcd, k8slocation: &K8sResourceLocation, value: Value) -> Result<()> {
    client
        .put(&k8slocation.as_etcd_key(), serde_json::to_string(&value)?.as_bytes().into())
        .await;
    Ok(())
}
