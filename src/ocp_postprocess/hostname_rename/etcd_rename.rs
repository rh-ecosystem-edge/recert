use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    k8s_etcd::{get_etcd_json, put_etcd_yaml, InMemoryK8sEtcd},
};
use anyhow::{Context, Result};
use futures_util::future::join_all;
use serde_json::{Map, Value};
use std::{sync::Arc};

pub(crate) async fn fix_etcd_all_certs(etcd_client: &Arc<InMemoryK8sEtcd>, hostname: &str) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("secrets/openshift-etcd/etcd-all-certs")
            .await?
            .into_iter()
            .map(|key| async move {
                let etcd_result = etcd_client
                    .get(key.clone())
                    .await
                    .with_context(|| format!("getting key {:?}", key))?
                    .context("key disappeared")?;
                let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;
                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let mut secret = get_etcd_json(etcd_client, &k8s_resource_location)
                    .await?
                    .context("getting secret")?;

                let data = &mut secret
                    .pointer_mut("/data")
                    .context("no /data")?
                    .as_object_mut()
                    .context("data not an object")?;

                let keys = vec![
                    ("etcd-peer-", ".crt"),
                    ("etcd-peer-", ".key"),
                    ("etcd-serving-", ".crt"),
                    ("etcd-serving-", ".key"),
                    ("etcd-serving-metrics-", ".crt"),
                    ("etcd-serving-metrics-", ".key"),
                ];
                // TODO: we ignore errors, but maybe we shouldn't?
                let _ = keys
                    .into_iter()
                    .filter_map(|(prefix, suffix)| replace_data_field(data, prefix, suffix, hostname, key.to_owned()).ok())
                    .collect::<Vec<_>>();

                put_etcd_yaml(etcd_client, &k8s_resource_location, secret)
                    .await
                    .context(format!("could not put etcd key: {}", key))?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

fn replace_data_field(data: &mut Map<String, Value>, prefix: &str, suffix: &str, hostname: &str, key: String) -> Result<()> {
    let (key, value) = data
        .into_iter()
        .filter(|(k, _v)| k.starts_with(prefix) && k.ends_with(suffix))
        .map(|(k, v)| (k.clone(), v.clone()))
        .next()
        .context(format!("no {}*{} key in {}", prefix, suffix, key))?
        .clone();
    data.insert(format!("{}{}{}", prefix, hostname, suffix), value);
    data.remove(&key);

    Ok(())
}

pub(crate) async fn fix_etcd_secrets(etcd_client: &Arc<InMemoryK8sEtcd>, hostname: &str) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("secrets/openshift-etcd/")
            .await?
            .into_iter()
            .filter(|key| {
                vec![
                    "etcd-peer-",
                    "etcd-serving-",
                    "etcd-serving-metrics-",
                ]
                .into_iter()
                .any(|prefix| key.contains(prefix))
            })
            .map(|key| async move {
                let etcd_result = etcd_client
                    .get(key.clone())
                    .await
                    .with_context(|| format!("getting key {:?}", key))?
                    .context("key disappeared")?;
                let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;
                let mut k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let mut secret = get_etcd_json(etcd_client, &k8s_resource_location)
                    .await?
                    .context("getting secret")?;
                let metadata = &mut secret
                    .pointer_mut("/metadata")
                    .context("no /metadata")?
                    .as_object_mut()
                    .context("data not an object")?;
                let (_, previous_name) = key.rsplit_once('/').unwrap();
                // TODO: what if the hostname contains a `-`
                let mut parts = previous_name.split('-').collect::<Vec<&str>>();
                if let Some(last) = parts.last_mut() {
                    *last = hostname;
                }
                let name: String = parts.join("-");
                metadata.insert("name".to_string(), serde_json::Value::String(name.clone()));
                k8s_resource_location.name = name.to_string();
                put_etcd_yaml(etcd_client, &k8s_resource_location, secret).await?;

                etcd_client.delete(&key).await.context(format!("deleting {}", key))?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

// TODO: needs change in the data.install-config[metadata.name]
// TODO: although this is probably the cluster name and not the hostname?
// pub(crate) async fn fix_cluster_config_v1(etcd_client: &Arc<InMemoryK8sEtcd>, hostname: &str) -> Result<()> {
//     let k8s_resource_location = K8sResourceLocation::new(Some("openshift-etcd"), "ConfigMap", "cluster-config-v1", "v1");
//     let mut configmap = get_etcd_json(etcd_client, &k8s_resource_location)
//         .await?
//         .context("getting configmap")?;
//     Ok(())
// }

// /kubernetes.io/configmaps/openshift-etcd/etcd-pod
// /kubernetes.io/configmaps/openshift-etcd/etcd-pod-2
// TODO: data["pod.yaml"] - env.[NODE_seed_ETCD_NAME,NODE_seed_ETCD_URL_HOST,NODE_seed_IP]
// TODO: we need to account for unsupported chars in the hostname being an env var name
//       e.g. "another-hostname" -> "another_hostname" when used in an env var name
pub(crate) async fn fix_etcd_pod(etcd_client: &Arc<InMemoryK8sEtcd>, _hostname: &str) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("configmaps/openshift-etcd/etcd-pod")
            .await?
            .into_iter()
            .map(|key| async move {
                let etcd_result = etcd_client
                    .get(key.clone())
                    .await
                    .with_context(|| format!("getting key {:?}", key))?
                    .context("key disappeared")?;
                let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;
                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let mut configmap = get_etcd_json(etcd_client, &k8s_resource_location)
                    .await?
                    .context("getting secret")?;

                let _data = &mut configmap
                    .pointer_mut("/data")
                    .context("no /data")?
                    .as_object_mut()
                    .context("data not an object")?;

                // TODO: implement - replace the hostname

                put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_etcd_scripts(etcd_client: &Arc<InMemoryK8sEtcd>, _hostname: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-etcd"), "ConfigMap", "etcd-scripts", "v1");
    let mut _configmap = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting configmap")?;
    // TODO: implement
    Ok(())
}

pub(crate) async fn fix_restore_etcd_pod(etcd_client: &Arc<InMemoryK8sEtcd>, _hostname: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-etcd"), "ConfigMap", "etcd-scripts", "v1");
    let mut _configmap = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting configmap")?;
    // TODO: implement
    Ok(())
}

pub(crate) async fn fix_kubeapiservers_cluster(etcd_client: &Arc<InMemoryK8sEtcd>, hostname: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "KubeAPIServer", "cluster", "operator.openshift.io/v1");
    let mut cluster = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting kubeapiservers/cluster")?;

    replace_node_status_name(&mut cluster, hostname)
        .context("could not replace nodeName for kubeapiservers/cluster")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, cluster).await?;

    Ok(())
}

pub(crate) async fn fix_kubeschedulers_cluster(etcd_client: &Arc<InMemoryK8sEtcd>, hostname: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "KubeScheduler", "cluster", "operator.openshift.io/v1");
    let mut cluster = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting kubeschedulers/cluster")?;

    replace_node_status_name(&mut cluster, hostname)
        .context("could not replace nodeName for kubeschedulers/cluster")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, cluster).await?;

    Ok(())
}

pub(crate) async fn fix_kubecontrollermanagers_cluster(etcd_client: &Arc<InMemoryK8sEtcd>, hostname: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "KubeControllerManager", "cluster", "operator.openshift.io/v1");
    let mut cluster = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting kubecontrollermanagers/cluster")?;

    replace_node_status_name(&mut cluster, hostname)
        .context("could not replace nodeName for kubecontrollermanagers/cluster")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, cluster).await?;

    Ok(())
}

fn replace_node_status_name(cluster: &mut Value, hostname: &str) -> Result<()> {
    let node_statuses = &mut cluster
        .pointer_mut("/status/nodeStatuses")
        .context("no /status/nodeStatuses")?
        .as_array_mut()
        .context("/status/nodeStatuses not an array")?;

    node_statuses
        .iter_mut()
        .for_each(|status: &mut Value| {
            status
                .as_object_mut()
                .unwrap()
                .insert("nodeName".to_string(), Value::String(hostname.to_string()));
        });

    Ok(())
}

