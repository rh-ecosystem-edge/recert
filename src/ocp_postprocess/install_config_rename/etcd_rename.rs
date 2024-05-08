use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    k8s_etcd::{get_etcd_json, put_etcd_yaml, InMemoryK8sEtcd},
};
use anyhow::{Context, Result};
use serde_json::Value;

pub(crate) async fn fix_configmap(
    etcd_client: &InMemoryK8sEtcd,
    install_config: &str,
    k8s_resource_location: K8sResourceLocation,
) -> Result<()> {
    let mut configmap = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context(format!("no {:?}", k8s_resource_location.as_etcd_key()))?;

    let data = configmap
        .pointer_mut("/data")
        .context("no /data")?
        .as_object_mut()
        .context("/data not an object")?;

    data.insert("install-config".to_string(), Value::String(install_config.to_string()));

    put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

    Ok(())
}
