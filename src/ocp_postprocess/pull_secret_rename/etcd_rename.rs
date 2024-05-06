use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    k8s_etcd::{get_etcd_json, put_etcd_yaml, InMemoryK8sEtcd},
    ocp_postprocess::rename_utils,
};
use anyhow::{Context, Result};
use std::sync::Arc;

pub(crate) async fn fix_machineconfigs(etcd_client: &Arc<InMemoryK8sEtcd>, content: &str) -> Result<()> {
    rename_utils::fix_etcd_machineconfigs(etcd_client, content, "/var/lib/kubelet/config.json")
        .await
        .context("fixing pull secret machine configs")?;
    Ok(())
}

pub(crate) async fn fix_pull_secret_secret(etcd_client: &Arc<InMemoryK8sEtcd>, pull_secret: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-config"), "Secret", "pull-secret", "v1");

    let mut secret = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context(format!("couldn't find {}", k8s_resource_location))?;

    let data = secret
        .pointer_mut("/data")
        .context("no .data")?
        .as_object_mut()
        .context("data not an object")?;

    data.insert(
        ".dockerconfigjson".to_string(),
        serde_json::Value::Array(
            pull_secret
                .as_bytes()
                .iter()
                .map(|byte| serde_json::Value::Number(serde_json::Number::from(*byte)))
                .collect(),
        ),
    );
    put_etcd_yaml(etcd_client, &k8s_resource_location, secret).await?;
    Ok(())
}
