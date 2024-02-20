use super::utils::override_machineconfig_source;
use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    k8s_etcd::{get_etcd_json, put_etcd_yaml, InMemoryK8sEtcd},
};
use anyhow::{Context, Result};
use futures_util::future::join_all;
use serde_json::Value;
use std::sync::Arc;

pub(crate) async fn fix_machineconfigs(etcd_client: &Arc<InMemoryK8sEtcd>, pull_secret: &str) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("machineconfiguration.openshift.io/machineconfigs")
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

                let mut machineconfig = get_etcd_json(etcd_client, &k8s_resource_location)
                    .await?
                    .context("no machineconfig")?;

                override_machineconfig_source(&mut machineconfig, pull_secret, "/var/lib/kubelet/config.json")
                    .context("fixing machineconfig")?;

                put_etcd_yaml(etcd_client, &k8s_resource_location, machineconfig).await?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_pull_secret_secret(etcd_client: &Arc<InMemoryK8sEtcd>, pull_secret: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-config"), "Secret", "pull-secret", "v1");

    log::info!("setting pull secret secret");
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
