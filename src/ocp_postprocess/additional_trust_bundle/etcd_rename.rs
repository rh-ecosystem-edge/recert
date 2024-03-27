use super::utils::fix_machineconfig;
use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    k8s_etcd::{get_etcd_json, put_etcd_yaml, InMemoryK8sEtcd},
    ocp_postprocess::fnv::fnv1_64,
    ocp_postprocess::go_base32::base32_encode as go_base32_encode,
};
use anyhow::{ensure, Context, Result};
use futures_util::future::join_all;
use regex::Regex;
use serde_json::Value;
use std::sync::Arc;

pub(crate) async fn fix_machineconfigs(etcd_client: &Arc<InMemoryK8sEtcd>, additional_trust_bundle: &str) -> Result<()> {
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

                fix_machineconfig(&mut machineconfig, additional_trust_bundle).context("fixing machineconfig")?;

                put_etcd_yaml(etcd_client, &k8s_resource_location, machineconfig).await?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

// There's an OCP operator that injects the trusted CA bundle into configmaps which have this
// label. We simply emulate that behavior here, should be a bit more robust than hardcoding a list
// of configmaps
pub(crate) async fn fix_labeled_configmaps(etcd_client: &InMemoryK8sEtcd, full_merged_bundle: &str) -> Result<()> {
    join_all(etcd_client.list_keys("configmaps/").await?.into_iter().map(|key| async move {
        let etcd_result = etcd_client
            .get(key.clone())
            .await
            .with_context(|| format!("getting key {:?}", key))?
            .context("key disappeared")?;
        let value: Value =
            serde_yaml::from_slice(etcd_result.value.as_slice()).with_context(|| format!("deserializing value of key {:?}", key,))?;

        let slash = "~1";
        if value
            .pointer(&format!("/metadata/labels/config.openshift.io{slash}inject-trusted-cabundle"))
            .is_none()
        {
            let unlabeled_exceptions = [
                // All other certs are injected from this configmap, so we need to fix it as well,
                // even though it's not labeled
                K8sResourceLocation::new(Some("openshift-config-managed"), "ConfigMap", "trusted-ca-bundle", "v1"),
                // ccm is quirky and builds its own configmap with a merged bundle. Usually it
                // contains also certs taken from the cloud config, so it could look different than
                // what network operator injects, but since we're doing SNO-none, the result is
                // identical to what the network operator injects, so we can fix it as well
                K8sResourceLocation::new(Some("openshift-cloud-controller-manager"), "ConfigMap", "ccm-trusted-ca", "v1"),
            ];

            if unlabeled_exceptions.iter().all(|location| location.as_etcd_key() != key) {
                // This is not a configmap we want to inject into and neither is it the source of
                // the injection, so it doesn't need to be fixed
                return Ok(());
            }
        }

        let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

        let mut configmap = get_etcd_json(etcd_client, &k8s_resource_location)
            .await?
            .context("no machineconfig")?;

        let data = configmap
            .pointer_mut("/data")
            .context("no /data in configmap")?
            .as_object_mut()
            .context("/data not an object")?;

        data.insert(
            "ca-bundle.crt".to_string(),
            serde_json::Value::String(full_merged_bundle.to_string()),
        );

        put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

        Ok(())
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_original_additional_trust_bundle(
    etcd_client: &InMemoryK8sEtcd,
    additional_trust_bundle: &str,
) -> Result<Option<String>> {
    let proxy_config_k8s_resource_location = K8sResourceLocation::new(None, "Proxy", "cluster", "config.openshift.io");

    let config = get_etcd_json(etcd_client, &proxy_config_k8s_resource_location)
        .await?
        .context("could not find proxy cluster config")?;

    let trusted_ca_configmap_name = config
        .pointer("/spec/trustedCA/name")
        .context("no trustedCA in proxy cluster config")?
        .as_str()
        .context("trustedCA not a string")?;

    if trusted_ca_configmap_name.is_empty() {
        return Ok(None);
    }

    let ca_configmap_k8s_resource_location =
        K8sResourceLocation::new(Some("openshift-config"), "ConfigMap", trusted_ca_configmap_name, "v1");

    let mut configmap = get_etcd_json(etcd_client, &ca_configmap_k8s_resource_location)
        .await?
        .context("could not find trustedCA configmap")?;

    let data = configmap
        .pointer_mut("/data")
        .context("no /data in configmap")?
        .as_object_mut()
        .context("/data not an object")?;

    let original_additional_trust_bundle = data.insert(
        "ca-bundle.crt".to_string(),
        serde_json::Value::String(additional_trust_bundle.to_string()),
    );

    put_etcd_yaml(etcd_client, &ca_configmap_k8s_resource_location, configmap).await?;

    Ok(Some(
        original_additional_trust_bundle
            .context("no ca-bundle.crt in trustedCA configmap")?
            .as_str()
            .context("ca-bundle.crt not a string")?
            .to_string(),
    ))
}

pub(crate) async fn fix_monitoring_configmaps(etcd_client: &InMemoryK8sEtcd, new_merged_bundle: &str) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("configmaps/openshift-monitoring/")
            .await?
            .into_iter()
            .map(|key| async move {
                let etcd_result = etcd_client
                    .get(key.clone())
                    .await
                    .with_context(|| format!("getting key {:?}", key))?
                    .context("key disappeared")?;
                let value: Value = serde_json::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;

                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let regex = &Regex::new(r"(?P<component>.*)-trusted-ca-bundle-(?P<hash>[0-9a-z]+)").context("compiling regex")?;
                let matches = regex.captures(&k8s_resource_location.name);

                let matches = match matches {
                    Some(matches) => matches,
                    None => return Ok(()),
                };

                let component = matches.name("component").context("no component")?.as_str();

                let mut configmap = get_etcd_json(etcd_client, &k8s_resource_location)
                    .await?
                    .context("no machineconfig")?;

                let current_data = configmap
                    .pointer("/data/ca-bundle.crt")
                    .context("no ca-bundle.crt in configmap")?
                    .as_str()
                    .context("ca-bundle.crt not a string")?
                    .as_bytes();

                let recert_calculated_original_hash = go_base32_encode(fnv1_64(current_data));

                let operator_calculated_hash = configmap
                    .pointer("/metadata/labels/monitoring.openshift.io~1hash")
                    .context("no monitoring.openshift.io/hash in configmap")?
                    .as_str()
                    .context("monitoring.openshift.io/hash not a string")?;

                // Sanity check to make sure our hash function is compatible with the one used by
                // the monitoring operator
                ensure!(
                    recert_calculated_original_hash == operator_calculated_hash,
                    format!("hash mismatch: {} != {}", recert_calculated_original_hash, operator_calculated_hash)
                );

                let new_hash = go_base32_encode(fnv1_64(new_merged_bundle.as_bytes()));

                configmap
                    .pointer_mut("/metadata/labels")
                    .context("no /metadata/labels in configmap")?
                    .as_object_mut()
                    .context("/metadata/labels not an object")?
                    .insert(
                        "monitoring.openshift.io/hash".to_string(),
                        serde_json::Value::String(new_hash.clone()),
                    );

                let data = configmap
                    .pointer_mut("/data")
                    .context("no /data in configmap")?
                    .as_object_mut()
                    .context("/data not an object")?;

                data.insert(
                    "ca-bundle.crt".to_string(),
                    serde_json::Value::String(new_merged_bundle.to_string()),
                );

                let new_resource_location = K8sResourceLocation::new(
                    k8s_resource_location.namespace.as_deref(),
                    &k8s_resource_location.kind,
                    &format!("{component}-trusted-ca-bundle-{new_hash}"),
                    &k8s_resource_location.apiversion,
                );

                put_etcd_yaml(etcd_client, &new_resource_location, configmap)
                    .await
                    .context("putting new configmap")?;

                etcd_client.delete(&key).await.context("deleting old configmap")?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_kcm_openshift_user_ca(etcd_client: &InMemoryK8sEtcd, additional_trust_bundle: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-controller-manager"), "ConfigMap", "openshift-user-ca", "v1");

    let mut configmap = get_etcd_json(etcd_client, &k8s_resource_location).await?.context("no configmap")?;

    let data = configmap
        .pointer_mut("/data")
        .context("no /data in configmap")?
        .as_object_mut()
        .context("/data not an object")?;

    data.insert(
        "ca-bundle.crt".to_string(),
        serde_json::Value::String(additional_trust_bundle.to_string()),
    );

    put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

    Ok(())
}
