use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    k8s_etcd::{get_etcd_json, put_etcd_yaml, InMemoryK8sEtcd},
    ocp_postprocess::rename_utils::{env_var_safe, fix_etcd_pod_yaml_hostname},
};
use anyhow::{ensure, Context, Result};
use futures_util::future::join_all;
use serde_json::{Map, Value};
use std::{collections::HashSet, fmt::Display, sync::Arc};

async fn fix_etcd_all_certs_secret(etcd_client: &Arc<InMemoryK8sEtcd>, key: &str, hostname: &str) -> Result<Option<String>> {
    let etcd_result = etcd_client
        .get(key.to_string())
        .await
        .with_context(|| format!("getting key {:?}", key))?
        .context("key disappeared")?;
    let value: Value =
        serde_yaml::from_slice(etcd_result.value.as_slice()).with_context(|| format!("deserializing value of key {:?}", key,))?;
    let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

    let mut secret = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting secret")?;

    let original_hostname = {
        let data = &mut secret
            .pointer_mut("/data")
            .context("no /data")?
            .as_object_mut()
            .context("data not an object")?;

        match data
            .iter()
            // etcd-peer is the only key that we can use to unambiguously identify the original hostname
            .find(|(k, _v)| k.starts_with("etcd-peer-") && k.ends_with(".crt"))
            .map(|(k, _v)| k.clone())
        {
            Some(data_key) => data_key.trim_start_matches("etcd-peer-").trim_end_matches(".crt").to_string(),
            None => {
                // This is OK, some of the secrets don't have data keys
                return anyhow::Ok(None);
            }
        }
    };

    let data_prefixes = ["etcd-peer-", "etcd-serving-", "etcd-serving-metrics-"];
    let managed_fields_data_prefixes = data_prefixes.iter().map(|prefix| format!("f:{}", prefix)).collect::<Vec<_>>();

    let suffixes = [".crt", ".key"];

    fn replace_keys(
        original_hostname: &str,
        new_hostname: &str,
        data_prefixes: &[impl Display],
        suffixes: &[impl Display],
        data: &mut &mut Map<String, Value>,
    ) -> Result<()> {
        let old_keys = data_prefixes.iter().flat_map(|prefix| {
            suffixes
                .iter()
                .map(move |suffix| format!("{}{}{}", prefix, original_hostname, suffix))
        });

        let new_keys = data_prefixes
            .iter()
            .flat_map(|prefix| suffixes.iter().map(move |suffix| format!("{}{}{}", prefix, new_hostname, suffix)));

        old_keys.zip(new_keys).for_each(|(old_key, new_key)| {
            // optionally try to replace fields, as we have seen managedFields missing
            if let Some(value) = data.remove(&old_key) {
                data.insert(new_key, value);
            }
        });

        Ok(())
    }

    // Adjust .data
    {
        let data = &mut secret
            .pointer_mut("/data")
            .context("no /data")?
            .as_object_mut()
            .context("data not an object")?;

        replace_keys(&original_hostname, hostname, &data_prefixes, &suffixes, data).context("could not replace keys")?;
    }

    // Adjust .metadata.managedFields.fieldsV1.data
    {
        let metadata = &mut secret
            .pointer_mut("/metadata")
            .context("no /metadata")?
            .as_object_mut()
            .context("data not an object")?;

        let managed_fields = metadata
            .get_mut("managedFields")
            .context("no managedFields")?
            .as_array_mut()
            .context("managedFields not an array")?;

        managed_fields.iter_mut().try_for_each(|managed_field| {
            let fields_v1_raw_byte_array = managed_field
                .pointer("/fieldsV1/raw")
                .context("no /fieldsV1/raw")?
                .as_array()
                .context("/fieldsV1/raw not an array")?;

            let mut fields_v1_raw_parsed: Value = serde_json::from_str(
                &String::from_utf8(
                    fields_v1_raw_byte_array
                        .iter()
                        .map(|v| v.as_u64().context("fieldsV1 not a number"))
                        .collect::<Result<Vec<_>>>()
                        .context("parsing byte array")?
                        .into_iter()
                        .map(|v| v as u8)
                        .collect::<Vec<_>>(),
                )
                .context("fieldsV1 not valid utf8")?,
            )
            .context("deserializing fieldsV1")?;

            let mut data = (match fields_v1_raw_parsed.pointer_mut("/f:data") {
                Some(data) => data,
                None => return anyhow::Ok(()),
            })
            .as_object_mut()
            .context("f:data not an object")?;

            replace_keys(&original_hostname, hostname, &managed_fields_data_prefixes, &suffixes, &mut data)
                .context("could not replace managed fields keys")?;

            managed_field
                .pointer_mut("/fieldsV1")
                .context("no /fieldsV1")?
                .as_object_mut()
                .context("/fieldsV1 not an object")?
                .insert(
                    "raw".to_string(),
                    serde_json::Value::Array(
                        serde_json::Value::String(serde_json::to_string(&fields_v1_raw_parsed).context("serializing fieldsV1")?)
                            .as_str()
                            .context("serialized not a string")?
                            .as_bytes()
                            .iter()
                            .map(|b| serde_json::Value::Number(serde_json::Number::from(*b)))
                            .collect(),
                    ),
                );

            anyhow::Ok(())
        })?;
    }

    put_etcd_yaml(etcd_client, &k8s_resource_location, secret)
        .await
        .context(format!("could not put etcd key: {}", key))?;

    Ok(Some(original_hostname))
}

pub(crate) async fn fix_etcd_all_certs(etcd_client: &Arc<InMemoryK8sEtcd>, hostname: &str) -> Result<String> {
    let hostnames = join_all(
        etcd_client
            .list_keys("secrets/openshift-etcd/etcd-all-certs")
            .await?
            .into_iter()
            .map(|key| async move { anyhow::Ok(fix_etcd_all_certs_secret(etcd_client, &key, hostname).await?) }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<Option<String>>>>()?;

    let hostnames = hostnames.into_iter().flatten().collect::<HashSet<_>>();

    ensure!(
        hostnames.len() == 1,
        "no hostnames or multiple hostnames found in etcd-all-certs secrets: {:?}",
        hostnames
    );

    // Length ensured above
    #[allow(clippy::unwrap_used)]
    let original_hostname = hostnames.into_iter().next().unwrap();

    Ok(original_hostname)
}

pub(crate) async fn fix_etcd_secrets(etcd_client: &Arc<InMemoryK8sEtcd>, original_hostname: &str, hostname: &str) -> Result<()> {
    for key_prefix in ["etcd-peer", "etcd-serving", "etcd-serving-metrics"] {
        join_all(
            etcd_client
                .list_keys(format!("secrets/openshift-etcd/{key_prefix}-{original_hostname}").as_str())
                .await?
                .into_iter()
                .map(|key| async move {
                    let etcd_result = etcd_client
                        .get(key.clone())
                        .await
                        .with_context(|| format!("getting key {key:?}"))?
                        .context("key disappeared")?;

                    let mut etcd_value: Value = serde_yaml::from_slice(etcd_result.value.as_slice()).context("deserializing value")?;

                    let new_secret_name = format!("{key_prefix}-{hostname}");

                    etcd_value
                        .pointer_mut("/metadata")
                        .context("no /metadata")?
                        .as_object_mut()
                        .context("/metadata not an object")?
                        .insert("name".to_string(), serde_json::Value::String(new_secret_name.clone()));

                    if let Some(description_annotation) = etcd_value.pointer_mut("/metadata/annotations/openshift.io~1description") {
                        *description_annotation = Value::String(
                            description_annotation
                                .as_str()
                                .context("openshift.io/description annotation not a string")?
                                .replace(original_hostname, hostname),
                        );
                    }

                    etcd_client
                        .put(
                            &(format!("/kubernetes.io/secrets/openshift-etcd/{new_secret_name}")),
                            serde_json::to_string(&etcd_value).context("serializing value")?.as_bytes().to_vec(),
                        )
                        .await
                        .context("putting in etcd")?;

                    etcd_client.delete(&key).await.context(format!("deleting {}", key))?;

                    Ok(())
                }),
        )
        .await
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    }

    Ok(())
}

pub(crate) async fn fix_etcd_pod(etcd_client: &Arc<InMemoryK8sEtcd>, original_hostname: &str, hostname: &str) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("configmaps/openshift-etcd/etcd-pod")
            .await?
            .into_iter()
            .chain(
                etcd_client
                    .list_keys("configmaps/openshift-etcd/restore-etcd-pod")
                    .await?
                    .into_iter(),
            )
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

                let data = &mut configmap
                    .pointer_mut("/data")
                    .context("no /data")?
                    .as_object_mut()
                    .context("data not an object")?;

                // TODO: We can't roundtrip arbitrary YAML, ask etcd folks to stop using YAML
                // That's why we have to do primitive string manipulation here instead of proper
                // parsing
                let pod_yaml = data
                    .get_mut("pod.yaml")
                    .context("no pod.yaml")?
                    .as_str()
                    .context("pod.yaml not a string")?
                    .to_string();

                let pod_yaml = fix_etcd_pod_yaml_hostname(&pod_yaml, original_hostname, hostname).context("could not fix pod yaml")?;

                data.insert("pod.yaml".to_string(), serde_json::Value::String(pod_yaml));

                put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_etcd_scripts(etcd_client: &Arc<InMemoryK8sEtcd>, original_hostname: &str, hostname: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-etcd"), "ConfigMap", "etcd-scripts", "v1");
    let mut configmap = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting configmap")?;

    let data = &mut configmap
        .pointer_mut("/data")
        .context("no /data")?
        .as_object_mut()
        .context("data not an object")?;

    // TODO: We can't roundtrip arbitrary YAML, ask etcd folks to stop using YAML
    // That's why we have to do primitive string manipulation here instead of proper
    // parsing
    let mut pod_yaml = data
        .get_mut("etcd.env")
        .context("no etcd.env")?
        .as_str()
        .context("etcd.env not a string")?
        .to_string();

    let patterns = [
        (
            format!(r#"export NODE_{original_hostname}_ETCD_NAME="{original_hostname}""#),
            r#"export NODE_{}_ETCD_NAME="{}""#,
        ),
        (
            format!(r#"export NODE_({original_hostname})_ETCD_URL_HOST="#),
            r#"export NODE_{}_ETCD_URL_HOST="#,
        ),
        (format!(r#"export NODE_{original_hostname}_IP="#), r#"export NODE_{}_IP="#),
    ];

    for (pattern, replacement) in patterns {
        let re = regex::Regex::new(&pattern).context("compiling regex")?;
        pod_yaml = re
            .replace_all(&pod_yaml, replacement.replace("{}", &env_var_safe(hostname)).as_str())
            .to_string();
    }

    data.insert("etcd.env".to_string(), serde_json::Value::String(pod_yaml));

    put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

    Ok(())
}

pub(crate) async fn fix_kubeapiservers_cluster(etcd_client: &Arc<InMemoryK8sEtcd>, hostname: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "KubeAPIServer", "cluster", "operator.openshift.io/v1");
    let mut cluster = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting kubeapiservers/cluster")?;

    replace_node_status_name(&mut cluster, hostname).context("could not replace nodeName for kubeapiservers/cluster")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, cluster).await?;

    Ok(())
}

pub(crate) async fn fix_kubeschedulers_cluster(etcd_client: &Arc<InMemoryK8sEtcd>, hostname: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "KubeScheduler", "cluster", "operator.openshift.io/v1");
    let mut cluster = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting kubeschedulers/cluster")?;

    replace_node_status_name(&mut cluster, hostname).context("could not replace nodeName for kubeschedulers/cluster")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, cluster).await?;

    Ok(())
}

pub(crate) async fn fix_kubecontrollermanagers_cluster(etcd_client: &Arc<InMemoryK8sEtcd>, hostname: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "KubeControllerManager", "cluster", "operator.openshift.io/v1");
    let mut cluster = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting kubecontrollermanagers/cluster")?;

    replace_node_status_name(&mut cluster, hostname).context("could not replace nodeName for kubecontrollermanagers/cluster")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, cluster).await?;

    Ok(())
}

pub(crate) async fn fix_etcds_cluster(etcd_client: &Arc<InMemoryK8sEtcd>, hostname: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "Etcd", "cluster", "operator.openshift.io/v1");
    let mut cluster = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting etcds/cluster")?;

    replace_node_status_name(&mut cluster, hostname).context("could not replace nodeName for etcds/cluster")?;

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
        .map(|status: &mut Value| {
            status
                .as_object_mut()
                .context("nodeStatus not an object")?
                .insert("nodeName".to_string(), Value::String(hostname.to_string()));

            Ok(())
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(())
}
