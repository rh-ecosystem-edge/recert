use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    k8s_etcd::{get_etcd_json, put_etcd_yaml, InMemoryK8sEtcd},
    ocp_postprocess::cluster_domain_rename::rename_utils::{fix_api_server_arguments_ip, fix_etcd_pod_yaml_ip},
};
use anyhow::{bail, ensure, Context, Result};
use futures_util::future::join_all;
use serde_json::Value;
use std::sync::Arc;

pub(crate) async fn fix_openshift_apiserver_configmap(etcd_client: &Arc<InMemoryK8sEtcd>, ip: &str) -> Result<String> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-apiserver"), "Configmap", "config", "v1");

    let mut configmap = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting configmap")?;

    let data = &mut configmap
        .pointer_mut("/data")
        .context("no /data")?
        .as_object_mut()
        .context("data not an object")?;

    let mut config: Value = serde_yaml::from_slice(data["config.yaml"].as_str().context("config.yaml not a string")?.as_bytes())
        .context("deserializing config.yaml")?;

    let original_ip = config
        .pointer("/storageConfig/urls/0")
        .context("no /storageConfig/urls/0")?
        .as_str()
        .context("/storageConfig/urls/0 not a string")?
        .strip_prefix("https://")
        .context("storageConfig/urls/0 not an https URL")?
        .strip_suffix(":2379")
        .context("storageConfig/urls/0 not an etcd URL")?
        .to_string();

    let original_ip = if original_ip.contains(':') {
        original_ip
            .strip_prefix('[')
            .context("IP containing ':' does not contain prefix '['")?
            .strip_suffix(']')
            .context("IP containing ':' does not contain suffix ']'")?
            .to_string()
    } else {
        original_ip
    };

    fix_storage_config(&mut config, ip)?;

    data.insert(
        "config.yaml".to_string(),
        serde_json::Value::String(serde_json::to_string(&config).context("serializing config.yaml")?),
    );

    put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

    Ok(original_ip)
}

fn fix_storage_config(config: &mut Value, ip: &str) -> Result<(), anyhow::Error> {
    let storage_config = config.pointer_mut("/storageConfig").context("storageConfig not found")?;

    let ip = if ip.contains(':') { format!("[{ip}]") } else { ip.to_string() };

    storage_config.as_object_mut().context("storageConfig not an object")?.insert(
        "urls".to_string(),
        serde_json::Value::Array(vec![serde_json::Value::String(format!("https://{ip}:2379"))]),
    );
    Ok(())
}

pub(crate) async fn fix_kube_apiserver_configs(etcd_client: &Arc<InMemoryK8sEtcd>, original_ip: &str, ip: &str) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("configmaps/openshift-kube-apiserver/config")
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
                    .context("could not find configmap")?;

                let data = &mut configmap
                    .pointer_mut("/data")
                    .context("no /data")?
                    .as_object_mut()
                    .context("data not an object")?;

                let mut config: Value =
                    serde_yaml::from_slice(data["config.yaml"].as_str().context("config.yaml not a string")?.as_bytes())
                        .context("deserializing config.yaml")?;

                fix_api_server_arguments_ip(&mut config, original_ip, ip)?;

                data.insert(
                    "config.yaml".to_string(),
                    serde_json::Value::String(serde_json::to_string(&config).context("serializing config.yaml")?),
                )
                .context("could not find original config.yaml")?;

                put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_etcd_endpoints(etcd_client: &Arc<InMemoryK8sEtcd>, ip: &str) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("configmaps/openshift-etcd/etcd-endpoints".to_string().as_str())
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

                let data = &mut configmap
                    .pointer_mut("/data")
                    .context("no /data")?
                    .as_object_mut()
                    .context("data not an object")?;

                ensure!(data.len() == 1, "data has more than one key, is this SNO?");

                let current_member_id = data.keys().next().unwrap().clone();
                data[&current_member_id] = serde_json::Value::String(ip.to_string());

                put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_etcd_pod(etcd_client: &Arc<InMemoryK8sEtcd>, original_ip: &str, ip: &str) -> Result<()> {
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

                let pod_yaml = fix_etcd_pod_yaml_ip(&pod_yaml, original_ip, ip).context("could not fix pod yaml")?;

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

pub(crate) async fn fix_etcd_scripts(etcd_client: &Arc<InMemoryK8sEtcd>, original_ip: &str, ip: &str) -> Result<()> {
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

    let original_ip = if original_ip.contains(':') {
        format!("[{original_ip}]")
    } else {
        original_ip.to_string()
    };

    let ip = if ip.contains(':') { format!("[{ip}]") } else { ip.to_string() };

    let patterns = [
        (
            format!(r#"export ALL_ETCD_ENDPOINTS="https://{original_ip}:2379""#),
            format!(r#"export ALL_ETCD_ENDPOINTS="https://{ip}:2379""#),
        ),
        (
            format!(r#"export ETCDCTL_ENDPOINTS="https://{original_ip}:2379""#),
            format!(r#"export ETCDCTL_ENDPOINTS="https://{ip}:2379""#),
        ),
        (format!(r#"_ETCD_URL_HOST="{original_ip}""#), format!(r#"_ETCD_URL_HOST="{ip}""#)),
        (format!(r#"_IP="{original_ip}""#), format!(r#"_IP="{ip}""#)),
    ];

    for (pattern, replacement) in patterns {
        pod_yaml = pod_yaml.replace(&pattern, &replacement).to_string();
    }

    data.insert("etcd.env".to_string(), serde_json::Value::String(pod_yaml));

    put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

    Ok(())
}

pub(crate) async fn fix_etcd_secrets(etcd_client: &Arc<InMemoryK8sEtcd>, original_ip: &str, ip: &str) -> Result<()> {
    for key_prefix in ["etcd-peer", "etcd-serving", "etcd-serving-metrics"] {
        join_all(
            etcd_client
                .list_keys(format!("secrets/openshift-etcd/{key_prefix}").as_str())
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
                        .context("could not find secret")?;

                    if let Some(certificate_hostnames) =
                        secret.pointer_mut("/metadata/annotations/auth.openshift.io~1certificate-hostnames")
                    {
                        *certificate_hostnames = serde_json::Value::String(
                            certificate_hostnames
                                .as_str()
                                .context("aut.openshift.io/certificate-hostnames annotation not a string")?
                                .replace(original_ip, ip),
                        );
                    }

                    put_etcd_yaml(etcd_client, &k8s_resource_location, secret).await?;

                    Ok(())
                }),
        )
        .await
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    }

    Ok(())
}

pub(crate) async fn fix_kubeapiservers_cluster(etcd_client: &Arc<InMemoryK8sEtcd>, original_ip: &str, ip: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "KubeAPIServer", "cluster", "operator.openshift.io/v1");
    let mut cluster = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting kubeapiservers/cluster")?;

    replace_etcd_servers(&mut cluster, original_ip, ip).context("could not replace etcd servers")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, cluster).await?;

    Ok(())
}

pub(crate) async fn fix_openshiftapiservers_cluster(etcd_client: &Arc<InMemoryK8sEtcd>, ip: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "OpenShiftAPIServer", "cluster", "operator.openshift.io/v1");
    let mut cluster = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting openshiftapiservers/cluster")?;

    let observed_config = cluster.pointer_mut("/spec/observedConfig").context("no /spec/observedConfig")?;

    fix_storage_config(observed_config, ip)?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, cluster).await?;

    Ok(())
}

pub(crate) async fn fix_authentications_cluster(etcd_client: &Arc<InMemoryK8sEtcd>, original_ip: &str, ip: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "Authentication", "cluster", "operator.openshift.io/v1");
    let mut cluster = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting openshiftapiservers/cluster")?;

    let oauth_api_server_observed = cluster
        .pointer_mut("/spec/observedConfig/oauthAPIServer")
        .context("no /spec/observedConfig/oauthAPIServer")?;

    fix_api_server_arguments_ip(oauth_api_server_observed, original_ip, ip)?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, cluster).await?;

    Ok(())
}

pub(crate) async fn fix_oauth_apiserver_deployment(etcd_client: &Arc<InMemoryK8sEtcd>, original_ip: &str, ip: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-oauth-apiserver"), "Deployment", "apiserver", "v1");
    let mut deployment = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting openshift-oauth-apiserver deployment/apiserver")?;

    let containers = &mut deployment
        .pointer_mut("/spec/template/spec/containers")
        .context("/spec/template/spec/containers not found")?
        .as_array_mut()
        .context("/spec/template/spec/containers not an array")?;

    if containers.is_empty() {
        bail!("expected at least one container in deployment");
    }

    containers
        .iter_mut()
        .filter(|container| container["name"] == Value::String("oauth-apiserver".to_string()))
        .try_for_each(|container| {
            let args = container
                .pointer_mut("/args")
                .context("args not found")?
                .as_array_mut()
                .context("args not an array")?;

            ensure!(!args.is_empty(), "expected at least one arg in container");

            let find = if original_ip.contains(':') {
                format!("--etcd-servers='https://[{original_ip}]:2379'")
            } else {
                format!("--etcd-servers=https://{original_ip}:2379")
            };

            let arg_idx = args
                .iter_mut()
                .enumerate()
                .find_map(|(i, arg)| arg.as_str()?.contains(&find).then_some(i))
                .context("name not found")?;

            let replace = if ip.contains(':') {
                format!("--etcd-servers='https://[{ip}]:2379'")
            } else {
                format!("--etcd-servers=https://{ip}:2379")
            };

            args[arg_idx] = serde_json::Value::String(args[arg_idx].as_str().context("arg not a string")?.replace(&find, &replace));

            Ok(())
        })?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, deployment).await?;

    Ok(())
}

pub(crate) async fn fix_networks_cluster(etcd_client: &Arc<InMemoryK8sEtcd>, ip: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "Network", "cluster", "operator.openshift.io/v1");

    let mut cluster = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting networks/cluster")?;

    // TODO: We observed that in OCP 4.15 there is no such annotation. Nevertheless, we should
    // verify whether this should be a soft replacement or not.
    if let Some(annotations) = cluster.pointer_mut("/metadata/annotations") {
        let annotations = annotations.as_object_mut().context("/metadata/annotations not an object")?;
        let key = "networkoperator.openshift.io/ovn-cluster-initiator";

        if annotations.contains_key(key) {
            annotations.insert(key.to_string(), Value::String(ip.to_string()));

            put_etcd_yaml(etcd_client, &k8s_resource_location, cluster).await?;
        }
    }

    Ok(())
}

fn replace_etcd_servers(cluster: &mut Value, original_ip: &str, ip: &str) -> Result<()> {
    let observed_config = cluster.pointer_mut("/spec/observedConfig").context("no /spec/observedConfig")?;

    fix_api_server_arguments_ip(observed_config, original_ip, ip)?;

    Ok(())
}
