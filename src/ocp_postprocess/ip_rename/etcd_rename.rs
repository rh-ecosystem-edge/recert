use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    k8s_etcd::{get_etcd_json, put_etcd_yaml, InMemoryK8sEtcd},
    ocp_postprocess::rename_utils::{fix_api_server_arguments_ip, fix_ip},
};
use anyhow::{bail, ensure, Context, Result};
use futures_util::future::join_all;
use serde_json::Value;
use std::net::Ipv6Addr;
use std::sync::Arc;

// Extract both original IPv4 and IPv6 IPs from dual-stack cluster node configuration
pub(crate) async fn extract_original_ips(etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<Vec<String>> {
    // Extract IPs from node addresses - works for both single-stack and dual-stack
    extract_original_ips_from_nodes(etcd_client).await
}

// Extract original IPs from node configuration - returns 1 IP for single-stack, 2 for dual-stack
async fn extract_original_ips_from_nodes(etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<Vec<String>> {
    let node_keys = etcd_client.list_keys("minions").await?;

    ensure!(
        node_keys.len() == 1,
        "Expected exactly one node in the cluster, found {}",
        node_keys.len()
    );

    let node_key = &node_keys[0];

    let etcd_result = etcd_client.get(node_key.clone()).await?.context("Failed to get node from etcd")?;

    let node: Value = serde_yaml::from_slice(&etcd_result.value).context("Failed to deserialize node value")?;

    let addresses = node
        .pointer("/status/addresses")
        .and_then(|a| a.as_array())
        .context("Node does not have /status/addresses array")?;

    let mut result = Vec::new();

    for address in addresses {
        if let (Some(addr_type), Some(addr_value)) = (
            address.pointer("/type").and_then(|t| t.as_str()),
            address.pointer("/address").and_then(|a| a.as_str()),
        ) {
            if addr_type == "InternalIP" {
                result.push(addr_value.to_string());
            }
        }
    }

    ensure!(!result.is_empty(), "No InternalIP addresses found in node configuration");

    if result.len() == 1 {
        log::info!("Found single-stack IP: {}", result[0]);
    } else {
        log::info!("Found {} InternalIP(s) {}", result.len(), result.join(", "));
    }

    Ok(result)
}

pub(crate) async fn fix_openshift_apiserver_configmap(etcd_client: &Arc<InMemoryK8sEtcd>, original_ip: &str, ip: &str) -> Result<()> {
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

    // Check if the current config contains the original IP before making changes
    let current_url = config
        .pointer("/storageConfig/urls/0")
        .context("no /storageConfig/urls/0")?
        .as_str()
        .context("/storageConfig/urls/0 not a string")?;

    let expected_original_url = if original_ip.contains(':') {
        format!("https://[{}]:2379", original_ip)
    } else {
        format!("https://{}:2379", original_ip)
    };

    // Only replace if the original IP is found
    if current_url == expected_original_url {
        fix_storage_config(&mut config, original_ip, ip)?;

        data.insert(
            "config.yaml".to_string(),
            serde_json::Value::String(serde_json::to_string(&config).context("serializing config.yaml")?),
        );

        put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;
    } else {
        log::info!(
            "Original IP {} not found in openshift apiserver configmap, current URL is {}, skipping replacement",
            original_ip,
            current_url
        );
    }

    Ok(())
}

fn fix_storage_config(config: &mut Value, original_ip: &str, ip: &str) -> Result<()> {
    let storage_config = config.pointer_mut("/storageConfig").context("storageConfig not found")?;

    let current_urls = storage_config
        .pointer("/urls")
        .and_then(|urls| urls.as_array())
        .context("storageConfig/urls not found or not an array")?;

    let original_ip_formatted = if original_ip.contains(':') {
        format!("[{original_ip}]")
    } else {
        original_ip.to_string()
    };
    let expected_url = format!("https://{original_ip_formatted}:2379");

    // Only replace if the original IP is found in the URLs
    let contains_original = current_urls.iter().any(|url| url.as_str().map_or(false, |s| s == expected_url));

    if contains_original {
        let new_ip = if ip.contains(':') { format!("[{ip}]") } else { ip.to_string() };
        storage_config.as_object_mut().context("storageConfig not an object")?.insert(
            "urls".to_string(),
            serde_json::Value::Array(vec![serde_json::Value::String(format!("https://{new_ip}:2379"))]),
        );
    } else {
        log::info!("Original IP {} not found in storage config URLs, skipping replacement", original_ip);
    }

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

pub(crate) async fn fix_etcd_endpoints(etcd_client: &Arc<InMemoryK8sEtcd>, original_ip: &str, ip: &str) -> Result<()> {
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

                // Ensure above guarantees that this unwrap will never panic
                #[allow(clippy::unwrap_used)]
                let current_member_id = data.keys().next().unwrap().clone();
                let current_value = data[&current_member_id].as_str().context("current member value not a string")?;

                // Only replace if the original IP is found
                if current_value == original_ip {
                    data[&current_member_id] = serde_json::Value::String(ip.to_string());
                    put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;
                } else {
                    log::info!(
                        "Original IP {} not found in etcd endpoints, current value is {}, skipping replacement",
                        original_ip,
                        current_value
                    );
                }

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

                let pod_yaml = fix_ip(&pod_yaml, original_ip, ip).context("could not fix pod yaml")?;

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

pub(crate) async fn fix_openshiftapiservers_cluster(etcd_client: &Arc<InMemoryK8sEtcd>, original_ip: &str, ip: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "OpenShiftAPIServer", "cluster", "operator.openshift.io/v1");
    let mut cluster = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting openshiftapiservers/cluster")?;

    let observed_config = cluster.pointer_mut("/spec/observedConfig").context("no /spec/observedConfig")?;

    fix_storage_config(observed_config, original_ip, ip)?;

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
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-oauth-apiserver"), "Deployment", "apiserver", "apps/v1");

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
                .find_map(|(i, arg)| arg.as_str()?.contains(&find).then_some(i));

            let Some(arg_idx) = arg_idx else {
                log::info!(
                    "etcd server argument with {} not found, skipping (this is normal for IPv6 in dual-stack)",
                    original_ip
                );
                return Ok(());
            };

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

pub(crate) async fn fix_networks_cluster(etcd_client: &Arc<InMemoryK8sEtcd>, original_ip: &str, ip: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "Network", "cluster", "operator.openshift.io/v1");

    let mut cluster = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting networks/cluster")?;

    // TODO: We observed that in OCP 4.15 there is no such annotation. Nevertheless, we should
    // verify whether this should be a soft replacement or not.
    if let Some(annotations) = cluster.pointer_mut("/metadata/annotations") {
        let annotations = annotations.as_object_mut().context("/metadata/annotations not an object")?;
        let key = "networkoperator.openshift.io/ovn-cluster-initiator";

        if let Some(current_value) = annotations.get(key) {
            let current_value_str = current_value.as_str().context("annotation value not a string")?;
            // Only replace if the original IP is found
            if current_value_str == original_ip {
                annotations.insert(key.to_string(), Value::String(ip.to_string()));
                put_etcd_yaml(etcd_client, &k8s_resource_location, cluster).await?;
            } else {
                log::info!(
                    "Original IP {} not found in networks cluster annotation, current value is {}, skipping replacement",
                    original_ip,
                    current_value_str
                );
            }
        } else {
            log::info!("Network cluster annotation {} not found, skipping replacement", key);
        }
    }

    Ok(())
}

pub(crate) async fn fix_etcd_member(etcd_client: &Arc<InMemoryK8sEtcd>, original_ip: &str, ip: &str) -> Result<()> {
    let etcd_client_ref = etcd_client.etcd_client.as_ref().context("etcd client not configured")?;

    // Get current member list to check if original IP is present
    let members_list = etcd_client_ref
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

    let current_member = &members[0];
    let expected_original_url = if original_ip.parse::<Ipv6Addr>().is_ok() {
        format!("https://[{}]:2380", original_ip)
    } else {
        format!("https://{}:2380", original_ip)
    };

    let contains_original = current_member.peer_urls().iter().any(|url| url == &expected_original_url);

    if contains_original {
        let new_member_url = if ip.parse::<Ipv6Addr>().is_ok() {
            format!("https://[{}]:2380", ip)
        } else {
            format!("https://{}:2380", ip)
        };

        log::debug!("Updating etcd member from {} to {}", expected_original_url, new_member_url);
        etcd_client
            .update_member(new_member_url)
            .await
            .context("failed to update etcd member")?;
    } else {
        log::info!(
            "Original IP {} not found in etcd member peer URLs, current URLs are {:?}, skipping replacement",
            original_ip,
            current_member.peer_urls()
        );
    }

    Ok(())
}

pub(crate) async fn fix_pods_status(etcd_client: &Arc<InMemoryK8sEtcd>, original_ip: &str, ip: &str) -> Result<()> {
    // Only mutate known Pod status IP fields if they equal the original IP
    fn replace_status_ips(pod: &mut Value, original_ip: &str, new_ip: &str) -> Result<bool> {
        let mut changed = false;

        // status.podIP
        if let Some(v) = pod.pointer_mut("/status/podIP") {
            if let Some(curr) = v.as_str() {
                if curr == original_ip {
                    *v = Value::String(new_ip.to_string());
                    changed = true;
                }
            }
        }

        // status.hostIP
        if let Some(v) = pod.pointer_mut("/status/hostIP") {
            if let Some(curr) = v.as_str() {
                if curr == original_ip {
                    *v = Value::String(new_ip.to_string());
                    changed = true;
                }
            }
        }

        // status.podIPs (array of objects {ip: string} or strings)
        if let Some(arr) = pod.pointer_mut("/status/podIPs").and_then(|v| v.as_array_mut()) {
            for entry in arr.iter_mut() {
                if let Some(s) = entry.as_str() {
                    if s == original_ip {
                        *entry = Value::String(new_ip.to_string());
                        changed = true;
                    }
                    continue;
                }
                if let Some(ip_field) = entry.as_object_mut().and_then(|m| m.get_mut("ip")) {
                    if let Some(s) = ip_field.as_str() {
                        if s == original_ip {
                            *ip_field = Value::String(new_ip.to_string());
                            changed = true;
                        }
                    }
                }
            }
        }

        // status.hostIPs (array of objects {ip: string} or strings) - if present
        if let Some(arr) = pod.pointer_mut("/status/hostIPs").and_then(|v| v.as_array_mut()) {
            for entry in arr.iter_mut() {
                if let Some(s) = entry.as_str() {
                    if s == original_ip {
                        *entry = Value::String(new_ip.to_string());
                        changed = true;
                    }
                    continue;
                }
                if let Some(ip_field) = entry.as_object_mut().and_then(|m| m.get_mut("ip")) {
                    if let Some(s) = ip_field.as_str() {
                        if s == original_ip {
                            *ip_field = Value::String(new_ip.to_string());
                            changed = true;
                        }
                    }
                }
            }
        }

        Ok(changed)
    }

    join_all(etcd_client.list_keys("pods/").await?.into_iter().map(|key| async move {
        let etcd_result = etcd_client
            .get(key.clone())
            .await
            .with_context(|| format!("getting key {:?}", key))?
            .context("key disappeared")?;
        let value: Value =
            serde_yaml::from_slice(etcd_result.value.as_slice()).with_context(|| format!("deserializing value of key {:?}", key,))?;
        let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

        let mut pod = get_etcd_json(etcd_client, &k8s_resource_location).await?.context("getting pod")?;

        if replace_status_ips(&mut pod, original_ip, ip)? {
            put_etcd_yaml(etcd_client, &k8s_resource_location, pod).await?;
        }

        Ok(())
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn delete_minions_if_exist(etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<()> {
    for key in etcd_client.list_keys("minions").await? {
        etcd_client.delete(&key).await.context(format!("deleting {}", key))?;
    }
    Ok(())
}

fn replace_etcd_servers(cluster: &mut Value, original_ip: &str, ip: &str) -> Result<()> {
    let observed_config = cluster.pointer_mut("/spec/observedConfig").context("no /spec/observedConfig")?;

    fix_api_server_arguments_ip(observed_config, original_ip, ip)?;

    Ok(())
}
