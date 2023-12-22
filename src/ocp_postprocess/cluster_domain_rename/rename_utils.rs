use anyhow::{bail, ensure, Context, Result};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde_json::Value;
use std::io::BufRead;

use crate::file_utils;

pub(crate) fn fix_apiserver_url_file(original_data: Vec<u8>, cluster_domain: &str) -> Result<String> {
    // In 4.15 this file might just be empty (e.g. /etc/machine-config-daemon/noorig/etc/kubernetes/apiserver-url.env.mcdnoorig)
    if original_data.is_empty() {
        return Ok("".to_string());
    }

    let mut found = false;
    let new = original_data
        .lines()
        .collect::<Result<Vec<_>, _>>()
        .context("parsing apiserver-url.env into lines")?
        .into_iter()
        .map(|line| {
            if line.starts_with("KUBERNETES_SERVICE_HOST='api-int.") {
                found = true;
                format!("KUBERNETES_SERVICE_HOST='api-int.{}'", cluster_domain)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    if !found {
        bail!("could not find line starting with KUBERNETES_SERVICE_HOST='api-int. in apiserver-url.env");
    }

    Ok(format!("{new}\n"))
}

pub(crate) fn fix_oauth_metadata(oauth_metadata: &mut Value, cluster_domain: &str) -> Result<()> {
    let oauth_metadata = oauth_metadata.as_object_mut().context("metadata not an object")?;

    oauth_metadata
        .insert(
            "issuer".to_string(),
            serde_json::Value::String(format!("https://oauth-openshift.apps.{cluster_domain}")),
        )
        .context("missing issuer")?;
    oauth_metadata
        .insert(
            "authorization_endpoint".to_string(),
            serde_json::Value::String(format!("https://oauth-openshift.apps.{cluster_domain}/oauth/authorize")),
        )
        .context("missing authorization_endpoint")?;
    oauth_metadata
        .insert(
            "token_endpoint".to_string(),
            serde_json::Value::String(format!("https://oauth-openshift.apps.{cluster_domain}/oauth/token")),
        )
        .context("missing token_endpoint")?;
    Ok(())
}

pub(crate) fn fix_api_server_arguments(config: &mut Value, cluster_domain: &str) -> Result<()> {
    let apiserver_arguments = &mut config
        .pointer_mut("/apiServerArguments")
        .context("apiServerArguments not found")?
        .as_object_mut()
        .context("apiServerArguments not an object")?;

    apiserver_arguments
        .insert(
            "service-account-jwks-uri".to_string(),
            Value::Array(vec![Value::String(format!("https://api-int.{cluster_domain}:6443/openid/v1/jwks"))]),
        )
        .context("missing service-account-jwks-uri")?;
    Ok(())
}

/// Based on https://github.com/openshift/installer/blob/e91df626c10e569e7613249053b7b9b264db42df/pkg/asset/installconfig/clusterid.go#L57-L79
pub(crate) fn generate_infra_id(cluster_name: &str) -> Result<String> {
    const CLUSTER_INFRA_ID_RANDOM_LEN: usize = 5;
    const CLUSTER_INFRA_ID_MAX_LEN: usize = 27;
    const MAX_NORMALIZED_CLUSTER_NAME_LEN: usize = CLUSTER_INFRA_ID_MAX_LEN - (CLUSTER_INFRA_ID_RANDOM_LEN + 1);

    const NON_ALPHANUM: &str = r"[^A-Za-z0-9-]";
    const REPEATED_DASH_SEQUENCES: &str = r"-{2,}";

    let normalized_cluster_name = regex::Regex::new(REPEATED_DASH_SEQUENCES)?
        .replace_all(&regex::Regex::new(NON_ALPHANUM)?.replace_all(cluster_name, "-"), "-")
        .to_string();

    let truncated_cluster_name = normalized_cluster_name
        .chars()
        .take(MAX_NORMALIZED_CLUSTER_NAME_LEN)
        .collect::<String>()
        .trim_end_matches('-')
        .to_string();

    let suffix = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(CLUSTER_INFRA_ID_RANDOM_LEN)
        .map(char::from)
        .collect::<String>();

    Ok(format!("{truncated_cluster_name}-{suffix}"))
}

pub(crate) fn fix_kcm_extended_args(config: &mut Value, generated_infra_id: &str) -> Result<()> {
    let kcm_arguments = &mut config
        .pointer_mut("/extendedArguments")
        .context("extendedArguments not found")?
        .as_object_mut()
        .context("extendedArguments not an object")?;

    kcm_arguments
        .insert(
            "cluster-name".to_string(),
            Value::Array(vec![Value::String(generated_infra_id.to_string())]),
        )
        .context("missing service-account-jwks-uri")?;

    Ok(())
}

pub(crate) async fn fix_kubeconfig(cluster_name: &str, cluster_domain: &str, kubeconfig: &mut Value) -> Result<()> {
    let is_kubelet_kubeconfig = kubeconfig
        .pointer_mut("/contexts")
        .context("contexts not found")?
        .as_array()
        .context("contexts not an array")?
        .iter()
        .any(|context| context.get("name") == Some(&serde_json::Value::String("kubelet".to_string())));

    let clusters = &mut kubeconfig
        .pointer_mut("/clusters")
        .context("clusters not found")?
        .as_array_mut()
        .context("clusters not an array")?;

    if clusters.is_empty() {
        bail!("expected at least one cluster in kubeconfig");
    }

    clusters.iter_mut().try_for_each(|cluster| {
        // Only the kubelet kubeconfig contains the cluster's name as a .clusters[].cluster.name,
        // so it's the only one that needs to be modified
        if is_kubelet_kubeconfig {
            fix_kubeconfig_cluster_cluster_name(cluster.as_object_mut().context("cluster not an object")?, cluster_name)
                .context("fixing cluster name")?;
        }
        // Every cluster has a nested field also called cluster, which is where we find the cluster
        // server URL
        let cluster = cluster
            .pointer_mut("/cluster")
            .context("cluster not found")?
            .as_object_mut()
            .context("cluster not an object")?;

        fix_kubeconfig_server(cluster, cluster_domain).context("fixing server")?;

        anyhow::Ok(())
    })?;

    // Also fix the context reference to the cluster
    if is_kubelet_kubeconfig {
        let contexts = &mut kubeconfig
            .pointer_mut("/contexts")
            .context("contexts not found")?
            .as_array_mut()
            .context("contexts not an array")?;

        contexts.iter_mut().try_for_each(|context| {
            // Every context has a nested field also called context, which is where we find the
            // cluster reference
            let context = context
                .pointer_mut("/context")
                .context("context not found")?
                .as_object_mut()
                .context("context not an object")?;

            fix_kubeconfig_context_cluster_name(context, cluster_name).context("fixing context name")?;

            anyhow::Ok(())
        })?;
    }

    Ok(())
}

fn fix_kubeconfig_server(cluster: &mut serde_json::Map<String, Value>, cluster_domain: &str) -> Result<()> {
    let previous_server = cluster
        .get_mut("server")
        .context("server not found")?
        .as_str()
        .context("server not a string")?;
    if previous_server.starts_with("https://api.") {
        cluster.insert(
            "server".to_string(),
            serde_json::Value::String(format!("https://api.{}:6443", cluster_domain)),
        )
    } else if previous_server.starts_with("https://api-int.") {
        cluster.insert(
            "server".to_string(),
            serde_json::Value::String(format!("https://api-int.{}:6443", cluster_domain)),
        )
    } else if previous_server.starts_with("https://[api-int.") {
        cluster.insert(
            "server".to_string(),
            serde_json::Value::String(format!("https://[api-int.{}]:6443", cluster_domain)),
        )
    } else {
        // Could be something like `https://localhost:6443`, ignore
        return Ok(());
    }
    .context("no previous value")?;

    Ok(())
}

fn fix_kubeconfig_cluster_cluster_name(cluster: &mut serde_json::Map<String, Value>, cluster_name: &str) -> Result<()> {
    cluster
        .insert("name".to_string(), serde_json::Value::String(cluster_name.to_string()))
        .context("no previous value")?;

    Ok(())
}

fn fix_kubeconfig_context_cluster_name(cluster: &mut serde_json::Map<String, Value>, cluster_name: &str) -> Result<()> {
    cluster
        .insert("cluster".to_string(), serde_json::Value::String(cluster_name.to_string()))
        .context("no previous value")?;

    Ok(())
}

pub(crate) fn fix_kcm_pod(pod: &mut Value, generated_infra_id: &str) -> Result<()> {
    let containers = &mut pod
        .pointer_mut("/spec/containers")
        .context("clusters not found")?
        .as_array_mut()
        .context("clusters not an object")?;

    if containers.is_empty() {
        bail!("expected at least one container in pod.yaml");
    }

    containers
        .iter_mut()
        .filter(|container| container["name"] == "kube-controller-manager")
        .try_for_each(|container| {
            let args = container
                .pointer_mut("/args")
                .context("args not found")?
                .as_array_mut()
                .context("args not an array")?;

            if args.is_empty() {
                bail!("expected at least one arg in kube-controller-manager");
            }

            let arg = args
                .iter_mut()
                .find_map(|arg| arg.as_str()?.contains("--cluster-name=").then_some(arg))
                .context("cluster-name not found")?;

            *arg = serde_json::Value::String(
                regex::Regex::new(r"--cluster-name=[^ ]+")
                    .unwrap()
                    .replace_all(
                        arg.as_str().context("arg not string")?,
                        format!("--cluster-name={}", generated_infra_id).as_str(),
                    )
                    .to_string(),
            );

            Ok(())
        })?;

    Ok(())
}

pub(crate) fn fix_pod_container_env(pod: &mut Value, domain: &str, container_name: &str, env_name: &str, init: bool) -> Result<()> {
    let containers = &mut pod
        .pointer_mut(&format!("/spec/{}", if init { "initContainers" } else { "containers" }))
        .context("clusters not found")?
        .as_array_mut()
        .context("clusters not an object")?;

    ensure!(!containers.is_empty(), "expected at least one container in pod.yaml");

    ensure!(
        containers
            .iter()
            .filter(|container| container["name"] == container_name)
            .collect::<Vec<_>>()
            .len()
            == 1,
        format!("expected exactly one container named {}", container_name)
    );

    containers
        .iter_mut()
        .filter(|container| container["name"] == container_name)
        .try_for_each(|container| {
            let env = container
                .pointer_mut("/env")
                .context("env not found")?
                .as_array_mut()
                .context("env not an array")?;

            if env.is_empty() {
                bail!("expected at least one env in container");
            }

            env.iter_mut()
                .find_map(|var| (var.get("name")? == env_name).then_some(var))
                .context(format!("env var {} not found", env_name))?
                .as_object_mut()
                .context("env var not an object")?
                .insert("value".to_string(), serde_json::Value::String(domain.to_string()))
                .context("no previous value")?;

            Ok(())
        })?;

    Ok(())
}

pub(crate) fn fix_mcd_pod_container_args(pod: &mut Value, cluster_domain: &str, container_name: &str) -> Result<()> {
    let containers = &mut pod
        .pointer_mut("/spec/containers")
        .context("clusters not found")?
        .as_array_mut()
        .context("clusters not an object")?;

    if containers.is_empty() {
        bail!("expected at least one container in pod.yaml");
    }

    containers
        .iter_mut()
        .filter(|container| container["name"] == container_name)
        .try_for_each(|container| {
            let args = container
                .pointer_mut("/args")
                .context("args not found")?
                .as_array_mut()
                .context("args not an array")?;

            ensure!(!args.is_empty(), "expected at least one arg in container");

            let arg_idx = args
                .iter_mut()
                .enumerate()
                .find_map(|(i, arg)| arg.as_str()?.starts_with("--apiserver-url=").then_some(i))
                .context("name not found")?;

            args[arg_idx] = serde_json::Value::String(format!("--apiserver-url=https://api-int.{}:6443", cluster_domain));

            Ok(())
        })?;

    Ok(())
}

pub(crate) fn fix_machineconfig(machineconfig: &mut Value, cluster_domain: &str) -> Result<()> {
    let pointer_mut = machineconfig.pointer_mut("/spec/config/storage/files");
    if pointer_mut.is_none() {
        // Not all machineconfigs have files to look at and that's ok
        return Ok(());
    };

    let find_map = pointer_mut
        .context("no /spec/config/storage/files")?
        .as_array_mut()
        .context("files not an array")?
        .iter_mut()
        .find_map(|file| (file.pointer("/path")? == "/etc/kubernetes/apiserver-url.env").then_some(file));

    if find_map.is_none() {
        // Not all machineconfigs have the file we're looking for and that's ok
        return Ok(());
    };

    let file_contents = find_map
        .context("no /etc/kubernetes/apiserver-url.env file in machineconfig")?
        .pointer_mut("/contents")
        .context("no .contents")?
        .as_object_mut()
        .context("annotations not an object")?;

    let original_data = file_contents["source"].as_str().context("source not a string")?;

    let (decoded, _fragment) = data_url::DataUrl::process(original_data)
        .ok()
        .context("dataurl processing")?
        .decode_to_vec()
        .ok()
        .context("dataurl decoding")?;

    let new = fix_apiserver_url_file(decoded, cluster_domain)?;

    file_contents.insert("source".to_string(), serde_json::Value::String(file_utils::dataurl_encode(&new)));

    Ok(())
}
