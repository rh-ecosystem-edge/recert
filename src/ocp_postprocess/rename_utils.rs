use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    k8s_etcd::{get_etcd_json, put_etcd_yaml, InMemoryK8sEtcd},
};
use anyhow::{bail, ensure, Context, Result};
use futures_util::future::join_all;
use itertools::Itertools;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde_json::Value;
use std::io::BufRead;
use std::path::Path;
use std::sync::Arc;

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

pub(crate) fn fix_api_server_arguments_domain(config: &mut Value, cluster_domain: &str) -> Result<()> {
    let apiserver_arguments = &mut config
        .pointer_mut("/apiServerArguments")
        .context("apiServerArguments not found")?
        .as_object_mut()
        .context("apiServerArguments not an object")?;

    let original_service_account_jwks_uris = apiserver_arguments
        .get("service-account-jwks-uri")
        .context("service-account-jwks-uri not found")?
        .as_array()
        .context("service-account-jwks-uri not an array")?
        .clone();

    let new_service_account_jwks_uris = original_service_account_jwks_uris
        .iter()
        .map(|uri| {
            let uri = uri.as_str().context("uri not a string")?;

            Ok(Value::String(
                regex::Regex::new(r"https://(?P<api_label>api-int|api)\.(?P<cluster_domain>.+):6443/openid/v1/jwks")
                    .context("compiling regex")?
                    .replace_all(uri, format!("https://$api_label.{cluster_domain}:6443/openid/v1/jwks").as_str())
                    .to_string(),
            ))
        })
        .collect::<Result<Vec<_>>>()
        .context("replacing service-account-jwks-uri")?;

    apiserver_arguments
        .insert("service-account-jwks-uri".to_string(), Value::Array(new_service_account_jwks_uris))
        .context("missing service-account-jwks-uri")?;

    Ok(())
}

pub(crate) fn fix_api_server_arguments_ip(config: &mut Value, original_ip: &str, ip: &str) -> Result<()> {
    let apiserver_arguments = &mut config
        .pointer_mut("/apiServerArguments")
        .context("apiServerArguments not found")?
        .as_object_mut()
        .context("apiServerArguments not an object")?;

    let original_etcd_servers = apiserver_arguments
        .get("etcd-servers")
        .context("etcd-servers not found")?
        .as_array()
        .context("etcd-servers not an array")?
        .clone();

    let original_ip = if original_ip.contains(':') {
        format!("[{original_ip}]")
    } else {
        original_ip.to_string()
    };

    let ip = if ip.contains(':') { format!("[{ip}]") } else { ip.to_string() };

    let new_etcd_servers = original_etcd_servers
        .iter()
        .map(|etcd_server| {
            Ok(Value::String(etcd_server.as_str().context("etcd server not a string")?.replace(
                format!("https://{original_ip}").as_str(),
                format!("https://{ip}").as_str(),
            )))
        })
        .collect::<Result<Vec<_>>>()
        .context("replacing etcd servers")?;

    apiserver_arguments.insert("etcd-servers".to_string(), Value::Array(new_etcd_servers));

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

pub(crate) fn fix_cluster_backup_sh(cluster_backup_sh: &str, original_hostname: &str, hostname: &str) -> Result<String> {
    let cluster_backup = cluster_backup_sh.to_string();
    let pattern = format!(r"NODE_{}_IP", env_var_safe(original_hostname));
    let replacement = format!(r"NODE_{}_IP", env_var_safe(hostname));
    Ok(cluster_backup.replace(&pattern, &replacement).to_string())
}

pub(crate) fn fix_etcd_env(etcd_env: &str, original_hostname: &str, hostname: &str) -> Result<String> {
    let mut etcd_env = etcd_env.to_string();
    let patterns = [
        (r#"NODE_{original_hostname_safe}_IP"#, r#"NODE_{hostname_safe}_IP"#),
        (
            r#"NODE_{original_hostname_safe}_ETCD_NAME="{original_hostname}""#,
            r#"NODE_{hostname_safe}_ETCD_NAME="{hostname}""#,
        ),
        (
            r#"NODE_{original_hostname_safe}_ETCD_URL_HOST"#,
            r#"NODE_{hostname_safe}_ETCD_URL_HOST"#,
        ),
        (
            "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-peer-{original_hostname}.crt",
            "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-peer-{hostname}.crt",
        ),
        (
            "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-peer-{original_hostname}.key",
            "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-peer-{hostname}.key",
        ),
    ];
    for (pattern, replacement) in patterns {
        let pattern = pattern
            .replace("{original_hostname}", original_hostname)
            .replace("{original_hostname_safe}", &env_var_safe(original_hostname));

        let replacement = replacement
            .replace("{hostname}", hostname)
            .replace("{hostname_safe}", &env_var_safe(hostname));

        etcd_env = etcd_env.replace(&pattern, &replacement).to_string();
    }

    Ok(etcd_env)
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
                    .context("compiling regex")?
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

// Mimics https://github.com/openshift/cluster-etcd-operator/blob/5973046e2d216b290740cf64a071a272bbf83aea/pkg/etcdenvvar/etcd_env.go#L244-L246
pub(crate) fn env_var_safe(node_name: &str) -> String {
    node_name.replace(['-', '.'], "_")
}

pub(crate) fn fix_etcd_pod_yaml_hostname(pod_yaml: &str, original_hostname: &str, hostname: &str) -> Result<String> {
    let mut pod_yaml = pod_yaml.to_string();

    // TODO: The "value:" replacement below is risky - if the hostname is "existing",
    // or "REVISION", or "true" this will wreak havoc because these appear in the
    // pod.yaml as values. Unlikely but crash if we see these values for now.
    ensure!(
        ["existing", "REVISION", "true"]
            .iter()
            .all(|invalid_hostname| invalid_hostname != &original_hostname),
        "{} hostname is unsupported at the moment, please use a different seed hostname",
        original_hostname
    );

    let patterns = [
        (
            r#"- name: "NODE_{original_hostname_safe}_ETCD_NAME"#,
            r#"- name: "NODE_{hostname_safe}_ETCD_NAME"#,
        ),
        (r#"value: "{original_hostname}""#, r#"value: "{hostname}""#),
        (
            r#"- name: "NODE_{original_hostname_safe}_ETCD_URL_HOST"#,
            r#"- name: "NODE_{hostname_safe}_ETCD_URL_HOST"#,
        ),
        (
            r#"- name: "NODE_{original_hostname_safe}_IP"#,
            r#"- name: "NODE_{hostname_safe}_IP"#,
        ),
        (
            r#"${NODE_{original_hostname_safe}_ETCD_URL_HOST"#,
            r#"${NODE_{hostname_safe}_ETCD_URL_HOST"#,
        ),
        (
            r#"${NODE_{original_hostname_safe}_ETCD_NAME"#,
            r#"${NODE_{hostname_safe}_ETCD_NAME""#,
        ),
        ("${NODE_{original_hostname_safe}_IP", "${NODE_{hostname_safe}_IP"),
        (
            "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-peer-{original_hostname}.crt",
            "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-peer-{hostname}.crt",
        ),
        (
            "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-peer-{original_hostname}.key",
            "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-peer-{hostname}.key",
        ),
        (
            "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-serving-metrics-{original_hostname}.crt",
            "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-serving-metrics-{hostname}.crt",
        ),
        (
            "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-serving-metrics-{original_hostname}.key",
            "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-serving-metrics-{hostname}.key",
        ),
        (
            "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-serving-{original_hostname}.key",
            "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-serving-{hostname}.key",
        ),
        (
            "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-serving-{original_hostname}.crt",
            "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-serving-{hostname}.crt",
        ),
        ("--target-name={original_hostname}", "--target-name={hostname}"),
    ];

    for (pattern, replacement) in patterns {
        let pattern = pattern
            .replace("{original_hostname}", original_hostname)
            .replace("{original_hostname_safe}", &env_var_safe(original_hostname));

        let replacement = replacement
            .replace("{hostname}", hostname)
            .replace("{hostname_safe}", &env_var_safe(hostname));

        pod_yaml = pod_yaml.replace(&pattern, &replacement).to_string();
    }

    Ok(pod_yaml)
}

pub(crate) fn fix_etcd_pod_yaml_ip(pod_yaml: &str, original_ip: &str, ip: &str) -> Result<String> {
    let mut pod_yaml = pod_yaml.to_string();

    let original_ip = if original_ip.contains(':') {
        format!("[{original_ip}]")
    } else {
        original_ip.to_string()
    };

    let ip = if ip.contains(':') { format!("[{ip}]") } else { ip.to_string() };

    let patterns = [
        (r#"value: "https://{original_ip}:2379""#, r#"value: "https://{ip}:2379""#),
        (r#"value: "{original_ip}""#, r#"value: "{ip}""#),
    ];

    for (pattern, replacement) in patterns {
        pod_yaml = pod_yaml
            .replace(
                &pattern.replace("{original_ip}", original_ip.as_str()),
                &replacement.replace("{ip}", ip.as_str()),
            )
            .to_string();
    }

    Ok(pod_yaml)
}

pub(crate) fn fix_etcd_static_pod(pod: &mut Value, original_hostname: &str, hostname: &str) -> Result<()> {
    {
        let init_containers = &mut pod
            .pointer_mut("/spec/initContainers")
            .context("initContainers not found")?
            .as_array_mut()
            .context("initContainers not an object")?;

        ensure!(!init_containers.is_empty(), "expected at least one init container in pod.yaml");

        init_containers
            .iter_mut()
            .try_for_each(|container| fix_etcd_static_pod_container(container, original_hostname, hostname))?;
    }

    {
        let containers = &mut pod
            .pointer_mut("/spec/containers")
            .context("containers not found")?
            .as_array_mut()
            .context("containers not an object")?;

        ensure!(!containers.is_empty(), "expected at least one container in pod.yaml");

        containers
            .iter_mut()
            .try_for_each(|container| {
                fix_etcd_static_pod_container(container, original_hostname, hostname)
                    .context(format!("fixing container {}", container.get("name").unwrap_or(&Value::Null)))
            })
            .context("fixing etcd static pod container")?;
    }

    Ok(())
}

fn fix_etcd_static_pod_container(container: &mut Value, original_hostname: &str, hostname: &str) -> Result<()> {
    'hostname_args_replace: {
        let args = container
            .pointer_mut("/command")
            .context("command not found")?
            .as_array_mut()
            .context("command not an array")?;

        ensure!(!args.is_empty(), "expected at least one arg in etcd static pod container");

        let shell_arg = args
            .iter_mut()
            .find_map(|arg| arg.as_str()?.starts_with("#!/bin/sh\n").then_some(arg));

        let shell_arg = match shell_arg {
            None => break 'hostname_args_replace,
            Some(shell_arg) => shell_arg,
        };

        for (pattern, replacement) in [
            ("NODE_{original_hostname_safe}_ETCD_URL_HOST", "NODE_{hostname_safe}_ETCD_URL_HOST"),
            ("NODE_{original_hostname_safe}_ETCD_NAME", "NODE_{hostname_safe}_ETCD_NAME"),
            ("NODE_{original_hostname_safe}_IP", "NODE_{hostname_safe}_IP"),
            (
                "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-peer-{original_hostname}.crt",
                "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-peer-{hostname}.crt",
            ),
            (
                "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-peer-{original_hostname}.key",
                "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-peer-{hostname}.key",
            ),
            ("--target-name={original_hostname}", "--target-name={hostname}"),
            (
                "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-serving-{original_hostname}.crt",
                "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-serving-{hostname}.crt",
            ),
            (
                "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-serving-{original_hostname}.key",
                "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-serving-{hostname}.key",
            ),
            (
                "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-serving-metrics-{original_hostname}.crt",
                "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-serving-metrics-{hostname}.crt",
            ),
            (
                "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-serving-metrics-{original_hostname}.key",
                "/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-serving-metrics-{hostname}.key",
            ),
        ] {
            let pattern = pattern
                .replace("{original_hostname}", original_hostname)
                .replace("{original_hostname_safe}", &env_var_safe(original_hostname));

            let replacement = replacement
                .replace("{hostname}", hostname)
                .replace("{hostname_safe}", &env_var_safe(hostname));

            *shell_arg = serde_json::Value::String(
                shell_arg
                    .as_str()
                    .context("arg not string")?
                    .replace(&pattern, &replacement)
                    .to_string(),
            );
        }
    }

    'hostname_env_replace: {
        let maybe_env = container.pointer_mut("/env");

        let envs = match maybe_env {
            Some(env) => env.as_array_mut().context("env not an array")?,
            None => break 'hostname_env_replace,
        };

        ensure!(!envs.is_empty(), "expected at least one env in etcd static pod container");

        for (key, new_name, new_value) in [
            (
                "ETCDCTL_CERT",
                None,
                Some(format!("/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-peer-{hostname}.crt").as_str()),
            ),
            (
                "ETCDCTL_KEY",
                None,
                Some(format!("/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-peer-{hostname}.key").as_str()),
            ),
            (
                "ETCDCTL_KEY_FILE",
                None,
                Some(format!("/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-peer-{hostname}.key").as_str()),
            ),
            (
                format!("NODE_{}_ETCD_NAME", &env_var_safe(original_hostname)).as_str(),
                Some(format!("NODE_{}_ETCD_NAME", &env_var_safe(hostname)).as_str()),
                Some(hostname),
            ),
            (
                format!("NODE_{}_ETCD_URL_HOST", &env_var_safe(original_hostname)).as_str(),
                Some(format!("NODE_{}_ETCD_URL_HOST", &env_var_safe(hostname)).as_str()),
                None,
            ),
            (
                format!("NODE_{}_IP", &env_var_safe(original_hostname)).as_str(),
                Some(format!("NODE_{}_IP", &env_var_safe(hostname)).as_str()),
                None,
            ),
        ] {
            adjust_env(envs, key, new_name, new_value).context(format!("adjusting env var {}", key))?;
        }
    }

    Ok(())
}

fn adjust_env(envs: &mut [Value], env_name: &str, new_name: Option<&str>, new_value: Option<&str>) -> Result<()> {
    let found_env = envs
        .iter_mut()
        .find_map(|env| (env.as_object()?.get("name") == Some(&Value::String(env_name.to_string()))).then_some(env));

    match found_env {
        None => Ok(()),
        Some(env) => {
            match new_name {
                None => {}
                Some(new_name) => {
                    env.as_object_mut()
                        .context("env var not an object")?
                        .insert("name".to_string(), serde_json::Value::String(new_name.to_string()));
                }
            };

            match new_value {
                None => {}
                Some(new_value) => {
                    env.as_object_mut()
                        .context("env var not an object")?
                        .insert("value".to_string(), serde_json::Value::String(new_value.to_string()));
                }
            };

            Ok(())
        }
    }
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

pub(crate) fn fix_kapi_startup_monitor_pod_container_args(pod: &mut Value, hostname: &str) -> Result<()> {
    let containers = &mut pod
        .pointer_mut("/spec/containers")
        .context("containers not found")?
        .as_array_mut()
        .context("containers not an object")?;

    if containers.is_empty() {
        bail!("expected at least one container in pod.yaml");
    }

    containers
        .iter_mut()
        .filter(|container| container["name"] == "startup-monitor")
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
                .find_map(|(i, arg)| arg.as_str()?.starts_with("--node-name=").then_some(i))
                .context("--node-name not found")?;

            args[arg_idx] = serde_json::Value::String(format!("--node-name={}", hostname));

            Ok(())
        })?;

    Ok(())
}

pub(crate) fn fix_kapi_startup_monitor_pod_yaml(pod_yaml: &str, original_hostname: &str, hostname: &str) -> Result<String> {
    let pod_yaml = pod_yaml.to_string();
    let pattern = format!(r"--node-name={}", original_hostname);
    let replacement = format!(r"--node-name={}", hostname);
    Ok(pod_yaml.replace(&pattern, &replacement))
}

pub(crate) fn override_machineconfig_source(machineconfig: &mut Value, new_source: &str, path: &str) -> Result<()> {
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
        .find_map(|file| (file.pointer("/path")? == path).then_some(file));

    if find_map.is_none() {
        // Not all machineconfigs have the file we're looking for and that's ok
        return Ok(());
    };

    let file_contents = find_map
        .context(format!("no {} file in machineconfig", &path))?
        .pointer_mut("/contents")
        .context("no .contents")?
        .as_object_mut()
        .context("annotations not an object")?;

    file_contents.insert(
        "source".to_string(),
        serde_json::Value::String(file_utils::dataurl_encode(new_source)),
    );

    Ok(())
}

pub(crate) async fn fix_etcd_machineconfigs(etcd_client: &Arc<InMemoryK8sEtcd>, content: &str, file_path: &str) -> Result<()> {
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

                override_machineconfig_source(&mut machineconfig, content, file_path).context("fixing machineconfig")?;

                put_etcd_yaml(etcd_client, &k8s_resource_location, machineconfig).await?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_filesystem_mcs_machine_config_content(new_content: &str, content_path: &str, mcc_file_path: &Path) -> Result<()> {
    if let Some(file_name) = mcc_file_path.file_name() {
        if let Some(file_name) = file_name.to_str() {
            if file_name == "mcs-machine-config-content.json" {
                let contents = file_utils::read_file_to_string(mcc_file_path)
                    .await
                    .context("reading machine config currentconfig")?;

                let mut config: Value = serde_json::from_str(&contents).context("parsing currentconfig")?;

                override_machineconfig_source(&mut config, new_content, content_path)?;

                file_utils::commit_file(mcc_file_path, serde_json::to_string(&config).context("serializing currentconfig")?)
                    .await
                    .context("writing currentconfig to disk")?;
            }
        }
    }

    Ok(())
}
