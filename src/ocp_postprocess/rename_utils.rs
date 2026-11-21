use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    k8s_etcd::{get_etcd_json, put_etcd_yaml, InMemoryK8sEtcd},
};
use anyhow::{ensure, Context, Result};
use futures_util::future::join_all;
use itertools::Itertools;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde_json::{Map, Value};
use std::io::BufRead;
use std::path::Path;
use std::sync::Arc;

use crate::file_utils;

/// Returns a string value from a ConfigMap/object data map without panicking on
/// a missing key. Indexing a `serde_json::Map` directly panics (`no entry found
/// for key`), which can be reached with real cluster data that lacks the key.
pub(crate) fn data_str<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    map.get(key)
        .with_context(|| format!("{key} not found"))?
        .as_str()
        .with_context(|| format!("{key} not a string"))
}

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

    ensure!(
        found,
        "could not find line starting with KUBERNETES_SERVICE_HOST='api-int. in apiserver-url.env"
    );

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

    let new_etcd_servers = original_etcd_servers
        .iter()
        .map(|etcd_server| {
            Ok(Value::String(fix_ip(
                etcd_server.as_str().context("etcd server not a string")?,
                original_ip,
                ip,
            )?))
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

    ensure!(!clusters.is_empty(), "expected at least one cluster in kubeconfig");

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

/// Returns the single container named `name`. Errors when the list is empty, when no container
/// carries that name, or when more than one does — indexing a `Value` for `name` would otherwise
/// yield `Null` and skip the container silently.
pub(crate) fn unique_container_mut<'a>(containers: &'a mut [Value], name: &str) -> Result<&'a mut Value> {
    ensure!(!containers.is_empty(), "expected at least one container");

    let expected = format!("expected exactly one container named {}", name);
    let mut matches = containers.iter_mut().filter(|container| container["name"] == name);
    let container = matches.next().context(expected.clone())?;

    ensure!(matches.next().is_none(), expected);

    Ok(container)
}

pub(crate) fn fix_kcm_pod(pod: &mut Value, generated_infra_id: &str) -> Result<()> {
    let containers = &mut pod
        .pointer_mut("/spec/containers")
        .context("clusters not found")?
        .as_array_mut()
        .context("clusters not an object")?;

    let container = unique_container_mut(containers, "kube-controller-manager")?;

    let args = container
        .pointer_mut("/args")
        .context("args not found")?
        .as_array_mut()
        .context("args not an array")?;

    ensure!(!args.is_empty(), "expected at least one arg in kube-controller-manager");

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

fn is_ip_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '_'
}

pub(crate) fn fix_ip(pod_yaml: &str, original_ip: &str, ip: &str) -> Result<String> {
    let original_ip = if original_ip.contains(':') {
        format!("[{original_ip}]")
    } else {
        original_ip.to_string()
    };

    let ip = if ip.contains(':') { format!("[{ip}]") } else { ip.to_string() };

    // Replace only whole address tokens: a bare substring replace would also hit the address when
    // it is a prefix of a longer one (10.0.0.1 inside 10.0.0.10), a CIDR, or an unrelated value.
    let mut out = String::with_capacity(pod_yaml.len());
    let mut last = 0;

    for (start, _) in pod_yaml.match_indices(original_ip.as_str()) {
        let end = start + original_ip.len();

        let starts_token = pod_yaml[..start].chars().next_back().map_or(true, |c| !is_ip_token_char(c));
        let ends_token = pod_yaml[end..].chars().next().map_or(true, |c| !is_ip_token_char(c));

        if starts_token && ends_token {
            out.push_str(&pod_yaml[last..start]);
            out.push_str(&ip);
            last = end;
        }
    }

    out.push_str(&pod_yaml[last..]);

    Ok(out)
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
    {
        let patterns = [
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
        ];

        ensure!(
            container
                .pointer("/command")
                .and_then(|c| c.as_array())
                .is_some_and(|a| !a.is_empty()),
            "expected at least one arg in etcd static pod container"
        );

        for field in ["/command", "/args"] {
            let Some(values) = container.pointer_mut(field).and_then(|v| v.as_array_mut()) else {
                continue;
            };

            for arg in values.iter_mut() {
                let Some(arg_str) = arg.as_str() else { continue };
                let mut replaced = arg_str.to_string();

                for (pattern, replacement) in &patterns {
                    let pattern = pattern
                        .replace("{original_hostname}", original_hostname)
                        .replace("{original_hostname_safe}", &env_var_safe(original_hostname));

                    let replacement = replacement
                        .replace("{hostname}", hostname)
                        .replace("{hostname_safe}", &env_var_safe(hostname));

                    replaced = replaced.replace(&pattern, &replacement);
                }

                *arg = serde_json::Value::String(replaced);
            }
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

    let container = unique_container_mut(containers, container_name)?;

    let env = container
        .pointer_mut("/env")
        .context("env not found")?
        .as_array_mut()
        .context("env not an array")?;

    ensure!(!env.is_empty(), "expected at least one env in container");

    env.iter_mut()
        .find_map(|var| (var.get("name")? == env_name).then_some(var))
        .context(format!("env var {} not found", env_name))?
        .as_object_mut()
        .context("env var not an object")?
        .insert("value".to_string(), serde_json::Value::String(domain.to_string()))
        .context("no previous value")?;

    Ok(())
}

pub(crate) fn fix_mcd_pod_container_args(pod: &mut Value, cluster_domain: &str, container_name: &str) -> Result<()> {
    let containers = &mut pod
        .pointer_mut("/spec/containers")
        .context("clusters not found")?
        .as_array_mut()
        .context("clusters not an object")?;

    let container = unique_container_mut(containers, container_name)?;

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

    let original_data = data_str(file_contents, "source")?;

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

    let container = unique_container_mut(containers, "startup-monitor")?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fix_apiserver_url_file_empty() {
        assert_eq!(fix_apiserver_url_file(vec![], "new.example.com").unwrap(), "");
    }

    #[test]
    fn test_fix_apiserver_url_file_rewrites_host() {
        let original = b"FOO=bar\nKUBERNETES_SERVICE_HOST='api-int.old.example.com'\nBAZ=qux\n";
        let updated = fix_apiserver_url_file(original.to_vec(), "new.example.com").unwrap();
        assert!(updated.contains("KUBERNETES_SERVICE_HOST='api-int.new.example.com'"));
        assert!(updated.contains("FOO=bar"));
        assert!(updated.ends_with('\n'));
    }

    #[test]
    fn test_fix_apiserver_url_file_missing_line_errors() {
        let err = fix_apiserver_url_file(b"FOO=bar\n".to_vec(), "new.example.com").unwrap_err();
        assert!(err
            .to_string()
            .contains("could not find line starting with KUBERNETES_SERVICE_HOST"));
    }

    #[test]
    fn test_fix_oauth_metadata() {
        let mut metadata = serde_json::json!({
            "issuer": "https://oauth-openshift.apps.old.example.com",
            "authorization_endpoint": "https://oauth-openshift.apps.old.example.com/oauth/authorize",
            "token_endpoint": "https://oauth-openshift.apps.old.example.com/oauth/token"
        });
        fix_oauth_metadata(&mut metadata, "new.example.com").unwrap();
        assert_eq!(metadata["issuer"], "https://oauth-openshift.apps.new.example.com");
        assert_eq!(
            metadata["authorization_endpoint"],
            "https://oauth-openshift.apps.new.example.com/oauth/authorize"
        );
        assert_eq!(
            metadata["token_endpoint"],
            "https://oauth-openshift.apps.new.example.com/oauth/token"
        );
    }

    #[test]
    fn test_data_str_returns_value() {
        let mut map = Map::new();
        map.insert("config.yaml".to_string(), Value::String("foo: bar".to_string()));
        assert_eq!(data_str(&map, "config.yaml").unwrap(), "foo: bar");
    }

    #[test]
    fn test_data_str_missing_key_errors_without_panicking() {
        let mut map = Map::new();
        map.insert("other".to_string(), Value::String("value".to_string()));
        let err = data_str(&map, "config.yaml").unwrap_err();
        assert!(err.to_string().contains("config.yaml not found"), "unexpected error: {err}");
    }

    #[test]
    fn test_data_str_non_string_errors() {
        let mut map = Map::new();
        map.insert("config.yaml".to_string(), Value::from(42));
        let err = data_str(&map, "config.yaml").unwrap_err();
        assert!(err.to_string().contains("config.yaml not a string"), "unexpected error: {err}");
    }

    #[test]
    fn test_fix_api_server_arguments_ip_replaces_target_only() {
        let mut config = serde_json::json!({
            "apiServerArguments": {
                "etcd-servers": [
                    "https://192.168.126.10:2379",
                    "https://192.168.126.100:2379",
                    "https://localhost:2379"
                ]
            }
        });

        fix_api_server_arguments_ip(&mut config, "192.168.126.10", "192.168.127.20").unwrap();

        assert_eq!(
            config.pointer("/apiServerArguments/etcd-servers"),
            Some(&serde_json::json!([
                "https://192.168.127.20:2379",
                "https://192.168.126.100:2379",
                "https://localhost:2379"
            ]))
        );
    }

    #[test]
    fn test_fix_api_server_arguments_ip_missing_etcd_servers_errors() {
        let mut config = serde_json::json!({"apiServerArguments": {}});
        let err = fix_api_server_arguments_ip(&mut config, "192.168.126.10", "192.168.127.20").unwrap_err();
        assert!(err.to_string().contains("etcd-servers not found"), "unexpected error: {err}");
    }

    #[test]
    fn test_fix_ip_replaces_whole_tokens_only() {
        let text = "peer=https://192.0.2.10:2379\ncidr=192.0.2.10/24\nlonger=192.0.2.100\nother=10.0.0.10\n";

        let replaced = fix_ip(text, "192.0.2.10", "192.0.2.20").unwrap();

        assert!(replaced.contains("peer=https://192.0.2.20:2379"));
        assert!(replaced.contains("cidr=192.0.2.20/24"));
        assert!(replaced.contains("longer=192.0.2.100"), "must not match inside a longer address");
        assert!(replaced.contains("other=10.0.0.10"));
    }

    #[test]
    fn test_fix_ip_ipv6_is_bracketed() {
        let text = "endpoints: [https://[fc00::1]:2379]\n";

        assert_eq!(fix_ip(text, "fc00::1", "fc00::2").unwrap(), "endpoints: [https://[fc00::2]:2379]\n");
    }

    #[test]
    fn test_fix_ip_without_match_is_unchanged() {
        let text = "no addresses here\n";

        assert_eq!(fix_ip(text, "192.0.2.10", "192.0.2.20").unwrap(), text);
    }

    fn container(name: Value) -> Value {
        serde_json::json!({ "name": name })
    }

    #[test]
    fn test_unique_container_mut_returns_the_matching_container() {
        let mut containers = vec![container(Value::String("a".to_string())), container(Value::String("b".to_string()))];

        let found = unique_container_mut(&mut containers, "b").unwrap();

        assert_eq!(found["name"], "b");
    }

    #[test]
    fn test_unique_container_mut_without_a_match_errors() {
        let mut containers = vec![container(Value::String("a".to_string()))];

        let err = unique_container_mut(&mut containers, "missing").unwrap_err();

        assert!(
            err.to_string().contains("expected exactly one container named missing"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_unique_container_mut_with_non_string_name_errors() {
        let mut containers = vec![container(serde_json::json!(1))];

        assert!(unique_container_mut(&mut containers, "1").is_err());
    }

    #[test]
    fn test_unique_container_mut_with_duplicates_errors() {
        let mut containers = vec![container(Value::String("a".to_string())), container(Value::String("a".to_string()))];

        let err = unique_container_mut(&mut containers, "a").unwrap_err();

        assert!(
            err.to_string().contains("expected exactly one container named a"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_unique_container_mut_with_no_containers_errors() {
        let mut containers: Vec<Value> = vec![];

        let err = unique_container_mut(&mut containers, "a").unwrap_err();

        assert!(err.to_string().contains("at least one container"), "unexpected error: {err}");
    }

    #[test]
    fn test_unique_container_mut_with_non_object_entry_errors() {
        let mut containers = vec![serde_json::json!("not a container")];

        assert!(unique_container_mut(&mut containers, "a").is_err());
    }

    #[test]
    fn test_fix_kcm_pod_replaces_cluster_name() {
        let mut pod = serde_json::json!({
            "spec": {"containers": [{"name": "kube-controller-manager", "args": ["--cluster-name=old"]}]}
        });

        fix_kcm_pod(&mut pod, "new-id").unwrap();

        assert_eq!(pod["spec"]["containers"][0]["args"][0], "--cluster-name=new-id");
    }

    #[test]
    fn test_fix_kcm_pod_without_the_named_container_errors() {
        let mut pod = serde_json::json!({"spec": {"containers": [{"name": "other"}]}});

        let err = fix_kcm_pod(&mut pod, "new-id").unwrap_err();

        assert!(
            err.to_string()
                .contains("expected exactly one container named kube-controller-manager"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_fix_pod_container_env_without_the_named_container_errors() {
        let mut pod = serde_json::json!({"spec": {"containers": [{"name": "other"}]}});

        let err = fix_pod_container_env(&mut pod, "new.example.com", "router", "ROUTER_DOMAIN", false).unwrap_err();

        assert!(
            err.to_string().contains("expected exactly one container named router"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_fix_mcd_pod_container_args_without_the_named_container_errors() {
        let mut pod = serde_json::json!({"spec": {"containers": [{"name": "other"}]}});

        let err = fix_mcd_pod_container_args(&mut pod, "new.example.com", "machine-config-server").unwrap_err();

        assert!(
            err.to_string()
                .contains("expected exactly one container named machine-config-server"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_fix_kapi_startup_monitor_pod_container_args_without_the_named_container_errors() {
        let mut pod = serde_json::json!({"spec": {"containers": [{"name": "other"}]}});

        let err = fix_kapi_startup_monitor_pod_container_args(&mut pod, "new-hostname").unwrap_err();

        assert!(
            err.to_string().contains("expected exactly one container named startup-monitor"),
            "unexpected error: {err}"
        );
    }
}
