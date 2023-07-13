use anyhow::{bail, Context, Result};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde_json::Value;
use std::io::BufRead;

pub(crate) fn fix_apiserver_url_file(original_data: Vec<u8>, cluster_domain: &str) -> Result<String> {
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

    Ok(new)
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
pub(crate) fn generate_infra_id(cluster_name: String) -> Result<String> {
    const CLUSTER_INFRA_ID_RANDOM_LEN: usize = 5;
    const CLUSTER_INFRA_ID_MAX_LEN: usize = 27;
    const MAX_NORMALIZED_CLUSTER_NAME_LEN: usize = CLUSTER_INFRA_ID_MAX_LEN - (CLUSTER_INFRA_ID_RANDOM_LEN + 1);

    const NON_ALPHANUM: &str = &r"[^A-Za-z0-9-]";
    const REPEATED_DASH_SEQUENCES: &str = &r"-{2,}";

    let normalized_cluster_name = regex::Regex::new(REPEATED_DASH_SEQUENCES)?
        .replace_all(&regex::Regex::new(NON_ALPHANUM)?.replace_all(&cluster_name, "-").to_string(), "-")
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
            serde_json::Value::String(generated_infra_id.to_string()),
        )
        .context("missing service-account-jwks-uri")?;

    Ok(())
}

pub(crate) async fn fix_kubeconfig(cluster_domain: &str, kubeconfig: &mut Value) -> Result<()> {
    let clusters = &mut kubeconfig
        .pointer_mut("/clusters")
        .context("clusters not found")?
        .as_array_mut()
        .context("clusters not an object")?;

    if clusters.len() == 0 {
        bail!("expected at least one cluster in kubeconfig");
    }

    clusters
        .into_iter()
        .map(|cluster| {
            let cluster = cluster
                .pointer_mut("/cluster")
                .context("cluster not found")?
                .as_object_mut()
                .context("cluster not an object")?;

            let previous_server = cluster
                .get_mut("server")
                .context("server not found")?
                .as_str()
                .context("server not a string")?;

            if previous_server.starts_with("https://api.") {
                cluster.insert(
                    "server".to_string(),
                    serde_json::Value::String(format!("https://api.{}:6443", cluster_domain)),
                );
            } else if previous_server.starts_with("https://api-int.") {
                cluster.insert(
                    "server".to_string(),
                    serde_json::Value::String(format!("https://api-int.{}:6443", cluster_domain)),
                );
            } else if previous_server.starts_with("https://[api-int.") {
                cluster.insert(
                    "server".to_string(),
                    serde_json::Value::String(format!("https://[api-int.{}]:6443", cluster_domain)),
                );
            } else {
                // Could be something like `https://localhost:6443`, ignore
            }

            Ok(())
        })
        .collect::<Result<()>>()?;

    Ok(())
}

pub(crate) fn fix_kcm_pod(pod: &mut Value, generated_infra_id: &str) -> Result<()> {
    let containers = &mut pod
        .pointer_mut("/spec/containers")
        .context("clusters not found")?
        .as_array_mut()
        .context("clusters not an object")?;

    if containers.len() == 0 {
        bail!("expected at least one container in pod.yaml");
    }

    containers
        .into_iter()
        .filter(|container| container["name"] == "kube-controller-manager")
        .map(|container| {
            let args = container
                .pointer_mut("/args")
                .context("args not found")?
                .as_array_mut()
                .context("args not an array")?;

            if args.len() == 0 {
                bail!("expected at least one arg in kube-controller-manager");
            }

            let arg = args
                .into_iter()
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
        })
        .collect::<Result<()>>()?;

    Ok(())
}

pub(crate) fn fix_pod(pod: &mut Value, domain: &str, container_name: &str, env_name: &str) -> Result<()> {
    let containers = &mut pod
        .pointer_mut("/spec/containers")
        .context("clusters not found")?
        .as_array_mut()
        .context("clusters not an object")?;

    if containers.len() == 0 {
        bail!("expected at least one container in pod.yaml");
    }

    containers
        .into_iter()
        .filter(|container| container["name"] == container_name)
        .map(|container| {
            let env = container
                .pointer_mut("/env")
                .context("env not found")?
                .as_array_mut()
                .context("env not an array")?;

            if env.len() == 0 {
                bail!("expected at least one env in container");
            }

            env.into_iter()
                .find_map(|var| (var.get("name")? == env_name).then_some(var))
                .context("name not found")?
                .as_object_mut()
                .context("env var not an object")?
                .insert(
                    "value".to_string(),
                    serde_json::Value::String(domain.to_string()),
                )
                .context("no previous value")?;

            Ok(())
        })
        .collect::<Result<()>>()?;

    Ok(())
}
