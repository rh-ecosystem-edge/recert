use std::ops::Not;

use super::args::Proxy;
use crate::file_utils;
use anyhow::{Context, Result};
use serde_json::Value;

pub(crate) fn rename_proxy_env_file_contents(proxy: &Proxy, contents: String) -> String {
    let mut new_config_lines = vec![];

    let http_proxy = &format!("HTTP_PROXY={}", proxy.status_proxy.http_proxy);
    let https_proxy = &format!("HTTPS_PROXY={}", proxy.status_proxy.https_proxy);
    let no_proxy = &format!("NO_PROXY={}", proxy.status_proxy.no_proxy);

    if !proxy.status_proxy.http_proxy.is_empty() {
        new_config_lines.push(http_proxy.as_str());
    }
    if !proxy.status_proxy.https_proxy.is_empty() {
        new_config_lines.push(https_proxy.as_str());
    }
    if !proxy.status_proxy.no_proxy.is_empty() {
        new_config_lines.push(no_proxy.as_str());
    }

    format!(
        "{}\n",
        contents
            .lines()
            .filter(|line| !line.starts_with("HTTP_PROXY=") && !line.starts_with("HTTPS_PROXY=") && !line.starts_with("NO_PROXY="))
            .chain(new_config_lines)
            .collect::<Vec<_>>()
            .join("\n")
    )
}

pub(crate) fn fix_machineconfig(machineconfig: &mut Value, proxy: &Proxy) -> Result<()> {
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
        .find_map(|file| (file.pointer("/path")? == "/etc/mco/proxy.env").then_some(file));

    if find_map.is_none() {
        // Not all machineconfigs have the file we're looking for and that's ok
        return Ok(());
    };

    let file_contents = find_map
        .context("no /etc/mco/proxy.env file in machineconfig")?
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

    let new = rename_proxy_env_file_contents(proxy, String::from_utf8(decoded).context("utf8 decoding")?);

    file_contents.insert("source".to_string(), serde_json::Value::String(file_utils::dataurl_encode(&new)));

    Ok(())
}

fn get_http_proxy_var_name(is_upper: bool) -> &'static str {
    if is_upper {
        "HTTP_PROXY"
    } else {
        "http_proxy"
    }
}

fn get_https_proxy_var_name(is_upper: bool) -> &'static str {
    if is_upper {
        "HTTPS_PROXY"
    } else {
        "https_proxy"
    }
}

fn get_no_proxy_var_name(is_upper: bool) -> &'static str {
    if is_upper {
        "NO_PROXY"
    } else {
        "no_proxy"
    }
}

pub(crate) fn fix_containers(config: &mut Value, proxy: &Proxy, prefix: &str) -> Result<()> {
    let suffixes = &["containers", "initContainers"];
    let casing_options = [true, false];

    for (is_uppercase, suffix) in casing_options.into_iter().flat_map(|x| suffixes.iter().map(move |y| (x, y))) {
        let pointer_mut = config.pointer_mut(format!("{prefix}/{suffix}").as_str());

        let containers = match pointer_mut {
            Some(containers) => containers,
            None => continue,
        };

        for container in containers.as_array_mut().context("containers not an array")? {
            let env = container.pointer_mut("/env");

            let env = match env {
                Some(env) => env,
                // Not all containers have an env section
                None => continue,
            };

            let container_env = env.as_array_mut().context("env not an array")?;

            let desired_proxies = [
                proxy
                    .status_proxy
                    .http_proxy
                    .is_empty()
                    .not()
                    .then_some((get_http_proxy_var_name(is_uppercase), proxy.status_proxy.http_proxy.as_str())),
                proxy
                    .status_proxy
                    .https_proxy
                    .is_empty()
                    .not()
                    .then_some((get_https_proxy_var_name(is_uppercase), proxy.status_proxy.https_proxy.as_str())),
                proxy
                    .status_proxy
                    .no_proxy
                    .is_empty()
                    .not()
                    .then_some((get_no_proxy_var_name(is_uppercase), proxy.status_proxy.no_proxy.as_str())),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

            let removal_result = remove_existing_proxy_env_vars(container_env, is_uppercase)?;

            match removal_result {
                Some((insertion_index, original_order)) => {
                    container_env.splice(
                        insertion_index..insertion_index,
                        {
                            let mut desired_proxies = desired_proxies.to_vec();
                            desired_proxies.sort_by_key(|(k, _)| original_order.iter().position(|x| x == k));
                            desired_proxies
                        }
                        .iter()
                        .map(|(k, v)| serde_json::json!({"name": k, "value": v}))
                        .collect::<Vec<_>>(),
                    );
                }
                None => continue,
            }
        }
    }

    Ok(())
}

/// Remove all existing proxy env vars from the container's env and return the index of where the
/// first proxy env var should be inserted. Also returns the order in which the proxy env vars
/// appeared in the original env.
fn remove_existing_proxy_env_vars(container_env: &mut Vec<Value>, is_upper: bool) -> Result<Option<(usize, Vec<String>)>> {
    let original_proxy_envs = container_env
        .iter()
        .enumerate()
        .filter_map(|(i, env)| {
            let name = env
                .pointer("/name")
                .context("no /name")
                .ok()?
                .as_str()
                .context("name not a string")
                .ok()?
                .to_owned();

            if [
                get_http_proxy_var_name(is_upper),
                get_https_proxy_var_name(is_upper),
                get_no_proxy_var_name(is_upper),
            ]
            .contains(&name.as_str())
            {
                Some((i, name))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let indices_to_remove = original_proxy_envs.iter().map(|(i, _)| *i).collect::<Vec<_>>();
    let name_order = original_proxy_envs.into_iter().map(|(_, name)| name).collect::<Vec<_>>();

    // Run backwards so we don't have to adjust the indices as we remove elements
    for i in indices_to_remove.iter().rev() {
        container_env.remove(*i);
    }

    if indices_to_remove.is_empty() {
        Ok(None)
    } else {
        Ok(Some((indices_to_remove[0], name_order)))
    }
}

#[cfg(test)]
mod tests {
    use crate::ocp_postprocess::proxy_rename::args::ProxyConfig;

    use super::*;
    use serde_json::json;

    #[test]
    fn test_fix_containers() {
        let data = r#"{"apiVersion":"apps/v1","kind":"Deployment","spec":{"template":{"spec":{"containers":[{"env":[{"name":"DEFAULT_DESTINATION_CA_PATH","value":"/var/run/configmaps/service-ca/service-ca.crt"},{"name":"HTTPS_PROXY","value":"http://squid.corp.redhats.com:3128"},{"name":"HTTP_PROXY","value":"http://squid.corp.redhat.com:3128"},{"name":"NO_PROXY","value":".cluster.local,.seed.ibo0.redhat.com,.svc,10.128.0.0/14,127.0.0.1,172.30.0.0/16,192.168.126.0/24,api-int.seed.ibo0.redhat.com,api-int.seed.redhat.com,localhost"},{"name":"RELOAD_INTERVAL","value":"5s"},{"name":"STATS_USERNAME_FILE","value":"/var/lib/haproxy/conf/metrics-auth/statsUsername"},{"name":"http_proxy","value":"http://squid.corp.redhat.com:3128"},{"name":"https_proxy","value":"http://squid.corp.redhats.com:3128"},{"name":"no_proxy","value":".cluster.local,.seed.ibo0.redhat.com,.svc,10.128.0.0/14,127.0.0.1,172.30.0.0/16,192.168.126.0/24,api-int.seed.ibo0.redhat.com,api-int.seed.redhat.com,localhost"}],"name":"router"}]}}}}"#;

        let mut config: Value = serde_json::from_str(data).unwrap();

        let proxy = Proxy {
            spec_proxy: ProxyConfig {
                http_proxy: "http://proxy.example.com".to_string(),
                https_proxy: "http://proxy.examples.com".to_string(),
                no_proxy: "localhost".to_string(),
            },
            status_proxy: ProxyConfig {
                http_proxy: "http://proxy.example.com".to_string(),
                https_proxy: "http://proxy.examples.com".to_string(),
                no_proxy: "localhost".to_string(),
            },
        };

        fix_containers(&mut config, &proxy, "/spec/template/spec").unwrap();

        assert!(!serde_json::to_string(&config).unwrap().contains("squid.corp.redhat.com"));

        let env = config.pointer("/spec/template/spec/containers/0/env").unwrap().as_array().unwrap();

        for (expected_name, expected_value) in [
            ("HTTP_PROXY", "http://proxy.example.com"),
            ("HTTPS_PROXY", "http://proxy.examples.com"),
            ("NO_PROXY", "localhost"),
            ("http_proxy", "http://proxy.example.com"),
            ("https_proxy", "http://proxy.examples.com"),
            ("no_proxy", "localhost"),
        ] {
            for env_var in dbg!(env).iter() {
                let name = env_var.pointer("/name").unwrap().as_str().unwrap();
                let value = env_var.pointer("/value").unwrap().as_str().unwrap();

                if name == expected_name {
                    assert_eq!(value, expected_value);
                }
            }
        }
    }

    #[test]
    fn test_remove_existing_proxy_env_vars() {
        let mut env = vec![
            json!({"name": "SOME", "value": "value"}),
            json!({"name": "HTTP_PROXY", "value": "http://proxy.example.com"}),
            json!({"name": "HTTPS_PROXY", "value": "http://proxy.examples.com"}),
            json!({"name": "NO_PROXY", "value": "localhost"}),
            json!({"name": "OTHER", "value": "value"}),
        ];

        let insertion_index = remove_existing_proxy_env_vars(&mut env, true).unwrap();

        assert_eq!(
            env,
            vec![
                json!({"name": "SOME", "value": "value"}),
                json!({"name": "OTHER", "value": "value"})
            ]
        );
        assert_eq!(
            insertion_index,
            Some((1, vec!["HTTP_PROXY".to_string(), "HTTPS_PROXY".to_string(), "NO_PROXY".to_string()]))
        );

        ////////////////////////////////////////////////////

        let mut env = vec![
            json!({"name": "HTTP_PROXY", "value": "http://proxy.example.com"}),
            json!({"name": "HTTPS_PROXY", "value": "http://proxy.examples.com"}),
            json!({"name": "NO_PROXY", "value": "localhost"}),
        ];

        let insertion_index = remove_existing_proxy_env_vars(&mut env, true).unwrap();

        assert!(env.is_empty());
        assert_eq!(
            insertion_index,
            Some((0, vec!["HTTP_PROXY".to_string(), "HTTPS_PROXY".to_string(), "NO_PROXY".to_string()]))
        );

        ////////////////////////////////////////////////////

        let mut env = vec![
            json!({"name": "SOME", "value": "value"}),
            json!({"name": "HTTPS_PROXY", "value": "http://proxy.example.com"}),
            json!({"name": "OTHER", "value": "value"}),
        ];

        let insertion_index = remove_existing_proxy_env_vars(&mut env, true).unwrap();

        assert_eq!(
            env,
            vec![
                json!({"name": "SOME", "value": "value"}),
                json!({"name": "OTHER", "value": "value"})
            ]
        );
        assert_eq!(insertion_index, Some((1, vec!["HTTPS_PROXY".to_string()])));

        ////////////////////////////////////////////////////

        let mut env = vec![
            json!({"name": "SOME", "value": "value"}),
            json!({"name": "https_proxy", "value": "http://proxy.example.com"}),
            json!({"name": "OTHER", "value": "value"}),
        ];

        let insertion_index = remove_existing_proxy_env_vars(&mut env, false).unwrap();

        assert_eq!(
            env,
            vec![
                json!({"name": "SOME", "value": "value"}),
                json!({"name": "OTHER", "value": "value"})
            ]
        );
        assert_eq!(insertion_index, Some((1, vec!["https_proxy".to_string()])));

        ////////////////////////////////////////////////////

        let mut env = vec![
            json!({"name": "SOME", "value": "value"}),
            json!({"name": "https_proxy", "value": "http://proxy.example.com"}),
            json!({"name": "OTHER", "value": "value"}),
        ];

        let insertion_index = remove_existing_proxy_env_vars(&mut env, true).unwrap();

        assert_eq!(
            env,
            vec![
                json!({"name": "SOME", "value": "value"}),
                json!({"name": "https_proxy", "value": "http://proxy.example.com"}),
                json!({"name": "OTHER", "value": "value"})
            ]
        );
        assert_eq!(insertion_index, None);
    }
}
