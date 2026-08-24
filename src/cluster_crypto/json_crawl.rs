use super::locations::{FieldEncoding, JsonLocation, LocationValueType};
use crate::rules::{self, IGNORE_LIST_CONFIGMAP};
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use fn_error_context::context;
use serde_json::Value;

#[derive(Debug)]
pub(crate) struct JsonValue {
    pub(crate) location: JsonLocation,
    pub(crate) value: Value,
}

pub(crate) fn crawl_json(json_value: Value) -> Result<Vec<JsonValue>> {
    let kind = json_value.get("kind");
    let apiversion = json_value.get("apiVersion");
    match kind {
        Some(kind) => match kind.as_str().context("non-unicode kind")? {
            "Secret" => scan_secret(&json_value),
            "ConfigMap" => scan_configmap(&json_value),
            "ValidatingWebhookConfiguration" => scan_webhookconfiguration(&json_value),
            "MutatingWebhookConfiguration" => scan_webhookconfiguration(&json_value),
            "APIService" => scan_apiservice(&json_value),
            "MachineConfig" => scan_machineconfig(&json_value),
            "ControllerConfig" => scan_controllerconfig(&json_value),
            "Config" => match apiversion {
                Some(apiversion) => match apiversion.as_str().context("non-string apiVersion")? {
                    "v1" => scan_kubeconfig(&json_value),
                    _ => Ok(Vec::new()),
                },
                None => Ok(Vec::new()),
            },
            _ => Ok(Vec::new()),
        },
        // Not all kubeconfigs and machineconfigs have a kind field, so we try to process any JSON
        // without a kind as if it were a kubeconfig/machineconfig
        None => {
            let kubeconfig_scan_result = scan_kubeconfig(&json_value)?;
            if !kubeconfig_scan_result.is_empty() {
                Ok(kubeconfig_scan_result)
            } else {
                scan_machineconfig(&json_value)
            }
        }
    }
}

pub(crate) fn scan_configmap(value: &Value) -> Result<Vec<JsonValue>> {
    let mut ret = Vec::new();

    if let Some(Value::Object(data)) = value.as_object().context("configmap is not object")?.get("data") {
        for (key, value) in data.iter() {
            if IGNORE_LIST_CONFIGMAP.contains(key) {
                continue;
            }

            ret.push(JsonValue {
                location: JsonLocation {
                    json_pointer: format!("/data/{key}"),
                    value: LocationValueType::YetUnknown,
                    encoding: FieldEncoding::None,
                },
                value: value.clone(),
            });
        }
    }

    Ok(ret)
}

pub(crate) fn scan_secret(value: &Value) -> Result<Vec<JsonValue>> {
    let mut res = Vec::new();
    if let Some(Value::Object(data)) = value.as_object().context("not object")?.get("data") {
        for (key, value) in data.iter() {
            if rules::IGNORE_LIST_SECRET.contains(key) {
                continue;
            }

            res.push(JsonValue {
                location: JsonLocation::new("/data", key, FieldEncoding::ByteArray),
                value: value.clone(),
            })
        }
    }

    if let Some(Value::Object(metadata)) = value.as_object().context("not object")?.get("metadata") {
        if let Some(Value::Object(annotations)) = metadata.get("annotations") {
            for (key, value) in annotations.iter() {
                res.push(JsonValue {
                    location: JsonLocation::new("/metadata/annotations", key, FieldEncoding::None),
                    value: value.clone(),
                })
            }
        }
    }

    Ok(res)
}

pub(crate) fn scan_webhookconfiguration(value: &Value) -> Result<Vec<JsonValue>> {
    let mut res = vec![];

    let Value::Array(webhooks) = value
        .as_object()
        .context("non-object WebhookConfiguration")?
        .get("webhooks")
        .context("no webhooks")?
    else {
        bail!("webhooks is not an array")
    };

    ensure!(!webhooks.is_empty(), "empty webhooks");

    for (webhook_index, webhook_value) in webhooks.iter().enumerate() {
        let Value::Object(client_config) = webhook_value.get("clientConfig").context("no clientConfig")? else {
            bail!("clientConfig is not an object")
        };

        let ca_bundle = client_config.get("caBundle").context("no caBundle")?;

        res.push(JsonValue {
            location: JsonLocation {
                json_pointer: format!("/webhooks/{webhook_index}/clientConfig/caBundle"),
                value: LocationValueType::YetUnknown,
                encoding: FieldEncoding::ByteArray,
            },
            value: ca_bundle.clone(),
        });
    }

    Ok(res)
}

pub(crate) fn scan_apiservice(value: &Value) -> Result<Vec<JsonValue>> {
    let mut res = Vec::new();
    if let Some(Value::Object(spec)) = value.as_object().context("non-object apiservice")?.get("spec") {
        if let Some(ca_bundle) = spec.get("caBundle") {
            res.push(JsonValue {
                location: JsonLocation {
                    json_pointer: "/spec/caBundle".to_string(),
                    value: LocationValueType::YetUnknown,
                    encoding: FieldEncoding::Base64,
                },
                value: ca_bundle.clone(),
            });
        }
    }

    Ok(res)
}

pub(crate) fn scan_machineconfig(value: &Value) -> Result<Vec<JsonValue>> {
    let mut res = Vec::new();
    if let Some(Value::Object(spec)) = value.as_object().context("non-object machineconfig")?.get("spec") {
        if let Some(Value::Object(config)) = spec.get("config") {
            if let Some(Value::Object(storage)) = config.get("storage") {
                if let Some(Value::Array(files)) = storage.get("files") {
                    for (file_index, file) in files.iter().enumerate() {
                        if let Value::Object(file) = file {
                            if let Some(Value::String(path)) = file.get("path") {
                                if path.ends_with(".pem") || path.ends_with(".crt") {
                                    if let Some(Value::Object(contents)) = file.get("contents") {
                                        if let Some(source) = contents.get("source") {
                                            res.push(JsonValue {
                                                location: JsonLocation {
                                                    json_pointer: format!("/spec/config/storage/files/{file_index}/contents/source"),
                                                    value: LocationValueType::YetUnknown,
                                                    encoding: FieldEncoding::DataUrl,
                                                },
                                                value: source.clone(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(res)
}

pub(crate) fn scan_controllerconfig(value: &Value) -> Result<Vec<JsonValue>> {
    let mut res = Vec::new();
    if let Some(Value::Object(spec)) = value.as_object().context("non-object controllerconfig")?.get("spec") {
        if let Some(ca_bundle) = spec.get("kubeAPIServerServingCAData") {
            res.push(JsonValue {
                location: JsonLocation {
                    json_pointer: "/spec/kubeAPIServerServingCAData".to_string(),
                    value: LocationValueType::YetUnknown,
                    encoding: FieldEncoding::Base64,
                },
                value: ca_bundle.clone(),
            });
        }

        if let Some(ca_bundle) = spec.get("rootCAData") {
            res.push(JsonValue {
                location: JsonLocation {
                    json_pointer: "/spec/rootCAData".to_string(),
                    value: LocationValueType::YetUnknown,
                    encoding: FieldEncoding::Base64,
                },
                value: ca_bundle.clone(),
            });
        }
    }

    Ok(res)
}

pub(crate) fn scan_kubeconfig(value: &Value) -> Result<Vec<JsonValue>> {
    let mut res = Vec::new();

    if let Some(Value::Array(users)) = value.get("users") {
        for (i, user) in users.iter().enumerate() {
            for user_field in ["client-certificate-data", "client-key-data"].iter() {
                if let Some(field_value) = user.as_object().context("non-object user")?["user"]
                    .as_object()
                    .context("non-object user")?
                    .get(user_field.to_string().as_str())
                {
                    res.push(JsonValue {
                        location: JsonLocation::new(&format!("/users/{}/user", i), user_field, FieldEncoding::Base64),
                        value: field_value.clone(),
                    });
                }
            }
        }
    }

    if let Some(Value::Array(clusters)) = value.get("clusters") {
        for (i, cluster) in clusters.iter().enumerate() {
            if let Some(cluster_cert) = cluster.as_object().context("non-object cluster")?["cluster"]
                .as_object()
                .context("non-object cluster")?
                .get("certificate-authority-data")
            {
                res.push(JsonValue {
                    location: JsonLocation::new(
                        &format!("/clusters/{}/cluster", i),
                        "certificate-authority-data",
                        FieldEncoding::Base64,
                    ),
                    value: cluster_cert.clone(),
                });
            }
        }
    }

    Ok(res)
}

#[context("decoding value at {:?}", json_value.location)]
pub(crate) fn decode_json_value(json_value: &JsonValue) -> Result<Option<(JsonLocation, String)>> {
    let decoded = match json_value.location.encoding {
        FieldEncoding::None => Some(json_value.value.as_str().context("non unicode JSON value")?.to_string()),
        FieldEncoding::Base64 => process_base64_value(&json_value.value).context("decoding base64 value")?,
        FieldEncoding::DataUrl => process_data_url_value(&json_value.value).context("decoding dataurl value")?,
        FieldEncoding::ByteArray => process_byte_array_value(&json_value.value).context("decoding byte array value")?,
    };

    Ok(decoded.map(|decoded| (json_value.location.clone(), decoded)))
}

fn process_byte_array_value(value: &Value) -> Result<Option<String>> {
    Ok(match value {
        Value::Array(array_value) => {
            let mut bytes = Vec::new();
            for byte in array_value {
                if let Value::Number(number) = byte {
                    bytes.push(u8::try_from(number.as_u64().context("non-integer in array")?).context("converting to u8")?);
                } else {
                    bail!("non-number in array");
                }
            }
            Some(String::from_utf8(bytes).context("non-utf8 decoded byte array value")?)
        }
        _ => None,
    })
}

/// Given a data-url-encoded value taken from a JSON field, decode it and scan it for
/// cryptographic keys and certificates and record them in the appropriate data structures.
fn process_data_url_value(value: &Value) -> Result<Option<String>> {
    Ok(if let Value::String(string_value) = value {
        let url = data_url::DataUrl::process(string_value).ok().context("dataurl failed processing")?;

        let (decoded, _fragment) = url.decode_to_vec().ok().context("non-unicode dataurl")?;

        #[allow(clippy::manual_ok_err)]
        if let Ok(decoded) = String::from_utf8(decoded) {
            Some(decoded)
        } else {
            // We don't search for crypto objects inside binaries
            None
        }
    } else {
        None
    })
}

/// Given a base64-encoded value taken from a JSON field, decode it and scan it for
/// cryptographic keys and certificates and record them in the appropriate data structures.
fn process_base64_value(value: &Value) -> Result<Option<String>> {
    Ok(match value {
        Value::String(string_value) => {
            Some(String::from_utf8(base64_standard.decode(string_value.as_bytes())?).context("non-utf8 decoded base64 value")?)
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_scan_secret_skips_ignore_list() {
        let secret = json!({
            "kind": "Secret",
            "data": {
                "tls.crt": [116, 108, 115],
                "prometheus.yaml.gz": [1, 2, 3]
            }
        });

        let found = crawl_json(secret).unwrap();
        let pointers: Vec<_> = found.iter().map(|v| v.location.json_pointer.as_str()).collect();
        assert!(pointers.contains(&"/data/tls.crt"));
        assert!(rules::IGNORE_LIST_SECRET.contains("prometheus.yaml.gz"));
        assert!(!pointers.contains(&"/data/prometheus.yaml.gz"));
        assert!(found
            .iter()
            .any(|v| v.location.json_pointer == "/data/tls.crt" && matches!(v.location.encoding, FieldEncoding::ByteArray)));
    }

    #[test]
    fn test_scan_configmap_skips_verifier_key() {
        let configmap = json!({
            "kind": "ConfigMap",
            "data": {
                "foo": "bar",
                "verifier-public-key-redhat": "skip-me"
            }
        });

        let found = crawl_json(configmap).unwrap();
        assert!(IGNORE_LIST_CONFIGMAP.contains("verifier-public-key-redhat"));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].location.json_pointer, "/data/foo");
        assert!(matches!(found[0].location.encoding, FieldEncoding::None));
    }

    #[test]
    fn test_scan_kubeconfig_without_kind() {
        let kubeconfig = json!({
            "users": [{
                "name": "admin",
                "user": {
                    "client-certificate-data": "Y2VydA==",
                    "client-key-data": "a2V5"
                }
            }],
            "clusters": [{
                "name": "cluster",
                "cluster": {
                    "certificate-authority-data": "Y2E="
                }
            }]
        });

        let found = crawl_json(kubeconfig).unwrap();
        let pointers: Vec<_> = found.iter().map(|v| v.location.json_pointer.as_str()).collect();
        assert!(pointers.contains(&"/users/0/user/client-certificate-data"));
        assert!(pointers.contains(&"/users/0/user/client-key-data"));
        assert!(pointers.contains(&"/clusters/0/cluster/certificate-authority-data"));
        assert!(found.iter().all(|v| matches!(v.location.encoding, FieldEncoding::Base64)));
    }

    #[test]
    fn test_unknown_kind_returns_empty() {
        let found = crawl_json(json!({"kind": "Deployment", "spec": {}})).unwrap();
        assert!(found.is_empty());
    }

    #[test]
    fn test_process_byte_array_value() {
        let decoded = process_byte_array_value(&json!([116, 108, 115])).unwrap();
        assert_eq!(decoded.as_deref(), Some("tls"));
        assert!(process_byte_array_value(&json!("not-an-array")).unwrap().is_none());
        assert!(process_byte_array_value(&json!([116, "nope"])).is_err());
    }

    #[test]
    fn test_process_base64_value() {
        let decoded = process_base64_value(&json!("dGxz")).unwrap();
        assert_eq!(decoded.as_deref(), Some("tls"));
        assert!(process_base64_value(&json!(123)).unwrap().is_none());
    }

    #[test]
    fn test_scan_machineconfig_pem_files() {
        let mc = json!({
            "kind": "MachineConfig",
            "spec": {
                "config": {
                    "storage": {
                        "files": [
                            {
                                "path": "/etc/kubernetes/ca.crt",
                                "contents": {"source": "data:,cert"}
                            },
                            {
                                "path": "/etc/hostname",
                                "contents": {"source": "data:,ignored"}
                            }
                        ]
                    }
                }
            }
        });

        let found = crawl_json(mc).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].location.json_pointer, "/spec/config/storage/files/0/contents/source");
        assert!(matches!(found[0].location.encoding, FieldEncoding::DataUrl));
    }
}
