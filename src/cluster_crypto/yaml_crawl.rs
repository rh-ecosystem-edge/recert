use super::locations::{FieldEncoding, LocationValueType, YamlLocation};
use crate::rules::{self, IGNORE_LIST_CONFIGMAP};
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use serde_json::Value;

pub(crate) struct YamlValue {
    pub(crate) location: YamlLocation,
    pub(crate) value: Value,
}

pub(crate) fn crawl_yaml(yaml_value: Value) -> Vec<YamlValue> {
    let kind = yaml_value.get("kind");
    let apiversion = yaml_value.get("apiVersion");
    match kind {
        Some(kind) => match kind.as_str().unwrap() {
            "Secret" => scan_secret(&yaml_value),
            "ConfigMap" => scan_configmap(&yaml_value),
            "ValidatingWebhookConfiguration" => scan_validatingwebhookconfiguration(&yaml_value),
            "APIService" => scan_apiservice(&yaml_value),
            "MachineConfig" => scan_machineconfig(&yaml_value),
            "Config" => match apiversion {
                Some(apiversion) => match apiversion.as_str().unwrap() {
                    "v1" => scan_kubeconfig(&yaml_value),
                    _ => Vec::new(),
                },
                None => Vec::new(),
            },
            _ => Vec::new(),
        },
        // Not all kubeconfigs have a kind field, so we try to process any YAML without a kind as
        // if it were a kubeconfig
        None => scan_kubeconfig(&yaml_value),
    }
}

pub(crate) fn scan_configmap(value: &Value) -> Vec<YamlValue> {
    let mut ret = Vec::new();

    if let Some(data) = value.as_object().unwrap().get("data") {
        if let Value::Object(data) = data {
            for (key, value) in data.iter() {
                if IGNORE_LIST_CONFIGMAP.contains(key) {
                    continue;
                }

                ret.push(YamlValue {
                    location: YamlLocation {
                        json_pointer: format!("/data/{key}"),
                        value: LocationValueType::Unknown,
                        encoding: FieldEncoding::None,
                    },
                    value: value.clone(),
                });
            }
        }
    }

    ret
}

pub(crate) fn scan_secret(value: &Value) -> Vec<YamlValue> {
    let mut res = Vec::new();
    if let Some(data) = value.as_object().unwrap().get("data") {
        if let Value::Object(data) = data {
            for (key, value) in data.iter() {
                if rules::IGNORE_LIST_SECRET.contains(key) {
                    continue;
                }

                res.push(YamlValue {
                    location: YamlLocation::new("/data", key, FieldEncoding::Base64),
                    value: value.clone(),
                })
            }
        }
    }

    if let Some(metadata) = value.as_object().unwrap().get("metadata") {
        if let Value::Object(metadata) = metadata {
            if let Some(annotations) = metadata.get("annotations") {
                if let Value::Object(annotations) = annotations {
                    for (key, value) in annotations.iter() {
                        res.push(YamlValue {
                            location: YamlLocation::new("/metadata/annotations", key, FieldEncoding::None),
                            value: value.clone(),
                        })
                    }
                }
            }
        }
    }

    res
}

pub(crate) fn scan_validatingwebhookconfiguration(value: &Value) -> Vec<YamlValue> {
    let mut res = vec![];
    if let Some(Value::Array(webhooks)) = value.as_object().unwrap().get("webhooks") {
        for (webhook_index, webhook_value) in webhooks.iter().enumerate() {
            if let Some(Value::Object(client_config)) = webhook_value.get("clientConfig") {
                if let Some(ca_bundle) = client_config.get("caBundle") {
                    res.push(YamlValue {
                        location: YamlLocation {
                            json_pointer: format!("/webhooks/{webhook_index}/clientConfig/caBundle"),
                            value: LocationValueType::Unknown,
                            encoding: FieldEncoding::Base64,
                        },
                        value: ca_bundle.clone(),
                    });
                }
            }
        }
    }

    res
}

pub(crate) fn scan_apiservice(value: &Value) -> Vec<YamlValue> {
    let mut res = Vec::new();
    if let Some(spec_object) = value.as_object().unwrap().get("spec") {
        if let Value::Object(spec) = spec_object {
            if let Some(ca_bundle) = spec.get("caBundle") {
                res.push(YamlValue {
                    location: YamlLocation {
                        json_pointer: format!("/spec/caBundle"),
                        value: LocationValueType::Unknown,
                        encoding: FieldEncoding::Base64,
                    },
                    value: ca_bundle.clone(),
                });
            }
        }
    }

    res
}

pub(crate) fn scan_machineconfig(value: &Value) -> Vec<YamlValue> {
    let mut res = Vec::new();
    if let Some(Value::Object(spec)) = value.as_object().unwrap().get("spec") {
        if let Some(Value::Object(config)) = spec.get("config") {
            if let Some(Value::Object(storage)) = config.get("storage") {
                if let Some(Value::Array(files)) = storage.get("files") {
                    for (file_index, file) in files.iter().enumerate() {
                        if let Value::Object(file) = file {
                            if let Some(Value::String(path)) = file.get("path") {
                                if path.ends_with(".pem") || path.ends_with(".crt") {
                                    if let Some(Value::Object(contents)) = file.get("contents") {
                                        if let Some(source) = contents.get("source") {
                                            res.push(YamlValue {
                                                location: YamlLocation {
                                                    json_pointer: format!("/spec/config/storage/files/{file_index}/contents/source"),
                                                    value: LocationValueType::Unknown,
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
    res
}

pub(crate) fn scan_kubeconfig(value: &Value) -> Vec<YamlValue> {
    let mut res = Vec::new();

    if let Some(Value::Array(users)) = value.get("users") {
        for (i, user) in users.into_iter().enumerate() {
            for user_field in ["client-certificate-data", "client-key-data"].iter() {
                if let Some(field_value) = user.as_object().unwrap()["user"]
                    .as_object()
                    .unwrap()
                    .get(user_field.to_string().as_str())
                {
                    res.push(YamlValue {
                        location: YamlLocation::new(&format!("/users/{}/user", i), user_field, FieldEncoding::Base64),
                        value: field_value.clone(),
                    });
                }
            }
        }
    }

    if let Some(Value::Array(clusters)) = value.get("clusters") {
        for (i, cluster) in clusters.into_iter().enumerate() {
            if let Some(cluster_cert) = cluster.as_object().unwrap()["cluster"]
                .as_object()
                .unwrap()
                .get("certificate-authority-data")
            {
                res.push(YamlValue {
                    location: YamlLocation::new(
                        &format!("/clusters/{}/cluster", i),
                        "certificate-authority-data",
                        FieldEncoding::Base64,
                    ),
                    value: cluster_cert.clone(),
                });
            }
        }
    }

    res
}

pub(crate) fn decode_yaml_value(yaml_value: &YamlValue) -> Option<String> {
    match yaml_value.location.encoding {
        FieldEncoding::None => Some(yaml_value.value.as_str().unwrap().to_string()),
        FieldEncoding::Base64 => process_base64_value(&yaml_value.value),
        FieldEncoding::DataUrl => process_data_url_value(&yaml_value.value),
    }
}

/// Given a data-url-encoded value taken from a YAML field, decode it and scan it for
/// cryptographic keys and certificates and record them in the appropriate data structures.
fn process_data_url_value(value: &Value) -> Option<String> {
    if let Value::String(string_value) = value {
        if let Ok(url) = data_url::DataUrl::process(string_value) {
            let (decoded, _fragment) = url.decode_to_vec().unwrap();
            if let Ok(decoded) = String::from_utf8(decoded) {
                Some(decoded)
            } else {
                // We don't search for crypto objects inside binaries
                None
            }
        } else {
            panic!("Failed to decode data-url");
        }
    } else {
        None
    }
}

/// Given a base64-encoded value taken from a YAML field, decode it and scan it for
/// cryptographic keys and certificates and record them in the appropriate data structures.
fn process_base64_value(value: &Value) -> Option<String> {
    if let Value::String(string_value) = value {
        if let Ok(value) = base64_standard.decode(string_value.as_bytes()) {
            Some(String::from_utf8(value).unwrap_or_else(|_| {
                panic!("Failed to decode base64");
            }))
        } else {
            panic!("Failed to decode base64");
        }
    } else {
        None
    }
}
