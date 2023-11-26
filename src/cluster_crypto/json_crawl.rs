use super::locations::{FieldEncoding, JsonLocation, LocationValueType};
use crate::rules::{self, IGNORE_LIST_CONFIGMAP};
use anyhow::{bail, ensure, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD as base64_standard, STANDARD_NO_PAD as base64_standard_no_pad},
    Engine as _,
};
use bytes::Bytes;
use fn_error_context::context;
use serde_json::Value;

#[derive(Debug, Clone, Copy)]
pub(crate) enum Hint {
    // This is the hint emitted for JWTs, and PEM-encoded certificates and keys, as they
    // can be easily distinguished from random data they don't need any hints.
    None,
    // Symmetric keys are hard to distinguish from random data, so we emit a hint for them during
    // crawling, because we know where to expect them. There's only a few symmetric keys in
    // OpenShift, so we can afford to do this without adding too much complexity.
    SymmetricKey,
}

#[derive(Debug)]
pub(crate) struct JsonValue {
    pub(crate) location: JsonLocation,
    pub(crate) value: Value,
    pub(crate) hint: Hint,
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
            "OAuthClient" => scan_oauth_client(&json_value),
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
                hint: Hint::None,
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
                hint: Hint::None,
            })
        }
    }

    if let Some(Value::Object(metadata)) = value.as_object().context("not object")?.get("metadata") {
        if let Some(Value::Object(annotations)) = metadata.get("annotations") {
            for (key, value) in annotations.iter() {
                res.push(JsonValue {
                    location: JsonLocation::new("/metadata/annotations", key, FieldEncoding::None),
                    value: value.clone(),
                    hint: Hint::None,
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
            hint: Hint::None,
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
                hint: Hint::None,
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
                                                hint: Hint::None,
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
                hint: Hint::None,
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
                hint: Hint::None,
            });
        }
    }

    Ok(res)
}

pub(crate) fn scan_oauth_client(value: &Value) -> Result<Vec<JsonValue>> {
    let mut res = Vec::new();

    if let Some(secret) = value.get("secret") {
        res.push(JsonValue {
            location: JsonLocation {
                json_pointer: "/secret".to_string(),
                value: LocationValueType::YetUnknown,
                encoding: FieldEncoding::Base64NoPadding,
            },
            value: secret.clone(),
            hint: Hint::SymmetricKey,
        });
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
                        hint: Hint::None,
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
                    hint: Hint::None,
                });
            }
        }
    }

    Ok(res)
}

#[context("decoding value at {:?}", json_value.location)]
pub(crate) fn decode_json_value(json_value: &JsonValue) -> Result<Option<(JsonLocation, Bytes, Hint)>> {
    let decoded = match json_value.location.encoding {
        FieldEncoding::None => Some(Bytes::copy_from_slice(
            json_value.value.as_str().context("non unicode JSON value")?.as_bytes(),
        )),
        FieldEncoding::Base64 => process_base64_value(&json_value.value, true).context("decoding base64 value")?,
        FieldEncoding::DataUrl => process_data_url_value(&json_value.value).context("decoding dataurl value")?,
        FieldEncoding::ByteArray => process_byte_array_value(&json_value.value).context("decoding byte array value")?,
        FieldEncoding::Base64NoPadding => process_base64_value(&json_value.value, false).context("decoding base64 value")?,
    };

    Ok(decoded.map(|decoded| (json_value.location.clone(), decoded, json_value.hint)))
}

fn process_byte_array_value(value: &Value) -> Result<Option<Bytes>> {
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
            Some(bytes.into())
        }
        _ => None,
    })
}

/// Given a data-url-encoded value taken from a JSON field, decode it and scan it for
/// cryptographic keys and certificates and record them in the appropriate data structures.
fn process_data_url_value(value: &Value) -> Result<Option<Bytes>> {
    Ok(if let Value::String(string_value) = value {
        let url = data_url::DataUrl::process(string_value).ok().context("dataurl failed processing")?;

        let (decoded, _fragment) = url.decode_to_vec().ok().context("non-unicode dataurl")?;
        if let Ok(decoded) = String::from_utf8(decoded) {
            Some(decoded.into())
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
fn process_base64_value(value: &Value, padding: bool) -> Result<Option<Bytes>> {
    Ok(match value {
        Value::String(string_value) => Some(
            if padding { base64_standard } else { base64_standard_no_pad }
                .decode(string_value.as_bytes())?
                .into(),
        ),
        _ => None,
    })
}
