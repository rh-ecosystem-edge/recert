use super::protobuf_gen::{
    github::com::openshift::api::{oauth::v1::OAuthClient, route::v1::Route},
    k8s::io::{
        api::{
            admissionregistration::v1::{MutatingWebhookConfiguration, ValidatingWebhookConfiguration},
            apps::v1::{ControllerRevision, DaemonSet, Deployment, StatefulSet},
            batch::v1::{CronJob, Job},
            core::v1::{ConfigMap, Node, Pod, Secret},
        },
        apimachinery::pkg::runtime::{TypeMeta, Unknown},
    },
};
use anyhow::{bail, Context, Result};
use prost::Message;
use serde_json::Value;

macro_rules! k8s_type {
    ($name:ident, $type:ident) => {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct $name {
            #[serde(flatten)]
            inner: $type,
            #[serde(flatten)]
            meta: TypeMeta,
        }

        impl From<$name> for Unknown {
            fn from(value: $name) -> Self {
                Unknown {
                    type_meta: Some(value.meta),
                    raw: Some(value.inner.encode_to_vec()),
                    content_encoding: None,
                    content_type: None,
                }
            }
        }

        impl TryFrom<Unknown> for $name {
            type Error = anyhow::Error;

            fn try_from(value: Unknown) -> Result<Self, Self::Error> {
                Ok(Self {
                    inner: $type::decode(value.raw())?,
                    meta: value.type_meta.unwrap(),
                })
            }
        }
    };
}

k8s_type!(RouteWithMeta, Route);
k8s_type!(DaemonsSetWithMeta, DaemonSet);
k8s_type!(DeploymentWithMeta, Deployment);
k8s_type!(ControllerRevisionWithMeta, ControllerRevision);
k8s_type!(JobWithMeta, Job);
k8s_type!(CronJobWithMeta, CronJob);
k8s_type!(StatefulSetWithMeta, StatefulSet);
k8s_type!(ConfigMapWithMeta, ConfigMap);
k8s_type!(NodeWithMeta, Node);
k8s_type!(SecretWithMeta, Secret);
k8s_type!(PodWithMeta, Pod);
k8s_type!(ValidatingWebhookConfigurationWithMeta, ValidatingWebhookConfiguration);
k8s_type!(MutatingWebhookConfigurationWithMeta, MutatingWebhookConfiguration);
k8s_type!(OAuthClientWithMeta, OAuthClient);

mod k8s_cbor;

#[derive(Clone, Copy)]
pub(crate) enum Encoding {
    Protobuf,
    Cbor,
    Json,
}

pub(crate) async fn decode(data: &[u8]) -> Result<(Vec<u8>, Encoding)> {
    if !data.starts_with("k8s\x00".as_bytes()) {
        // k8s uses CBOR with the self-describing tag 55799, we can use its bytes to detect CBOR
        if data.starts_with([0xd9, 0xd9, 0xf7].as_ref()) {
            // It's CBOR, just convert to JSON
            let json_value = k8s_cbor::k8s_cbor_bytes_to_json(data).context("converting CBOR to JSON")?;
            return Ok((serde_json::to_vec(&json_value)?, Encoding::Cbor));
        }

        // Not CBOR, not protobuf, it's probably just raw JSON, return as-is
        return Ok((data.to_vec(), Encoding::Json));
    }

    let data = &data[4..];
    let unknown = Unknown::decode(data)?;
    let kind = unknown
        .type_meta
        .as_ref()
        .context("missing meta")?
        .kind
        .as_ref()
        .context("missing kind")?
        .as_str();

    let decoded_data = match kind {
        "Route" => serde_json::to_vec(&RouteWithMeta::try_from(unknown)?)?,
        "Deployment" => serde_json::to_vec(&DeploymentWithMeta::try_from(unknown)?)?,
        "ControllerRevision" => serde_json::to_vec(&ControllerRevisionWithMeta::try_from(unknown)?)?,
        "Job" => serde_json::to_vec(&JobWithMeta::try_from(unknown)?)?,
        "CronJob" => serde_json::to_vec(&CronJobWithMeta::try_from(unknown)?)?,
        "StatefulSet" => serde_json::to_vec(&StatefulSetWithMeta::try_from(unknown)?)?,
        "DaemonSet" => serde_json::to_vec(&DaemonsSetWithMeta::try_from(unknown)?)?,
        "ConfigMap" => serde_json::to_vec(&ConfigMapWithMeta::try_from(unknown)?)?,
        "Node" => serde_json::to_vec(&NodeWithMeta::try_from(unknown)?)?,
        "Secret" => serde_json::to_vec(&SecretWithMeta::try_from(unknown)?)?,
        "Pod" => serde_json::to_vec(&PodWithMeta::try_from(unknown)?)?,
        "ValidatingWebhookConfiguration" => serde_json::to_vec(&ValidatingWebhookConfigurationWithMeta::try_from(unknown)?)?,
        "MutatingWebhookConfiguration" => serde_json::to_vec(&MutatingWebhookConfigurationWithMeta::try_from(unknown)?)?,
        "OAuthClient" => serde_json::to_vec(&OAuthClientWithMeta::try_from(unknown)?)?,
        _ => bail!("unknown kind {}", kind),
    };

    Ok((decoded_data, Encoding::Protobuf))
}

pub(crate) async fn encode(data: &[u8], encoding: Encoding) -> Result<Vec<u8>> {
    match encoding {
        Encoding::Json => Ok(data.to_vec()),
        Encoding::Cbor => k8s_cbor::json_to_k8s_cbor_bytes(serde_json::from_slice(data)?).context("converting JSON to CBOR"),
        Encoding::Protobuf => {
            let value: Value = serde_json::from_slice(data)?;
            let kind = value
                .pointer("/kind")
                .context("missing kind")?
                .as_str()
                .context("kind is not a string")?;

            let mut result = b"k8s\x00".to_vec();

            result.extend(
                match kind {
                    "ConfigMap" => Unknown::from(serde_json::from_slice::<ConfigMapWithMeta>(data)?),
                    "Route" => Unknown::from(serde_json::from_slice::<RouteWithMeta>(data)?),
                    "Secret" => Unknown::from(serde_json::from_slice::<SecretWithMeta>(data)?),
                    "Node" => Unknown::from(serde_json::from_slice::<NodeWithMeta>(data)?),
                    "Pod" => Unknown::from(serde_json::from_slice::<PodWithMeta>(data)?),
                    "Deployment" => Unknown::from(serde_json::from_slice::<DeploymentWithMeta>(data)?),
                    "ControllerRevision" => Unknown::from(serde_json::from_slice::<ControllerRevisionWithMeta>(data)?),
                    "Job" => Unknown::from(serde_json::from_slice::<JobWithMeta>(data)?),
                    "CronJob" => Unknown::from(serde_json::from_slice::<CronJobWithMeta>(data)?),
                    "StatefulSet" => Unknown::from(serde_json::from_slice::<StatefulSetWithMeta>(data)?),
                    "DaemonSet" => Unknown::from(serde_json::from_slice::<DaemonsSetWithMeta>(data)?),
                    "ValidatingWebhookConfiguration" => {
                        Unknown::from(serde_json::from_slice::<ValidatingWebhookConfigurationWithMeta>(data)?)
                    }
                    "MutatingWebhookConfiguration" => Unknown::from(serde_json::from_slice::<MutatingWebhookConfigurationWithMeta>(data)?),
                    "OAuthClient" => Unknown::from(serde_json::from_slice::<OAuthClientWithMeta>(data)?),
                    _ => return Ok(data.to_vec()),
                }
                .encode_to_vec(),
            );

            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configmap_json() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "foo",
                "namespace": "bar",
                "labels": {},
                "annotations": {},
                "ownerReferences": [],
                "finalizers": [],
                "managedFields": []
            },
            "data": {"hello": "world"},
            "binaryData": {}
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn test_decode_plain_json_passthrough() {
        let json = br#"{"kind":"ConfigMap","apiVersion":"v1","metadata":{"name":"foo"}}"#;
        let (decoded, encoding) = decode(json).await.unwrap();
        assert!(matches!(encoding, Encoding::Json));
        assert_eq!(decoded, json);
    }

    #[tokio::test]
    async fn test_encode_unknown_kind_stays_json() {
        let json = br#"{"kind":"Foo","apiVersion":"v1","metadata":{"name":"x"}}"#;
        let encoded = encode(json, Encoding::Protobuf).await.unwrap();
        assert_eq!(encoded, json);
        assert!(!encoded.starts_with(b"k8s\x00"));
    }

    #[tokio::test]
    async fn test_configmap_protobuf_roundtrip() {
        let json = configmap_json();
        let encoded = encode(&json, Encoding::Protobuf).await.unwrap();
        assert!(encoded.starts_with(b"k8s\x00"), "protobuf values start with k8s\\x00");

        let (decoded, encoding) = decode(&encoded).await.unwrap();
        assert!(matches!(encoding, Encoding::Protobuf));

        let value: Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(value.pointer("/kind").and_then(Value::as_str), Some("ConfigMap"));
        assert_eq!(value.pointer("/metadata/name").and_then(Value::as_str), Some("foo"));
        assert_eq!(value.pointer("/data/hello").and_then(Value::as_str), Some("world"));
    }

    #[tokio::test]
    async fn test_encode_json_encoding_stays_json() {
        let json = configmap_json();
        let encoded = encode(&json, Encoding::Json).await.unwrap();
        assert_eq!(encoded, json);
        assert!(!encoded.starts_with(b"k8s\x00"));
    }

    #[tokio::test]
    async fn test_encode_json_passthrough_non_json() {
        let raw = b"not-json";
        let encoded = encode(raw, Encoding::Json).await.unwrap();
        assert_eq!(encoded, raw);
    }

    #[tokio::test]
    async fn test_encode_protobuf_missing_kind_errors() {
        let err = encode(br#"{"apiVersion":"v1"}"#, Encoding::Protobuf).await.unwrap_err();
        assert!(err.to_string().contains("missing kind"));
    }

    #[tokio::test]
    async fn test_encode_cbor_invalid_json_errors() {
        assert!(encode(b"not-json", Encoding::Cbor).await.is_err());
    }

    #[tokio::test]
    async fn test_cbor_roundtrip() {
        let json = serde_json::json!({"kind": "Foo", "hello": "world"});
        let bytes = serde_json::to_vec(&json).unwrap();
        let encoded = encode(&bytes, Encoding::Cbor).await.unwrap();
        assert_eq!(&encoded[..3], [0xd9, 0xd9, 0xf7]);

        let (decoded, encoding) = decode(&encoded).await.unwrap();
        assert!(matches!(encoding, Encoding::Cbor));
        let value: Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(value["kind"], "Foo");
        assert_eq!(value["hello"], "world");
    }

    #[tokio::test]
    async fn test_decode_untagged_cbor_treated_as_json() {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&ciborium::value::Value::Map(vec![]), &mut bytes).unwrap();
        let (decoded, encoding) = decode(&bytes).await.unwrap();
        assert!(matches!(encoding, Encoding::Json));
        assert_eq!(decoded, bytes);
    }
}
