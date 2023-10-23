use self::k8s_etcd_protobuf::k8s::io::apimachinery::pkg::runtime::TypeMeta;
use anyhow::{bail, Context, Result};
use k8s_etcd_protobuf::github::com::openshift::api::route::v1::Route;
use k8s_etcd_protobuf::k8s::io::{
    api::{
        admissionregistration::v1::{MutatingWebhookConfiguration, ValidatingWebhookConfiguration},
        apps::v1::{DaemonSet, Deployment},
        core::v1::{ConfigMap, Secret},
    },
    apimachinery::pkg::runtime::Unknown,
};
use prost::Message;
use serde_json::Value;

mod k8s_etcd_protobuf {
    #![allow(clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/_includes.rs"));
}

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
k8s_type!(ConfigMapWithMeta, ConfigMap);
k8s_type!(SecretWithMeta, Secret);
k8s_type!(ValidatingWebhookConfigurationWithMeta, ValidatingWebhookConfiguration);
k8s_type!(MutatingWebhookConfigurationWithMeta, MutatingWebhookConfiguration);

pub(crate) async fn decode(data: &[u8]) -> Result<Vec<u8>> {
    if !data.starts_with("k8s\x00".as_bytes()) {
        return Ok(data.to_vec());
    }

    let data = &data[4..];
    let unknown = Unknown::decode(data)?;
    let kind = unknown.type_meta.as_ref().unwrap().kind.as_ref().unwrap().as_str();
    Ok(match kind {
        "Route" => serde_json::to_vec(&RouteWithMeta::try_from(unknown)?)?,
        "Deployment" => serde_json::to_vec(&DeploymentWithMeta::try_from(unknown)?)?,
        "DaemonSet" => serde_json::to_vec(&DaemonsSetWithMeta::try_from(unknown)?)?,
        "ConfigMap" => serde_json::to_vec(&ConfigMapWithMeta::try_from(unknown)?)?,
        "Secret" => serde_json::to_vec(&SecretWithMeta::try_from(unknown)?)?,
        "ValidatingWebhookConfiguration" => serde_json::to_vec(&ValidatingWebhookConfigurationWithMeta::try_from(unknown)?)?,
        "MutatingWebhookConfiguration" => serde_json::to_vec(&MutatingWebhookConfigurationWithMeta::try_from(unknown)?)?,
        _ => bail!("unknown kind {}", kind),
    })
}

pub(crate) async fn encode(data: &[u8]) -> Result<Vec<u8>> {
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
            "Deployment" => Unknown::from(serde_json::from_slice::<DeploymentWithMeta>(data)?),
            "DaemonSet" => Unknown::from(serde_json::from_slice::<DaemonsSetWithMeta>(data)?),
            "ValidatingWebhookConfiguration" => Unknown::from(serde_json::from_slice::<ValidatingWebhookConfigurationWithMeta>(data)?),
            "MutatingWebhookConfiguration" => Unknown::from(serde_json::from_slice::<MutatingWebhookConfigurationWithMeta>(data)?),
            _ => return Ok(data.to_vec()),
        }
        .encode_to_vec(),
    );

    Ok(result)
}
