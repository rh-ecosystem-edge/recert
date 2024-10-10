use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    config::EncryptionCustomizations,
    encrypt::EncryptionConfiguration,
    k8s_etcd::{get_etcd_json, put_etcd_yaml, InMemoryK8sEtcd},
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use futures_util::future::join_all;
use std::sync::Arc;

async fn update_encryption_config(namespace: &str, etcd_client: &Arc<InMemoryK8sEtcd>, config: &EncryptionConfiguration) -> Result<()> {
    join_all(
        etcd_client
            .list_keys(&format!("secrets/{}/encryption-config", namespace).to_string())
            .await?
            .into_iter()
            .chain(
                etcd_client
                    .list_keys(&format!("secrets/openshift-config-managed/encryption-config-{}", namespace).to_string())
                    .await?
                    .into_iter(),
            )
            .map(|key| async move {
                let etcd_result = etcd_client
                    .get(key.clone())
                    .await
                    .with_context(|| format!("getting key {:?}", key))?
                    .context("key disappeared")?;
                let value: serde_json::Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;
                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let mut secret = get_etcd_json(etcd_client, &k8s_resource_location)
                    .await?
                    .context("getting secret")?;

                let data = &mut secret
                    .pointer_mut("/data")
                    .context("no /data")?
                    .as_object_mut()
                    .context("data not an object")?;

                data.insert(
                    "encryption-config".to_string(),
                    serde_json::Value::Array(
                        base64_standard
                            .encode(serde_json::to_string(&config)?)
                            .as_bytes()
                            .iter()
                            .map(|byte| serde_json::Value::Number(serde_json::Number::from(*byte)))
                            .collect(),
                    ),
                )
                .context("could not find original encryption-config")?;

                put_etcd_yaml(etcd_client, &k8s_resource_location, secret).await?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn update_kube_apiserver_encryption_config(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    encryption_customizations: &EncryptionCustomizations,
) -> Result<()> {
    if let Some(kube_encryption_config) = &encryption_customizations.kube_encryption_config {
        update_encryption_config("openshift-kube-apiserver", etcd_client, &kube_encryption_config.config).await?
    }

    Ok(())
}

pub(crate) async fn update_openshift_apiserver_encryption_config(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    encryption_customizations: &EncryptionCustomizations,
) -> Result<()> {
    if let Some(openshift_encryption_config) = &encryption_customizations.openshift_encryption_config {
        update_encryption_config("openshift-apiserver", etcd_client, &openshift_encryption_config.config).await?
    }

    Ok(())
}

pub(crate) async fn update_oauth_apiserver_encryption_config(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    encryption_customizations: &EncryptionCustomizations,
) -> Result<()> {
    if let Some(oauth_encryption_config) = &encryption_customizations.oauth_encryption_config {
        update_encryption_config("openshift-oauth-apiserver", etcd_client, &oauth_encryption_config.config).await?
    }

    Ok(())
}
