use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    config::EncryptionCustomizations,
    encrypt::{EncryptionConfiguration, Provider},
    k8s_etcd::{get_etcd_json, put_etcd_yaml, InMemoryK8sEtcd},
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use futures_util::future::join_all;
use std::sync::Arc;

const ENCRYPTION_KEY_NAME: &str = "encryption.apiserver.operator.openshift.io-key";

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
                        format!("{}\n", serde_json::to_string(&config).context("serializing encryption-config")?)
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

async fn update_encryption_key(component: &str, etcd_client: &Arc<InMemoryK8sEtcd>, config: &EncryptionConfiguration) -> Result<()> {
    join_all(
        etcd_client
            .list_keys(&format!("secrets/openshift-config-managed/encryption-key-{}", component).to_string())
            .await?
            .into_iter()
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

                let (encryption_key, key_name) = match &config.resources[0].providers[0] {
                    Provider {
                        aesgcm: Some(aesgcm),
                        aescbc: None,
                        identity: _,
                    } => (aesgcm.keys[0].secret.clone(), aesgcm.keys[0].name.clone()),
                    Provider {
                        aesgcm: None,
                        aescbc: Some(aescbc),
                        identity: _,
                    } => (aescbc.keys[0].secret.clone(), aescbc.keys[0].name.clone()),
                    _ => bail!("unsupported provider"),
                };

                if *data.get(ENCRYPTION_KEY_NAME).context("cound not find encryption-key")?.to_string() != encryption_key {
                    let encryption_key_bytes = base64_standard.decode(encryption_key.as_bytes())?;

                    data.insert(
                        ENCRYPTION_KEY_NAME.to_string(),
                        serde_json::Value::Array(
                            encryption_key_bytes
                                .iter()
                                .map(|byte| serde_json::Value::Number(serde_json::Number::from(*byte)))
                                .collect(),
                        ),
                    )
                    .context("could not find original encryption-key")?;

                    if key_name == key.rsplit('-').next().context("cound not rsplit key")? {
                        put_etcd_yaml(etcd_client, &k8s_resource_location, secret).await?;
                    } else {
                        let metadata = &mut secret
                            .pointer_mut("/metadata")
                            .context("no /metadata")?
                            .as_object_mut()
                            .context("metadata not an object")?;
                        metadata
                            .insert(
                                "name".to_string(),
                                serde_json::Value::String(format!("encryption-key-{}-{}", component, key_name)),
                            )
                            .context("could not find original name")?;

                        etcd_client
                            .put(
                                &(format!(
                                    "/kubernetes.io/secrets/openshift-config-managed/encryption-key-{}-{}",
                                    component, key_name
                                )),
                                serde_json::to_string(&secret).context("serializing value")?.as_bytes().to_vec(),
                            )
                            .await;
                        etcd_client.delete(&key).await.context(format!("deleting {}", key))?;
                    }
                }

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn update_kube_apiserver_encryption_key(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    encryption_customizations: &EncryptionCustomizations,
) -> Result<()> {
    if let Some(kube_encryption_config) = &encryption_customizations.kube_encryption_config {
        update_encryption_key("openshift-kube-apiserver", etcd_client, &kube_encryption_config.config).await?
    }

    Ok(())
}

pub(crate) async fn update_openshift_apiserver_encryption_key(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    encryption_customizations: &EncryptionCustomizations,
) -> Result<()> {
    if let Some(openshift_encryption_config) = &encryption_customizations.openshift_encryption_config {
        update_encryption_key("openshift-apiserver", etcd_client, &openshift_encryption_config.config).await?
    }

    Ok(())
}

pub(crate) async fn update_oauth_apiserver_encryption_key(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    encryption_customizations: &EncryptionCustomizations,
) -> Result<()> {
    if let Some(oauth_encryption_config) = &encryption_customizations.oauth_encryption_config {
        update_encryption_key("openshift-oauth-apiserver", etcd_client, &oauth_encryption_config.config).await?
    }

    Ok(())
}
