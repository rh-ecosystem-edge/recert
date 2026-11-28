use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    config::EncryptionCustomizations,
    encrypt::{EncryptionConfiguration, Key, Provider, Resource},
    k8s_etcd::{get_etcd_json, put_etcd_yaml, InMemoryK8sEtcd},
};
use anyhow::{bail, ensure, Context, Result};
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
                    .await?,
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

/// Returns the secret and name of the primary key of a single resource entry.
fn resource_primary_key(resource: &Resource) -> Result<&Key> {
    let provider = resource.providers.first().context("encryption config has no providers")?;

    let keys = match provider {
        Provider {
            aesgcm: Some(aesgcm),
            aescbc: None,
            identity: _,
        } => &aesgcm.keys,
        Provider {
            aesgcm: None,
            aescbc: Some(aescbc),
            identity: _,
        } => &aescbc.keys,
        _ => bail!("unsupported provider"),
    };

    keys.first().context("encryption provider has no keys")
}

/// Returns the secret and name of the key in the config's primary provider. A component has a
/// single encryption-key Secret, so every resource entry must share the same primary key;
/// otherwise the Secret would silently disagree with the key some resources are encrypted with.
/// Errors instead of panicking when the config has no resources, no providers, or no keys.
fn primary_encryption_key(config: &EncryptionConfiguration) -> Result<(Vec<u8>, String)> {
    let (first, rest) = config.resources.split_first().context("encryption config has no resources")?;
    let key = resource_primary_key(first)?;

    for resource in rest {
        // An identity-first entry leaves its resources unencrypted, so it uses no component key.
        if matches!(
            resource.providers.first(),
            Some(Provider {
                aesgcm: None,
                aescbc: None,
                identity: Some(_),
            })
        ) {
            continue;
        }
        let other = resource_primary_key(resource)?;
        ensure!(
            other.name == key.name && other.secret == key.secret,
            "encryption config resources {:?} and {:?} use different primary keys",
            first.resources,
            resource.resources
        );
    }

    Ok((key.secret.clone(), key.name.clone()))
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

                let (encryption_key, key_name) = primary_encryption_key(config)?;

                let encryption_key_base64 = base64_standard.encode(encryption_key.clone());

                if *data.get(ENCRYPTION_KEY_NAME).context("cound not find encryption-key")?.to_string() != encryption_key_base64 {
                    data.insert(
                        ENCRYPTION_KEY_NAME.to_string(),
                        serde_json::Value::Array(
                            encryption_key
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

                        let encoding = etcd_client.encoding_of(&key).await?;
                        etcd_client
                            .put(
                                &(format!(
                                    "/kubernetes.io/secrets/openshift-config-managed/encryption-key-{}-{}",
                                    component, key_name
                                )),
                                serde_json::to_string(&secret).context("serializing value")?.as_bytes().to_vec(),
                                Some(encoding),
                            )
                            .await
                            .context("putting in etcd")?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::{AesCbc, AesGcm, Identity};

    fn config(resources: Vec<Resource>) -> EncryptionConfiguration {
        EncryptionConfiguration {
            kind: "EncryptionConfiguration".to_string(),
            apiVersion: "apiserver.config.k8s.io/v1".to_string(),
            resources,
        }
    }

    fn resource(providers: Vec<Provider>) -> Resource {
        Resource {
            resources: vec!["secrets".to_string()],
            providers,
        }
    }

    fn key() -> Key {
        Key {
            name: "1".to_string(),
            secret: vec![1, 2, 3],
        }
    }

    fn aesgcm(keys: Vec<Key>) -> Provider {
        Provider {
            aesgcm: Some(AesGcm { keys }),
            aescbc: None,
            identity: None,
        }
    }

    fn aescbc(keys: Vec<Key>) -> Provider {
        Provider {
            aesgcm: None,
            aescbc: Some(AesCbc { keys }),
            identity: None,
        }
    }

    #[test]
    fn test_primary_encryption_key_aesgcm() {
        let config = config(vec![resource(vec![aesgcm(vec![key()])])]);
        assert_eq!(primary_encryption_key(&config).unwrap(), (vec![1, 2, 3], "1".to_string()));
    }

    #[test]
    fn test_primary_encryption_key_aescbc() {
        let config = config(vec![resource(vec![aescbc(vec![key()])])]);
        assert_eq!(primary_encryption_key(&config).unwrap(), (vec![1, 2, 3], "1".to_string()));
    }

    #[test]
    fn test_primary_encryption_key_without_resources_errors_without_panicking() {
        let err = primary_encryption_key(&config(vec![])).unwrap_err();
        assert!(err.to_string().contains("no resources"), "unexpected error: {err}");
    }

    #[test]
    fn test_primary_encryption_key_without_providers_errors_without_panicking() {
        let err = primary_encryption_key(&config(vec![resource(vec![])])).unwrap_err();
        assert!(err.to_string().contains("no providers"), "unexpected error: {err}");
    }

    #[test]
    fn test_primary_encryption_key_without_keys_errors_without_panicking() {
        let err = primary_encryption_key(&config(vec![resource(vec![aesgcm(vec![])])])).unwrap_err();
        assert!(err.to_string().contains("no keys"), "unexpected error: {err}");
    }

    #[test]
    fn test_primary_encryption_key_identity_provider_is_unsupported() {
        let identity = Provider {
            aesgcm: None,
            aescbc: None,
            identity: Some(Identity {}),
        };
        let err = primary_encryption_key(&config(vec![resource(vec![identity])])).unwrap_err();
        assert!(err.to_string().contains("unsupported provider"), "unexpected error: {err}");
    }

    fn named_resource(name: &str, providers: Vec<Provider>) -> Resource {
        Resource {
            resources: vec![name.to_string()],
            providers,
        }
    }

    #[test]
    fn test_primary_encryption_key_shared_across_resources() {
        // The kube-apiserver shape: configmaps and secrets entries sharing one key.
        let config = config(vec![
            named_resource("configmaps", vec![aesgcm(vec![key()])]),
            named_resource("secrets", vec![aesgcm(vec![key()])]),
        ]);
        assert_eq!(primary_encryption_key(&config).unwrap(), (vec![1, 2, 3], "1".to_string()));
    }

    #[test]
    fn test_primary_encryption_key_without_secrets_entry() {
        // openshift-apiserver and oauth-apiserver configs have no secrets entry.
        let config = config(vec![named_resource("routes.route.openshift.io", vec![aescbc(vec![key()])])]);
        assert_eq!(primary_encryption_key(&config).unwrap(), (vec![1, 2, 3], "1".to_string()));
    }

    #[test]
    fn test_primary_encryption_key_mismatched_secret_errors() {
        let other = Key {
            name: "1".to_string(),
            secret: vec![9, 9, 9],
        };
        let config = config(vec![
            named_resource("configmaps", vec![aesgcm(vec![key()])]),
            named_resource("secrets", vec![aesgcm(vec![other])]),
        ]);
        let err = primary_encryption_key(&config).unwrap_err();
        assert!(err.to_string().contains("different primary keys"), "unexpected error: {err}");
    }

    #[test]
    fn test_primary_encryption_key_mismatched_name_errors() {
        let other = Key {
            name: "2".to_string(),
            secret: vec![1, 2, 3],
        };
        let config = config(vec![
            named_resource("configmaps", vec![aesgcm(vec![key()])]),
            named_resource("secrets", vec![aesgcm(vec![other])]),
        ]);
        let err = primary_encryption_key(&config).unwrap_err();
        assert!(err.to_string().contains("different primary keys"), "unexpected error: {err}");
    }

    #[test]
    fn test_primary_encryption_key_skips_identity_first_later_entries() {
        let identity = Provider {
            aesgcm: None,
            aescbc: None,
            identity: Some(Identity {}),
        };
        let config = config(vec![
            named_resource("secrets", vec![aesgcm(vec![key()])]),
            named_resource("configmaps", vec![identity, aesgcm(vec![key()])]),
        ]);
        assert_eq!(primary_encryption_key(&config).unwrap(), (vec![1, 2, 3], "1".to_string()));
    }

    #[test]
    fn test_primary_encryption_key_validates_later_entries() {
        let config = config(vec![
            named_resource("configmaps", vec![aesgcm(vec![key()])]),
            named_resource("secrets", vec![aesgcm(vec![])]),
        ]);
        let err = primary_encryption_key(&config).unwrap_err();
        assert!(err.to_string().contains("no keys"), "unexpected error: {err}");
    }
}
