use self::transformer::Transformer;
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::process::Command;

pub(crate) mod aescbc;
pub(crate) mod aesgcm;
pub(crate) mod transformer;

const API_VERSION: &str = "apiserver.config.k8s.io/v1";
const KIND: &str = "EncryptionConfiguration";

#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct EncryptionConfiguration {
    pub(crate) kind: String,
    pub(crate) apiVersion: String,
    pub(crate) resources: Vec<Resource>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct Resource {
    pub(crate) resources: Vec<String>,
    pub(crate) providers: Vec<Provider>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct Provider {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) aesgcm: Option<AesGcm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) aescbc: Option<AesCbc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) identity: Option<Identity>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct AesGcm {
    pub(crate) keys: Vec<Key>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct AesCbc {
    pub(crate) keys: Vec<Key>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct Key {
    pub(crate) name: String,
    pub(crate) secret: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct Identity {}

#[derive(Clone)]
pub(crate) struct ResourceTransformers {
    pub(crate) resource_to_prefix_transformers: HashMap<String, Vec<Box<dyn Transformer + Send + Sync>>>,
}

impl EncryptionConfiguration {
    pub(crate) async fn new(resource_names: Vec<String>, encryption_type: String) -> Result<Self> {
        // use the same key for the resources of an EncryptionConfiguration object
        let key = generate_key().await.context("could not generate key")?;

        let mut resources = Vec::<Resource>::new();
        for res in resource_names {
            let mut resource = Resource {
                resources: vec![res.to_string()],
                providers: vec![],
            };
            let provider = match encryption_type.as_str() {
                "aesgcm" => Provider {
                    aesgcm: Some(AesGcm {
                        keys: vec![Key {
                            name: "1".to_string(),
                            secret: key.clone(),
                        }],
                    }),
                    aescbc: None,
                    identity: None,
                },
                "aescbc" => Provider {
                    aesgcm: None,
                    aescbc: Some(AesCbc {
                        keys: vec![Key {
                            name: "1".to_string(),
                            secret: key.clone(),
                        }],
                    }),
                    identity: None,
                },
                "identity" => Provider {
                    aesgcm: None,
                    aescbc: None,
                    identity: Some(Identity {}),
                },
                _ => {
                    bail!("unsupported encryption type");
                }
            };
            resource.providers.push(provider);
            // Always put identity in the providers
            resource.providers.push(Provider {
                aesgcm: None,
                aescbc: None,
                identity: Some(Identity {}),
            });
            resources.push(resource);
        }

        Ok(Self {
            apiVersion: API_VERSION.to_string(),
            kind: KIND.to_string(),
            resources,
        })
    }

    pub(crate) async fn new_kube_apiserver_config(encryption_type: String) -> Result<Self> {
        Self::new(vec!["configmaps".to_string(), "secrets".to_string()], encryption_type).await
    }

    pub(crate) async fn new_openshift_apiserver_config(encryption_type: String) -> Result<Self> {
        Self::new(vec!["routes.route.openshift.io".to_string()], encryption_type).await
    }

    pub(crate) async fn new_oauth_apiserver_config(encryption_type: String) -> Result<Self> {
        Self::new(
            vec![
                "oauthaccesstokens.oauth.openshift.io".to_string(),
                "oauthauthorizetokens.oauth.openshift.io".to_string(),
            ],
            encryption_type,
        )
        .await
    }

    pub(crate) fn parse_from_file(config_bytes: Vec<u8>) -> Result<Self> {
        let config: EncryptionConfiguration = serde_json::from_slice(&config_bytes)?;

        ensure!(config.kind == KIND, format!("kind should equal {}, found {}", KIND, config.kind));
        ensure!(
            config.apiVersion == API_VERSION,
            format!("apiVersion should equal {}, found {}", API_VERSION, config.apiVersion)
        );

        Ok(config)
    }

    pub(crate) fn remove_redundant_providers(&mut self) {
        for res in &mut self.resources {
            if res.providers.len() > 1 {
                res.providers = vec![res.providers[0].clone()]
            }
        }
    }
}

async fn generate_key() -> Result<String> {
    let output = Command::new("openssl")
        .arg("rand")
        .arg("-base64")
        .arg("32")
        .output()
        .await
        .context("failed to run openssl command")?;

    if !output.status.success() {
        return Err(anyhow::anyhow!("openssl command failed with status: {}", output.status));
    }

    let key = String::from_utf8(output.stdout).context("could not convert output to utf8")?;

    Ok(key.trim().to_string())
}

impl ResourceTransformers {
    pub(crate) fn parse_from_encryption_configuration(config: EncryptionConfiguration) -> Result<Self> {
        let mut transformers: HashMap<String, Vec<Box<dyn Transformer + Send + Sync>>> = HashMap::new();

        for resources in config.resources {
            let mut providers: Vec<Box<dyn Transformer + Send + Sync>> = Vec::new();

            for provider in resources.providers {
                match (provider.aesgcm, provider.aescbc, provider.identity) {
                    (Some(aesgcm), None, None) => {
                        let prefix = "k8s:enc:aesgcm:v1:";
                        for key in aesgcm.keys {
                            let prefix = format!("{}{}:", prefix, key.name);
                            providers.push(Box::new(aesgcm::AesGcm::new(prefix, key.secret)));
                        }
                    }
                    (None, Some(aescbc), None) => {
                        let prefix = "k8s:enc:aescbc:v1:";
                        for key in aescbc.keys {
                            let prefix = format!("{}{}:", prefix, key.name);
                            providers.push(Box::new(aescbc::AesCbc::new(prefix, key.secret)));
                        }
                    }
                    (None, None, Some(_)) => {
                        // Nothing to implement
                    }
                    _ => {
                        bail!("unsupported provider");
                    }
                }
            }
            for resource in resources.resources {
                if let Some(key) = resource.split('.').next() {
                    transformers.insert(key.to_string(), providers.clone());
                }
            }
        }

        Ok(Self {
            resource_to_prefix_transformers: transformers,
        })
    }
}
