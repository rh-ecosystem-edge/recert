use crate::cluster_crypto::locations::K8sResourceLocation;
use crate::config::{EncryptionCustomizations, RecertConfig};
use crate::encrypt::{EncryptionConfiguration, ResourceTransformers};
use crate::encrypt_config::EncryptionConfig;
use crate::file_utils::{self, read_file_to_string};
use crate::k8s_etcd::get_etcd_json;
use crate::k8s_etcd::InMemoryK8sEtcd;
use anyhow::{ensure, Context, Result};
use futures_util::Future;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::get_etcd_endpoint;

pub(crate) async fn is_encryption_enabled(in_memory_etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<bool> {
    let k8s_location = K8sResourceLocation::new(None, "APIServer", "cluster", "config.openshift.io/v1");

    let cluster = get_etcd_json(in_memory_etcd_client, &k8s_location)
        .await?
        .context(format!("could not get {}", k8s_location))?;

    if let Some(encryption_type) = cluster.pointer("/spec/encryption/type") {
        let encryption_type = encryption_type.as_str().context("spec.encryption.type not a string")?;

        ensure!(
            encryption_type == "aescbc" || encryption_type == "aesgcm",
            format!(
                "Unsupported encryption type {}, the supported encryption types are 'aescbc' and 'aesgcm'.",
                encryption_type
            )
        );

        Ok(true)
    } else {
        Ok(false)
    }
}

async fn get_latest_encryption_config(recert_config: &RecertConfig) -> Result<String> {
    let all_encryption_config_files = &recert_config
        .cluster_customizations
        .dirs
        .iter()
        .map(|dir| file_utils::globvec(dir, "**/encryption-config/encryption-config"))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<HashSet<_>>();

    // Get latest revision from kube-apiserver-pod-(\d+) in the file path
    let regex = regex::Regex::new(r"kube-apiserver-pod-(\d+)").context("compiling regex")?;
    let captures = &all_encryption_config_files
        .iter()
        .filter_map(|file_pathbuf| {
            let file_path = file_pathbuf.to_str()?;
            Some((regex.captures(file_path)?[1].parse::<u32>().ok()?, file_pathbuf))
        })
        .collect::<HashSet<_>>();
    let (_, latest_encryption_config) = captures
        .iter()
        .max_by_key(|(revision, _pathbuf)| revision)
        .context("no kube-apiserver-pod-* found")?;

    let latest_encryption_config_contents = &read_file_to_string(latest_encryption_config)
        .await
        .context("reading latest encryption-config")?;

    Ok(latest_encryption_config_contents.to_string())
}

pub(crate) async fn get_apiserver_encryption_type(in_memory_etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<String> {
    let k8s_location = K8sResourceLocation::new(None, "APIServer", "cluster", "config.openshift.io/v1");

    let apiserver = get_etcd_json(in_memory_etcd_client, &k8s_location)
        .await?
        .context(format!("could not get {}", k8s_location))?;

    let encryption_type = apiserver
        .pointer("/spec/encryption/type")
        .context("no /spec/encryption/type")?
        .as_str()
        .context("spec.encryption.type not a string")?;

    Ok(encryption_type.to_string())
}

pub(crate) async fn build_decryption_transformers(
    recert_config: &RecertConfig,
    in_memory_etcd_client: &mut Arc<InMemoryK8sEtcd>,
) -> Result<ResourceTransformers> {
    // Auto-discover seed encryption configs
    let contents = get_latest_encryption_config(recert_config).await?;
    let encryption_config = EncryptionConfiguration::parse_from_file(contents.into()).context("could not parse encryption-config")?;

    let mut decrypt_resource_transformers =
        ResourceTransformers::parse_from_encryption_configuration(encryption_config.clone()).context("parsing encryption configuration")?;

    // Use kube-apiserver encryption-config to decrypt the OpenShift Secrets
    *in_memory_etcd_client = get_etcd_endpoint(recert_config, Some(decrypt_resource_transformers.clone()), None).await?;

    // Add OpenShift resources to kube-apiserver resource transformers
    decrypt_resource_transformers = add_openshift_resource_transformers(in_memory_etcd_client, decrypt_resource_transformers).await?;

    Ok(decrypt_resource_transformers)
}

async fn get_encryption_config<F, Fut>(
    config_option: &Option<EncryptionConfig>,
    default_fn: F,
    encryption_type: String,
) -> anyhow::Result<EncryptionConfiguration>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<EncryptionConfiguration>>,
{
    if let Some(config) = config_option {
        let mut encryption_config = config.config.clone();
        encryption_config.remove_redundant_providers();
        Ok(encryption_config)
    } else {
        default_fn(encryption_type).await
    }
}

pub(crate) async fn build_encryption_customizations(
    recert_config: &RecertConfig,
    encryption_type: String,
) -> Result<EncryptionCustomizations> {
    let kube_encryption_config = get_encryption_config(
        &recert_config.encryption_customizations.kube_encryption_config,
        EncryptionConfiguration::new_kube_apiserver_config,
        encryption_type.clone(),
    )
    .await?;

    let openshift_encryption_config = get_encryption_config(
        &recert_config.encryption_customizations.openshift_encryption_config,
        EncryptionConfiguration::new_openshift_apiserver_config,
        encryption_type.clone(),
    )
    .await?;

    let oauth_encryption_config = get_encryption_config(
        &recert_config.encryption_customizations.oauth_encryption_config,
        EncryptionConfiguration::new_oauth_apiserver_config,
        encryption_type.clone(),
    )
    .await?;

    Ok(EncryptionCustomizations {
        kube_encryption_config: Some(EncryptionConfig::new(kube_encryption_config)),
        openshift_encryption_config: Some(EncryptionConfig::new(openshift_encryption_config)),
        oauth_encryption_config: Some(EncryptionConfig::new(oauth_encryption_config)),
    })
}

pub(crate) async fn build_encryption_transformers(encryption_customizations: &EncryptionCustomizations) -> Result<ResourceTransformers> {
    let kube_encryption_config = match &encryption_customizations.kube_encryption_config {
        Some(config) => &config.config,
        None => return Err(anyhow::anyhow!("Missing kube encryption config")),
    };

    let openshift_encryption_config = match &encryption_customizations.openshift_encryption_config {
        Some(config) => &config.config,
        None => return Err(anyhow::anyhow!("Missing openshift encryption config")),
    };

    let oauth_encryption_config = match &encryption_customizations.oauth_encryption_config {
        Some(config) => &config.config,
        None => return Err(anyhow::anyhow!("Missing oauth encryption config")),
    };

    let mut encrypt_resource_transformers = ResourceTransformers::parse_from_encryption_configuration(kube_encryption_config.clone())
        .context("parsing kube encryption configuration")?;

    let openshift_resource_transformers = ResourceTransformers::parse_from_encryption_configuration(openshift_encryption_config.clone())
        .context("parsing openshift encryption configuration")?;

    let oauth_resource_transformers = ResourceTransformers::parse_from_encryption_configuration(oauth_encryption_config.clone())
        .context("parsing oauth encryption configuration")?;

    let size_before = encrypt_resource_transformers.resource_to_prefix_transformers.len()
        + openshift_resource_transformers.resource_to_prefix_transformers.len()
        + oauth_resource_transformers.resource_to_prefix_transformers.len();

    encrypt_resource_transformers.resource_to_prefix_transformers.extend(
        openshift_resource_transformers
            .resource_to_prefix_transformers
            .into_iter()
            .chain(oauth_resource_transformers.resource_to_prefix_transformers),
    );

    let size_after = encrypt_resource_transformers.resource_to_prefix_transformers.len();

    ensure!(size_before == size_after, "encryption configurations contain overlapping resources");

    Ok(encrypt_resource_transformers)
}

async fn add_openshift_resource_transformers(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    resource_transformers: ResourceTransformers,
) -> Result<ResourceTransformers> {
    let resource_to_prefix_transformers: HashMap<_, _> = resource_transformers.resource_to_prefix_transformers;

    let apiserver_location = K8sResourceLocation::new(Some("openshift-apiserver"), "Secret", "encryption-config", "v1");
    let resource_to_prefix_transformers = if let Some(apiserver_resource_transformers) =
        get_openshift_resource_transformers(in_memory_etcd_client, &apiserver_location).await?
    {
        resource_to_prefix_transformers
            .clone()
            .into_iter()
            .chain(apiserver_resource_transformers.resource_to_prefix_transformers)
            .collect()
    } else {
        resource_to_prefix_transformers
    };

    let oauth_apiserver_location = K8sResourceLocation::new(Some("openshift-oauth-apiserver"), "Secret", "encryption-config", "v1");
    let resource_to_prefix_transformers = if let Some(oauth_apiserver_resource_transformers) =
        get_openshift_resource_transformers(in_memory_etcd_client, &oauth_apiserver_location).await?
    {
        resource_to_prefix_transformers
            .clone()
            .into_iter()
            .chain(oauth_apiserver_resource_transformers.resource_to_prefix_transformers)
            .collect()
    } else {
        resource_to_prefix_transformers
    };

    Ok(ResourceTransformers {
        resource_to_prefix_transformers,
    })
}

async fn get_openshift_resource_transformers(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    k8s_location: &K8sResourceLocation,
) -> Result<Option<ResourceTransformers>> {
    let secret = get_etcd_json(in_memory_etcd_client, k8s_location)
        .await?
        .context(format!("could not get {}", k8s_location))?;
    let data = secret
        .pointer("/data")
        .context("no /data")?
        .as_object()
        .context("data not an object")?;

    if let Some(config) = data.get("encryption-config") {
        let config = String::from_utf8(
            config
                .as_array()
                .context("not an array")?
                .iter()
                .filter_map(|v| v.as_u64().map(|b| b as u8))
                .collect(),
        )?;

        let encryption_config =
            EncryptionConfiguration::parse_from_file(config.as_bytes().to_vec()).context(format!("could not parse {}", k8s_location))?;

        return Ok(Some(
            ResourceTransformers::parse_from_encryption_configuration(encryption_config)
                .context(format!("could not parse transformers from {}", k8s_location))?,
        ));
    }

    Ok(None)
}
