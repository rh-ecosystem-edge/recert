use crate::{
    cluster_crypto::{crypto_utils::ensure_openssl_version, locations::K8sResourceLocation, scanning, ClusterCryptoObjects},
    config::{ClusterCustomizations, CryptoCustomizations, EncryptionCustomizations, RecertConfig},
    encrypt::{EncryptionConfiguration, ResourceTransformers},
    encrypt_config::EncryptionConfig,
    file_utils::{self, read_file_to_string},
    k8s_etcd::{get_etcd_json, InMemoryK8sEtcd},
    ocp_postprocess::{encryption_config, ocp_postprocess},
    rsa_key_pool, server_ssh_keys,
};
use anyhow::{ensure, Context, Result};
use etcd_client::Client as EtcdClient;
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    path::Path,
    sync::Arc,
};

use self::timing::{combine_timings, FinalizeTiming, RecertifyTiming, RunTime, RunTimes};

pub(crate) mod timing;

pub(crate) async fn run(recert_config: &RecertConfig, cluster_crypto: &mut ClusterCryptoObjects) -> Result<RunTimes> {
    ensure_openssl_version().context("checking openssl version compatibility")?;

    let (in_memory_etcd_client, encryption_customizations) = setup_etcd_client(recert_config).await?;

    let recertify_timing = if !recert_config.postprocess_only {
        recertify(
            cluster_crypto,
            Arc::clone(&in_memory_etcd_client),
            &recert_config.crypto_customizations,
        )
        .await
        .context("scanning and recertification")?
    } else {
        RecertifyTiming::immediate()
    };

    let finalize_timing = finalize(
        Arc::clone(&in_memory_etcd_client),
        cluster_crypto,
        &recert_config.cluster_customizations,
        encryption_customizations,
        recert_config.regenerate_server_ssh_keys.as_deref(),
        recert_config.dry_run,
        recert_config.etcd_defrag,
    )
    .await
    .context("finalizing")?;

    Ok(combine_timings(recertify_timing, finalize_timing))
}

async fn is_encryption_enabled(in_memory_etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<bool> {
    let k8s_location = K8sResourceLocation::new(None, "APIServer", "cluster", "config.openshift.io/v1");

    let cluster = get_etcd_json(in_memory_etcd_client, &k8s_location)
        .await?
        .context(format!("could not get {}", k8s_location))?;

    if let Some(encryption_type) = cluster.pointer("/spec/encryption/type") {
        let encryption_type = encryption_type.as_str().context("spec.encryption.type not a string")?;

        Ok(encryption_type == "aescbc" || encryption_type == "aesgcm")
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

async fn get_apiserver_encryption_type(in_memory_etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<String> {
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

async fn setup_etcd_client(recert_config: &RecertConfig) -> Result<(Arc<InMemoryK8sEtcd>, Option<EncryptionCustomizations>)> {
    let mut in_memory_etcd_client = get_etcd_endpoint(recert_config, None, None).await?;

    log::info!("Connected to etcd");

    let mut encryption_customizations: Option<EncryptionCustomizations> = None;

    if is_encryption_enabled(&in_memory_etcd_client).await? {
        let decrypt_resource_transformers = build_decryption_transformers(recert_config, &mut in_memory_etcd_client).await?;

        let encryption_type = get_apiserver_encryption_type(&in_memory_etcd_client).await?;

        log::info!("OpenShift etcd encryption type {} detected", encryption_type);

        let customizations = build_encryption_customizations(recert_config, encryption_type).await?;
        let encrypt_resource_transformers = build_encryption_transformers(&customizations).await?;

        encryption_customizations = Some(customizations);
        in_memory_etcd_client = get_etcd_endpoint(
            recert_config,
            Some(decrypt_resource_transformers.clone()),
            Some(encrypt_resource_transformers.clone()),
        )
        .await?;
    }

    Ok((in_memory_etcd_client, encryption_customizations))
}

async fn build_decryption_transformers(
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

async fn build_encryption_customizations(recert_config: &RecertConfig, encryption_type: String) -> Result<EncryptionCustomizations> {
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

async fn build_encryption_transformers(encryption_customizations: &EncryptionCustomizations) -> Result<ResourceTransformers> {
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

async fn get_etcd_endpoint(
    recert_config: &RecertConfig,
    decrypt_resource_transformers: Option<ResourceTransformers>,
    encrypt_resource_transformers: Option<ResourceTransformers>,
) -> Result<Arc<InMemoryK8sEtcd>> {
    let in_memory_etcd_client = Arc::new(InMemoryK8sEtcd::new(
        match &recert_config.etcd_endpoint {
            Some(etcd_endpoint) => Some(
                EtcdClient::connect([etcd_endpoint.as_str()], None)
                    .await
                    .context("connecting to etcd")?,
            ),
            None => None,
        },
        decrypt_resource_transformers,
        encrypt_resource_transformers,
    ));

    Ok(in_memory_etcd_client)
}

async fn recertify(
    cluster_crypto: &mut ClusterCryptoObjects,
    in_memory_etcd_client: Arc<InMemoryK8sEtcd>,
    crypto_customizations: &CryptoCustomizations,
) -> Result<RecertifyTiming> {
    let external_certs = if in_memory_etcd_client.etcd_client.is_some() {
        scanning::external_certs::discover_external_certs(Arc::clone(&in_memory_etcd_client))
            .await
            .context("discovering external certs to ignore")?
    } else {
        HashSet::new()
    };

    log::info!("Discovered {} external certificates to ignore", external_certs.len());

    // We want to scan the etcd and the filesystem in parallel to generating RSA keys as both take
    // a long time and are independent
    let all_discovered_crypto_objects = tokio::spawn(scanning::crypto_scan(
        in_memory_etcd_client,
        crypto_customizations.dirs.clone(),
        crypto_customizations.files.clone(),
        external_certs.clone(),
    ));
    let rsa_keys = tokio::spawn(fill_keys());

    // Wait for the parallelizable tasks to finish and get their results
    let (scan_run_time, all_discovered_crypto_objects) = all_discovered_crypto_objects.await?.context("scanning etcd/filesystem")?;
    let (rsa_run_time, rsa_pool) = rsa_keys.await?.context("generating rsa keys")?;

    // We discovered all crypto objects, process them
    let start = std::time::Instant::now();
    cluster_crypto
        .process_objects(all_discovered_crypto_objects, crypto_customizations, rsa_pool)
        .context("processing discovered objects")?;
    let processing_run_time = RunTime::since_start(start);

    Ok(RecertifyTiming {
        scan_run_time,
        rsa_run_time,
        processing_run_time,
    })
}

async fn fill_keys() -> Result<(RunTime, rsa_key_pool::RsaKeyPool)> {
    log::info!("Generating RSA keys");
    let start_time = std::time::Instant::now();
    let pool = rsa_key_pool::RsaKeyPool::fill(120, 10).await?;
    log::info!("Generated {} RSA keys", pool.len());
    Ok((RunTime::since_start(start_time), pool))
}

async fn finalize(
    in_memory_etcd_client: Arc<InMemoryK8sEtcd>,
    cluster_crypto: &mut ClusterCryptoObjects,
    cluster_customizations: &ClusterCustomizations,
    encryption_customizations: Option<EncryptionCustomizations>,
    regenerate_server_ssh_keys: Option<&Path>,
    dry_run: bool,
    etcd_defrag: bool,
) -> Result<FinalizeTiming> {
    log::info!("Committing cryptographic objects to etcd and disk");

    let start = std::time::Instant::now();
    cluster_crypto
        .commit_to_etcd_and_disk(&in_memory_etcd_client)
        .await
        .context("commiting the cryptographic objects back to memory etcd and to disk")?;
    let commit_to_etcd_and_disk_run_time = RunTime::since_start(start);

    log::info!("Performing OCP post-processing and rename");

    let start = std::time::Instant::now();
    if in_memory_etcd_client.etcd_client.is_some() {
        ocp_postprocess(&in_memory_etcd_client, cluster_customizations)
            .await
            .context("performing ocp specific post-processing")?;

        if let Some(encryption_customizations) = encryption_customizations {
            encryption_config::rename_all(
                &in_memory_etcd_client,
                &encryption_customizations,
                &cluster_customizations.dirs,
                &cluster_customizations.files,
            )
            .await
            .context("renaming all")?;

            in_memory_etcd_client
                .reencrypt_resources()
                .await
                .context("re-encrypting resources")?;
        }
    }
    let ocp_postprocessing_run_time = RunTime::since_start(start);

    if let Some(regenerate_server_ssh_keys) = regenerate_server_ssh_keys {
        server_ssh_keys::write_new_keys(
            regenerate_server_ssh_keys,
            server_ssh_keys::remove_old_keys(regenerate_server_ssh_keys).context("removing old server SSH keys")?,
        )
        .context("regenerating new server SSH keys")?;
    }

    let start = std::time::Instant::now();

    log::info!("Committing to actual etcd");

    // Since we're using an in-memory fake etcd, we need to also commit the changes to the real
    // etcd after we're done (unless we're doing a dry run)
    if !dry_run {
        in_memory_etcd_client
            .commit_to_actual_etcd()
            .await
            .context("commiting etcd cache to actual etcd")?;
    }

    // in case etcd maintenance flag was set we gonna run it after finishing all etcd work
    if etcd_defrag {
        log::info!("Defragmenting etcd");
        in_memory_etcd_client.defragment().await.context("defragmenting etcd")?;
    }

    let commit_to_actual_etcd_run_time = RunTime::since_start(start);

    Ok(FinalizeTiming {
        commit_to_etcd_and_disk_run_time,
        ocp_postprocessing_run_time,
        commit_to_actual_etcd_run_time,
    })
}
