use crate::{
    cluster_crypto::{crypto_utils::ensure_openssl_version, scanning, ClusterCryptoObjects},
    config::{ClusterCustomizations, CryptoCustomizations, EncryptionCustomizations, RecertConfig},
    encrypt::ResourceTransformers,
    k8s_etcd::InMemoryK8sEtcd,
    ocp_postprocess::{encryption_config, ocp_postprocess},
    recert::encrypt_utils::{
        build_decryption_transformers, build_encryption_customizations, build_encryption_transformers, get_apiserver_encryption_type,
        is_encryption_enabled,
    },
    rsa_key_pool, server_ssh_keys,
};
use anyhow::{Context, Result};
use etcd_client::Client as EtcdClient;
use std::{collections::HashSet, path::Path, sync::Arc};

use self::timing::{combine_timings, FinalizeTiming, RecertifyTiming, RunTime, RunTimes};

pub(crate) mod timing;

mod encrypt_utils;

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

async fn setup_etcd_client(recert_config: &RecertConfig) -> Result<(Arc<InMemoryK8sEtcd>, Option<EncryptionCustomizations>)> {
    let mut in_memory_etcd_client = get_etcd_endpoint(recert_config, None, None).await?;

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

    log::info!("Connected to etcd");

    Ok((in_memory_etcd_client, encryption_customizations))
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
