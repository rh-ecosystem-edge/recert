use crate::{
    cluster_crypto::{crypto_utils::ensure_openssl_version, scanning, ClusterCryptoObjects},
    config::{ClusterCustomizations, ConfigPath, CryptoCustomizations, RecertConfig},
    k8s_etcd::InMemoryK8sEtcd,
    ocp_postprocess::ocp_postprocess,
    rsa_key_pool, server_ssh_keys,
};
use anyhow::{Context, Result};
use etcd_client::Client as EtcdClient;
use std::{collections::HashSet, path::Path, sync::Arc};

use self::timing::{combine_timings, FinalizeTiming, RecertifyTiming, RunTime, RunTimes};

pub(crate) mod timing;

pub(crate) async fn run(recert_config: &RecertConfig, cluster_crypto: &mut ClusterCryptoObjects) -> Result<RunTimes> {
    ensure_openssl_version().context("checking openssl version compatibility")?;

    let in_memory_etcd_client = get_etcd_endpoint(recert_config).await?;

    let recertify_timing = recertify(
        cluster_crypto,
        Arc::clone(&in_memory_etcd_client),
        recert_config.static_dirs.clone(),
        recert_config.static_files.clone(),
        &recert_config.crypto_customizations,
    )
    .await
    .context("scanning and recertification")?;

    let finalize_timing = finalize(
        Arc::clone(&in_memory_etcd_client),
        cluster_crypto,
        &recert_config.cluster_customizations,
        &recert_config.static_dirs,
        &recert_config.static_files,
        recert_config.regenerate_server_ssh_keys.as_deref(),
        recert_config.dry_run,
    )
    .await
    .context("finalizing")?;

    Ok(combine_timings(recertify_timing, finalize_timing))
}

async fn get_etcd_endpoint(recert_config: &RecertConfig) -> Result<Arc<InMemoryK8sEtcd>, anyhow::Error> {
    let in_memory_etcd_client = Arc::new(InMemoryK8sEtcd::new(match &recert_config.etcd_endpoint {
        Some(etcd_endpoint) => Some(
            EtcdClient::connect([etcd_endpoint.as_str()], None)
                .await
                .context("connecting to etcd")?,
        ),
        None => None,
    }));
    Ok(in_memory_etcd_client)
}

async fn recertify(
    cluster_crypto: &mut ClusterCryptoObjects,
    in_memory_etcd_client: Arc<InMemoryK8sEtcd>,
    static_dirs: Vec<ConfigPath>,
    static_files: Vec<ConfigPath>,
    crypto_customizations: &CryptoCustomizations,
) -> Result<RecertifyTiming> {
    let external_certs = if in_memory_etcd_client.etcd_client.is_some() {
        scanning::external_certs::discover_external_certs(Arc::clone(&in_memory_etcd_client))
            .await
            .context("discovering external certs to ignore")?
    } else {
        HashSet::new()
    };

    // We want to scan the etcd and the filesystem in parallel to generating RSA keys as both take
    // a long time and are independent
    let all_discovered_crypto_objects = tokio::spawn(scanning::crypto_scan(
        in_memory_etcd_client,
        static_dirs,
        static_files,
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
    let start_time = std::time::Instant::now();
    let pool = rsa_key_pool::RsaKeyPool::fill(120, 10).await?;
    Ok((RunTime::since_start(start_time), pool))
}

async fn finalize(
    in_memory_etcd_client: Arc<InMemoryK8sEtcd>,
    cluster_crypto: &mut ClusterCryptoObjects,
    cluster_customizations: &ClusterCustomizations,
    static_dirs: &Vec<ConfigPath>,
    static_files: &Vec<ConfigPath>,
    regenerate_server_ssh_keys: Option<&Path>,
    dry_run: bool,
) -> Result<FinalizeTiming> {
    let start = std::time::Instant::now();
    cluster_crypto
        .commit_to_etcd_and_disk(&in_memory_etcd_client)
        .await
        .context("commiting the cryptographic objects back to memory etcd and to disk")?;
    let commit_to_etcd_and_disk_run_time = RunTime::since_start(start);

    let start = std::time::Instant::now();
    if in_memory_etcd_client.etcd_client.is_some() {
        ocp_postprocess(&in_memory_etcd_client, cluster_customizations, static_dirs, static_files)
            .await
            .context("performing ocp specific post-processing")?;
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

    // Since we're using an in-memory fake etcd, we need to also commit the changes to the real
    // etcd after we're done (unless we're doing a dry run)
    if !dry_run {
        in_memory_etcd_client
            .commit_to_actual_etcd()
            .await
            .context("commiting etcd cache to actual etcd")?;
    }

    let commit_to_actual_etcd_run_time = RunTime::since_start(start);

    Ok(FinalizeTiming {
        commit_to_etcd_and_disk_run_time,
        ocp_postprocessing_run_time,
        commit_to_actual_etcd_run_time,
    })
}
