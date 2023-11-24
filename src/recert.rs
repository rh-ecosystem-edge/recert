use crate::{
    cluster_crypto::{scanning, ClusterCryptoObjects},
    config::{ConfigPath, Customizations, RecertConfig},
    k8s_etcd::InMemoryK8sEtcd,
    ocp_postprocess::{cluster_domain_rename::params::ClusterRenameParameters, ocp_postprocess},
    rsa_key_pool, server_ssh_keys,
};
use anyhow::{Context, Result};
use etcd_client::Client as EtcdClient;
use std::{path::Path, sync::Arc};

#[derive(Clone)]
struct RunTime {
    start: std::time::Instant,
    end: std::time::Instant,
}

impl serde::Serialize for RunTime {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let duration = self.end - self.start;
        serializer.serialize_str(&format!("{}.{:03}s", duration.as_secs(), duration.subsec_millis()))
    }
}

#[derive(serde::Serialize, Clone)]
pub(crate) struct RunTimes {
    rsa_key_pool_and_scanning_run_time: RunTime,
    processing_run_time: RunTime,
    commit_to_etcd_and_disk_run_time: RunTime,
    ocp_postprocessing_run_time: RunTime,
    commit_to_actual_etcd_run_time: RunTime,
}

pub(crate) async fn run(
    parsed_cli: &RecertConfig,
    cluster_crypto: &mut ClusterCryptoObjects,
) -> std::result::Result<RunTimes, anyhow::Error> {
    let in_memory_etcd_client = Arc::new(InMemoryK8sEtcd::new(match &parsed_cli.etcd_endpoint {
        Some(etcd_endpoint) => Some(
            EtcdClient::connect([etcd_endpoint.as_str()], None)
                .await
                .context("connecting to etcd")?,
        ),
        None => None,
    }));

    let (rsa_key_pool_and_scanning_run_time, processing_run_time) = recertify(
        cluster_crypto,
        Arc::clone(&in_memory_etcd_client),
        parsed_cli.static_dirs.clone(),
        parsed_cli.static_files.clone(),
        &parsed_cli.customizations,
    )
    .await
    .context("scanning and recertification")?;

    let (commit_to_etcd_and_disk_run_time, ocp_postprocessing_run_time, commit_to_actual_etcd_run_time) = finalize(
        Arc::clone(&in_memory_etcd_client),
        cluster_crypto,
        &parsed_cli.cluster_rename,
        &parsed_cli.static_dirs,
        &parsed_cli.static_files,
        parsed_cli.regenerate_server_ssh_keys.as_deref(),
        parsed_cli.dry_run,
    )
    .await
    .context("finalizing")?;

    Ok(RunTimes {
        rsa_key_pool_and_scanning_run_time,
        processing_run_time,
        commit_to_etcd_and_disk_run_time,
        ocp_postprocessing_run_time,
        commit_to_actual_etcd_run_time,
    })
}

async fn recertify(
    cluster_crypto: &mut ClusterCryptoObjects,
    in_memory_etcd_client: Arc<InMemoryK8sEtcd>,
    static_dirs: Vec<ConfigPath>,
    static_files: Vec<ConfigPath>,
    customizations: &Customizations,
) -> Result<(RunTime, RunTime)> {
    let start = std::time::Instant::now();
    if in_memory_etcd_client.etcd_client.is_some() {
        scanning::discover_external_certs(Arc::clone(&in_memory_etcd_client))
            .await
            .context("discovering external certs to ignore")?;
    }

    // We want to scan the etcd and the filesystem in parallel to generating RSA keys as both take
    // a long time and are independent
    let all_discovered_crypto_objects = tokio::spawn(scanning::crypto_scan(in_memory_etcd_client, static_dirs, static_files));
    let rsa_keys = tokio::spawn(rsa_key_pool::RsaKeyPool::fill(120, 10));

    // Wait for the parallelizable tasks to finish and get their results
    let all_discovered_crypto_objects = all_discovered_crypto_objects.await?.context("scanning etcd/filesystem")?;
    let rsa_pool = rsa_keys.await?.context("generating rsa keys")?;

    let end = std::time::Instant::now();

    let rsa_key_pool_and_scanning_run_time = RunTime { start, end };

    // We discovered all crypto objects, process them
    let start = std::time::Instant::now();
    cluster_crypto
        .process_objects(all_discovered_crypto_objects, customizations, rsa_pool)
        .context("processing discovered objects")?;
    let end = std::time::Instant::now();

    let processing_run_time = RunTime { start, end };

    Ok((rsa_key_pool_and_scanning_run_time, processing_run_time))
}

async fn finalize(
    in_memory_etcd_client: Arc<InMemoryK8sEtcd>,
    cluster_crypto: &mut ClusterCryptoObjects,
    cluster_rename: &Option<ClusterRenameParameters>,
    static_dirs: &Vec<ConfigPath>,
    static_files: &Vec<ConfigPath>,
    regenerate_server_ssh_keys: Option<&Path>,
    dry_run: bool,
) -> Result<(RunTime, RunTime, RunTime)> {
    let start = std::time::Instant::now();
    cluster_crypto
        .commit_to_etcd_and_disk(&in_memory_etcd_client)
        .await
        .context("commiting the cryptographic objects back to memory etcd and to disk")?;
    let end = std::time::Instant::now();
    let commit_to_etcd_and_disk_run_time = RunTime { start, end };

    let start = std::time::Instant::now();
    if in_memory_etcd_client.etcd_client.is_some() {
        ocp_postprocess(&in_memory_etcd_client, cluster_rename, static_dirs, static_files)
            .await
            .context("performing ocp specific post-processing")?;
    }
    let end = std::time::Instant::now();

    let ocp_postprocessing_run_time = RunTime { start, end };

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

    let end = std::time::Instant::now();

    let commit_to_actual_etcd_run_time = RunTime { start, end };

    Ok((
        commit_to_etcd_and_disk_run_time,
        ocp_postprocessing_run_time,
        commit_to_actual_etcd_run_time,
    ))
}
