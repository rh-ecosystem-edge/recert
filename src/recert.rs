use crate::{
    cluster_crypto::{crypto_utils::ensure_openssl_version, scanning, ClusterCryptoObjects},
    config::{ConfigPath, Customizations, RecertConfig},
    k8s_etcd::InMemoryK8sEtcd,
    ocp_postprocess::{cluster_domain_rename::params::ClusterRenameParameters, ocp_postprocess},
    rsa_key_pool, server_ssh_keys,
};
use anyhow::{Context, Result};
use etcd_client::Client as EtcdClient;
use std::{collections::HashSet, path::Path, sync::Arc};

#[derive(Clone)]
pub(crate) struct RunTime {
    start: std::time::Instant,
    end: std::time::Instant,
}

impl RunTime {
    pub(crate) fn since_start(start: std::time::Instant) -> Self {
        Self {
            start,
            end: std::time::Instant::now(),
        }
    }
}

impl serde::Serialize for RunTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let duration = self.end - self.start;
        serializer.serialize_str(&format!("{}.{:03}s", duration.as_secs(), duration.subsec_millis()))
    }
}

#[derive(serde::Serialize, Clone)]
pub(crate) struct RunTimes {
    scan_run_time: RunTime,
    rsa_run_time: RunTime,
    processing_run_time: RunTime,
    commit_to_etcd_and_disk_run_time: RunTime,
    ocp_postprocessing_run_time: RunTime,
    commit_to_actual_etcd_run_time: RunTime,
}

pub(crate) async fn run(parsed_cli: &RecertConfig, cluster_crypto: &mut ClusterCryptoObjects) -> Result<RunTimes> {
    ensure_openssl_version().context("checking openssl version compatibility")?;

    let in_memory_etcd_client = Arc::new(InMemoryK8sEtcd::new(match &parsed_cli.etcd_endpoint {
        Some(etcd_endpoint) => Some(
            EtcdClient::connect([etcd_endpoint.as_str()], None)
                .await
                .context("connecting to etcd")?,
        ),
        None => None,
    }));

    let (scan_run_time, rsa_run_time, processing_run_time) = recertify(
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
        &parsed_cli.hostname,
        &parsed_cli.ip,
        &parsed_cli.kubeadmin_password_hash,
        &parsed_cli.pull_secret,
        &parsed_cli.static_dirs,
        &parsed_cli.static_files,
        parsed_cli.regenerate_server_ssh_keys.as_deref(),
        parsed_cli.dry_run,
    )
    .await
    .context("finalizing")?;

    Ok(RunTimes {
        scan_run_time,
        rsa_run_time,
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
) -> Result<(RunTime, RunTime, RunTime)> {
    let external_certs = if in_memory_etcd_client.etcd_client.is_some() {
        scanning::discover_external_certs(Arc::clone(&in_memory_etcd_client))
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
        .process_objects(all_discovered_crypto_objects, customizations, rsa_pool)
        .context("processing discovered objects")?;
    let processing_run_time = RunTime::since_start(start);

    Ok((scan_run_time, rsa_run_time, processing_run_time))
}

async fn fill_keys() -> Result<(RunTime, rsa_key_pool::RsaKeyPool)> {
    let start_time = std::time::Instant::now();
    let pool = rsa_key_pool::RsaKeyPool::fill(120, 10).await?;
    Ok((RunTime::since_start(start_time), pool))
}

#[allow(clippy::too_many_arguments)]
async fn finalize(
    in_memory_etcd_client: Arc<InMemoryK8sEtcd>,
    cluster_crypto: &mut ClusterCryptoObjects,
    cluster_rename: &Option<ClusterRenameParameters>,
    hostname: &Option<String>,
    ip: &Option<String>,
    kubeadmin_password_hash: &Option<String>,
    pull_secret: &Option<String>,
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
    let commit_to_etcd_and_disk_run_time = RunTime::since_start(start);

    let start = std::time::Instant::now();
    if in_memory_etcd_client.etcd_client.is_some() {
        ocp_postprocess(
            &in_memory_etcd_client,
            cluster_rename,
            hostname,
            ip,
            kubeadmin_password_hash,
            pull_secret,
            static_dirs,
            static_files,
        )
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

    Ok((
        commit_to_etcd_and_disk_run_time,
        ocp_postprocessing_run_time,
        commit_to_actual_etcd_run_time,
    ))
}
