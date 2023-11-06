use crate::{cluster_crypto::scanning, ocp_postprocess::cluster_domain_rename::params::ClusterRenameParameters};
use anyhow::{Context, Result};
use cli::{Customizations, ParsedCLI};
use clio::ClioPath;
use cluster_crypto::{ClusterCryptoObjects, REDACT_SECRETS};
use etcd_client::Client as EtcdClient;
use k8s_etcd::InMemoryK8sEtcd;
use std::{
    path::Path,
    sync::{atomic::Ordering::Relaxed, Arc},
};

mod cli;
mod cluster_crypto;
mod cnsanreplace;
mod etcd_encoding;
mod file_utils;
mod json_tools;
mod k8s_etcd;
mod ocp_postprocess;
mod protobuf_gen;
mod rsa_key_pool;
mod rules;
mod runtime;
mod server_ssh_keys;
mod use_cert;
mod use_key;

fn main() -> Result<()> {
    let parsed_cli = cli::parse_cli().context("parsing CLI")?;
    runtime::prepare_tokio_runtime(parsed_cli.threads)?.block_on(async { main_internal(parsed_cli).await })
}

async fn main_internal(parsed_cli: ParsedCLI) -> Result<()> {
    let mut cluster_crypto = ClusterCryptoObjects::new();
    file_utils::DRY_RUN.store(parsed_cli.dry_run, Relaxed);
    let run_result = run(&parsed_cli, &mut cluster_crypto).await;

    generate_summary(parsed_cli.summary_file, cluster_crypto, parsed_cli.summary_file_clean)?;

    run_result
}

async fn run(parsed_cli: &ParsedCLI, cluster_crypto: &mut ClusterCryptoObjects) -> std::result::Result<(), anyhow::Error> {
    let in_memory_etcd_client = Arc::new(InMemoryK8sEtcd::new(match &parsed_cli.etcd_endpoint {
        Some(etcd_endpoint) => Some(
            EtcdClient::connect([etcd_endpoint.as_str()], None)
                .await
                .context("connecting to etcd")?,
        ),
        None => None,
    }));

    recertify(
        cluster_crypto,
        Arc::clone(&in_memory_etcd_client),
        parsed_cli.static_dirs.clone(),
        parsed_cli.static_files.clone(),
        &parsed_cli.customizations,
    )
    .await
    .context("scanning and recertification")?;

    finalize(
        in_memory_etcd_client,
        cluster_crypto,
        &parsed_cli.cluster_rename,
        &parsed_cli.static_dirs,
        &parsed_cli.static_files,
        parsed_cli.regenerate_server_ssh_keys.as_deref(),
        parsed_cli.dry_run,
    )
    .await
    .context("finalizing")?;

    Ok(())
}

async fn recertify(
    cluster_crypto: &mut ClusterCryptoObjects,
    in_memory_etcd_client: Arc<InMemoryK8sEtcd>,
    static_dirs: Vec<ClioPath>,
    static_files: Vec<ClioPath>,
    customizations: &Customizations,
) -> Result<()> {
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

    // We discovered all crypto objects, process them
    cluster_crypto
        .process_objects(all_discovered_crypto_objects, customizations, rsa_pool)
        .context("processing discovered objects")?;

    Ok(())
}

async fn finalize(
    in_memory_etcd_client: Arc<InMemoryK8sEtcd>,
    cluster_crypto: &mut ClusterCryptoObjects,
    cluster_rename: &Option<ClusterRenameParameters>,
    static_dirs: &Vec<ClioPath>,
    static_files: &Vec<ClioPath>,
    regenerate_server_ssh_keys: Option<&Path>,
    dry_run: bool,
) -> Result<()> {
    cluster_crypto
        .commit_to_etcd_and_disk(&in_memory_etcd_client)
        .await
        .context("commiting the cryptographic objects back to memory etcd and to disk")?;

    if in_memory_etcd_client.etcd_client.is_some() {
        ocp_postprocess::ocp_postprocess(&in_memory_etcd_client, cluster_rename, static_dirs, static_files)
            .await
            .context("performing ocp specific post-processing")?;
    }

    if let Some(regenerate_server_ssh_keys) = regenerate_server_ssh_keys {
        server_ssh_keys::write_new_keys(
            regenerate_server_ssh_keys,
            server_ssh_keys::remove_old_keys(regenerate_server_ssh_keys).context("removing old server SSH keys")?,
        )
        .context("regenerating new server SSH keys")?;
    }

    // Since we're using an in-memory fake etcd, we need to also commit the changes to the real
    // etcd after we're done (unless we're doing a dry run)
    if !dry_run {
        in_memory_etcd_client
            .commit_to_actual_etcd()
            .await
            .context("commiting etcd cache to actual etcd")?;
    }

    Ok(())
}

fn generate_summary(
    summary_file: Option<ClioPath>,
    cluster_crypto: ClusterCryptoObjects,
    summary_file_clean: Option<ClioPath>,
) -> Result<()> {
    if let Some(summary_file) = summary_file {
        let summary_file = summary_file.create().context("opening summary file for writing")?;
        serde_yaml::to_writer(summary_file, &cluster_crypto).context("serializing cluster crypto into summary file")?;
    }
    if let Some(summary_file_clean) = summary_file_clean {
        let summary_file_clean = summary_file_clean.create().context("opening summary file for writing")?;

        REDACT_SECRETS.store(true, Relaxed);
        serde_yaml::to_writer(summary_file_clean, &cluster_crypto).context("serializing cluster crypto into summary file")?;
        REDACT_SECRETS.store(false, Relaxed);
    };
    Ok(())
}
