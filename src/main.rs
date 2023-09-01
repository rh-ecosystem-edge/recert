use crate::{cluster_crypto::scanning, ocp_postprocess::cluster_domain_rename::params::ClusterRenameParameters};
use anyhow::{Context, Result};
use cli::{Customizations, ParsedCLI};
use cluster_crypto::ClusterCryptoObjects;
use etcd_client::Client as EtcdClient;
use k8s_etcd::InMemoryK8sEtcd;
use std::{path::PathBuf, sync::Arc};

mod cli;
mod cluster_crypto;
mod cnsanreplace;
mod file_utils;
mod json_tools;
mod k8s_etcd;
mod ocp_postprocess;
mod rsa_key_pool;
mod rules;
mod runtime;
mod use_cert;
mod use_key;

fn main() -> Result<()> {
    let parsed_cli = cli::parse_cli().context("parsing CLI")?;
    runtime::prepare_tokio_runtime(parsed_cli.threads)?.block_on(async { main_internal(parsed_cli).await })
}

async fn main_internal(mut parsed_cli: ParsedCLI) -> Result<()> {
    let etcd_client = EtcdClient::connect([parsed_cli.etcd_endpoint.as_str()], None)
        .await
        .context("connecting to etcd")?;
    let in_memory_etcd_client = Arc::new(InMemoryK8sEtcd::new(etcd_client));

    recertify(
        Arc::clone(&in_memory_etcd_client),
        &mut parsed_cli.cluster_crypto,
        parsed_cli.static_dirs.clone(),
        parsed_cli.customizations,
    )
    .await
    .context("scanning and recertification")?;

    finalize(
        in_memory_etcd_client,
        &mut parsed_cli.cluster_crypto,
        parsed_cli.cluster_rename,
        parsed_cli.static_dirs,
    )
    .await
    .context("finalizing")?;

    parsed_cli.cluster_crypto.display();

    Ok(())
}

async fn recertify(
    in_memory_etcd_client: Arc<InMemoryK8sEtcd>,
    cluster_crypto: &mut ClusterCryptoObjects,
    static_dirs: Vec<PathBuf>,
    customizations: Customizations,
) -> Result<()> {
    scanning::discover_external_certs(Arc::clone(&in_memory_etcd_client))
        .await
        .context("discovering external certs to ignore")?;

    // We want to scan the etcd and the filesystem in parallel to generating RSA keys as both take
    // a long time and are independent
    let all_discovered_crypto_objects = tokio::spawn(scanning::crypto_scan(in_memory_etcd_client, static_dirs));
    let rsa_keys = tokio::spawn(rsa_key_pool::RsaKeyPool::fill(300, 20));

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
    cluster_rename: Option<ClusterRenameParameters>,
    static_dirs: Vec<PathBuf>,
) -> Result<()> {
    cluster_crypto
        .commit_to_etcd_and_disk(&in_memory_etcd_client)
        .await
        .context("commiting the cryptographic objects back to memory etcd and to disk")?;

    ocp_postprocess::ocp_postprocess(&in_memory_etcd_client, cluster_rename, static_dirs)
        .await
        .context("performing ocp specific post-processing")?;

    // Since we're using an in-memory fake etcd, we need to also commit the changes to the real
    // etcd after we're done
    in_memory_etcd_client
        .commit_to_actual_etcd()
        .await
        .context("commiting etcd cache to actual etcd")?;

    Ok(())
}
