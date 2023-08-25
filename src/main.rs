use crate::{cluster_crypto::scanning, ocp_postprocess::cluster_domain_rename::params::ClusterRenameParameters};
use anyhow::{Context, Result};
use clap::Parser;
use cluster_crypto::ClusterCryptoObjects;
use cnsanreplace::CnSanReplaceRules;
use etcd_client::Client as EtcdClient;
use k8s_etcd::InMemoryK8sEtcd;
use std::{path::PathBuf, sync::Arc};
use use_cert::UseCertRules;
use use_key::UseKeyRules;

mod cli;
mod cluster_crypto;
mod cnsanreplace;
mod file_utils;
mod json_tools;
mod k8s_etcd;
mod ocp_postprocess;
mod rsa_key_pool;
mod rules;
mod use_cert;
mod use_key;

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() -> Result<()> {
    let args = cli::Cli::parse();
    main_internal(args).await
}

async fn main_internal(args: cli::Cli) -> Result<()> {
    let (static_dirs, mut cluster_crypto, memory_etcd, cn_san_replace_rules, use_key_rules, use_cert_rules, cluster_rename) =
        init(args).await.context("initializing")?;

    recertify(
        Arc::clone(&memory_etcd),
        &mut cluster_crypto,
        static_dirs.clone(),
        cn_san_replace_rules,
        use_key_rules,
        use_cert_rules,
    )
    .await
    .context("scanning and recertification")?;

    finalize(memory_etcd, &mut cluster_crypto, cluster_rename, static_dirs)
        .await
        .context("finalizing")?;

    cluster_crypto.display();

    Ok(())
}

async fn init(
    cli: cli::Cli,
) -> Result<(
    Vec<PathBuf>,
    ClusterCryptoObjects,
    Arc<InMemoryK8sEtcd>,
    CnSanReplaceRules,
    UseKeyRules,
    UseCertRules,
    Option<ClusterRenameParameters>,
)> {
    let etcd_client = EtcdClient::connect([cli.etcd_endpoint.as_str()], None)
        .await
        .context("connecting to etcd")?;

    // The main data structure for recording all crypto objects
    let cluster_crypto = ClusterCryptoObjects::new();

    // The in-memory etcd client, used for performance through caching etcd access
    let in_memory_etcd_client = Arc::new(InMemoryK8sEtcd::new(etcd_client));

    // User provided certificate CN/SAN domain name replacement rules
    let cn_san_replace_rules = CnSanReplaceRules::try_from(cli.cn_san_replace).context("parsing cli cn-san-replace")?;

    // User provided keys for particular CNs, when the user wants to use existing keys instead of
    // generating new ones
    let use_key_rules = UseKeyRules::try_from(cli.use_key).context("parsing cli use-key")?;

    // User provided keys for particular CNs, when the user wants to use existing keys instead of
    // generating new ones
    let use_cert_rules = UseCertRules::try_from(cli.use_cert).context("parsing cli use-key")?;

    Ok((
        cli.static_dir,
        cluster_crypto,
        in_memory_etcd_client,
        cn_san_replace_rules,
        use_key_rules,
        use_cert_rules,
        if let Some(cluster_rename) = cli.cluster_rename {
            Some(ClusterRenameParameters::try_from(cluster_rename)?)
        } else {
            None
        },
    ))
}

async fn recertify(
    in_memory_etcd_client: Arc<InMemoryK8sEtcd>,
    cluster_crypto: &mut ClusterCryptoObjects,
    static_dirs: Vec<PathBuf>,
    cn_san_replace_rules: CnSanReplaceRules,
    use_key_rules: UseKeyRules,
    use_cert_rules: UseCertRules,
) -> Result<()> {
    // We want to scan the etcd and the filesystem in parallel to generating RSA keys as both take
    // a long time and are independent
    let all_discovered_crypto_objects = tokio::spawn(scanning::crypto_scan(in_memory_etcd_client, static_dirs));
    let rsa_keys = tokio::spawn(rsa_key_pool::RsaKeyPool::fill(300, 20));

    // Wait for the parallelizable tasks to finish and get their results
    let all_discovered_crypto_objects = all_discovered_crypto_objects.await?.context("scanning etcd/filesystem")?;
    let rsa_pool = rsa_keys.await?.context("generating rsa keys")?;

    // We discovered all crypto objects, process them
    cluster_crypto
        .process_objects(
            all_discovered_crypto_objects,
            cn_san_replace_rules,
            use_key_rules,
            use_cert_rules,
            rsa_pool,
        )
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
    ocp_postprocess(&in_memory_etcd_client, cluster_rename, static_dirs)
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

/// Perform some OCP-related post-processing to make some OCP operators happy
async fn ocp_postprocess(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    cluster_rename: Option<ClusterRenameParameters>,
    static_dirs: Vec<PathBuf>,
) -> Result<()> {
    ocp_postprocess::fix_olm_secret_hash_annotation(in_memory_etcd_client)
        .await
        .context("fixing olm secret hash annotation")?;

    if let Some(cluster_rename) = cluster_rename {
        ocp_postprocess::cluster_rename(in_memory_etcd_client, cluster_rename, static_dirs)
            .await
            .context("renaming cluster")?;
    }

    Ok(())
}
