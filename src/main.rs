use crate::{cluster_crypto::scanning, ocp_postprocess::cluster_domain_rename::params::ClusterRenameParameters};
use anyhow::{Context, Result};
use clap::Parser;
use cluster_crypto::{locations::K8sResourceLocation, ClusterCryptoObjects};
use cnsanreplace::CnSanReplaceRules;
use etcd_client::Client as EtcdClient;
use k8s_etcd::{get_etcd_yaml, InMemoryK8sEtcd};
use std::{path::PathBuf, sync::Arc};
use use_cert::UseCertRules;
use use_key::UseKeyRules;
use x509_certificate::X509Certificate;

mod cli;
mod cluster_crypto;
mod cnsanreplace;
mod file_utils;
mod json_tools;
mod k8s_etcd;
mod ocp_postprocess;
mod rsa_key_pool;
mod rules;
mod ulimit;
mod use_cert;
mod use_key;

/// All the user requested customizations, coalesced into a single struct for convenience
pub(crate) struct Customizations {
    cn_san_replace_rules: CnSanReplaceRules,
    use_key_rules: UseKeyRules,
    use_cert_rules: UseCertRules,
    extend_expiration: bool,
}

/// All parsed CLI arguments, coalesced into a single struct for convenience
struct Recert {
    etcd_endpoint: String,
    static_dirs: Vec<PathBuf>,
    cluster_crypto: ClusterCryptoObjects,
    customizations: Customizations,
    cluster_rename: Option<ClusterRenameParameters>,
    threads: Option<usize>,
}

fn main() -> Result<()> {
    // Set the max open files limit to the maximum allowed by the kernel
    ulimit::set_max_open_files_limit();

    let recert = init(cli::Cli::parse()).context("initializing")?;
    prepare_tokio_runtime(&recert)?.block_on(async { main_internal(recert).await })
}

fn prepare_tokio_runtime(recert: &Recert) -> Result<tokio::runtime::Runtime> {
    Ok(if let Some(threads) = recert.threads {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(threads)
            .enable_all()
            .build()
            .context("building tokio runtime")?
    } else {
        tokio::runtime::Runtime::new()?
    })
}

async fn main_internal(mut recert: Recert) -> Result<()> {
    let etcd_client = EtcdClient::connect([recert.etcd_endpoint.as_str()], None)
        .await
        .context("connecting to etcd")?;
    let in_memory_etcd_client = Arc::new(InMemoryK8sEtcd::new(etcd_client));

    recertify(
        Arc::clone(&in_memory_etcd_client),
        &mut recert.cluster_crypto,
        recert.static_dirs.clone(),
        recert.customizations,
    )
    .await
    .context("scanning and recertification")?;

    finalize(
        in_memory_etcd_client,
        &mut recert.cluster_crypto,
        recert.cluster_rename,
        recert.static_dirs,
    )
    .await
    .context("finalizing")?;

    recert.cluster_crypto.display();

    Ok(())
}

fn init(cli: cli::Cli) -> Result<Recert> {
    let etcd_endpoint = cli.etcd_endpoint;

    let static_dirs = cli.static_dir;

    // The main data structure for recording all crypto objects
    let cluster_crypto = ClusterCryptoObjects::new();

    // User provided certificate CN/SAN domain name replacement rules
    let cn_san_replace_rules = CnSanReplaceRules::try_from(cli.cn_san_replace).context("parsing cli cn-san-replace")?;

    // User provided keys for particular CNs, when the user wants to use existing keys instead of
    // generating new ones
    let use_key_rules = UseKeyRules::try_from(cli.use_key).context("parsing cli use-key")?;

    // User provided keys for particular CNs, when the user wants to use existing keys instead of
    // generating new ones
    let use_cert_rules = UseCertRules::try_from(cli.use_cert).context("parsing cli use-key")?;

    let cluster_rename = if let Some(cluster_rename) = cli.cluster_rename {
        Some(ClusterRenameParameters::try_from(cluster_rename)?)
    } else {
        None
    };

    let extend_expiration = cli.extend_expiration;

    let customizations = Customizations {
        cn_san_replace_rules,
        use_key_rules,
        use_cert_rules,
        extend_expiration,
    };

    let threads = cli.threads;

    Ok(Recert {
        etcd_endpoint,
        static_dirs,
        cluster_crypto,
        customizations,
        cluster_rename,
        threads,
    })
}

async fn get_external_certs(in_memory_etcd_client: Arc<InMemoryK8sEtcd>) -> Result<()> {
    let yaml = get_etcd_yaml(
        &in_memory_etcd_client,
        &K8sResourceLocation {
            namespace: Some("openshift-apiserver-operator".into()),
            kind: "ConfigMap".into(),
            apiversion: "v1".into(),
            name: "trusted-ca-bundle".into(),
        },
    )
    .await
    .context("getting")?;

    let pem_bundle = pem::parse_many(
        yaml.pointer("/data/ca-bundle.crt")
            .context("parsing ca-bundle.crt")?
            .as_str()
            .context("must be string")?,
    )
    .context("parsing ca-bundle.crt")?;

    for pem in pem_bundle {
        if pem.tag() != "CERTIFICATE" {
            continue;
        }

        let crt = X509Certificate::from_der(pem.contents()).context("parsing certificate from ca-bundle.crt")?;
        let cn = crt.subject_name().user_friendly_str().unwrap_or("undecodable".to_string());

        rules::EXTERNAL_CERTS.write().unwrap().insert(cn.to_string());
    }

    Ok(())
}

async fn recertify(
    in_memory_etcd_client: Arc<InMemoryK8sEtcd>,
    cluster_crypto: &mut ClusterCryptoObjects,
    static_dirs: Vec<PathBuf>,
    customizations: Customizations,
) -> Result<()> {
    get_external_certs(Arc::clone(&in_memory_etcd_client)).await?;

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
