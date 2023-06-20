use crate::cluster_crypto::scanning;
use anyhow::{Context, Result};
use clap::Parser;
use cluster_crypto::ClusterCryptoObjects;
use cnsanreplace::CnSanReplaceRules;
use etcd_client::Client as EtcdClient;
use k8s_etcd::InMemoryK8sEtcd;
use std::{path::PathBuf, sync::Arc};

mod cluster_crypto;
mod cnsanreplace;
mod file_utils;
mod json_tools;
mod k8s_etcd;
mod ocp_postprocess;
mod rsa_key_pool;
mod rules;

/// A program to regenerate cluster certificates, keys and tokens
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // etcd endpoint to recertify
    #[arg(short, long)]
    etcd_endpoint: String,

    /// Directory to recertifiy, such as /var/lib/kubelet, /etc/kubernetes and /etc/machine-config-daemon. Can specify multiple times
    #[arg(short, long)]
    static_dir: Vec<PathBuf>,

    /// Optionally, your kubeconfig so its cert/keys can be regenerated as well and you can still
    /// log in after recertification
    #[arg(short, long)]
    kubeconfig: Option<PathBuf>,

    /// A list of strings to replace in the subject name of all certificates. Can specify multiple.
    /// Must come in pairs of old and new values, separated by a space. For example:
    /// --cn-san-replace "foo bar" --cn-san-replace "baz qux" will replace all instances of "foo"
    /// with "bar" and all instances of "baz" with "qux" in the CN/SAN of all certificates.
    #[arg(short, long)]
    cn_san_replace: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    main_internal(args).await
}

async fn main_internal(args: Args) -> Result<()> {
    let (kubeconfig, static_dirs, mut cluster_crypto, memory_etcd, cn_san_replace_rules) = init(args).await.context("initializing")?;

    // Scanning and recertification
    recertify(
        Arc::clone(&memory_etcd),
        &mut cluster_crypto,
        kubeconfig,
        static_dirs,
        cn_san_replace_rules,
    )
    .await
    .context("recertification")?;

    // Apply changes
    finalize(memory_etcd, &mut cluster_crypto).await.context("finalization")?;

    // Log
    print_summary(cluster_crypto).await;

    Ok(())
}

async fn init(
    args: Args,
) -> Result<(
    Option<PathBuf>,
    Vec<PathBuf>,
    ClusterCryptoObjects,
    Arc<InMemoryK8sEtcd>,
    CnSanReplaceRules,
)> {
    let etcd_client = EtcdClient::connect([args.etcd_endpoint.as_str()], None).await?;

    let kubeconfig = args.kubeconfig;
    let cluster_crypto = ClusterCryptoObjects::new();
    let in_memory_etcd_client = Arc::new(InMemoryK8sEtcd::new(etcd_client));

    let cn_san_replace_rules = CnSanReplaceRules::try_from(args.cn_san_replace).context("parsing cli cn-san-replace")?;

    Ok((
        kubeconfig,
        args.static_dir,
        cluster_crypto,
        in_memory_etcd_client,
        cn_san_replace_rules,
    ))
}

async fn recertify(
    in_memory_etcd_client: Arc<InMemoryK8sEtcd>,
    cluster_crypto: &mut ClusterCryptoObjects,
    kubeconfig: Option<PathBuf>,
    static_dirs: Vec<PathBuf>,
    cn_san_replace_rules: CnSanReplaceRules,
) -> Result<()> {
    // Perform parallelizable tasks like generating raw RSA keys to be used later and scanning for
    // crypto objeccts
    println!("Scanning etcd/filesystem... This might take a while");
    let all_discovered_crypto_objects = tokio::spawn(scanning::crypto_scan(in_memory_etcd_client, static_dirs, kubeconfig));
    let rsa_keys = tokio::spawn(rsa_key_pool::RsaKeyPool::fill(300));

    // Wait for the parallelizable tasks to finish and get their results
    let all_discovered_crypto_objects = all_discovered_crypto_objects.await?.context("scanning")?;
    println!("Scanning complete, waiting for random key generation to complete...");
    let rsa_pool = rsa_keys.await?.context("rsa key generation")?;
    println!("Key generation complete");

    println!("Registering discovered crypto objects...");
    cluster_crypto.register_discovered_crypto_objects(all_discovered_crypto_objects);

    println!("Establishing relationships...");
    establish_relationships(cluster_crypto).await.context("relationships")?;

    println!("Regenerating cryptographic objects...");
    cluster_crypto
        .regenerate_crypto(rsa_pool, cn_san_replace_rules)
        .context("regeneration")?;

    Ok(())
}

async fn finalize(in_memory_etcd_client: Arc<InMemoryK8sEtcd>, cluster_crypto: &mut ClusterCryptoObjects) -> Result<()> {
    // Commit the cryptographic objects back to memory etcd and to disk
    commit_cryptographic_objects_back(&in_memory_etcd_client, cluster_crypto).await?;
    ocp_postprocess(&in_memory_etcd_client).await?;

    // Since we're using an in-memory fake etcd, we need to also commit the changes to the real
    // etcd after we're done
    println!("Committing to etcd...");
    in_memory_etcd_client.commit_to_actual_etcd().await
}

async fn print_summary(cluster_crypto: ClusterCryptoObjects) {
    println!("Crypto graph...");
    cluster_crypto.display();
}

async fn commit_cryptographic_objects_back(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    cluster_crypto: &mut ClusterCryptoObjects,
) -> Result<()> {
    println!("Committing changes...");
    let etcd_client = in_memory_etcd_client;
    cluster_crypto.commit_to_etcd_and_disk(&etcd_client).await
}

/// Perform some OCP-related post-processing to make some OCP operators happy
async fn ocp_postprocess(in_memory_etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<()> {
    println!("OCP postprocessing...");
    ocp_postprocess::fix_olm_secret_hash_annotation(in_memory_etcd_client).await
}

async fn establish_relationships(cluster_crypto: &mut ClusterCryptoObjects) -> Result<()> {
    println!("- Pairing certs and keys...");
    cluster_crypto.pair_certs_and_keys()?;
    println!("- Calculating cert signers...");
    cluster_crypto.fill_cert_key_signers()?;
    println!("- Calculating jwt signers...");
    cluster_crypto.fill_jwt_signers()?;
    println!("- Calculating signees...");
    cluster_crypto.fill_signees()?;
    println!("- Associating standalone public keys...");
    cluster_crypto.associate_public_keys()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_init() -> Result<()> {
        let args = super::Args {
            etcd_endpoint: "http://localhost:2379".to_string(),
            static_dir: vec![
                PathBuf::from("./cluster-files/kubernetes"),
                PathBuf::from("./cluster-files/machine-config-daemon"),
                PathBuf::from("./cluster-files/kubelet"),
            ],
            kubeconfig: None,
            cn_san_replace: vec![
                "api-int.test-cluster.redhat.com api-int.test-cluster2.redhat.com".to_string(),
                "api.test-cluster.redhat.com api.test-cluster2.redhat.com".to_string(),
                "*.apps.test-cluster.redhat.com *.apps.test-cluster2.redhat.com".to_string(),
            ],
        };

        main_internal(args).await
    }
}
