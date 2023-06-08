use crate::cluster_crypto::scanning;
use clap::Parser;
use cluster_crypto::ClusterCryptoObjects;
use etcd_client::Client as EtcdClient;
use k8s_etcd::InMemoryK8sEtcd;
use std::{path::PathBuf, sync::Arc};

mod cluster_crypto;
mod file_utils;
mod json_tools;
mod k8s_etcd;
mod ocp_postprocess;
mod progress;
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
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    main_internal(args).await;
}

async fn main_internal(args: Args) {
    let (kubeconfig, static_dirs, mut cluster_crypto, memory_etcd) = init(args).await;
    recertify(Arc::clone(&memory_etcd), &mut cluster_crypto, kubeconfig, static_dirs).await;
    finalize(memory_etcd, &mut cluster_crypto).await;
    print_summary(cluster_crypto).await;
}

async fn init(args: Args) -> (Option<PathBuf>, Vec<PathBuf>, ClusterCryptoObjects, Arc<InMemoryK8sEtcd>) {
    let etcd_client = EtcdClient::connect([args.etcd_endpoint.as_str()], None).await.unwrap();

    let kubeconfig = args.kubeconfig;
    let cluster_crypto = ClusterCryptoObjects::new();
    let in_memory_etcd_client = Arc::new(InMemoryK8sEtcd::new(etcd_client));

    (kubeconfig, args.static_dir, cluster_crypto, in_memory_etcd_client)
}

async fn recertify(
    in_memory_etcd_client: Arc<InMemoryK8sEtcd>,
    cluster_crypto: &mut ClusterCryptoObjects,
    kubeconfig: Option<PathBuf>,
    static_dirs: Vec<PathBuf>,
) {
    // Perform parallelizable tasks like generating raw RSA keys to be used later and scanning for
    // crypto objeccts
    println!("Scanning etcd/filesystem... This might take a while");
    let all_crypto_objects = tokio::spawn(scanning::crypto_scan(in_memory_etcd_client, static_dirs, kubeconfig));
    let rsa_keys = tokio::spawn(rsa_key_pool::RsaKeyPool::fill(300));

    // Wait for the parallelizable tasks to finish and get their results
    let all_crypto_objects = all_crypto_objects.await.unwrap();
    println!("Scanning complete, waiting for random key generation to complete...");
    let rsa_pool = rsa_keys.await.unwrap();
    println!("Key generation complete");

    // Perform non-parallizable tasks like registering discovered crypto objects, establishing the
    // relationships between them, and regenerating the cryptographic objects using the pregenerated
    // RSA keys
    println!("Registering discovered crypto objects...");
    cluster_crypto.register_discovered_crypto_objects(all_crypto_objects).await;
    println!("Establishing relationships...");
    establish_relationships(cluster_crypto).await;
    println!("Regenerating cryptographic objects...");
    regenerate_cryptographic_objects(&cluster_crypto, rsa_pool).await;
}

async fn finalize(in_memory_etcd_client: Arc<InMemoryK8sEtcd>, cluster_crypto: &mut ClusterCryptoObjects) {
    // Commit the cryptographic objects back to memory etcd and to disk
    commit_cryptographic_objects_back(&in_memory_etcd_client, &cluster_crypto).await;
    ocp_postprocess(&in_memory_etcd_client).await;

    // Since we're using an in-memory fake etcd, we need to also commit the changes to the real
    // etcd after we're done
    println!("Committing to etcd...");
    in_memory_etcd_client.commit_to_actual_etcd().await;
}

async fn print_summary(cluster_crypto: ClusterCryptoObjects) {
    println!("Crypto graph...");
    cluster_crypto.display().await;
}

async fn commit_cryptographic_objects_back(in_memory_etcd_client: &Arc<InMemoryK8sEtcd>, cluster_crypto: &ClusterCryptoObjects) {
    println!("Committing changes...");
    let etcd_client = in_memory_etcd_client;
    cluster_crypto.commit_to_etcd_and_disk(&etcd_client).await;
}

async fn regenerate_cryptographic_objects(cluster_crypto: &ClusterCryptoObjects, rsa_key_pool: rsa_key_pool::RsaKeyPool) {
    cluster_crypto.regenerate_crypto(rsa_key_pool).await;
}

/// Perform some OCP-related post-processing to make some OCP operators happy
async fn ocp_postprocess(in_memory_etcd_client: &Arc<InMemoryK8sEtcd>) {
    println!("OCP postprocessing...");
    ocp_postprocess::fix_olm_secret_hash_annotation(in_memory_etcd_client).await;
}

async fn establish_relationships(cluster_crypto: &mut ClusterCryptoObjects) {
    println!("- Pairing certs and keys...");
    cluster_crypto.pair_certs_and_keys().await;
    println!("- Calculating cert signers...");
    cluster_crypto.fill_cert_key_signers().await;
    println!("- Calculating jwt signers...");
    cluster_crypto.fill_jwt_signers().await;
    println!("- Calculating signees...");
    cluster_crypto.fill_signees().await;
    println!("- Associating standalone public keys...");
    cluster_crypto.associate_public_keys().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_init() {
        let args = super::Args {
            etcd_endpoint: "http://localhost:2379".to_string(),
            static_dir: vec![
                PathBuf::from("./kubernetes"),
                PathBuf::from("./machine-config-daemon"),
                PathBuf::from("./kubelet"),
            ],
            kubeconfig: None,
        };

        main_internal(args).await;
    }
}
