use anyhow::{Context, Result};
use cluster_crypto::ClusterCryptoObjects;
use config::RecertConfig;
use std::sync::atomic::Ordering::Relaxed;

mod cluster_crypto;
mod cnsanreplace;
mod config;
mod etcd_encoding;
mod file_utils;
mod json_tools;
mod k8s_etcd;
mod logging;
mod ocp_postprocess;
mod protobuf_gen;
mod recert;
mod rsa_key_pool;
mod rules;
mod runtime;
mod server_ssh_keys;
mod use_cert;
mod use_key;

fn main() -> Result<()> {
    logging::init().context("initializing logging")?;

    let config = RecertConfig::new().context("recert config")?;

    runtime::prepare_tokio_runtime(config.threads)?.block_on(async { main_internal(config).await })
}

async fn main_internal(config: RecertConfig) -> Result<()> {
    let mut cluster_crypto = ClusterCryptoObjects::new();

    file_utils::DRY_RUN.store(config.dry_run, Relaxed);

    let run_result = recert::run(&config, &mut cluster_crypto).await;

    logging::generate_summary(config, cluster_crypto)?;

    run_result
}
