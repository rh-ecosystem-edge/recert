use crate::{cluster_crypto::locations::K8sResourceLocation, config::path::ConfigPath, k8s_etcd::InMemoryK8sEtcd};
use anyhow::{Context, Result};
use std::{path::Path, sync::Arc};

mod etcd_rename;
mod filesystem_rename;
mod utils;

pub(crate) async fn rename_all(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    install_config: &str,
    static_dirs: &[ConfigPath],
    static_files: &[ConfigPath],
) -> Result<(), anyhow::Error> {
    fix_etcd_resources(etcd_client, install_config)
        .await
        .context("renaming etcd resources")?;

    fix_filesystem_resources(install_config, static_dirs, static_files)
        .await
        .context("renaming filesystem resources")?;

    Ok(())
}

async fn fix_filesystem_resources(install_config: &str, static_dirs: &[ConfigPath], static_files: &[ConfigPath]) -> Result<()> {
    for dir in static_dirs {
        fix_dir_resources(install_config, dir).await?;
    }

    for file in static_files {
        fix_file_resources(install_config, file).await?;
    }

    Ok(())
}

async fn fix_dir_resources(_install_config: &str, _dir: &Path) -> Result<()> {
    Ok(())
}

async fn fix_file_resources(_install_config: &str, _file: &Path) -> Result<()> {
    Ok(())
}

async fn fix_etcd_resources(etcd_client: &Arc<InMemoryK8sEtcd>, install_config: &str) -> Result<()> {
    etcd_rename::fix_configmap(
        etcd_client,
        install_config,
        K8sResourceLocation::new(Some("kube-system"), "ConfigMap", "cluster-config-v1", "v1"),
    )
    .await
    .context("fixing kube-system configmap")?;

    etcd_rename::fix_configmap(
        etcd_client,
        install_config,
        K8sResourceLocation::new(Some("openshift-etcd"), "ConfigMap", "cluster-config-v1", "v1"),
    )
    .await
    .context("fixing openshift-etcd configmap")?;

    Ok(())
}
