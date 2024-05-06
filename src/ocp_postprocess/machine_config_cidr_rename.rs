use crate::{cluster_crypto::locations::K8sResourceLocation, config::path::ConfigPath, k8s_etcd::InMemoryK8sEtcd};
use anyhow::{Context, Result};
use std::{path::Path, sync::Arc};

mod etcd_rename;
mod filesystem_rename;

pub(crate) async fn rename_all(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    machine_config_cidr: &str,
    dirs: &[ConfigPath],
    files: &[ConfigPath],
) -> Result<(), anyhow::Error> {
    fix_etcd_resources(etcd_client, machine_config_cidr)
        .await
        .context("renaming etcd resources")?;

    fix_filesystem_resources(machine_config_cidr, dirs, files)
        .await
        .context("renaming filesystem resources")?;

    Ok(())
}

async fn fix_filesystem_resources(machine_config_cidr: &str, dirs: &[ConfigPath], files: &[ConfigPath]) -> Result<(), anyhow::Error> {
    for dir in dirs {
        fix_dir_resources(machine_config_cidr, dir).await?;
    }
    for file in files {
        fix_file_resources(machine_config_cidr, file).await?;
    }

    Ok(())
}

async fn fix_dir_resources(_machine_config_cidr: &str, _dir: &Path) -> Result<(), anyhow::Error> {
    Ok(())
}

async fn fix_file_resources(_machine_config_cidr: &str, _file: &Path) -> Result<(), anyhow::Error> {
    Ok(())
}

async fn fix_etcd_resources(etcd_client: &Arc<InMemoryK8sEtcd>, machine_config_cidr: &str) -> Result<()> {
    etcd_rename::fix_configmap(
        etcd_client,
        machine_config_cidr,
        K8sResourceLocation::new(Some("kube-system"), "ConfigMap", "cluster-config-v1", "v1"),
    )
    .await
    .context("fixing kube-system configmap")?;

    etcd_rename::fix_configmap(
        etcd_client,
        machine_config_cidr,
        K8sResourceLocation::new(Some("openshift-etcd"), "ConfigMap", "cluster-config-v1", "v1"),
    )
    .await
    .context("fixing openshift-etcd configmap")?;
    Ok(())
}
