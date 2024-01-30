use crate::{config::ConfigPath, k8s_etcd::InMemoryK8sEtcd};
use anyhow::{Context, Result};
use std::{path::Path, sync::Arc};

mod etcd_rename;
mod filesystem_rename;

pub(crate) async fn rename_all(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    hostname: &str,
    static_dirs: &[ConfigPath],
    static_files: &[ConfigPath],
) -> Result<(), anyhow::Error> {
    let original_hostname = fix_etcd_resources(etcd_client, hostname).await.context("renaming etcd resources")?;

    fix_filesystem_resources(&original_hostname, hostname, static_dirs, static_files)
        .await
        .context("renaming filesystem resources")?;

    Ok(())
}

async fn fix_filesystem_resources(
    original_hostname: &str,
    hostname: &str,
    static_dirs: &[ConfigPath],
    static_files: &[ConfigPath],
) -> Result<(), anyhow::Error> {
    for dir in static_dirs {
        fix_dir_resources(original_hostname, hostname, dir).await?;
    }

    for file in static_files {
        fix_file_resources(original_hostname, hostname, file).await?;
    }

    Ok(())
}

async fn fix_dir_resources(original_hostname: &str, hostname: &str, dir: &Path) -> Result<()> {
    filesystem_rename::fix_filesystem_etcd_static_pods(original_hostname, hostname, dir)
        .await
        .context("fixing etcd static pods")?;

    filesystem_rename::fix_filesystem_etcd_configmap_pod_yaml(original_hostname, hostname, dir)
        .await
        .context("fixing etcd static pod configmap pod yaml")?;

    filesystem_rename::fix_filesystem_etcd_scripts_cluster_backup_sh(original_hostname, hostname, dir)
        .await
        .context("fixing etcd scripts cluster-backup.sh")?;

    filesystem_rename::fix_filesystem_etcd_scripts_etcd_env(original_hostname, hostname, dir)
        .await
        .context("fixing etcd scripts etcd.env")?;

    filesystem_rename::fix_filesystem_kapi_startup_monitor_pod(hostname, dir)
        .await
        .context("fixing kube-apiserver-startup-monitor-pod")?;

    filesystem_rename::fix_filesystem_kapi_startup_monitor_configmap_pod_yaml(original_hostname, hostname, dir)
        .await
        .context("fixing kube-apiserver-startup-monitor-pod configmap pod yaml")?;

    filesystem_rename::fix_filesystem_etcd_all_certs(original_hostname, hostname, dir)
        .await
        .context("renaming etcd-{peer,serving,serving-metrics}-*.{crt,key} etcd-all-certs secrets")?;

    Ok(())
}

async fn fix_file_resources(_original_hostname: &str, _hostname: &str, _file: &Path) -> Result<()> {
    Ok(())
}

async fn fix_etcd_resources(etcd_client: &Arc<InMemoryK8sEtcd>, hostname: &str) -> Result<String> {
    let original_hostname = etcd_rename::fix_etcd_all_certs(etcd_client, hostname)
        .await
        .context("fixing etcd-all-certs")?;
    etcd_rename::fix_etcd_secrets(etcd_client, &original_hostname, hostname)
        .await
        .context("fixing etcd secrets")?;
    etcd_rename::fix_etcd_pod(etcd_client, &original_hostname, hostname)
        .await
        .context("fixing etcd-pod")?;
    etcd_rename::fix_etcd_scripts(etcd_client, &original_hostname, hostname)
        .await
        .context("fixing etcd-scripts")?;
    etcd_rename::fix_kubeapiservers_cluster(etcd_client, hostname)
        .await
        .context("fixing kubeapiservers/cluster")?;
    etcd_rename::fix_kubeschedulers_cluster(etcd_client, hostname)
        .await
        .context("fixing kubeschedulers/cluster")?;
    etcd_rename::fix_kubecontrollermanagers_cluster(etcd_client, hostname)
        .await
        .context("fixing kubecontrollermanagers/cluster")?;
    etcd_rename::fix_etcds_cluster(etcd_client, hostname)
        .await
        .context("fixing etcds/cluster")?;

    Ok(original_hostname)
}
