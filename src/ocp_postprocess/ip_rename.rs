use crate::{config::path::ConfigPath, k8s_etcd::InMemoryK8sEtcd};
use anyhow::{Context, Result};
use std::{path::Path, sync::Arc};

mod etcd_rename;
mod filesystem_rename;

pub(crate) async fn rename_all(etcd_client: &Arc<InMemoryK8sEtcd>, ip: &str, dirs: &[ConfigPath], files: &[ConfigPath]) -> Result<()> {
    let original_ip = fix_etcd_resources(etcd_client, ip).await.context("renaming etcd resources")?;

    fix_filesystem_resources(&original_ip, ip, dirs, files)
        .await
        .context("renaming filesystem resources")?;

    Ok(())
}

async fn fix_filesystem_resources(original_ip: &str, ip: &str, dirs: &[ConfigPath], files: &[ConfigPath]) -> Result<()> {
    for dir in dirs {
        fix_dir_resources(original_ip, ip, dir).await?;
    }

    for file in files {
        fix_file_resources(original_ip, ip, file).await?;
    }

    Ok(())
}

async fn fix_dir_resources(original_ip: &str, ip: &str, dir: &Path) -> Result<()> {
    filesystem_rename::fix_filesystem_ip(original_ip, ip, dir)
        .await
        .context(format!("fix filesystem ip in {:?}", dir))?;
    Ok(())
}

async fn fix_file_resources(_original_ip: &str, _ip: &str, _file: &Path) -> Result<()> {
    Ok(())
}

async fn fix_etcd_resources(etcd_client: &Arc<InMemoryK8sEtcd>, ip: &str) -> Result<String> {
    let original_ip = etcd_rename::fix_openshift_apiserver_configmap(etcd_client, ip)
        .await
        .context("fixing openshift apiserver config configmap")?;

    etcd_rename::fix_etcd_endpoints(etcd_client, ip)
        .await
        .context("fixing etcd secrets")?;

    etcd_rename::fix_etcd_pod(etcd_client, &original_ip, ip)
        .await
        .context("fixing etcd-pod")?;

    etcd_rename::fix_etcd_scripts(etcd_client, &original_ip, ip)
        .await
        .context("fixing etcd-scripts")?;

    etcd_rename::fix_etcd_secrets(etcd_client, &original_ip, ip)
        .await
        .context("fixing etcd secrets")?;

    etcd_rename::fix_kube_apiserver_configs(etcd_client, &original_ip, ip)
        .await
        .context("fixing kube apiserver configs")?;

    etcd_rename::fix_kubeapiservers_cluster(etcd_client, &original_ip, ip)
        .await
        .context("fixing kubeapiservers/cluster")?;

    etcd_rename::fix_authentications_cluster(etcd_client, &original_ip, ip)
        .await
        .context("fixing kubeapiservers/cluster")?;

    etcd_rename::fix_openshiftapiservers_cluster(etcd_client, ip)
        .await
        .context("fixing kubeapiservers/cluster")?;

    etcd_rename::fix_networks_cluster(etcd_client, ip)
        .await
        .context("fixing networks/cluster")?;

    etcd_rename::fix_oauth_apiserver_deployment(etcd_client, &original_ip, ip)
        .await
        .context("fixing oauth apiserver deployment")?;

    Ok(original_ip)
}
