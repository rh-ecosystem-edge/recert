pub(crate) mod args;

use crate::{config::path::ConfigPath, k8s_etcd::InMemoryK8sEtcd};
use anyhow::{Context, Result};
use std::{path::Path, sync::Arc};

use self::args::Proxy;

mod etcd_rename;
mod filesystem_rename;
mod utils;

pub(crate) async fn rename_all(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    proxy: &Proxy,
    static_dirs: &[ConfigPath],
    static_files: &[ConfigPath],
) -> Result<(), anyhow::Error> {
    fix_etcd_resources(etcd_client, proxy).await.context("renaming etcd resources")?;

    fix_filesystem_resources(proxy, static_dirs, static_files)
        .await
        .context("renaming filesystem resources")?;

    Ok(())
}

async fn fix_filesystem_resources(proxy: &Proxy, static_dirs: &[ConfigPath], static_files: &[ConfigPath]) -> Result<()> {
    for dir in static_dirs {
        fix_dir_resources(proxy, dir).await?;
    }

    for file in static_files {
        fix_file_resources(proxy, file).await?;
    }

    Ok(())
}

async fn fix_dir_resources(proxy: &Proxy, dir: &Path) -> Result<()> {
    filesystem_rename::rename_proxy_env_dir(proxy, dir)
        .await
        .context("rename proxy env dir")?;

    filesystem_rename::fix_filesystem_currentconfig(proxy, dir)
        .await
        .context("renaming currentconfig")?;

    filesystem_rename::fix_pods_yaml(proxy, dir).await.context("renaming pod yaml")?;

    Ok(())
}

async fn fix_file_resources(proxy: &Proxy, file: &Path) -> Result<()> {
    filesystem_rename::rename_proxy_env_file(proxy, file)
        .await
        .context("rename proxy env file")?;

    Ok(())
}

async fn fix_etcd_resources(etcd_client: &Arc<InMemoryK8sEtcd>, proxy: &Proxy) -> Result<()> {
    etcd_rename::fix_machineconfigs(etcd_client, proxy)
        .await
        .context("fixing machineconfigs")?;

    etcd_rename::fix_proxy(etcd_client, proxy).await.context("fixing proxy")?;

    etcd_rename::fix_storages(etcd_client, proxy).await.context("fixing storages")?;

    etcd_rename::fix_openshiftapiserver(etcd_client, proxy)
        .await
        .context("fixing openshiftapiserver")?;

    etcd_rename::fix_kubeapiserver(etcd_client, proxy)
        .await
        .context("fixing kubeapiserver")?;

    etcd_rename::fix_kubecontrollermanager(etcd_client, proxy)
        .await
        .context("fixing kubecontrolermanager")?;

    etcd_rename::fix_controllerconfigs(etcd_client, proxy)
        .await
        .context("fixing controllerconfigs")?;

    etcd_rename::fix_containers(etcd_client, proxy).await.context("fixing containers")?;

    etcd_rename::fix_configmap_pods(etcd_client, proxy)
        .await
        .context("fixing pod configmaps")?;

    Ok(())
}
