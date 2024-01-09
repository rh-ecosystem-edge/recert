use crate::{
    config::ConfigPath,
    k8s_etcd::{InMemoryK8sEtcd},
};
use anyhow::{Context, Result};
use std::{sync::Arc};

mod etcd_rename;

pub(crate) async fn rename_all(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    hostname: &str,
    _static_dirs: &Vec<ConfigPath>,
    _static_files: &Vec<ConfigPath>,
) -> Result<(), anyhow::Error> {

    fix_etcd_resources(etcd_client, hostname)
        .await
        .context("renaming etcd resources")?;

    Ok(())
}

async fn fix_etcd_resources(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    hostname: &str,
) -> Result<(), anyhow::Error> {
    etcd_rename::fix_etcd_all_certs(etcd_client, hostname)
        .await
        .context("fixing etcd-all-certs")?;
    etcd_rename::fix_etcd_secrets(etcd_client, hostname)
        .await
        .context("fixing etcd secrets")?;
    etcd_rename::fix_etcd_pod(etcd_client, hostname)
        .await
        .context("fixing etcd-pod")?;
    etcd_rename::fix_etcd_scripts(etcd_client, hostname)
        .await
        .context("fixing etcd-scripts")?;
    etcd_rename::fix_restore_etcd_pod(etcd_client, hostname)
        .await
        .context("fixing restore-etcd-pod")?;
    etcd_rename::fix_kubeapiservers_cluster(etcd_client, hostname)
        .await
        .context("fixing kubeapiservers/cluster")?;
    etcd_rename::fix_kubeschedulers_cluster(etcd_client, hostname)
        .await
        .context("fixing kubeschedulers/cluster")?;
    etcd_rename::fix_kubecontrollermanagers_cluster(etcd_client, hostname)
        .await
        .context("fixing kubecontrollermanagers/cluster")?;

    Ok(())
}
