use crate::config::EncryptionCustomizations;
use crate::{config::path::ConfigPath, k8s_etcd::InMemoryK8sEtcd};
use anyhow::{Context, Result};
use std::{path::Path, sync::Arc};

mod etcd_rename;
mod filesystem_rename;

pub(crate) async fn rename_all(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    encryption_customizations: &EncryptionCustomizations,
    dirs: &[ConfigPath],
    files: &[ConfigPath],
) -> Result<()> {
    fix_etcd_resources(etcd_client, encryption_customizations)
        .await
        .context("renaming etcd resources")?;

    fix_filesystem_resources(encryption_customizations, dirs, files)
        .await
        .context("renaming filesystem resources")?;

    Ok(())
}

async fn fix_filesystem_resources(
    encryption_customizations: &EncryptionCustomizations,
    dirs: &[ConfigPath],
    files: &[ConfigPath],
) -> Result<()> {
    for dir in dirs {
        fix_dir_resources(encryption_customizations, dir).await?;
    }

    for file in files {
        fix_file_resources(encryption_customizations, file).await?;
    }

    Ok(())
}

async fn fix_dir_resources(encryption_customizations: &EncryptionCustomizations, dir: &Path) -> Result<()> {
    filesystem_rename::fix_filesystem_kas_pods(encryption_customizations, dir)
        .await
        .context(format!("fix filesystem kube-apiserver encryption-config in {:?}", dir))?;
    Ok(())
}

async fn fix_file_resources(_encryption_customizations: &EncryptionCustomizations, _file: &Path) -> Result<()> {
    Ok(())
}

async fn fix_etcd_resources(etcd_client: &Arc<InMemoryK8sEtcd>, encryption_customizations: &EncryptionCustomizations) -> Result<()> {
    etcd_rename::update_kube_apiserver_encryption_config(etcd_client, encryption_customizations)
        .await
        .context("updating kube-apiserver encryption-config")?;

    etcd_rename::update_openshift_apiserver_encryption_config(etcd_client, encryption_customizations)
        .await
        .context("updating openshift-apiserver encryption-config")?;

    etcd_rename::update_oauth_apiserver_encryption_config(etcd_client, encryption_customizations)
        .await
        .context("updating oauth-apiserver encryption-config")?;

    etcd_rename::update_kube_apiserver_encryption_key(etcd_client, encryption_customizations)
        .await
        .context("updating secrets/openshift-config-managed/encryption-key-openshift-kube-apiserver")?;

    etcd_rename::update_openshift_apiserver_encryption_key(etcd_client, encryption_customizations)
        .await
        .context("updating secrets/openshift-config-managed/encryption-key-openshift-apiserver")?;

    etcd_rename::update_oauth_apiserver_encryption_key(etcd_client, encryption_customizations)
        .await
        .context("updating secrets/openshift-config-managed/ncryption-key-openshift-oauth-apiserver")?;

    Ok(())
}
