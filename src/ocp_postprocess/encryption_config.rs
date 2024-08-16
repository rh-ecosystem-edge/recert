use crate::config::EncryptionCustomizations;
use crate::{config::path::ConfigPath, k8s_etcd::InMemoryK8sEtcd};
use anyhow::{Context, Result};
use futures_util::future::join_all;
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

    delete_encryption_keys(etcd_client)
        .await
        .context("deleting openshift-config-managed encryption-key secrets")?;

    Ok(())
}

async fn delete_encryption_keys(etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("secrets/openshift-config-managed/encryption-key-openshift-")
            .await?
            .into_iter()
            .map(|key| async move {
                etcd_client.delete(&key).await.context(format!("deleting {}", key))?;
                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

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

    Ok(())
}
