use crate::{config::path::ConfigPath, k8s_etcd::InMemoryK8sEtcd};
use anyhow::{Context, Result};
use std::{path::Path, sync::Arc};

mod etcd_rename;
mod filesystem_rename;
mod utils;

pub(crate) async fn rename_all(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    pull_secret: &str,
    dirs: &[ConfigPath],
    files: &[ConfigPath],
) -> Result<()> {
    fix_etcd_resources(etcd_client, pull_secret)
        .await
        .context("renaming etcd resources")?;

    fix_filesystem_resources(pull_secret, dirs, files)
        .await
        .context("renaming filesystem resources")?;

    Ok(())
}

async fn fix_filesystem_resources(pull_secret: &str, dirs: &[ConfigPath], files: &[ConfigPath]) -> Result<()> {
    for dir in dirs {
        fix_dir_resources(pull_secret, dir).await?;
    }
    for file in files {
        fix_file_resources(pull_secret, file).await?;
    }

    Ok(())
}

async fn fix_dir_resources(pull_secret: &str, dir: &Path) -> Result<()> {
    filesystem_rename::fix_filesystem_currentconfig(pull_secret, dir)
        .await
        .context("renaming currentconfig")?;

    filesystem_rename::fix_filesystem_pull_secret(pull_secret, dir)
        .await
        .context("renaming config.json")?;
    Ok(())
}

async fn fix_file_resources(pull_secret: &str, file: &Path) -> Result<()> {
    filesystem_rename::fix_filesystem_mcs_machine_config_content(pull_secret, file)
        .await
        .context("fix filesystem mcs machine config content")?;
    Ok(())
}

async fn fix_etcd_resources(etcd_client: &Arc<InMemoryK8sEtcd>, pull_secret: &str) -> Result<()> {
    etcd_rename::fix_machineconfigs(etcd_client, pull_secret)
        .await
        .context("fixing machine configs")?;
    etcd_rename::fix_pull_secret_secret(etcd_client, pull_secret)
        .await
        .context("fixing secret")?;
    Ok(())
}
