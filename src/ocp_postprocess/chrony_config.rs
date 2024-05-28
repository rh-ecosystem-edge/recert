use crate::{config::path::ConfigPath, k8s_etcd::InMemoryK8sEtcd};

use anyhow::{Context, Result};
use std::{path::Path, sync::Arc};

mod etcd_rename;
mod filesystem_rename;
mod utils;

const CHRONY_PATH: &str = "/etc/chrony.conf";

pub(crate) async fn rename_all(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    chrony_content: &str,
    static_dirs: &[ConfigPath],
    static_files: &[ConfigPath],
) -> Result<()> {
    fix_etcd_resources(etcd_client, chrony_content)
        .await
        .context("overriding etcd resources")?;

    fix_filesystem_resources(chrony_content, static_dirs, static_files)
        .await
        .context("overriding filesystem resources")?;

    Ok(())
}

async fn fix_filesystem_resources(chrony_content: &str, static_dirs: &[ConfigPath], static_files: &[ConfigPath]) -> Result<()> {
    for dir in static_dirs {
        fix_dir_resources(chrony_content, dir).await?;
    }
    for file in static_files {
        fix_file_resources(chrony_content, file).await?;
    }

    Ok(())
}

async fn fix_dir_resources(chrony_config: &str, dir: &Path) -> Result<()> {
    utils::fix_filesystem_currentconfig(chrony_config, CHRONY_PATH, dir)
        .await
        .context("renaming currentconfig")?;

    Ok(())
}

async fn fix_file_resources(chrony_content: &str, file: &Path) -> Result<()> {
    filesystem_rename::fix_filesystem_mcs_machine_config_content(chrony_content, CHRONY_PATH, file)
        .await
        .context("fix filesystem mcs machine config content")?;

    filesystem_rename::fix_filesystem_chrony_config(chrony_content, file)
        .await
        .context("fix filesystem chrony config")?;

    Ok(())
}

async fn fix_etcd_resources(etcd_client: &Arc<InMemoryK8sEtcd>, chrony_content: &str) -> Result<()> {
    etcd_rename::fix_machineconfigs(etcd_client, chrony_content, CHRONY_PATH)
        .await
        .context("fixing chrony.conf in machine configs")?;

    Ok(())
}
