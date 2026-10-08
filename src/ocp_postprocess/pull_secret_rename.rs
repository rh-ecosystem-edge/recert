use crate::{config::path::ConfigPath, k8s_etcd::InMemoryK8sEtcd};
use anyhow::{Context, Result};
use futures_util::future::try_join_all;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

mod etcd_rename;
mod filesystem_rename;
mod utils;

pub(crate) async fn rename_all(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    pull_secret: &str,
    dirs: &[ConfigPath],
    files: &[ConfigPath],
) -> Result<()> {
    let pull_secret_candidates = try_join_all(
        dirs.iter()
            .map(|dir| filesystem_rename::validate_filesystem_pull_secret_candidates(dir)),
    )
    .await?;

    fix_etcd_resources(etcd_client, pull_secret)
        .await
        .context("renaming etcd resources")?;

    fix_filesystem_resources(pull_secret, dirs, files, &pull_secret_candidates)
        .await
        .context("renaming filesystem resources")?;

    Ok(())
}

async fn fix_filesystem_resources(
    pull_secret: &str,
    dirs: &[ConfigPath],
    files: &[ConfigPath],
    pull_secret_candidates: &[Vec<PathBuf>],
) -> Result<()> {
    for (dir, candidates) in dirs.iter().zip(pull_secret_candidates) {
        fix_dir_resources(pull_secret, dir, candidates).await?;
    }
    for file in files {
        fix_file_resources(pull_secret, file).await?;
    }

    Ok(())
}

async fn fix_dir_resources(pull_secret: &str, dir: &Path, pull_secret_candidates: &[PathBuf]) -> Result<()> {
    filesystem_rename::fix_filesystem_currentconfig(pull_secret, dir)
        .await
        .context("renaming currentconfig")?;

    filesystem_rename::fix_filesystem_pull_secret(pull_secret, pull_secret_candidates)
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
