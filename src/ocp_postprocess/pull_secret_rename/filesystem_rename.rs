use super::utils::override_machineconfig_source;
use crate::{
    file_utils::{self, commit_file, read_file_to_string},
    ocp_postprocess::rename_utils,
};
use anyhow::{self, Context, Result};
use futures_util::future::join_all;
use serde_json::Value;
use std::path::Path;

pub(crate) async fn fix_filesystem_mcs_machine_config_content(pull_secret: &str, file_path: &Path) -> Result<()> {
    rename_utils::fix_filesystem_mcs_machine_config_content(pull_secret, "/var/lib/kubelet/config.json", file_path)
        .await
        .context("fix filesystem mcs machine config pull secret content")?;
    Ok(())
}

pub(crate) async fn fix_filesystem_currentconfig(pull_secret: &str, dir: &Path) -> Result<()> {
    join_all(file_utils::globvec(dir, "**/currentconfig")?.into_iter().map(|file_path| {
        let config_path = file_path.clone();
        let pull_secret = pull_secret.to_string();
        tokio::spawn(async move {
            async move {
                let contents = read_file_to_string(&file_path).await.context("reading pull secret data")?;
                let mut config: Value = serde_json::from_str(&contents).context("parsing currentconfig")?;

                override_machineconfig_source(&mut config, &pull_secret, "/var/lib/kubelet/config.json")?;

                commit_file(file_path, serde_json::to_string(&config).context("serializing currentconfig")?)
                    .await
                    .context("writing currentconfig to disk")?;

                anyhow::Ok(())
            }
            .await
            .context(format!("fixing currentconfig {:?}", config_path))
        })
    }))
    .await
    .into_iter()
    .collect::<core::result::Result<Vec<_>, _>>()?
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_filesystem_pull_secret(pull_secret: &str, dir: &Path) -> Result<()> {
    let dir_name = dir.file_name().context("no file name")?.to_str().context("path not utf-8")?;
    if dir_name != "kubelet" {
        return Ok(());
    }
    // TODO: add verification that config.json as actually pull_secret
    log::info!("setting pull secret in config.json");
    join_all(file_utils::globvec(dir, "**/config.json")?.into_iter().map(|file_path| {
        let config_path = file_path.clone();
        let pull_secret = pull_secret.to_string();
        tokio::spawn(async move {
            async move {
                commit_file(file_path, &pull_secret).await.context("writing config.json to disk")?;

                anyhow::Ok(())
            }
            .await
            .context(format!("fixing config.json {:?}", config_path))
        })
    }))
    .await
    .into_iter()
    .collect::<core::result::Result<Vec<_>, _>>()?
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}
