use crate::file_utils::{self, commit_file, read_file_to_string};
use anyhow::{self, Context, Result};
use futures_util::future::join_all;
use serde_json::Value;
use std::path::Path;

use super::utils::fix_machineconfig;

pub(crate) async fn fix_filesystem_ca_trust_anchors(additional_trust_bundle: &str, dir: &Path) -> Result<()> {
    join_all(
        file_utils::globvec(dir, "**/anchors/openshift-config-user-ca-bundle.crt")?
            .into_iter()
            .map(|file_path| {
                let additional_trust_bundle = additional_trust_bundle.to_string();
                tokio::spawn(async move {
                    async move {
                        commit_file(file_path, additional_trust_bundle.clone())
                            .await
                            .context("writing to disk")?;

                        anyhow::Ok(())
                    }
                    .await
                    .context("fixing system CA bundle")
                })
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_filesystem_currentconfig(additional_trust_bundle: &str, dir: &Path) -> Result<()> {
    join_all(file_utils::globvec(dir, "**/currentconfig")?.into_iter().map(|file_path| {
        let kcm_config_path = file_path.clone();
        let additional_trust_bundle = additional_trust_bundle.to_string();
        tokio::spawn(async move {
            async move {
                let contents = read_file_to_string(&file_path).await.context("reading currentconfig")?;
                let mut config: Value = serde_json::from_str(&contents).context("parsing currentconfig")?;

                fix_machineconfig(&mut config, &additional_trust_bundle)?;

                commit_file(file_path, serde_json::to_string(&config).context("serializing currentconfig")?)
                    .await
                    .context("writing currentconfig to disk")?;

                anyhow::Ok(())
            }
            .await
            .context(format!("fixing currentconfig {:?}", kcm_config_path))
        })
    }))
    .await
    .into_iter()
    .collect::<core::result::Result<Vec<_>, _>>()?
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_static_configmap_trusted_ca_bundle(new_merged_bundle: &str, dir: &Path) -> Result<()> {
    join_all(
        file_utils::globvec(dir, "**/configmaps/trusted-ca-bundle/ca-bundle.crt")?
            .into_iter()
            .map(|file_path| {
                let ca_bundle_path = file_path.clone();
                let new_merged_bundle = new_merged_bundle.to_string();
                tokio::spawn(async move {
                    async move {
                        commit_file(file_path, new_merged_bundle.clone()).await.context("writing to disk")?;

                        anyhow::Ok(())
                    }
                    .await
                    .context(format!("fixing static configmap trusted ca bundle {:?}", ca_bundle_path))
                })
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}
