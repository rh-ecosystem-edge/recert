use crate::file_utils::{self, commit_file, read_file_to_string};
use crate::ocp_postprocess::rename_utils::override_machineconfig_source;
use anyhow::{Context, Result};
use futures_util::future::join_all;
use serde_json::Value;

use std::path::Path;

pub(crate) async fn fix_filesystem_currentconfig(new_content: &str, file_path_to_change: &str, dir: &Path) -> Result<()> {
    join_all(file_utils::globvec(dir, "**/currentconfig")?.into_iter().map(|file_path| {
        let config_path = file_path.clone();
        let new_content = new_content.to_string();
        let file_path_to_change = file_path_to_change.to_string();
        tokio::spawn(async move {
            async move {
                let contents = read_file_to_string(&file_path).await.context("reading currentconfig data")?;
                let mut config: Value = serde_json::from_str(&contents).context("parsing currentconfig")?;

                override_machineconfig_source(&mut config, &new_content, &file_path_to_change)?;

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
