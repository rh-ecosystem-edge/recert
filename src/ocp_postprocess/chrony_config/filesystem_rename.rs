use crate::{file_utils::commit_file, ocp_postprocess::rename_utils};
use anyhow::{self, Context, Result};
use std::path::Path;

pub(crate) async fn fix_filesystem_chrony_config(chrony_config: &str, file_path: &Path) -> Result<()> {
    if let Some(file_name) = file_path.file_name() {
        if let Some(file_name) = file_name.to_str() {
            if file_name == "chrony.conf" {
                let chrony_config = chrony_config.to_string();
                commit_file(file_path, &chrony_config)
                    .await
                    .context("writing chrony.conf to disk")?;
            }
        }
    }

    Ok(())
}

pub(crate) async fn fix_filesystem_mcs_machine_config_content(
    chrony_config: &str,
    chrony_config_path: &str,
    file_path: &Path,
) -> Result<()> {
    rename_utils::fix_filesystem_mcs_machine_config_content(chrony_config, chrony_config_path, file_path)
        .await
        .context("fix filesystem mcs machine config with new chrony config content")?;
    Ok(())
}
