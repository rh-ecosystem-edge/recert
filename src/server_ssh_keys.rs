use crate::file_utils;
use anyhow::{ensure, Context, Result};
use std::{collections::HashSet, path::Path};

const PATTERN: &str = r"^ssh_host_([a-z\d]+)_key(?:\.pub)?$";

pub(crate) fn write_new_keys(regenerate_server_ssh_keys: &Path, original_key_types: HashSet<String>) -> Result<()> {
    let temp_dir = &tempfile::tempdir().context("creating temporary directory for new SSH server keys")?;
    let temp_dir_path = temp_dir.path();
    std::fs::create_dir_all(temp_dir_path.join("etc/ssh")).context("creating new SSH server key directory structure")?;

    let command = std::process::Command::new("ssh-keygen")
        .arg("-A") // Regenerate all types of server SSH keys
        .arg("-f")
        .arg(temp_dir_path)
        .output()
        .context("running ssh-keygen")?;

    ensure!(
        command.status.success(),
        "ssh-keygen failed with status code {}, stderr: {}",
        command.status,
        String::from_utf8_lossy(&command.stderr),
    );

    // Copy the keys to the target directory
    let generated_key_files = file_utils::globvec(temp_dir_path, "**/ssh_host_*_key*")?;
    ensure!(
        !generated_key_files.is_empty(),
        "No SSH server keys found in {}",
        temp_dir_path.display()
    );

    let generated_key_types = generated_key_files
        .iter()
        .map(|key| get_key_type(key))
        .collect::<Result<HashSet<_>>>()?;
    ensure!(
        original_key_types.is_subset(&generated_key_types),
        "Failed to find all expected SSH server key types. Expected: {:?}, found: {:?}",
        original_key_types,
        generated_key_types
    );

    generated_key_files
        .iter()
        .filter(|key_file| original_key_types.contains(&get_key_type(key_file).unwrap()))
        .try_for_each(|key_file| {
            std::fs::copy(
                key_file,
                regenerate_server_ssh_keys.join(key_file.file_name().context("no file component")?),
            )
            .context(format!(
                "failed to copy new SSH server key file {} to {}",
                key_file.display(),
                regenerate_server_ssh_keys.display()
            ))
            .map(|_| ())
        })
        .context("copying new SSH server key files")?;

    Ok(())
}

pub(crate) fn remove_old_keys(regenerate_server_ssh_keys: &Path) -> Result<HashSet<String>> {
    let key_files = file_utils::globvec(regenerate_server_ssh_keys, "**/ssh_host_*_key*")?;

    ensure!(
        !key_files.is_empty(),
        "No SSH server keys found in {}",
        regenerate_server_ssh_keys.display()
    );

    for key_file in &key_files {
        std::fs::remove_file(key_file).with_context(|| format!("Failed to remove old SSH server key file {}", key_file.display()))?;
    }

    Ok(key_files
        .iter()
        .map(|key| get_key_type(key))
        .collect::<Result<Vec<_>>>()
        .context("getting key type")?
        .into_iter()
        .collect::<HashSet<String>>())
}

fn get_key_type(key_file: &Path) -> Result<String> {
    let re = regex::Regex::new(PATTERN).context("compiling file name regex")?;

    Ok(re
        .captures(
            key_file
                .file_name()
                .context("no file component")?
                .to_str()
                .context("file name must be unicode")?,
        )
        .and_then(|captures| captures.get(1))
        .context(format!("extracting key type from file name {:?}", key_file.file_name()))?
        .as_str()
        .to_string())
}
