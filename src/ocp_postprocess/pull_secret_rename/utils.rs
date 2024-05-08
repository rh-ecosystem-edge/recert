use anyhow::{Context, Result};
use serde_json::Value;

use crate::file_utils;

pub(crate) fn override_machineconfig_source(machineconfig: &mut Value, new_source: &str, path: &str) -> Result<()> {
    let pointer_mut = machineconfig.pointer_mut("/spec/config/storage/files");
    if pointer_mut.is_none() {
        // Not all machineconfigs have files to look at and that's ok
        return Ok(());
    };

    let find_map = pointer_mut
        .context("no /spec/config/storage/files")?
        .as_array_mut()
        .context("files not an array")?
        .iter_mut()
        .find_map(|file| (file.pointer("/path")? == path).then_some(file));

    if find_map.is_none() {
        // Not all machineconfigs have the file we're looking for and that's ok
        return Ok(());
    };

    let file_contents = find_map
        .context(format!("no {} file in machineconfig", &path))?
        .pointer_mut("/contents")
        .context("no .contents")?
        .as_object_mut()
        .context("annotations not an object")?;

    file_contents.insert(
        "source".to_string(),
        serde_json::Value::String(file_utils::dataurl_encode(new_source)),
    );

    Ok(())
}
