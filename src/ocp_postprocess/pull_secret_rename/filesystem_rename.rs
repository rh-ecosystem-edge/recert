use super::utils::override_machineconfig_source;
use crate::{
    file_utils::{self, commit_file, read_file_to_string},
    ocp_postprocess::rename_utils,
};
use anyhow::{self, Context, Result};
use futures_util::future::{join_all, try_join_all};
use serde_json::Value;
use std::path::{Path, PathBuf};

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

pub(crate) async fn validate_filesystem_pull_secret_candidates(dir: &Path) -> Result<Vec<PathBuf>> {
    let dir_name = dir.file_name().context("no file name")?.to_str().context("path not utf-8")?;
    if dir_name != "kubelet" {
        return Ok(Vec::new());
    }

    let candidates = try_join_all(
        file_utils::globvec(dir, "**/config.json")?
            .into_iter()
            .map(|config_path| async move {
                let contents = read_file_to_string(&config_path).await.context("reading kubelet config.json")?;
                let is_pull_secret =
                    serde_json::from_str::<Value>(&contents).is_ok_and(|config| config.get("auths").is_some_and(Value::is_object));
                if !is_pull_secret {
                    log::warn!("skipping {:?}: not a valid pull secret (no object-valued auths field)", config_path);
                }
                anyhow::Ok(is_pull_secret.then_some(config_path))
            }),
    )
    .await?;

    Ok(candidates.into_iter().flatten().collect())
}

pub(crate) async fn fix_filesystem_pull_secret(pull_secret: &str, config_paths: &[PathBuf]) -> Result<()> {
    join_all(config_paths.iter().cloned().map(|file_path| {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write_config(root: &Path, relative_path: &str, contents: &str) -> PathBuf {
        let path = root.join(relative_path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, contents).unwrap();
        path
    }

    #[tokio::test]
    async fn validates_nonempty_and_empty_auths_objects() {
        let parent = tempdir().unwrap();
        let kubelet = parent.path().join("kubelet");
        fs::create_dir_all(&kubelet).unwrap();
        let nonempty = write_config(&kubelet, "node-a/config.json", r#"{"auths":{"registry":{}}}"#);
        let empty = write_config(&kubelet, "node-b/config.json", r#"{"auths":{}}"#);

        let paths = validate_filesystem_pull_secret_candidates(&kubelet).await.unwrap();

        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&nonempty));
        assert!(paths.contains(&empty));
    }

    #[tokio::test]
    async fn skips_invalid_pull_secret_json_shapes() {
        for contents in ["{", r#"{"other":{}}"#, r#"{"auths":[]}"#] {
            let parent = tempdir().unwrap();
            let kubelet = parent.path().join("kubelet");
            fs::create_dir_all(&kubelet).unwrap();
            write_config(&kubelet, "node/config.json", contents);

            let paths = validate_filesystem_pull_secret_candidates(&kubelet).await.unwrap();
            assert!(paths.is_empty(), "expected skip for {contents}, got {paths:?}");
        }
    }

    #[tokio::test]
    async fn non_kubelet_and_empty_candidate_sets_are_noops() {
        let parent = tempdir().unwrap();
        let other_dir = parent.path().join("other");
        fs::create_dir_all(&other_dir).unwrap();
        write_config(&other_dir, "node/config.json", "invalid");
        let kubelet = parent.path().join("kubelet");
        fs::create_dir_all(&kubelet).unwrap();

        assert!(validate_filesystem_pull_secret_candidates(&other_dir).await.unwrap().is_empty());
        assert!(validate_filesystem_pull_secret_candidates(&kubelet).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn skips_invalid_and_overwrites_valid_candidates() {
        let parent = tempdir().unwrap();
        let kubelet = parent.path().join("kubelet");
        fs::create_dir_all(&kubelet).unwrap();
        let valid = write_config(&kubelet, "node-a/config.json", r#"{"auths":{}}"#);
        let invalid = write_config(&kubelet, "node-b/config.json", "not json");

        let paths = validate_filesystem_pull_secret_candidates(&kubelet).await.unwrap();
        assert_eq!(paths, vec![valid.clone()]);

        fix_filesystem_pull_secret(r#"{"auths":{"new":{}}}"#, &paths).await.unwrap();
        assert_eq!(fs::read_to_string(&valid).unwrap(), r#"{"auths":{"new":{}}}"#);
        assert_eq!(fs::read_to_string(&invalid).unwrap(), "not json");
    }

    #[tokio::test]
    async fn writes_only_the_validated_candidate_paths() {
        let parent = tempdir().unwrap();
        let kubelet = parent.path().join("kubelet");
        fs::create_dir_all(&kubelet).unwrap();
        let config = write_config(&kubelet, "node/config.json", r#"{"auths":{}}"#);
        let paths = validate_filesystem_pull_secret_candidates(&kubelet).await.unwrap();

        fix_filesystem_pull_secret(r#"{"auths":{"new":{}}}"#, &paths).await.unwrap();

        assert_eq!(fs::read_to_string(config).unwrap(), r#"{"auths":{"new":{}}}"#);
    }
}
