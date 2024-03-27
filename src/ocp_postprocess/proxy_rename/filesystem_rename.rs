use super::{
    args::Proxy,
    utils::{self, fix_containers, fix_machineconfig},
};
use crate::file_utils::{self, commit_file, read_file_to_string};
use anyhow::{self, ensure, Context, Result};
use futures_util::future::join_all;
use serde_json::Value;
use std::{collections::HashSet, path::Path};

pub(crate) async fn rename_proxy_env_file(proxy: &Proxy, file: &Path) -> Result<()> {
    if file
        .file_name()
        .context("getting file name")?
        .to_str()
        .context("converting file name to string")?
        != "proxy.env"
    {
        return Ok(());
    }

    rename_proxy_env(file, proxy).await?;

    Ok(())
}

async fn rename_proxy_env(file: &Path, proxy: &Proxy) -> Result<(), anyhow::Error> {
    commit_file(
        file,
        utils::rename_proxy_env_file_contents(proxy, read_file_to_string(file).await.context("reading proxy.env")?),
    )
    .await
    .context("writing proxy.env to disk")?;
    Ok(())
}

pub(crate) async fn rename_proxy_env_dir(proxy: &Proxy, dir: &Path) -> Result<()> {
    join_all(
        file_utils::globvec(dir, "**/proxy.env.mcdorig")?
            .into_iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .map(|file_path| {
                let proxy = proxy.clone();
                let mcdorig_file_path = file_path.clone();
                tokio::spawn(async move {
                    async move {
                        rename_proxy_env(&mcdorig_file_path, &proxy)
                            .await
                            .context("renaming proxy.env.mcdorig")?;

                        anyhow::Ok(())
                    }
                    .await
                    .context("renaming proxy.env.mcdorig")
                })
            }),
    )
    .await
    .into_iter()
    .collect::<core::result::Result<Vec<_>, _>>()?
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_filesystem_currentconfig(proxy: &Proxy, dir: &Path) -> Result<()> {
    join_all(file_utils::globvec(dir, "**/currentconfig")?.into_iter().map(|file_path| {
        let proxy_path = file_path.clone();
        let proxy = proxy.clone();
        tokio::spawn(async move {
            async move {
                let contents = read_file_to_string(&file_path)
                    .await
                    .context("reading kube-apiserver oauthMetadata")?;

                let mut config: Value = serde_json::from_str(&contents).context("parsing currentconfig")?;

                fix_machineconfig(&mut config, &proxy)?;

                commit_file(file_path, serde_json::to_string(&config).context("serializing currentconfig")?)
                    .await
                    .context("writing currentconfig to disk")?;

                anyhow::Ok(())
            }
            .await
            .context(format!("fixing currentconfig {:?}", proxy_path))
        })
    }))
    .await
    .into_iter()
    .collect::<core::result::Result<Vec<_>, _>>()?
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_pods_yaml(proxy: &Proxy, dir: &Path) -> Result<()> {
    join_all(file_utils::globvec(dir, "**/*pod.yaml")?.into_iter().map(|file_path| {
        let pod_path = file_path.clone();
        let proxy = proxy.clone();
        tokio::spawn(async move {
            async move {
                let contents = read_file_to_string(&file_path).await.context("reading pods.yaml")?;

                let parsed_as_json = serde_json::from_str(&contents);

                let pod = match parsed_as_json {
                    Ok(mut value) => {
                        fix_containers(&mut value, &proxy, "/spec").context("fixing containers")?;
                        serde_json::to_string(&value).context("serializing pods.yaml")?
                    }
                    Err(_) => {
                        // We will reach here when the file is non-JSON YAML. For now, none of the
                        // such files have PROXY env vars so we can skip them. We don't want to
                        // parse them and then re-serialize them as that could cause formatting
                        // changes which could lead to rollouts.
                        ensure!(!contents.contains("HTTP_PROXY"), "HTTP_PROXY env var found in non-JSON YAML file");
                        ensure!(!contents.contains("HTTPS_PROXY"), "HTTPS_PROXY env var found in non-JSON YAML file");
                        ensure!(!contents.contains("NO_PROXY"), "NO_PROXY env var found in non-JSON YAML file");
                        return anyhow::Ok(());
                    }
                };

                commit_file(file_path, pod).await.context("writing pods.yaml to disk")?;

                anyhow::Ok(())
            }
            .await
            .context(format!("fixing pods.yaml {:?}", pod_path))
        })
    }))
    .await
    .into_iter()
    .collect::<core::result::Result<Vec<_>, _>>()?
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}
