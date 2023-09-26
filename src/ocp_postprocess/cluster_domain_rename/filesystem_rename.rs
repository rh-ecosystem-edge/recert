use super::{
    rename_utils::fix_api_server_arguments,
    rename_utils::fix_apiserver_url_file,
    rename_utils::fix_kcm_extended_args,
    rename_utils::fix_kubeconfig,
    rename_utils::fix_oauth_metadata,
    rename_utils::{fix_kcm_pod, fix_machineconfig},
};
use crate::file_utils::{self, read_file_to_string};
use anyhow::{self, Context, Result};
use futures_util::future::join_all;
use serde_json::Value;
use std::{collections::HashSet, path::Path};

pub(crate) async fn fix_filesystem_kcm_pods(generated_infra_id: &str, dir: &Path) -> Result<()> {
    join_all(
        file_utils::globvec(dir, "**/kube-controller-manager-pod.yaml")?
            .into_iter()
            .chain(file_utils::globvec(dir, "**/kube-controller-manager-pod/pod.yaml")?.into_iter())
            .map(|file_path| {
                let kcm_pod_path = file_path.clone();
                let generated_infra_id = generated_infra_id.to_string();
                tokio::spawn(async move {
                    async move {
                        let contents = read_file_to_string(file_path.clone())
                            .await
                            .context("reading kube-controller-manager-pod.yaml")?;
                        let mut pod: Value = serde_yaml::from_str(&contents).context("parsing kube-controller-manager-pod.yaml")?;

                        fix_kcm_pod(&mut pod, &generated_infra_id)?;

                        tokio::fs::write(
                            file_path,
                            serde_json::to_string(&pod).context("serializing kube-controller-manager-pod.yaml")?,
                        )
                        .await
                        .context("writing kube-controller-manager-pod.yaml to disk")?;

                        anyhow::Ok(())
                    }
                    .await
                    .context(format!("fixing kube-controller-manager-pod.yaml {:?}", kcm_pod_path))
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

pub(crate) async fn fix_filesystem_kcm_configs(generated_infra_id: &str, dir: &Path) -> Result<()> {
    join_all(
        file_utils::globvec(dir, "**/kube-controller-manager-pod*/configmaps/config/config.yaml")?
            .into_iter()
            .map(|file_path| {
                let kcm_config_path = file_path.clone();
                let generated_infra_id = generated_infra_id.to_string();
                tokio::spawn(async move {
                    async move {
                        let contents = read_file_to_string(file_path.clone())
                            .await
                            .context("reading kube-controller-manager config.yaml")?;
                        let mut config: Value = serde_yaml::from_str(&contents).context("parsing kube-controller-manager config.yaml")?;

                        fix_kcm_extended_args(&mut config, &generated_infra_id)?;

                        tokio::fs::write(
                            file_path,
                            serde_json::to_string(&config).context("serializing kube-controller-manager config.yaml")?,
                        )
                        .await
                        .context("writing kube-controller-manager config.yaml to disk")?;

                        anyhow::Ok(())
                    }
                    .await
                    .context(format!("fixing kube-controller-manager config.yaml {:?}", kcm_config_path))
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

pub(crate) async fn fix_filesystem_kube_apiserver_configs(cluster_domain: &str, dir: &Path) -> Result<()> {
    join_all(
        file_utils::globvec(dir, "**/kube-apiserver-pod*/configmaps/config/config.yaml")?
            .into_iter()
            .map(|file_path| {
                let kcm_config_path = file_path.clone();
                let cluster_domain = cluster_domain.to_string();
                tokio::spawn(async move {
                    async move {
                        let contents = read_file_to_string(file_path.clone())
                            .await
                            .context("reading kube-apiserver config.yaml")?;
                        let mut config: Value = serde_yaml::from_str(&contents).context("parsing kube-apiserver config.yaml")?;

                        fix_api_server_arguments(&mut config, &cluster_domain)?;

                        tokio::fs::write(
                            file_path,
                            serde_json::to_string(&config).context("serializing kube-apiserver config.yaml")?,
                        )
                        .await
                        .context("writing kube-apiserver config.yaml to disk")?;

                        anyhow::Ok(())
                    }
                    .await
                    .context(format!("fixing kube-apiserver config.yaml {:?}", kcm_config_path))
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

pub(crate) async fn fix_filesystem_kube_apiserver_oauth_metadata(cluster_domain: &str, dir: &Path) -> Result<()> {
    join_all(
        file_utils::globvec(dir, "**/kube-apiserver-pod*/configmaps/oauth-metadata/oauthMetadata")?
            .into_iter()
            .map(|file_path| {
                let kcm_config_path = file_path.clone();
                let cluster_domain = cluster_domain.to_string();
                tokio::spawn(async move {
                    async move {
                        let contents = read_file_to_string(file_path.clone())
                            .await
                            .context("reading kube-apiserver oauthMetadata")?;
                        let mut config: Value = serde_yaml::from_str(&contents).context("parsing kube-apiserver oauthMetadata")?;

                        fix_oauth_metadata(&mut config, &cluster_domain)?;

                        tokio::fs::write(
                            file_path,
                            serde_json::to_string(&config).context("serializing kube-apiserver oauthMetadata")?,
                        )
                        .await
                        .context("writing kube-apiserver oauthMetadata to disk")?;

                        anyhow::Ok(())
                    }
                    .await
                    .context(format!("fixing kube-apiserver config.yaml {:?}", kcm_config_path))
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

pub(crate) async fn fix_filesystem_currentconfig(cluster_domain: &str, dir: &Path) -> Result<()> {
    join_all(file_utils::globvec(dir, "**/currentconfig")?.into_iter().map(|file_path| {
        let kcm_config_path = file_path.clone();
        let cluster_domain = cluster_domain.to_string();
        tokio::spawn(async move {
            async move {
                let contents = read_file_to_string(file_path.clone())
                    .await
                    .context("reading kube-apiserver oauthMetadata")?;
                let mut config: Value = serde_json::from_str(&contents).context("parsing currentconfig")?;

                fix_machineconfig(&mut config, &cluster_domain)?;

                tokio::fs::write(file_path, serde_json::to_string(&config).context("serializing currentconfig")?)
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

pub(crate) async fn fix_filesystem_apiserver_url_env_files(cluster_domain: &str, dir: &Path) -> Result<()> {
    join_all(file_utils::globvec(dir, "**/apiserver-url.env*")?.into_iter().map(|file_path| {
        let cluster_domain = cluster_domain.to_string();
        let kubeconfig_path = file_path.clone();
        tokio::spawn(async move {
            async move {
                let contents = read_file_to_string(file_path.clone()).await.context("reading apiserver-url.env")?;

                // write back to disk
                tokio::fs::write(file_path, fix_apiserver_url_file(contents.as_bytes().into(), &cluster_domain)?)
                    .await
                    .context("writing kubeconfig to disk")?;

                anyhow::Ok(())
            }
            .await
            .context(format!("fixing kubeconfig {:?}", kubeconfig_path))
        })
    }))
    .await
    .into_iter()
    .collect::<core::result::Result<Vec<_>, _>>()?
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_filesystem_kubeconfigs(cluster_domain: &str, dir: &Path) -> Result<()> {
    join_all(
        file_utils::globvec(dir, "**/*kubeconfig")?
            .into_iter()
            .chain(file_utils::globvec(dir, "**/kubeconfig")?.into_iter())
            .chain(file_utils::globvec(dir, "**/kubeConfig")?.into_iter())
            // dedup to avoid races
            .collect::<HashSet<_>>()
            .into_iter()
            .map(|file_path| {
                let cluster_domain = cluster_domain.to_string();
                let kubeconfig_path = file_path.clone();
                tokio::spawn(async move {
                    async move {
                        let contents = read_file_to_string(file_path.clone()).await.context("reading kubeconfig")?;
                        let mut yaml_value = serde_yaml::from_str::<Value>(contents.as_str())
                            .context(format!("parsing kubeconfig {:?} as yaml", contents))?;

                        fix_kubeconfig(&cluster_domain, &mut yaml_value)
                            .await
                            .context("fixing kubeconfig")?;

                        tokio::fs::write(file_path, serde_yaml::to_string(&yaml_value).context("serializing kubeconfig")?)
                            .await
                            .context("writing kubeconfig to disk")?;

                        anyhow::Ok(())
                    }
                    .await
                    .context(format!("fixing kubeconfig {:?}", kubeconfig_path))
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
