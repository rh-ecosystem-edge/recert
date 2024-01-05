use crate::{
    file_utils::{self, commit_file, read_file_to_string, DRY_RUN},
    ocp_postprocess::cluster_domain_rename::rename_utils,
};
use anyhow::{self, Context, Result};
use futures_util::future::join_all;
use serde_json::Value;
use std::{fs, path::Path, sync::atomic::Ordering::Relaxed};

pub(crate) async fn fix_filesystem_etcd_static_pods(original_hostname: &str, hostname: &str, dir: &Path) -> Result<()> {
    join_all(file_utils::globvec(dir, "**/etcd-pod.yaml")?.into_iter().map(|file_path| {
        let etcd_pod_path = file_path.clone();
        let original_hostname = original_hostname.to_string();
        let hostname = hostname.to_string();
        tokio::spawn(async move {
            async move {
                let contents = read_file_to_string(&file_path).await.context("reading etcd-pod.yaml")?;

                let mut pod: Value = serde_json::from_str(&contents).context("parsing etcd.yaml")?;

                rename_utils::fix_etcd_static_pod(&mut pod, &original_hostname, &hostname).context("fixing etcd-pod.yaml")?;

                commit_file(file_path, serde_json::to_string(&pod).context("serializing etcd-pod.yaml")?)
                    .await
                    .context("writing etcd-pod.yaml to disk")?;

                anyhow::Ok(())
            }
            .await
            .context(format!("fixing etcd-pod.yaml {:?}", etcd_pod_path))
        })
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_filesystem_etcd_configmap_pod_yaml(original_hostname: &str, hostname: &str, dir: &Path) -> Result<()> {
    join_all(file_utils::globvec(dir, "**/*etcd-pod/pod.yaml")?.into_iter().map(|file_path| {
        let etcd_pod_path = file_path.clone();
        let original_hostname = original_hostname.to_string();
        let hostname = hostname.to_string();
        tokio::spawn(async move {
            async move {
                let contents = read_file_to_string(&file_path).await.context("reading etcd-pod.yaml")?;

                commit_file(
                    file_path,
                    rename_utils::fix_etcd_pod_yaml(&contents, &original_hostname, &hostname).context("fixing etcd-pod.yaml")?,
                )
                .await
                .context("writing etcd-pod.yaml to disk")?;

                anyhow::Ok(())
            }
            .await
            .context(format!("fixing etcd-pod.yaml {:?}", etcd_pod_path))
        })
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_filesystem_etcd_scripts_cluster_backup_sh(original_hostname: &str, hostname: &str, dir: &Path) -> Result<()> {
    join_all(
        file_utils::globvec(dir, "**/etcd-scripts/cluster-backup.sh")?
            .into_iter()
            .map(|file_path| {
                let cluster_backup_path = file_path.clone();
                let original_hostname = original_hostname.to_string();
                let hostname = hostname.to_string();
                tokio::spawn(async move {
                    async move {
                        let contents = read_file_to_string(&file_path).await.context("reading cluster-backup.sh")?;

                        commit_file(
                            file_path,
                            rename_utils::fix_cluster_backup_sh(&contents, &original_hostname, &hostname)
                                .context("fixing cluster-backup.sh")?,
                        )
                        .await
                        .context("writing cluster-backup.sh to disk")?;

                        anyhow::Ok(())
                    }
                    .await
                    .context(format!("fixing  cluster-backup.sh {:?}", cluster_backup_path))
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

pub(crate) async fn fix_filesystem_etcd_scripts_etcd_env(original_hostname: &str, hostname: &str, dir: &Path) -> Result<()> {
    join_all(file_utils::globvec(dir, "**/etcd-scripts/etcd.env")?.into_iter().map(|file_path| {
        let etcd_env_path = file_path.clone();
        let original_hostname = original_hostname.to_string();
        let hostname = hostname.to_string();
        tokio::spawn(async move {
            async move {
                let contents = read_file_to_string(&file_path).await.context("reading etcd.env")?;

                commit_file(
                    file_path,
                    rename_utils::fix_etcd_env(&contents, &original_hostname, &hostname).context("fixing etcd.env")?,
                )
                .await
                .context("writing etcd.env to disk")?;

                anyhow::Ok(())
            }
            .await
            .context(format!("fixing etcd.env {:?}", etcd_env_path))
        })
    }))
    .await
    .into_iter()
    .collect::<core::result::Result<Vec<_>, _>>()?
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_filesystem_kapi_startup_monitor_pod(hostname: &str, dir: &Path) -> Result<()> {
    join_all(
        file_utils::globvec(dir, "**/kube-apiserver-startup-monitor-pod.yaml")?
            .into_iter()
            .map(|file_path| {
                let kapi_startup_monitor_pod_path = file_path.clone();
                let hostname = hostname.to_string();
                tokio::spawn(async move {
                    async move {
                        let contents = read_file_to_string(&file_path)
                            .await
                            .context("reading kube-apiserver-startup-monitor-pod.yaml")?;

                        let mut pod: Value = serde_json::from_str(&contents).context("parsing kube-apiserver-startup-monitor-pod.yaml")?;

                        rename_utils::fix_kapi_startup_monitor_pod_container_args(&mut pod, &hostname)
                            .context("fixing kube-apiserver-startup-monitor-pod.yaml")?;

                        commit_file(
                            file_path,
                            serde_json::to_string(&pod).context("serializing kube-apiserver-startup-monitor-pod.yaml")?,
                        )
                        .await
                        .context("writing kube-apiserver-startup-monitor-pod.yaml to disk")?;

                        anyhow::Ok(())
                    }
                    .await
                    .context(format!(
                        "fixing kube-apiserver-startup-monitor-pod.yaml {:?}",
                        kapi_startup_monitor_pod_path
                    ))
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

pub(crate) async fn fix_filesystem_kapi_startup_monitor_configmap_pod_yaml(
    original_hostname: &str,
    hostname: &str,
    dir: &Path,
) -> Result<()> {
    join_all(
        file_utils::globvec(
            dir,
            "**/kube-apiserver-pod*/configmaps/kube-apiserver-pod/kube-apiserver-startup-monitor-pod.yaml",
        )?
        .into_iter()
        .map(|file_path| {
            let kapi_startup_monitor_pod_path = file_path.clone();
            let original_hostname = original_hostname.to_string();
            let hostname = hostname.to_string();
            tokio::spawn(async move {
                async move {
                    let contents = read_file_to_string(&file_path)
                        .await
                        .context("reading kube-apiserver-startup-monitor-pod.yaml")?;

                    commit_file(
                        file_path,
                        rename_utils::fix_kapi_startup_monitor_pod_yaml(&contents, &original_hostname, &hostname)
                            .context("fixing kube-apiserver-startup-monitor-pod.yaml")?,
                    )
                    .await
                    .context("writing kube-apiserver-startup-monitor-pod.yaml to disk")?;

                    anyhow::Ok(())
                }
                .await
                .context(format!(
                    "fixing kube-apiserver-startup-monitor-pod.yaml {:?}",
                    kapi_startup_monitor_pod_path
                ))
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

pub(crate) async fn fix_filesystem_etcd_all_certs(original_hostname: &str, hostname: &str, dir: &Path) -> Result<()> {
    join_all(file_utils::globvec(dir, "**/etcd-all-certs/etcd-*")?.into_iter().map(|file_path| {
        let original_path = file_path.clone();
        let new_path = file_path
            .clone()
            .into_os_string()
            .into_string()
            .unwrap()
            .replace(original_hostname, hostname);
        tokio::spawn(async move {
            async move {
                if !DRY_RUN.load(Relaxed) {
                    fs::rename(original_path, new_path)?;
                }

                anyhow::Ok(())
            }
            .await
            .context(format!("renaming {:?}", file_path))
        })
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}
