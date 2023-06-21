use self::params::ClusterRenameParameters;
use crate::{cluster_crypto::locations::K8sResourceLocation, k8s_etcd::InMemoryK8sEtcd};
use anyhow::{Context, Result};
use std::{path::PathBuf, sync::Arc};

mod etcd_rename;
mod filesystem_rename;
pub(crate) mod params;
mod rename_utils;

pub(crate) async fn rename_all(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    cluster_rename: ClusterRenameParameters,
    static_dirs: Vec<PathBuf>,
) -> Result<(), anyhow::Error> {
    let cluster_domain = cluster_rename.cluster_domain();
    let generated_infra_id = rename_utils::generate_infra_id(cluster_rename.cluster_name.to_string())?;

    fix_etcd_resources(etcd_client, &cluster_domain, generated_infra_id.clone(), &cluster_rename)
        .await
        .context("renaming etcd resources")?;

    fix_filesystem_resources(&cluster_domain, static_dirs, generated_infra_id.clone())
        .await
        .context("renaming filesystem resources")?;

    Ok(())
}

async fn fix_filesystem_resources(
    cluster_domain: &str,
    static_dirs: Vec<PathBuf>,
    generated_infra_id: String,
) -> Result<(), anyhow::Error> {
    for dir in &static_dirs {
        fix_dir_resources(cluster_domain, dir, &generated_infra_id).await?;
    }

    Ok(())
}

async fn fix_dir_resources(cluster_domain: &str, dir: &PathBuf, generated_infra_id: &String) -> Result<(), anyhow::Error> {
    filesystem_rename::fix_filesystem_kubeconfigs(&cluster_domain, &dir)
        .await
        .context("renaming kubeconfigs")?;
    filesystem_rename::fix_filesystem_apiserver_url_env_files(&cluster_domain, &dir)
        .await
        .context("renaming apiserver-url.env")?;
    filesystem_rename::fix_filesystem_kcm_pods(generated_infra_id, &dir)
        .await
        .context("renaming apiserver-url.env")?;
    filesystem_rename::fix_filesystem_kcm_configs(generated_infra_id, &dir)
        .await
        .context("renaming apiserver-url.env")?;
    filesystem_rename::fix_filesystem_kube_apiserver_configs(cluster_domain, &dir)
        .await
        .context("renaming apiserver-url.env")?;
    filesystem_rename::fix_filesystem_kube_apiserver_oauth_metadata(cluster_domain, &dir)
        .await
        .context("renaming apiserver-url.env")?;
    Ok(())
}

async fn fix_etcd_resources(
    mut etcd_client: &Arc<InMemoryK8sEtcd>,
    cluster_domain: &str,
    generated_infra_id: String,
    cluster_rename: &ClusterRenameParameters,
) -> Result<(), anyhow::Error> {
    etcd_rename::fix_router_certs(
        &mut etcd_client,
        &cluster_domain,
        K8sResourceLocation::new(Some("openshift-authentication"), "Secret", "v4-0-config-system-router-certs", "v1"),
    )
    .await
    .context("fixing v4-0-config-system-router-certs")?;
    etcd_rename::fix_router_certs(
        &mut etcd_client,
        &cluster_domain,
        K8sResourceLocation::new(Some("openshift-config-managed"), "Secret", "router-certs", "v1"),
    )
    .await
    .context("fixing router-certs")?;
    etcd_rename::fix_loadbalancer_serving_certkey(&mut etcd_client, &cluster_domain, "api", "external-loadbalancer-serving-certkey")
        .await
        .context("fixing external-loadbalancer-serving-certkey")?;
    etcd_rename::fix_loadbalancer_serving_certkey(
        &mut etcd_client,
        &cluster_domain,
        "api-int",
        "internal-loadbalancer-serving-certkey",
    )
    .await
    .context("fixing internal-loadbalancer-serving-certkey")?;
    etcd_rename::fix_machineconfigs(&mut etcd_client, &cluster_domain)
        .await
        .context("fixing machineconfigs")?;
    etcd_rename::fix_apiserver_config(&mut etcd_client, &cluster_domain)
        .await
        .context("fixing apiserver config")?;
    etcd_rename::fix_authentication_config(&mut etcd_client, &cluster_domain)
        .await
        .context("fixing authentication config")?;
    etcd_rename::fix_authentication_system_metadata(
        &mut etcd_client,
        &cluster_domain,
        K8sResourceLocation::new(Some("openshift-authentication"), "Configmap", "v4-0-config-system-metadata", "v1"),
    )
    .await
    .context("fixing authentication system metadata")?;
    etcd_rename::fix_authentication_system_metadata(
        &mut etcd_client,
        &cluster_domain,
        K8sResourceLocation::new(Some("openshift-config-managed"), "Configmap", "oauth-openshift", "v1"),
    )
    .await
    .context("fixing authentication system metadata (config managed)")?;
    etcd_rename::fix_console_public_config(&mut etcd_client, &cluster_domain)
        .await
        .context("fixing console public config")?;
    etcd_rename::fix_console_cluster_config(&mut etcd_client, &cluster_domain)
        .await
        .context("fixing console cluster config")?;
    etcd_rename::fix_dns_cluster_config(&mut etcd_client, &cluster_domain)
        .await
        .context("fixing dns cluster config")?;
    etcd_rename::fix_infrastructure_cluster_config(&mut etcd_client, &cluster_domain, &generated_infra_id)
        .await
        .context("fixing infrastructure cluster config")?;
    etcd_rename::fix_ingresses_cluster_config(&mut etcd_client, &cluster_domain)
        .await
        .context("fixing ingresses cluster config")?;
    etcd_rename::fix_console_cli_downloads(&mut etcd_client, &cluster_domain)
        .await
        .context("fixing console cli downloads")?;
    etcd_rename::fix_monitoring_config(&mut etcd_client, &cluster_domain)
        .await
        .context("fixing monitoring config")?;
    etcd_rename::fix_console_config(&mut etcd_client, &cluster_domain)
        .await
        .context("fixing console config")?;
    etcd_rename::fix_kube_apiserver_configs(&mut etcd_client, &cluster_domain)
        .await
        .context("fixing kube apiserver system metadata")?;
    etcd_rename::fix_oauth_metadata_configmap(&mut etcd_client, &cluster_domain)
        .await
        .context("fixing oauth metadata")?;
    etcd_rename::fix_kcm_config(&mut etcd_client, &generated_infra_id)
        .await
        .context("fixing kcm config")?;
    etcd_rename::fix_kcm_kubeconfig(&mut etcd_client, &cluster_domain)
        .await
        .context("fixing kcm kubeconfig")?;
    etcd_rename::fix_ovnkube_config(&mut etcd_client, &cluster_domain)
        .await
        .context("fixing ovnkube config")?;
    etcd_rename::fix_install_config(
        &mut etcd_client,
        &cluster_rename.cluster_name,
        &cluster_rename.cluster_base_domain,
        K8sResourceLocation::new(Some("kube-system"), "Configmap", "cluster-config-v1", "v1"),
    )
    .await
    .context("fixing kube-system install-config")?;
    etcd_rename::fix_install_config(
        &mut etcd_client,
        &cluster_rename.cluster_name,
        &cluster_rename.cluster_base_domain,
        K8sResourceLocation::new(Some("openshift-etcd"), "Configmap", "cluster-config-v1", "v1"),
    )
    .await
    .context("fixing etc install-config")?;
    etcd_rename::fix_kcm_pods(&mut etcd_client, &generated_infra_id)
        .await
        .context("fixing kcm pods")?;
    etcd_rename::fix_cvo_deployment(&mut etcd_client, &cluster_domain)
        .await
        .context("fixing cvo deployment")?;
    etcd_rename::delete_resources(&mut etcd_client).await.context("fixing kcm pods")?;
    Ok(())
}
