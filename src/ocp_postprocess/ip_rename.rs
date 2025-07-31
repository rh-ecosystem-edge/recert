use crate::{config::path::ConfigPath, k8s_etcd::InMemoryK8sEtcd};
use anyhow::{ensure, Context, Result};
use std::{path::Path, sync::Arc};

mod etcd_rename;
mod filesystem_rename;

pub(crate) async fn rename_all(etcd_client: &Arc<InMemoryK8sEtcd>, ip: &str, dirs: &[ConfigPath], files: &[ConfigPath]) -> Result<()> {
    let original_ip = fix_etcd_resources(etcd_client, ip).await.context("renaming etcd resources")?;

    fix_filesystem_resources(&original_ip, ip, dirs, files)
        .await
        .context("renaming filesystem resources")?;

    Ok(())
}

pub(crate) async fn rename_all_dual_stack(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    ips: &[String],
    dirs: &[ConfigPath],
    files: &[ConfigPath],
) -> Result<()> {
    let original_ips = extract_original_dual_stack_ips(etcd_client)
        .await
        .context("extracting original dual-stack IPs")?;

    fix_etcd_resources_dual_stack(etcd_client, &original_ips, ips)
        .await
        .context("modifying etcd resources for dual stack")?;

    fix_filesystem_resources_dual_stack(&original_ips, ips, dirs, files)
        .await
        .context("renaming filesystem resources for dual stack")?;

    Ok(())
}

async fn fix_filesystem_resources(original_ip: &str, ip: &str, dirs: &[ConfigPath], files: &[ConfigPath]) -> Result<()> {
    for dir in dirs {
        fix_dir_resources(original_ip, ip, dir).await?;
    }

    for file in files {
        fix_file_resources(original_ip, ip, file).await?;
    }

    Ok(())
}

async fn fix_filesystem_resources_dual_stack(
    original_ips: &[String],
    ips: &[String],
    dirs: &[ConfigPath],
    files: &[ConfigPath],
) -> Result<()> {
    for dir in dirs {
        fix_dir_resources_dual_stack(original_ips, ips, dir).await?;
    }

    for file in files {
        fix_file_resources_dual_stack(original_ips, ips, file).await?;
    }

    Ok(())
}

async fn fix_dir_resources(original_ip: &str, ip: &str, dir: &Path) -> Result<()> {
    filesystem_rename::fix_filesystem_ip(original_ip, ip, dir)
        .await
        .context(format!("fix filesystem ip in {:?}", dir))?;
    Ok(())
}

async fn fix_dir_resources_dual_stack(original_ips: &[String], ips: &[String], dir: &Path) -> Result<()> {
    // Apply IPv4 replacement (original IPv4 → new IPv4)
    filesystem_rename::fix_filesystem_ip(&original_ips[0], &ips[0], dir)
        .await
        .context(format!("fix filesystem IPv4 in {:?}", dir))?;

    // Apply IPv6 replacement (original IPv6 → new IPv6) - both are guaranteed to be present
    filesystem_rename::fix_filesystem_ip(&original_ips[1], &ips[1], dir)
        .await
        .context(format!("fix filesystem IPv6 in {:?}", dir))?;

    Ok(())
}

async fn fix_file_resources(_original_ip: &str, _ip: &str, _file: &Path) -> Result<()> {
    Ok(())
}

async fn fix_file_resources_dual_stack(_original_ips: &[String], _ips: &[String], _file: &Path) -> Result<()> {
    // Keep consistent with single-stack version (no-op)
    Ok(())
}

async fn fix_etcd_resources_for_ip_pair(etcd_client: &Arc<InMemoryK8sEtcd>, original_ip: &str, new_ip: &str) -> Result<()> {
    etcd_rename::fix_openshift_apiserver_configmap(etcd_client, original_ip, new_ip)
        .await
        .context("fixing openshift apiserver config configmap")?;

    etcd_rename::fix_etcd_endpoints(etcd_client, original_ip, new_ip)
        .await
        .context("fixing etcd endpoints")?;

    etcd_rename::fix_etcd_pod(etcd_client, original_ip, new_ip)
        .await
        .context("fixing etcd-pod")?;

    etcd_rename::fix_etcd_scripts(etcd_client, original_ip, new_ip)
        .await
        .context("fixing etcd-scripts")?;

    etcd_rename::fix_etcd_secrets(etcd_client, original_ip, new_ip)
        .await
        .context("fixing etcd secrets")?;

    etcd_rename::fix_kube_apiserver_configs(etcd_client, original_ip, new_ip)
        .await
        .context("fixing kube apiserver configs")?;

    etcd_rename::fix_kubeapiservers_cluster(etcd_client, original_ip, new_ip)
        .await
        .context("fixing kubeapiservers/cluster")?;

    etcd_rename::fix_authentications_cluster(etcd_client, original_ip, new_ip)
        .await
        .context("fixing authentications/cluster")?;

    etcd_rename::fix_openshiftapiservers_cluster(etcd_client, original_ip, new_ip)
        .await
        .context("fixing openshiftapiservers/cluster")?;

    etcd_rename::fix_networks_cluster(etcd_client, original_ip, new_ip)
        .await
        .context("fixing networks/cluster")?;

    etcd_rename::fix_oauth_apiserver_deployment(etcd_client, original_ip, new_ip)
        .await
        .context("fixing oauth apiserver deployment")?;

    etcd_rename::fix_etcd_member(etcd_client, original_ip, new_ip)
        .await
        .context("fixing etcd member")?;

    Ok(())
}

async fn fix_etcd_resources(etcd_client: &Arc<InMemoryK8sEtcd>, ip: &str) -> Result<String> {
    let original_ips = etcd_rename::extract_original_ips(etcd_client)
        .await
        .context("extracting original IPs from node configuration")?;

    ensure!(
        original_ips.len() == 1,
        "Expected single-stack (1 IP) but found {} IPs",
        original_ips.len()
    );
    let original_ip = &original_ips[0];

    fix_etcd_resources_for_ip_pair(etcd_client, original_ip, ip)
        .await
        .context("applying etcd resource fixes")?;

    Ok(original_ip.clone())
}

async fn extract_original_dual_stack_ips(etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<Vec<String>> {
    let original_ips = etcd_rename::extract_original_ips(etcd_client)
        .await
        .context("extracting original IPs from node configuration")?;

    ensure!(
        original_ips.len() == 2,
        "Expected dual-stack (2 IPs) but found {} IPs",
        original_ips.len()
    );

    Ok(original_ips)
}

async fn fix_etcd_resources_dual_stack(etcd_client: &Arc<InMemoryK8sEtcd>, original_ips: &[String], new_ips: &[String]) -> Result<()> {
    let original_ipv4 = &original_ips[0];
    let original_ipv6 = &original_ips[1];

    let new_ipv4 = &new_ips[0];
    let new_ipv6 = new_ips.get(1).context("Second IP (IPv6) is required for dual-stack processing")?;

    log::info!(
        "Applying dual-stack IP changes - IPv4: {} → {}, IPv6: {} → {}",
        original_ipv4,
        new_ipv4,
        original_ipv6,
        new_ipv6
    );

    log::info!("Applying IPv4 replacements: {} → {}", original_ipv4, new_ipv4);

    fix_etcd_resources_for_ip_pair(etcd_client, original_ipv4, new_ipv4)
        .await
        .context("applying IPv4 etcd resource fixes")?;

    log::info!("Applying IPv6 replacements: {} → {}", original_ipv6, new_ipv6);

    fix_etcd_resources_for_ip_pair(etcd_client, original_ipv6, new_ipv6)
        .await
        .context("applying IPv6 etcd resource fixes")?;

    Ok(())
}
