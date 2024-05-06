use crate::{config::path::ConfigPath, k8s_etcd::InMemoryK8sEtcd};
use anyhow::{Context, Result};
use std::{path::Path, sync::Arc};

use self::params::ProxyAdditionalTrustBundleSet;

mod etcd_rename;
mod filesystem_rename;
pub(crate) mod params;
mod utils;

pub(crate) async fn rename_all(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    user_ca_bundle: &Option<String>,
    proxy_trusted_ca_bundle: &Option<ProxyAdditionalTrustBundleSet>,
    dirs: &[ConfigPath],
    files: &[ConfigPath],
) -> Result<()> {
    let new_merged_proxy_bundle = fix_etcd_resources(etcd_client, user_ca_bundle, proxy_trusted_ca_bundle)
        .await
        .context("renaming etcd resources")?;

    fix_filesystem_resources(user_ca_bundle, new_merged_proxy_bundle.as_deref(), dirs, files)
        .await
        .context("renaming filesystem resources")?;

    Ok(())
}

async fn fix_filesystem_resources(
    user_ca_bundle: &Option<String>,
    new_merged_bundle: Option<&str>,
    dirs: &[ConfigPath],
    files: &[ConfigPath],
) -> Result<()> {
    for dir in dirs {
        fix_dir_resources(user_ca_bundle, new_merged_bundle, dir).await?;
    }
    for file in files {
        fix_file_resources(user_ca_bundle, new_merged_bundle, file).await?;
    }

    Ok(())
}

async fn fix_dir_resources(user_ca_bundle: &Option<String>, new_merged_bundle: Option<&str>, dir: &Path) -> Result<()> {
    if let Some(user_ca_bundle) = user_ca_bundle {
        // NOTE: This only fixes the trust anchors, the user should run "update-ca-trust" to fully
        // update the system trust store after this change (this is also what MCO does).
        filesystem_rename::fix_filesystem_ca_trust_anchors(user_ca_bundle, dir)
            .await
            .context("fixing ca trust anchors")?;

        filesystem_rename::fix_filesystem_currentconfig(user_ca_bundle, dir)
            .await
            .context("renaming currentconfig")?;
    }

    if let Some(new_merged_bundle) = new_merged_bundle {
        filesystem_rename::fix_static_configmap_trusted_ca_bundle(new_merged_bundle, dir)
            .await
            .context("fixing static configmap trusted ca bundle")?;
    }

    Ok(())
}

async fn fix_file_resources(_user_ca_bundle: &Option<String>, _new_merged_bundle: Option<&str>, _file: &Path) -> Result<()> {
    Ok(())
}

async fn fix_etcd_resources(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    user_ca_bundle: &Option<String>,
    proxy_trusted_ca_bundle: &Option<ProxyAdditionalTrustBundleSet>,
) -> Result<Option<String>> {
    if let Some(user_ca_bundle) = user_ca_bundle {
        etcd_rename::fix_machineconfigs(etcd_client, user_ca_bundle)
            .await
            .context("fixing machineconfigs")?;

        etcd_rename::fix_controllerconfigs(etcd_client, user_ca_bundle)
            .await
            .context("fixing controllerconfigs")?;

        etcd_rename::fix_user_ca_bundle(etcd_client, user_ca_bundle)
            .await
            .context("fixing machineconfigs")?;
    }

    if let Some(proxy_trusted_ca_bundle) = proxy_trusted_ca_bundle {
        let original_proxy_bundle = etcd_rename::replace_and_get_proxy_trust_bundle(etcd_client, proxy_trusted_ca_bundle)
            .await
            .context("fixing labeled configmaps")?;

        let just_the_system_certs = utils::derive_system_certs_from_merged_bundle(
            original_proxy_bundle,
            utils::get_merged_bundle(etcd_client).await.context("getting merged bundle")?,
        )
        .context("getting unmerged bundle")?;

        let new_merged_bundle = utils::merge_bundles(&proxy_trusted_ca_bundle.ca_bundle, &just_the_system_certs);

        etcd_rename::fix_labeled_configmaps(etcd_client, &new_merged_bundle)
            .await
            .context("fixing labeled configmaps")?;

        etcd_rename::fix_monitoring_configmaps(etcd_client, &new_merged_bundle)
            .await
            .context("fixing labeled configmaps")?;

        etcd_rename::fix_kcm_openshift_user_ca(etcd_client, &proxy_trusted_ca_bundle.ca_bundle)
            .await
            .context("fixing kcm openshift user ca")?;

        return Ok(Some(new_merged_bundle));
    }

    Ok(None)
}
