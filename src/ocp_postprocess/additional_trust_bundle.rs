use crate::{config::path::ConfigPath, k8s_etcd::InMemoryK8sEtcd};
use anyhow::{Context, Result};
use std::{path::Path, sync::Arc};

mod etcd_rename;
mod filesystem_rename;
mod utils;

pub(crate) async fn rename_all(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    additional_trust_bundle: &str,
    static_dirs: &[ConfigPath],
    static_files: &[ConfigPath],
) -> Result<()> {
    let new_merged_bundle = fix_etcd_resources(etcd_client, additional_trust_bundle)
        .await
        .context("renaming etcd resources")?;

    let new_merged_bundle = match new_merged_bundle {
        Some(bundle) => bundle,
        None => return Ok(()),
    };

    fix_filesystem_resources(&new_merged_bundle, additional_trust_bundle, static_dirs, static_files)
        .await
        .context("renaming filesystem resources")?;

    Ok(())
}

async fn fix_filesystem_resources(
    additional_trust_bundle: &str,
    new_merged_bundle: &str,
    static_dirs: &[ConfigPath],
    static_files: &[ConfigPath],
) -> Result<()> {
    for dir in static_dirs {
        fix_dir_resources(additional_trust_bundle, new_merged_bundle, dir).await?;
    }
    for file in static_files {
        fix_file_resources(additional_trust_bundle, new_merged_bundle, file).await?;
    }

    Ok(())
}

async fn fix_dir_resources(additional_trust_bundle: &str, new_merged_bundle: &str, dir: &Path) -> Result<()> {
    // NOTE: This only fixes the trust anchors, the user should run "update-ca-trust" to fully
    // update the system trust store after this change (this is also what MCO does).
    filesystem_rename::fix_filesystem_ca_trust_anchors(additional_trust_bundle, dir)
        .await
        .context("fixing ca trust anchors")?;

    filesystem_rename::fix_filesystem_currentconfig(additional_trust_bundle, dir)
        .await
        .context("renaming currentconfig")?;

    filesystem_rename::fix_static_configmap_trusted_ca_bundle(new_merged_bundle, dir)
        .await
        .context("fixing static configmap trusted ca bundle")?;

    Ok(())
}

async fn fix_file_resources(_additional_trust_bundle: &str, _new_merged_bundle: &str, _file: &Path) -> Result<()> {
    Ok(())
}

async fn fix_etcd_resources(etcd_client: &Arc<InMemoryK8sEtcd>, additional_trust_bundle: &str) -> Result<Option<String>> {
    // kubernetes.io/configmaps/openshift-config/custom-ca
    let original_additional_trust_bundle = etcd_rename::fix_original_additional_trust_bundle(etcd_client, additional_trust_bundle)
        .await
        .context("fixing labeled configmaps")?;

    let original_additional_trust_bundle = match original_additional_trust_bundle {
        Some(bundle) => bundle,
        None => return Ok(None),
    };

    let system_certs = utils::derive_system_certs_from_merged_bundle(
        original_additional_trust_bundle,
        utils::get_merged_bundle(etcd_client).await.context("getting merged bundle")?,
    )
    .context("getting unmerged bundle")?;

    let new_merged_bundle = utils::merge_bundles(additional_trust_bundle, &system_certs);

    etcd_rename::fix_labeled_configmaps(etcd_client, &new_merged_bundle)
        .await
        .context("fixing labeled configmaps")?;

    etcd_rename::fix_monitoring_configmaps(etcd_client, &new_merged_bundle)
        .await
        .context("fixing labeled configmaps")?;

    etcd_rename::fix_machineconfigs(etcd_client, additional_trust_bundle)
        .await
        .context("fixing machineconfigs")?;

    etcd_rename::fix_kcm_openshift_user_ca(etcd_client, additional_trust_bundle)
        .await
        .context("fixing kcm openshift user ca")?;

    Ok(Some(new_merged_bundle))
}
