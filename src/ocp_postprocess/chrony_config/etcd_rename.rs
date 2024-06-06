use crate::{k8s_etcd::InMemoryK8sEtcd, ocp_postprocess::rename_utils};
use anyhow::{Context, Result};
use std::sync::Arc;

pub(crate) async fn fix_machineconfigs(etcd_client: &Arc<InMemoryK8sEtcd>, chrony_content: &str, chrony_content_path: &str) -> Result<()> {
    rename_utils::fix_etcd_machineconfigs(etcd_client, chrony_content, chrony_content_path)
        .await
        .context("fixing chrony config content in machine configs")?;
    Ok(())
}
