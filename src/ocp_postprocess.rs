use self::cluster_domain_rename::params::ClusterRenameParameters;
use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    k8s_etcd::{self, get_etcd_json, put_etcd_yaml},
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use clio::ClioPath;
use futures_util::future::join_all;
use k8s_etcd::InMemoryK8sEtcd;
use sha2::Digest;
use std::sync::Arc;

pub(crate) mod cluster_domain_rename;

/// Perform some OCP-related post-processing to make some OCP operators happy
pub(crate) async fn ocp_postprocess(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    cluster_rename_params: &Option<ClusterRenameParameters>,
    static_dirs: &Vec<ClioPath>,
    static_files: &Vec<ClioPath>,
) -> Result<()> {
    fix_olm_secret_hash_annotation(in_memory_etcd_client)
        .await
        .context("fixing olm secret hash annotation")?;

    delete_leases(in_memory_etcd_client).await.context("deleting leases")?;
    delete_pods(in_memory_etcd_client).await.context("deleting leases")?;
    delete_node_kubeconfigs(in_memory_etcd_client)
        .await
        .context("deleting node-kubeconfigs")?;

    if let Some(cluster_rename_params) = cluster_rename_params {
        cluster_rename(in_memory_etcd_client, cluster_rename_params, static_dirs, static_files)
            .await
            .context("renaming cluster")?;
    }

    Ok(())
}

/// The OLM packageserver operator requires that its secret's olmcahash sha256 hash annotation be
/// set to the sha256 hash of its APIServer's CA cert. Otherwise it makes no effort to reconcile
/// it. This method does that. Ideally we should get OLM to be more tolerant of this and remove
/// this post-processing step.
pub(crate) async fn fix_olm_secret_hash_annotation(in_memory_etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<()> {
    let etcd_client = in_memory_etcd_client;
    let mut hasher = sha2::Sha256::new();

    hasher.update(
        base64_standard.decode(
            get_etcd_json(
                etcd_client,
                &K8sResourceLocation::new(None, "APIService", "v1.packages.operators.coreos.com", "apiregistration.k8s.io/v1"),
            )
            .await?
            .context("couldn't find OLM APIService")?
            .pointer("/spec/caBundle")
            .context("couldn't find OLM .spec.caBundle")?
            .as_str()
            .context("couldn't find OLM caBundle")?,
        )?,
    );
    let hash = hasher.finalize();

    let package_serving_cert_secret_k8s_resource_location = K8sResourceLocation::new(
        Some("openshift-operator-lifecycle-manager"),
        "Secret",
        "packageserver-service-cert",
        "v1",
    );

    let mut packageserver_serving_cert_secret = get_etcd_json(etcd_client, &package_serving_cert_secret_k8s_resource_location)
        .await?
        .context("couldn't find packageserver-service-cert")?;
    packageserver_serving_cert_secret
        .pointer_mut("/metadata/annotations")
        .context("no .metadata.annotations")?
        .as_object_mut()
        .context("annotations not an object")?
        .insert("olmcahash".to_string(), serde_json::Value::String(format!("{:x}", hash)));

    put_etcd_yaml(
        etcd_client,
        &package_serving_cert_secret_k8s_resource_location,
        packageserver_serving_cert_secret,
    )
    .await?;

    Ok(())
}

/// These kubeconfigs nested inside a secret are far too complicated to handle in recert, so we
/// just delete them and hope that a reconcile will take care of them.
pub(crate) async fn delete_node_kubeconfigs(in_memory_etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    etcd_client
        .delete(&K8sResourceLocation::new(Some("openshift-kube-apiserver"), "Secret", "node-kubeconfigs", "v1").as_etcd_key())
        .await
        .context("deleting node-kubeconfigs")?;

    Ok(())
}

/// Delete all the leases to help the node come up faster
pub(crate) async fn delete_leases(etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<()> {
    join_all(etcd_client.list_keys("leases/").await?.into_iter().map(|key| async move {
        etcd_client.delete(&key).await.context(format!("deleting {}", key))?;
        Ok(())
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn delete_pods(etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<()> {
    join_all(etcd_client.list_keys("pods/").await?.into_iter().map(|key| async move {
        etcd_client.delete(&key).await.context(format!("deleting {}", key))?;
        Ok(())
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn cluster_rename(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    cluster_rename: &ClusterRenameParameters,
    static_dirs: &Vec<ClioPath>,
    static_files: &Vec<ClioPath>,
) -> Result<()> {
    let etcd_client = in_memory_etcd_client;
    cluster_domain_rename::rename_all(etcd_client, cluster_rename, static_dirs, static_files)
        .await
        .context("renaming all")?;

    Ok(())
}
