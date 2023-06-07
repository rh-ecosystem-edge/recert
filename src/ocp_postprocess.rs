use crate::{cluster_crypto::locations::K8sResourceLocation, k8s_etcd::{self, get_etcd_yaml, put_etcd_yaml}};
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use k8s_etcd::InMemoryK8sEtcd;
use sha2::Digest;
use std::sync::Arc;
use tokio::sync::Mutex;

/// The OLM packageserver operator requires that its secret's olmcahash sha256 hash annotation be
/// set to the sha256 hash of its APIServer's CA cert. Otherwise it makes no effort to reconcile
/// it. This method does that. Ideally we should get OLM to be more tolerant of this and remove
/// this post-processing step.
pub(crate) async fn fix_olm_secret_hash_annotation(in_memory_etcd_client: &Arc<Mutex<InMemoryK8sEtcd>>) {
    let mut etcd_client = in_memory_etcd_client.lock().await;
    let mut hasher = sha2::Sha256::new();

    hasher.update(
        base64_standard
            .decode(
                get_etcd_yaml(
                    &mut etcd_client,
                    &K8sResourceLocation::new(None, "APIService", "v1.packages.operators.coreos.com", "apiregistration.k8s.io/v1"),
                )
                .await
                .pointer("/spec/caBundle")
                .unwrap()
                .as_str()
                .unwrap(),
            )
            .unwrap(),
    );
    let hash = hasher.finalize();

    let package_serving_cert_secret_k8s_resource_location = K8sResourceLocation::new(
        Some("openshift-operator-lifecycle-manager"),
        "Secret",
        "packageserver-service-cert",
        "v1",
    );

    let mut packageserver_serving_cert_secret = get_etcd_yaml(&mut etcd_client, &package_serving_cert_secret_k8s_resource_location).await;
    packageserver_serving_cert_secret.pointer_mut("/metadata/annotations").unwrap().as_object_mut().unwrap().insert(
        "olmcahash".to_string(),
        serde_json::Value::String(format!("{:x}", hash)),
    );

    put_etcd_yaml(
        &mut etcd_client,
        &package_serving_cert_secret_k8s_resource_location,
        packageserver_serving_cert_secret,
    )
    .await;
}
