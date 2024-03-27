use self::{cluster_domain_rename::params::ClusterNamesRename, proxy_rename::args::Proxy};
use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    config::{path::ConfigPath, ClusterCustomizations},
    file_utils::{self, read_file_to_string},
    k8s_etcd::{self, get_etcd_json, put_etcd_yaml},
};
use anyhow::{Context, Result};
use base64::{
    engine::general_purpose::{STANDARD as base64_standard, URL_SAFE as base64_url},
    Engine as _,
};
use futures_util::future::join_all;
use k8s_etcd::InMemoryK8sEtcd;
use sha2::Digest;
use std::{collections::HashSet, sync::Arc};

pub(crate) mod additional_trust_bundle;
pub(crate) mod cluster_domain_rename;
mod fnv;
mod go_base32;
pub(crate) mod hostname_rename;
pub(crate) mod install_config_rename;
pub(crate) mod ip_rename;
pub(crate) mod proxy_rename;
pub(crate) mod pull_secret_rename;

/// Perform some OCP-related post-processing to make some OCP operators happy
#[allow(clippy::too_many_arguments)]
pub(crate) async fn ocp_postprocess(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    cluster_customizations: &ClusterCustomizations,
) -> Result<()> {
    fix_olm_secret_hash_annotation(in_memory_etcd_client)
        .await
        .context("fixing olm secret hash annotation")?;

    // Leases are meaningless when the cluster is down, so delete them to help the node come up
    // faster
    delete_all(in_memory_etcd_client, "leases/").await?;

    delete_node_kubeconfigs(in_memory_etcd_client)
        .await
        .context("deleting node-kubeconfigs")?;

    sync_webhook_authenticators(in_memory_etcd_client, &cluster_customizations.dirs)
        .await
        .context("syncing webhook authenticators")?;

    run_cluster_customizations(cluster_customizations, in_memory_etcd_client).await?;

    fix_deployment_dep_annotations(
        in_memory_etcd_client,
        K8sResourceLocation::new(Some("openshift-apiserver"), "Deployment", "apiserver", "v1"),
    )
    .await
    .context("fixing dep annotations for openshift-apiserver")?;

    fix_deployment_dep_annotations(
        in_memory_etcd_client,
        K8sResourceLocation::new(Some("openshift-oauth-apiserver"), "Deployment", "apiserver", "v1"),
    )
    .await
    .context("fixing dep annotations for openshift-oauth-apiserver")?;

    Ok(())
}

async fn run_cluster_customizations(
    cluster_customizations: &ClusterCustomizations,
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
) -> Result<(), anyhow::Error> {
    let dirs = &cluster_customizations.dirs;
    let files = &cluster_customizations.files;

    if let Some(cluster_names_rename) = &cluster_customizations.cluster_rename {
        cluster_rename(in_memory_etcd_client, cluster_names_rename, dirs, files)
            .await
            .context("renaming cluster")?;
    }

    if let Some(hostname) = &cluster_customizations.hostname {
        hostname_rename(in_memory_etcd_client, hostname, dirs, files)
            .await
            .context("renaming hostname")?;
    }

    if let Some(ip) = &cluster_customizations.ip {
        ip_rename(in_memory_etcd_client, ip, dirs, files).await.context("renaming IP")?;
    }

    if let Some(kubeadmin_password_hash) = &cluster_customizations.kubeadmin_password_hash {
        log::info!("setting kubeadmin password hash");
        set_kubeadmin_password_hash(in_memory_etcd_client, kubeadmin_password_hash)
            .await
            .context("setting kubeadmin password hash")?;
    }

    if let Some(proxy) = &cluster_customizations.proxy {
        proxy_rename(in_memory_etcd_client, proxy, dirs, files)
            .await
            .context("renaming proxy")?;
    }

    if let Some(install_config) = &cluster_customizations.install_config {
        install_config_rename(in_memory_etcd_client, install_config, dirs, files)
            .await
            .context("renaming install_config")?;
    }

    if let Some(pull_secret) = &cluster_customizations.pull_secret {
        log::info!("setting new pull_secret");
        pull_secret_rename(in_memory_etcd_client, pull_secret, dirs, files)
            .await
            .context("renaming pull_secret")?;
    };

    if let Some(additional_trust_bundle) = &cluster_customizations.additional_trust_bundle {
        additional_trust_bundle_rename(in_memory_etcd_client, additional_trust_bundle, dirs, files)
            .await
            .context("renaming additional_trust_bundle")?;
    }

    Ok(())
}

async fn set_kubeadmin_password_hash(in_memory_etcd_client: &InMemoryK8sEtcd, kubeadmin_password_hash: &str) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    let k8s_resource_location = &K8sResourceLocation::new(Some("kube-system"), "Secret", "kubeadmin", "v1");

    let key = k8s_resource_location.as_etcd_key();

    match kubeadmin_password_hash.is_empty() {
        true => {
            log::info!("deleting kubeadmin password secret as requested");
            etcd_client.delete(&key).await.context(format!("deleting {}", key))?;
            Ok(())
        }
        false => {
            log::info!("setting kubeadmin password hash");
            let mut secret = get_etcd_json(etcd_client, k8s_resource_location)
                .await?
                .context(format!("couldn't find {}", k8s_resource_location))?;

            let data = secret
                .pointer_mut("/data")
                .context("no .data")?
                .as_object_mut()
                .context("data not an object")?;

            data.insert(
                "kubeadmin".to_string(),
                serde_json::Value::Array(
                    kubeadmin_password_hash
                        .as_bytes()
                        .iter()
                        .map(|byte| serde_json::Value::Number(serde_json::Number::from(*byte)))
                        .collect(),
                ),
            );

            put_etcd_yaml(etcd_client, k8s_resource_location, secret).await?;

            Ok(())
        }
    }
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

pub(crate) async fn fix_deployment_dep_annotations(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    k8s_resource_location: K8sResourceLocation,
) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    let mut deployment = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context(format!("couldn't find {}", k8s_resource_location))?;

    let metadata_annotations = deployment
        .pointer_mut("/metadata/annotations")
        .context("no .metadata.annotations")?
        .as_object_mut()
        .context("annotations not an object")?;

    fix_dep_annotations(metadata_annotations, &k8s_resource_location, etcd_client).await?;

    let spec_template_metadata_annotations = deployment
        .pointer_mut("/spec/template/metadata/annotations")
        .context("no .spec.template.metadata.annotations")?
        .as_object_mut()
        .context("pod template annotations not an object")?;

    fix_dep_annotations(spec_template_metadata_annotations, &k8s_resource_location, etcd_client).await?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, deployment).await?;

    Ok(())
}

async fn fix_dep_annotations(
    annotations: &mut serde_json::Map<String, serde_json::Value>,
    k8s_resource_location: &K8sResourceLocation,
    etcd_client: &Arc<InMemoryK8sEtcd>,
) -> Result<(), anyhow::Error> {
    for annotation_key in annotations.keys().cloned().collect::<Vec<_>>() {
        if !annotation_key.starts_with("operator.openshift.io/dep-") {
            continue;
        }

        let annotation_parts = annotation_key
            .split('/')
            .nth(1)
            .context("couldn't parse annotation")?
            .strip_prefix("dep-")
            .context("couldn't parse annotation")?
            .split('.')
            .collect::<Vec<_>>();

        if annotation_parts.len() != 3 {
            // This avoids the operator.openshift.io/dep-desired.generation annotation
            continue;
        }

        let resource_k8s_resource_location = K8sResourceLocation::new(
            Some(annotation_parts[0]),
            match annotation_parts[2] {
                "secret" => "secret",
                "configmap" => "ConfigMap",
                kind => {
                    log::warn!(
                        "unsupported resource kind {} in annotation {} at {}",
                        kind,
                        annotation_key,
                        k8s_resource_location
                    );
                    continue;
                }
            },
            annotation_parts[1],
            "v1",
        );

        let data_json = &serde_json::to_string(
            get_etcd_json(etcd_client, &resource_k8s_resource_location)
                .await?
                .context(format!("couldn't find {}", resource_k8s_resource_location))?
                .pointer("/data")
                .context("no .data")?,
        )
        .context("couldn't serialize data")?;

        annotations.insert(
            annotation_key,
            serde_json::Value::String(base64_url.encode(fnv::fnv1_32((format!("{}\n", data_json)).as_bytes()).to_be_bytes())),
        );
    }

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

// The webhook authenticator secret has a kubeConfig field that is too complicated to handle in
// recert. We could simply delete it and it will be reconciled, but that's a bit too slow for us as
// it causes a kube-apiserver rollout. To speed things up, we'll just "reconcile" it ourselves by
// copying the kubeConfig contents from the kubeConfig file on disk that we already processed with
// recert.
pub(crate) async fn sync_webhook_authenticators(in_memory_etcd_client: &Arc<InMemoryK8sEtcd>, static_dirs: &[ConfigPath]) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    let namespace = Some("openshift-kube-apiserver");
    let base_name = "webhook-authenticator";

    let all_static_webhook_authenticator_kubeconfig_files = static_dirs
        .iter()
        .map(|dir| file_utils::globvec(dir, &format!("**/{}/kubeConfig", base_name)))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<HashSet<_>>();

    // Get latest revision from kube-apiserver-pod-(\d+) in the file path
    let regex = regex::Regex::new(r"kube-apiserver-pod-(\d+)").context("compiling regex")?;
    let captures = &all_static_webhook_authenticator_kubeconfig_files
        .iter()
        .filter_map(|file_pathbuf| {
            let file_path = file_pathbuf.to_str()?;
            Some((regex.captures(file_path)?[1].parse::<u32>().unwrap(), file_pathbuf))
        })
        .collect::<HashSet<_>>();
    let (latest_revision, latest_kubeconfig) = captures
        .iter()
        .max_by_key(|(revision, _pathbuf)| revision)
        .context("no kube-apiserver-pod-* found")?;

    let latest_kubeconfig_contents_with_trailing_newline =
        &read_file_to_string(latest_kubeconfig).await.context("reading latest kubeconfig")?;

    let latest_kubeconfig_contents = latest_kubeconfig_contents_with_trailing_newline.trim_end();

    for (namespace, secret_location_name) in [
        // We're modifying two secrets - the latest revision and the secret that doesn't have a
        // revision suffix, they're both supposed to be the same, otherwise the kube-apiserver will
        // trigger a rollout.
        (namespace, format!("{}-{}", base_name, latest_revision)),
        (namespace, base_name.to_string()),
        // We're also modifying the webhook-authentication-integrated-oauth secret, which is in a
        // different namespace and also has this kubeConfig field, and also seems to trigger a rollout
        // if left out of sync.
        (Some("openshift-config"), "webhook-authentication-integrated-oauth".to_string()),
    ] {
        let secret_location = K8sResourceLocation::new(namespace, "Secret", &secret_location_name, "v1");

        let mut webhook_authenticator_secret = get_etcd_json(etcd_client, &secret_location)
            .await?
            .context("couldn't find webhook-authenticator")?;

        webhook_authenticator_secret
            .pointer_mut("/data")
            .context("no .data")?
            .as_object_mut()
            .context("data not an object")?
            .insert(
                "kubeConfig".to_string(),
                serde_json::Value::Array(
                    latest_kubeconfig_contents
                        .as_bytes()
                        .iter()
                        .map(|byte| serde_json::Value::Number(serde_json::Number::from(*byte)))
                        .collect(),
                ),
            );

        put_etcd_yaml(etcd_client, &secret_location, webhook_authenticator_secret).await?;
    }

    Ok(())
}

pub(crate) async fn delete_all(etcd_client: &Arc<InMemoryK8sEtcd>, resource_etcd_key_prefix: &str) -> Result<()> {
    join_all(
        etcd_client
            .list_keys(resource_etcd_key_prefix)
            .await?
            .into_iter()
            .map(|key| async move {
                etcd_client.delete(&key).await.context(format!("deleting {}", key))?;
                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;
    Ok(())
}

pub(crate) async fn cluster_rename(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    cluster_rename: &ClusterNamesRename,
    static_dirs: &Vec<ConfigPath>,
    static_files: &Vec<ConfigPath>,
) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    for resource_key_prefix_to_delete in [
        // CSRs are always junk, so delete them as they contain the old node name
        "certificatesigningrequests/",
        // Delete all node-specific resources
        "tuned.openshift.io/profiles",
        "csinodes/",
        "ptp.openshift.io/nodeptpdevices/",
        "minions/",
        "sriovnetwork.openshift.io/sriovnetworknodestates/",
        // Delete all events as they contain the name
        "events/",
        // Delete all endsponts and endpointslices as they contain node names and pod references
        "services/endpoints/",
        "endpointslices/",
        // Delete ptp-configmap as it contains node-specific PTP config
        "configmaps/openshift-ptp/ptp-configmap",
        // The existing pods and replicasets are likely to misbehave after all the renaming we're doing
        "pods/",
        "replicasets/",
        // Delete ovnkube-node daemonset as it has cluster name in bash script
        "daemonsets/openshift-ovn-kubernetes/ovnkube-node",
    ]
    .iter()
    {
        delete_all(in_memory_etcd_client, resource_key_prefix_to_delete)
            .await
            .context(format!("deleting {}", resource_key_prefix_to_delete))?;
    }

    cluster_domain_rename::rename_all(etcd_client, cluster_rename, static_dirs, static_files)
        .await
        .context("renaming all")?;

    Ok(())
}

pub(crate) async fn hostname_rename(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    hostname: &str,
    static_dirs: &[ConfigPath],
    static_files: &[ConfigPath],
) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    hostname_rename::rename_all(etcd_client, hostname, static_dirs, static_files)
        .await
        .context("renaming all")?;

    Ok(())
}

pub(crate) async fn ip_rename(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    ip: &str,
    static_dirs: &[ConfigPath],
    static_files: &[ConfigPath],
) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    ip_rename::rename_all(etcd_client, ip, static_dirs, static_files)
        .await
        .context("renaming all")?;

    Ok(())
}

pub(crate) async fn pull_secret_rename(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    pull_secret: &str,
    static_dirs: &[ConfigPath],
    static_files: &[ConfigPath],
) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    pull_secret_rename::rename_all(etcd_client, pull_secret, static_dirs, static_files)
        .await
        .context("renaming all")?;

    Ok(())
}

pub(crate) async fn additional_trust_bundle_rename(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    additional_trust_bundle: &str,
    static_dirs: &[ConfigPath],
    static_files: &[ConfigPath],
) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    additional_trust_bundle::rename_all(etcd_client, additional_trust_bundle, static_dirs, static_files)
        .await
        .context("renaming all")?;

    Ok(())
}

pub(crate) async fn proxy_rename(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    proxy: &Proxy,
    static_dirs: &[ConfigPath],
    static_files: &[ConfigPath],
) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    proxy_rename::rename_all(etcd_client, proxy, static_dirs, static_files)
        .await
        .context("renaming all")?;

    Ok(())
}

pub(crate) async fn install_config_rename(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    install_config: &str,
    static_dirs: &[ConfigPath],
    static_files: &[ConfigPath],
) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    install_config_rename::rename_all(etcd_client, install_config, static_dirs, static_files)
        .await
        .context("renaming all")?;

    Ok(())
}
