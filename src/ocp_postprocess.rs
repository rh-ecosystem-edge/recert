use self::{
    additional_trust_bundle::params::ProxyAdditionalTrustBundle, cluster_domain_rename::params::ClusterNamesRename,
    proxy_rename::args::Proxy,
};
use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    config::{path::ConfigPath, ClusterCustomizations},
    file_utils::{self, read_file_to_string},
    k8s_etcd::{self, get_etcd_json, put_etcd_yaml},
};
use anyhow::{bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD as base64_standard, URL_SAFE as base64_url},
    Engine as _,
};
use futures_util::future::join_all;
use k8s_etcd::InMemoryK8sEtcd;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

pub(crate) mod additional_trust_bundle;
mod arguments;
pub(crate) mod chrony_config;
pub(crate) mod cluster_domain_rename;
pub(crate) mod encryption_config;
mod fnv;
mod go_base32;
pub(crate) mod hostname_rename;
pub(crate) mod install_config_rename;
pub(crate) mod ip_rename;
pub(crate) mod machine_config_cidr_rename;
pub(crate) mod proxy_rename;
pub(crate) mod pull_secret_rename;
pub mod rename_utils;

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

    // When OpenShift pods/containers start, CVO is still stuck on its last known status and it
    // takes a couple of minutes for it to update its status to the current cluster conditions. When
    // its last known status is set to Available=True, it incorrectly shows that OpenShift is
    // stabilized while it's not. Since we want to watch the CVO status to signal the cluster
    // installation/update completion, this flapping CVO status makes it difficult. By setting CVO's
    // Available status condition to False here, it allows us to monitor CVO's status to signal the
    // cluster installation/update completion, as it will set it to True only once OpenShift is
    // stabilized.
    set_cluster_version_available_false(in_memory_etcd_client).await?;

    fix_deployment_dep_annotations(
        in_memory_etcd_client,
        K8sResourceLocation::new(Some("openshift-apiserver"), "Deployment", "apiserver", "v1"),
    )
    .await
    .context("fixing dep annotations for openshift-apiserver")?;

    fix_deployment_spec_hash_annotation(
        in_memory_etcd_client,
        K8sResourceLocation::new(Some("openshift-apiserver"), "Deployment", "apiserver", "v1"),
    )
    .await
    .context("fixing spec-hash annotation for openshift-apiserver")?;

    fix_deployment_dep_annotations(
        in_memory_etcd_client,
        K8sResourceLocation::new(Some("openshift-oauth-apiserver"), "Deployment", "apiserver", "v1"),
    )
    .await
    .context("fixing dep annotations for openshift-oauth-apiserver")?;

    fix_deployment_spec_hash_annotation(
        in_memory_etcd_client,
        K8sResourceLocation::new(Some("openshift-oauth-apiserver"), "Deployment", "apiserver", "v1"),
    )
    .await
    .context("fixing spec-hash annotation for openshift-oauth-apiserver")?;

    Ok(())
}

async fn set_cluster_version_available_false(etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "ClusterVersion", "version", "config.openshift.io/v1");
    let mut version = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting config.openshift.io/clusterversion/version")?;

    let conditions = &mut version
        .pointer_mut("/status/conditions")
        .context("no /status/conditions")?
        .as_array_mut()
        .context("/status/conditions not an array")?;

    conditions
        .iter_mut()
        .map(|condition: &mut serde_json::Value| {
            let condition = &mut condition.as_object_mut().context("condition not an object")?;
            let condition_type = condition
                .get("type")
                .context("type not found")?
                .as_str()
                .context("type not a string")?;
            if condition_type == "Available" {
                condition.insert("status".to_string(), serde_json::Value::String("False".to_string()));
                condition.insert(
                    "message".to_string(),
                    serde_json::Value::String("Cluster version status unknown".to_string()),
                );
            }

            Ok(())
        })
        .collect::<Result<Vec<_>>>()?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, version).await?;

    Ok(())
}

async fn run_cluster_customizations(
    cluster_customizations: &ClusterCustomizations,
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
) -> Result<()> {
    let dirs = &cluster_customizations.dirs;
    let files = &cluster_customizations.files;

    if let Some(cluster_names_rename) = &cluster_customizations.cluster_rename {
        cluster_rename(in_memory_etcd_client, cluster_names_rename, dirs, files)
            .await
            .context("renaming cluster")?;
    }

    if let Some(ip) = &cluster_customizations.ip {
        ip_rename(in_memory_etcd_client, ip, dirs, files).await.context("renaming IP")?;
    }

    if let Some(hostname) = &cluster_customizations.hostname {
        hostname_rename(in_memory_etcd_client, hostname, dirs, files)
            .await
            .context("renaming hostname")?;
    }

    if let Some(kubeadmin_password_hash) = &cluster_customizations.kubeadmin_password_hash {
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
        pull_secret_rename(in_memory_etcd_client, pull_secret, dirs, files)
            .await
            .context("renaming pull_secret")?;
    };

    additional_trust_bundle_rename(
        in_memory_etcd_client,
        &cluster_customizations.user_ca_bundle,
        &cluster_customizations.proxy_trusted_ca_bundle,
        dirs,
        files,
    )
    .await
    .context("renaming additional trust bundle")?;

    if let Some(machine_network_cidr) = &cluster_customizations.machine_network_cidr {
        fix_machine_network_cidr(in_memory_etcd_client, machine_network_cidr, dirs, files)
            .await
            .context("fixing machine network CIDR")?;
    }

    if let Some(chrony_config) = &cluster_customizations.chrony_config {
        chrony_config_rename(in_memory_etcd_client, chrony_config, dirs, files)
            .await
            .context("overriding chrony config")?;
    };

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

// https://github.com/openshift/library-go/blob/15d11d2f6bfcbe15679acd184ac69c77aa2e65bc/pkg/operator/loglevel/util.go#L13-L27
fn operand_log_level(log_level: &str) -> String {
    match log_level {
        "Normal" => "2",
        "Debug" => "4",
        "Trace" => "6",
        "TraceAll" => "8",
        _ => "2",
    }
    .to_string()
}

async fn get_kube_apiserver_operator_image(in_memory_etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<String> {
    let etcd_client = in_memory_etcd_client;

    let location = &K8sResourceLocation::new(
        Some("openshift-apiserver-operator"),
        "Deployment",
        "openshift-apiserver-operator",
        "apps/v1",
    );
    let operator_deployment = get_etcd_json(etcd_client, location)
        .await?
        .context(format!("couldn't find {}", location))?;

    let containers = operator_deployment
        .pointer("/spec/template/spec/containers")
        .context("no spec.template.spec.containers")?
        .as_array()
        .context("spec.template.spec.containers not an array")?;

    let env = containers
        .iter()
        .find(|container| container["name"] == "openshift-apiserver-operator")
        .context("could not find container named 'openshift-apiserver-operator'")?
        .get("env")
        .context("env not found")?
        .as_array()
        .context("env not an array")?;

    let image = env
        .iter()
        .find_map(|var| {
            (var.as_object()?.get("name") == Some(&serde_json::Value::String("KUBE_APISERVER_OPERATOR_IMAGE".to_string())))
                .then_some(var.get("value")?)
        })
        .context("expected KUBE_APISERVER_OPERATOR_IMAGE to be in env vars")?
        .as_str()
        .context("value not a string")?;

    Ok(image.to_string())
}

async fn get_openshift_apiserver_log_level(in_memory_etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<String> {
    let etcd_client = in_memory_etcd_client;

    let cluster = get_etcd_json(
        etcd_client,
        &K8sResourceLocation::new(None, "OpenShiftAPIServer", "cluster", "operator.openshift.io/v1"),
    )
    .await?
    .context("couldn't find openshiftapiserver.operator/cluster resource")?;

    let log_level = operand_log_level(
        cluster
            .pointer("/spec/logLevel")
            .context("no spec.logLevel")?
            .as_str()
            .context("spec.logLevel")?,
    );

    Ok(log_level.to_string())
}

async fn get_proxy_env_vars(in_memory_etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<Option<BTreeMap<String, String>>> {
    let etcd_client = in_memory_etcd_client;

    let cluster = get_etcd_json(
        etcd_client,
        &K8sResourceLocation::new(None, "OpenShiftAPIServer", "cluster", "operator.openshift.io/v1"),
    )
    .await?
    .context("couldn't find openshiftapiserver.operator/cluster resource")?;

    if let Some(proxy_config) = cluster.pointer("/spec/observedConfig/workloadcontroller/proxy") {
        let vars: BTreeMap<_, _> = proxy_config
            .as_object()
            .context("spec.observedConfig.workloadcontroller.proxy not an object")?
            .iter()
            .map(|(k, v)| Ok((k.clone(), String::from(v.as_str().context("value not a string")?))))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .collect();
        Ok(Some(vars))
    } else {
        Ok(None)
    }
}

pub(crate) async fn fix_deployment_spec_hash_annotation(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    k8s_resource_location: K8sResourceLocation,
) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    let mut deployment = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context(format!("couldn't find {}", k8s_resource_location))?;
    let dep = deployment.clone();

    let revision = dep
        .pointer("/metadata/labels/revision")
        .context("no .metadata.labels.revision")?
        .as_str()
        .context("revision not a str")?;

    let metadata_annotations = deployment
        .pointer_mut("/metadata/annotations")
        .context("no .metadata.annotations")?
        .as_object_mut()
        .context("annotations not an object")?;

    match k8s_resource_location.namespace.as_deref() {
        Some("openshift-apiserver") => {
            let log_level = get_openshift_apiserver_log_level(in_memory_etcd_client)
                .await
                .context("could not get openshift-apiserver log level")?;

            let kube_apiserver_operator_image = get_kube_apiserver_operator_image(in_memory_etcd_client)
                .await
                .context("could not get KUBE_APISERVER_OPERATOR_IMAGE")?;

            let proxy_env_vars = get_proxy_env_vars(in_memory_etcd_client)
                .await
                .context("could not get proxy env vars")?;

            fix_openshift_apiserver_spec_hash_annotation(
                metadata_annotations,
                revision,
                &log_level,
                &kube_apiserver_operator_image,
                proxy_env_vars,
            )
            .await?
        }
        Some("openshift-oauth-apiserver") => {
            let container_image = dep
                .pointer("/spec/template/spec/containers")
                .context("no spec.template.spec.containers")?
                .as_array()
                .context("spec.template.spec.containers not an array")?
                .iter()
                .find(|container| container["name"] == "oauth-apiserver")
                .context("could not find container named 'oauth-apiserver'")?
                .get("image")
                .context("image not found")?
                .as_str()
                .context("image not a string")?;

            let mut authentication = get_etcd_json(
                etcd_client,
                &K8sResourceLocation::new(None, "Authentication", "cluster", "operator.openshift.io/v1"),
            )
            .await?
            .context("couldn't find authentication.operator/cluster resource")?;

            let log_level = operand_log_level(
                authentication
                    .pointer("/spec/logLevel")
                    .context("no spec.logLevel")?
                    .as_str()
                    .context("spec.logLevel")?,
            );

            let args = authentication
                .pointer_mut("/spec/observedConfig/oauthAPIServer/apiServerArguments")
                .context("spec.observedConfig.oauthAPIServer.apiServerArguments not found")?
                .as_object_mut()
                .context("spec.observedConfig.oauthAPIServer.apiServerArguments not an object")?;
            args.insert("v".to_string(), serde_json::Value::String(log_level.clone()));

            fix_openshift_oauth_apiserver_spec_hash_annotation(
                metadata_annotations,
                revision,
                &log_level,
                container_image,
                arguments::encode_with_delimeter(args.clone(), r" \\\n  ")
                    .context("could not encode arguments")?
                    .as_str(),
            )
            .await?
        }
        _ => bail!("spec-hash annotation fix not supported for resource: '{}'", k8s_resource_location),
    }

    put_etcd_yaml(etcd_client, &k8s_resource_location, deployment).await?;

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
) -> Result<()> {
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

        let data = get_etcd_json(etcd_client, &resource_k8s_resource_location)
            .await?
            .context(format!("couldn't find {}", resource_k8s_resource_location))?
            .pointer("/data")
            .context("no .data")?
            .as_object()
            .context("data not an object")?
            .clone();

        let data_json = if resource_k8s_resource_location.kind == "secret" {
            // https://cs.opensource.google/go/go/+/refs/tags/go1.22.1:src/encoding/json/encode.go;l=751-753
            // https://cs.opensource.google/go/go/+/refs/tags/go1.22.1:src/encoding/json/encode.go;l=790
            let sorted: BTreeMap<_, _> = data
                .iter()
                .map(|(k, v)| {
                    Ok((
                        k,
                        base64_standard
                            .encode(serde_json::from_value::<Vec<u8>>(v.clone()).context("error tranforming serde_json value to Vec<u8>")?),
                    ))
                })
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .collect();
            serde_json::to_string(&sorted).context("couldn't serialize sorted data")?
        } else if data.is_empty() {
            // https://cs.opensource.google/go/go/+/refs/tags/go1.22.1:src/encoding/json/encode.go;l=724
            "null".to_string()
        } else {
            serde_json::to_string(&data).context("couldn't serialize data")?
        };

        annotations.insert(
            annotation_key,
            serde_json::Value::String(base64_url.encode(fnv::fnv1_32((format!("{}\n", data_json)).as_bytes()).to_be_bytes())),
        );
    }

    Ok(())
}

async fn fix_openshift_apiserver_spec_hash_annotation(
    annotations: &mut serde_json::Map<String, serde_json::Value>,
    revision: &str,
    log_level: &str,
    kube_apiserver_operator_image: &str,
    proxy_env_vars: Option<BTreeMap<String, String>>,
) -> Result<(), anyhow::Error> {
    let bytes = include_bytes!("bindata/openshift-apiserver-deployment.json");
    let mut spec_json = String::from_utf8(bytes.to_vec()).context("invalid UTF-8 string")?;

    let patterns = [
        ("${IMAGE}", "openshiftapiservers.operator.openshift.io/pull-spec"),
        ("${CONFIG_HASH}", "operator.openshift.io/dep-openshift-apiserver.config.configmap"),
        (
            "${ETCD_CLIENT_HASH}",
            "operator.openshift.io/dep-openshift-apiserver.etcd-client.secret",
        ),
        (
            "${ETCD_SERVING_CA_HASH}",
            "operator.openshift.io/dep-openshift-apiserver.etcd-serving-ca.configmap",
        ),
        (
            "${IMAGE_IMPORT_CA_HASH}",
            "operator.openshift.io/dep-openshift-apiserver.image-import-ca.configmap",
        ),
        (
            "${TRUSTED_CA_BUNDLE_HASH}",
            "operator.openshift.io/dep-openshift-apiserver.trusted-ca-bundle.configmap",
        ),
        ("${DESIRED_GENERATION}", "operator.openshift.io/dep-desired.generation"),
    ];

    for (pattern, key) in patterns {
        spec_json = spec_json.replace(
            pattern,
            annotations
                .get(key)
                .context(format!("key {key} not found"))?
                .clone()
                .as_str()
                .context(format!("{key} not a string"))?,
        );
    }

    spec_json = spec_json.replace("${REVISION}", revision);
    spec_json = spec_json.replace("${VERBOSITY}", log_level);
    spec_json = spec_json.replace("${KUBE_APISERVER_OPERATOR_IMAGE}", kube_apiserver_operator_image);

    match proxy_env_vars {
        Some(vars) => {
            for (key, value) in vars {
                spec_json = spec_json.replace(format!("${{{}}}", key).as_str(), &value);
            }
        }
        None => {
            for var in ["HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"] {
                spec_json = spec_json.replace(format!(",{{\"name\":\"{0}\",\"value\":\"${{{0}}}\"}}", var).as_str(), "");
            }
        }
    }

    let mut sha256 = Sha256::new();
    sha256.update(spec_json);
    let spec_hash: String = format!("{:x}", sha256.finalize());
    annotations.insert("operator.openshift.io/spec-hash".to_string(), serde_json::Value::String(spec_hash));

    Ok(())
}

async fn fix_openshift_oauth_apiserver_spec_hash_annotation(
    annotations: &mut serde_json::Map<String, serde_json::Value>,
    revision: &str,
    log_level: &str,
    image: &str,
    args: &str,
) -> Result<(), anyhow::Error> {
    let bytes = include_bytes!("bindata/openshift-oauth-apiserver-deployment.json");
    let mut spec_json = String::from_utf8(bytes.to_vec()).context("invalid UTF-8 string")?;

    let patterns = [
        (
            "${ETCD_CLIENT_HASH}",
            "operator.openshift.io/dep-openshift-oauth-apiserver.etcd-client.secret",
        ),
        (
            "${ETCD_SERVING_CA_HASH}",
            "operator.openshift.io/dep-openshift-oauth-apiserver.etcd-serving-ca.configmap",
        ),
    ];

    for (pattern, key) in patterns {
        spec_json = spec_json.replace(
            pattern,
            annotations
                .get(key)
                .context(format!("key {key} not found"))?
                .clone()
                .as_str()
                .context(format!("{key} not a string"))?,
        );
    }

    spec_json = spec_json.replace("${IMAGE}", image);
    spec_json = spec_json.replace("${REVISION}", revision);
    spec_json = spec_json.replace("${FLAGS}", args);
    spec_json = spec_json.replace("${VERBOSITY}", log_level);

    let mut sha256 = Sha256::new();
    sha256.update(spec_json);
    let spec_hash: String = format!("{:x}", sha256.finalize());
    annotations.insert("operator.openshift.io/spec-hash".to_string(), serde_json::Value::String(spec_hash));

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
pub(crate) async fn sync_webhook_authenticators(in_memory_etcd_client: &Arc<InMemoryK8sEtcd>, crypto_dirs: &[ConfigPath]) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    let namespace = Some("openshift-kube-apiserver");
    let base_name = "webhook-authenticator";

    let all_webhook_authenticator_kubeconfig_files = crypto_dirs
        .iter()
        .map(|dir| file_utils::globvec(dir, &format!("**/{}/kubeConfig", base_name)))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<HashSet<_>>();

    // Get latest revision from kube-apiserver-pod-(\d+) in the file path
    let regex = regex::Regex::new(r"kube-apiserver-pod-(\d+)").context("compiling regex")?;
    let captures = &all_webhook_authenticator_kubeconfig_files
        .iter()
        .filter_map(|file_pathbuf| {
            let file_path = file_pathbuf.to_str()?;
            Some((regex.captures(file_path)?[1].parse::<u32>().ok()?, file_pathbuf))
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
    dirs: &Vec<ConfigPath>,
    files: &Vec<ConfigPath>,
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

    cluster_domain_rename::rename_all(etcd_client, cluster_rename, dirs, files)
        .await
        .context("renaming all")?;

    Ok(())
}

pub(crate) async fn hostname_rename(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    hostname: &str,
    dirs: &[ConfigPath],
    files: &[ConfigPath],
) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    hostname_rename::rename_all(etcd_client, hostname, dirs, files)
        .await
        .context("renaming all")?;

    Ok(())
}

pub(crate) async fn ip_rename(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    ip: &str,
    dirs: &[ConfigPath],
    files: &[ConfigPath],
) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    ip_rename::rename_all(etcd_client, ip, dirs, files).await.context("renaming all")?;

    Ok(())
}

pub(crate) async fn pull_secret_rename(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    pull_secret: &str,
    dirs: &[ConfigPath],
    files: &[ConfigPath],
) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    pull_secret_rename::rename_all(etcd_client, pull_secret, dirs, files)
        .await
        .context("renaming all")?;

    Ok(())
}

async fn additional_trust_bundle_rename(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    user_ca_bundle: &Option<String>,
    proxy_trusted_ca_bundle: &Option<ProxyAdditionalTrustBundle>,
    dirs: &[ConfigPath],
    files: &[ConfigPath],
) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    let proxy_trusted_ca_bundle = match proxy_trusted_ca_bundle {
        Some(proxy_trusted_ca_bundle) => match proxy_trusted_ca_bundle.configmap_name.as_str() {
            "user-ca-bundle" => match proxy_trusted_ca_bundle.ca_bundle {
                Some(_) => {
                    bail!("user-ca-bundle configmap name requires ca-bundle to be empty");
                }
                None => match user_ca_bundle {
                    Some(user_ca_bundle) => Some(proxy_trusted_ca_bundle.set_bundle(user_ca_bundle)),
                    None => {
                        bail!("proxy user-ca-bundle configmap name requires user-ca-bundle to be set");
                    }
                },
            },
            _ => Some(proxy_trusted_ca_bundle.try_into().context("converting to set bundle")?),
        },
        None => None,
    };

    additional_trust_bundle::rename_all(etcd_client, user_ca_bundle, &proxy_trusted_ca_bundle, dirs, files)
        .await
        .context("renaming all")?;

    Ok(())
}

pub(crate) async fn proxy_rename(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    proxy: &Proxy,
    dirs: &[ConfigPath],
    files: &[ConfigPath],
) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    proxy_rename::rename_all(etcd_client, proxy, dirs, files)
        .await
        .context("renaming all")?;

    Ok(())
}

pub(crate) async fn install_config_rename(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    install_config: &str,
    dirs: &[ConfigPath],
    files: &[ConfigPath],
) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    install_config_rename::rename_all(etcd_client, install_config, dirs, files)
        .await
        .context("renaming all")?;

    Ok(())
}

async fn fix_machine_network_cidr(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    machine_network_cidr: &str,
    dirs: &[ConfigPath],
    files: &[ConfigPath],
) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    machine_config_cidr_rename::rename_all(etcd_client, machine_network_cidr, dirs, files)
        .await
        .context("renaming all")?;

    Ok(())
}

pub(crate) async fn chrony_config_rename(
    in_memory_etcd_client: &Arc<InMemoryK8sEtcd>,
    chrony_config: &str,
    static_dirs: &[ConfigPath],
    static_files: &[ConfigPath],
) -> Result<()> {
    let etcd_client = in_memory_etcd_client;

    chrony_config::rename_all(etcd_client, chrony_config, static_dirs, static_files)
        .await
        .context("renaming all")?;

    Ok(())
}
