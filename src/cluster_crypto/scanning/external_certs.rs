use super::super::locations::K8sResourceLocation;
use super::ExternalCerts;
use crate::k8s_etcd::get_etcd_json;
use crate::k8s_etcd::InMemoryK8sEtcd;
use anyhow::{bail, Context, Result};
use itertools::Itertools;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;
use x509_certificate::X509Certificate;

pub(crate) async fn discover_external_certs(in_memory_etcd_client: Arc<InMemoryK8sEtcd>) -> Result<ExternalCerts> {
    let proxy_trusted_certs = vec![get_openshift_proxy_trusted_certs(&in_memory_etcd_client)
        .await
        .context("openshift trusted certs")?];

    // MCO reads the user-ca-bundle from the openshift-config namespace directly regardless of whether
    // the Proxy CR points at it or not, so we should consider the certs in that configmap to be
    // external.
    let ocp_trusted_certs = match get_openshift_user_ca_bundle(&in_memory_etcd_client)
        .await
        .context("openshift trusted certs")?
    {
        Some(certs) => vec![certs],
        None => vec![],
    };
    let image_trusted_certs = get_openshift_image_trusted_certs(&in_memory_etcd_client)
        .await
        .context("image trusted certs")?;

    // These sometimes diverge from the normal bundle of internet certs, as they seem to be taken
    // from the ccm container image:
    // https://github.com/openshift/cluster-cloud-controller-manager-operator/blob/e58049fbf77e3be8f2e51eeb51476e01ed08a25f/pkg/controllers/trusted_ca_bundle_controller.go#L85
    // so we should treat all of them as external certs.
    let ccm_trusted_certs = get_openshift_ccm_trusted_certs(&in_memory_etcd_client)
        .await
        .context("openshift ccm trusted certs")?;

    let all_certs_bundled = proxy_trusted_certs
        .into_iter()
        .chain(image_trusted_certs)
        .chain(ocp_trusted_certs)
        // .chain(ccm_trusted_certs)
        .join("\n");

    Ok(ExternalCerts(
        pem::parse_many(all_certs_bundled)
            .context("parsing")?
            .into_iter()
            .map(|pem| match pem.tag() {
                "CERTIFICATE" => Ok({
                    let der_bytes = pem.contents();
                    let crt = X509Certificate::from_der(der_bytes).context("from der")?;
                    let cn = crt.subject_name().user_friendly_str().unwrap_or("undecodable".to_string());

                    let hash = {
                        let mut sha256 = Sha256::new();
                        sha256.update(der_bytes);
                        let digest = sha256.finalize();
                        hex::encode(digest)
                    };

                    (cn, hash)
                }),
                _ => bail!("unexpected tag"),
            })
            .collect::<Result<HashSet<_>>>()
            .context("failed to parse certs")?,
    ))
}

pub(crate) async fn get_openshift_image_trusted_certs(in_memory_etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<Vec<String>> {
    let mut pem_strings = vec![];

    let image_config = get_etcd_json(
        in_memory_etcd_client,
        &(K8sResourceLocation::new(None, "Image", "cluster", "config.openshift.io")),
    )
    .await
    .context("getting image config")?
    .context("image config not found")?;

    if let Some(additional_trusted_ca) = image_config.pointer("/spec/additionalTrustedCA/name") {
        let user_image_ca_configmap = get_etcd_json(
            in_memory_etcd_client,
            &(K8sResourceLocation {
                namespace: Some("openshift-config".into()),
                kind: "ConfigMap".into(),
                apiversion: "v1".into(),
                name: additional_trusted_ca.as_str().context("must be string")?.into(),
            }),
        )
        .await
        .context("getting user image ca configmap")?
        .context("user image ca configmap not found")?;

        for (k, v) in user_image_ca_configmap
            .pointer("/data")
            .context("parsing registry-cas")?
            .as_object()
            .context("must be object")?
        {
            pem_strings.push(v.as_str().context(format!("must be string ({k})"))?.to_string());
        }
    }

    Ok(pem_strings)
}

pub(crate) async fn get_openshift_proxy_trusted_certs(in_memory_etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<String> {
    let trusted_ca_bundle_configmap = get_etcd_json(
        in_memory_etcd_client,
        &(K8sResourceLocation {
            namespace: Some("openshift-config-managed".into()),
            kind: "ConfigMap".into(),
            apiversion: "v1".into(),
            name: "trusted-ca-bundle".into(),
        }),
    )
    .await
    .context("getting trusted-ca-bundle")?
    .context("trusted-ca-bundle not found")?;

    Ok(trusted_ca_bundle_configmap
        .pointer("/data/ca-bundle.crt")
        .context("parsing ca-bundle.crt")?
        .as_str()
        .context("must be string")?
        .to_string())
}

pub(crate) async fn get_openshift_user_ca_bundle(in_memory_etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<Option<String>> {
    let trusted_ca_bundle_configmap = get_etcd_json(
        in_memory_etcd_client,
        &(K8sResourceLocation {
            namespace: Some("openshift-config".into()),
            kind: "ConfigMap".into(),
            apiversion: "v1".into(),
            name: "user-ca-bundle".into(),
        }),
    )
    .await
    .context("getting trusted-ca-bundle")?;

    match trusted_ca_bundle_configmap {
        None => {
            log::info!("user-ca-bundle configmap not present, skipping external certs lookup");
            Ok(None)
        }
        Some(trusted_ca_bundle_configmap) => Ok(Some(
            trusted_ca_bundle_configmap
                .pointer("/data/ca-bundle.crt")
                .context("parsing ca-bundle.crt")?
                .as_str()
                .context("must be string")?
                .to_string(),
        )),
    }
}

pub(crate) async fn get_openshift_ccm_trusted_certs(in_memory_etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<Option<String>> {
    let trusted_ca_bundle_configmap = get_etcd_json(
        in_memory_etcd_client,
        &(K8sResourceLocation {
            namespace: Some("openshift-cloud-controller-manager".into()),
            kind: "ConfigMap".into(),
            apiversion: "v1".into(),
            name: "ccm-trusted-ca".into(),
        }),
    )
    .await
    .context("getting ccm-trusted-ca")?;

    match trusted_ca_bundle_configmap {
        None => {
            log::info!("ccm-trusted-ca configmap not present, skipping external certs lookup");
            Ok(None)
        }
        Some(trusted_ca_bundle_configmap) => Ok(Some(
            trusted_ca_bundle_configmap
                .pointer("/data/ca-bundle.crt")
                .context("parsing ca-bundle.crt")?
                .as_str()
                .context("must be string")?
                .to_string(),
        )),
    }
}
