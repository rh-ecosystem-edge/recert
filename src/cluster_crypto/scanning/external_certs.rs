use super::super::locations::K8sResourceLocation;
use crate::k8s_etcd::get_etcd_json;
use crate::k8s_etcd::InMemoryK8sEtcd;
use anyhow::{bail, Context, Result};
use itertools::Itertools;
use std::collections::HashSet;
use std::sync::Arc;
use x509_certificate::X509Certificate;

pub(crate) async fn discover_external_certs(in_memory_etcd_client: Arc<InMemoryK8sEtcd>) -> Result<HashSet<String>> {
    let proxy_trusted_certs = vec![get_openshift_proxy_trusted_certs(&in_memory_etcd_client)
        .await
        .context("openshift trusted certs")?];
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

    let all_certs_bundled = proxy_trusted_certs
        .into_iter()
        .chain(image_trusted_certs)
        .chain(ocp_trusted_certs)
        .join("\n");

    pem::parse_many(all_certs_bundled)
        .context("parsing")?
        .into_iter()
        .map(|pem| match pem.tag() {
            "CERTIFICATE" => Ok({
                let crt = X509Certificate::from_der(pem.contents()).context("from der")?;
                let cn = crt.subject_name().user_friendly_str().unwrap_or("undecodable".to_string());

                log::trace!("Found external certificate: {}", cn);

                cn.to_string()
            }),
            _ => bail!("unexpected tag"),
        })
        .collect::<Result<HashSet<_>>>()
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

/// MCO reads the user-ca-bundle from the openshift-config namespace directly regardless of whether
/// the Proxy CR points at it or not, so we should consider the certs in that configmap to be
/// external.
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
        None => Ok(None),
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
