use super::super::locations::K8sResourceLocation;
use crate::k8s_etcd::get_etcd_json;
use crate::k8s_etcd::InMemoryK8sEtcd;
use anyhow::{Context, Result};
use itertools::Itertools;
use std::collections::HashSet;
use std::sync::Arc;
use x509_certificate::X509Certificate;

/// Patterns used to identify OpenShift-specific certificates that should be
/// filtered out from external certificates.
const OPENSHIFT_CN_PATTERNS: &[&str] = &[
    "ou=openshift",
    "cn=ingress-operator@",
    "cn=openshift-kube-apiserver-operator_localhost-recovery-serving-signer@",
];

/// Determines if a certificate is an OpenShift internal certificate by
/// checking if its subject contains any of the OpenShift-specific patterns.
/// The check is case-insensitive.
fn is_openshift_certificate(subject: &str) -> bool {
    let subject_lower = subject.to_lowercase();
    OPENSHIFT_CN_PATTERNS.iter().any(|pattern| subject_lower.contains(*pattern))
}

pub(crate) async fn discover_external_certs(in_memory_etcd_client: Arc<InMemoryK8sEtcd>) -> Result<HashSet<String>> {
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

    let all_certs_bundled = proxy_trusted_certs
        .into_iter()
        .chain(image_trusted_certs)
        .chain(ocp_trusted_certs)
        .join("\n");

    pem::parse_many(all_certs_bundled)
        .context("parsing")?
        .into_iter()
        .filter_map(|pem| match pem.tag() {
            "CERTIFICATE" => match X509Certificate::from_der(pem.contents()) {
                Ok(crt) => {
                    let cn = crt.subject_name().user_friendly_str().unwrap_or("undecodable".to_string());

                    if is_openshift_certificate(&cn) {
                        log::trace!("Ignoring OpenShift certificate found in external certificates: {}", cn);
                        None
                    } else {
                        log::trace!("Found external certificate: {}", cn);
                        Some(Ok(cn))
                    }
                }
                Err(e) => Some(Err(anyhow::Error::new(e).context("from der"))),
            },
            _ => Some(Err(anyhow::anyhow!("unexpected tag"))),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_openshift_certificate() {
        // These should match
        assert!(is_openshift_certificate("OU=OpenShift,CN=service"));
        assert!(is_openshift_certificate("CN=ingress-operator@something,O=cluster"));
        assert!(is_openshift_certificate(
            "CN=openshift-kube-apiserver-operator_localhost-recovery-serving-signer@example,DC=com"
        ));
        assert!(is_openshift_certificate("DC=com,OU=openshift,CN=service"));

        // Case insensitivity tests
        assert!(is_openshift_certificate("ou=openshift,CN=service"));
        assert!(is_openshift_certificate("CN=INGRESS-OPERATOR@something,O=cluster"));

        // Test with more complex DN strings
        assert!(is_openshift_certificate("CN=service,OU=OpenShift,O=Example,L=City,ST=State,C=US"));
        assert!(is_openshift_certificate(
            "C=US,ST=State,L=City,O=Example,OU=Department,CN=ingress-operator@cluster"
        ));

        // These should not match
        assert!(!is_openshift_certificate("CN=service,OU=kubernetes"));
        assert!(!is_openshift_certificate("CN=operator,O=cluster"));
        assert!(!is_openshift_certificate("CN=kube-apiserver,DC=example,DC=com"));
        assert!(!is_openshift_certificate("DC=com,OU=other,CN=service"));

        // Edge cases
        assert!(!is_openshift_certificate(""));
        assert!(!is_openshift_certificate("CN=almost-ingress-operator-but-not"));
        assert!(!is_openshift_certificate("CN=openshift-kube-apiserver-operator-no-at-sign"));
        assert!(!is_openshift_certificate("OUopenshift")); // No equals sign, should not match
    }
}
