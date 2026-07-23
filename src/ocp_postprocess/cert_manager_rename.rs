use crate::{cnsanreplace::CnSanReplaceRules, k8s_etcd::InMemoryK8sEtcd, ocp_postprocess::delete_all};
use anyhow::{Context, Result};
use futures_util::future::join_all;
use std::sync::Arc;

pub(crate) async fn fix_cert_manager_certificates(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    cn_san_replace_rules: &CnSanReplaceRules,
) -> Result<()> {
    if cn_san_replace_rules.is_empty() {
        return Ok(());
    }

    let cert_keys = etcd_client.list_keys("cert-manager.io/certificates/").await?;

    if cert_keys.is_empty() {
        return Ok(());
    }

    log::info!("Checking {} cert-manager Certificate CRs for spec field updates", cert_keys.len());

    join_all(cert_keys.into_iter().map(|key| async move {
        let etcd_result = etcd_client
            .get(key.clone())
            .await
            .with_context(|| format!("getting cert-manager certificate {}", key))?
            .with_context(|| format!("cert-manager certificate {} disappeared", key))?;

        let mut value: serde_json::Value =
            serde_json::from_slice(&etcd_result.value).with_context(|| format!("parsing cert-manager certificate {}", key))?;

        if apply_cn_san_replace_to_certificate(&mut value, cn_san_replace_rules) {
            etcd_client
                .put(&key, serde_json::to_string(&value)?.as_bytes().into(), None)
                .await
                .context("putting in etcd")?;
        }

        Ok(())
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    // Delete stale CertificateRequest objects. Recert regenerates private keys in TLS
    // Secrets, but the old CertificateRequests still reference the previous key fingerprint.
    // cert-manager detects this mismatch and reissues with a fresh key. By deleting the
    // CertificateRequests, cert-manager will only compare the Certificate CR spec against
    // the TLS Secret — and since we've already updated both, it won't trigger reissuance.
    log::info!("Deleting stale cert-manager CertificateRequest objects");
    delete_all(etcd_client, "cert-manager.io/certificaterequests/").await?;

    Ok(())
}

/// Apply CN/SAN replacement rules to a cert-manager Certificate CR JSON value.
/// Updates spec.commonName, spec.dnsNames, spec.ipAddresses, spec.uris, and spec.emailAddresses fields.
/// Returns true if any modifications were made.
const ARRAY_FIELDS: &[(&str, &str)] = &[
    ("/spec/dnsNames", "dnsName"),
    ("/spec/ipAddresses", "ipAddress"),
    ("/spec/uris", "uri"),
    ("/spec/emailAddresses", "emailAddress"),
];

fn apply_cn_san_replace_to_certificate(value: &mut serde_json::Value, cn_san_replace_rules: &CnSanReplaceRules) -> bool {
    let mut modified = false;

    if let Some(common_name) = value.pointer_mut("/spec/commonName") {
        if let Some(cn_str) = common_name.as_str() {
            let new_cn = cn_san_replace_rules.replace(cn_str);
            if new_cn != cn_str {
                log::info!("Updating cert-manager Certificate commonName: {} -> {}", cn_str, new_cn);
                *common_name = serde_json::Value::String(new_cn);
                modified = true;
            }
        }
    }

    for (pointer, label) in ARRAY_FIELDS {
        modified |= replace_string_array(value, pointer, label, cn_san_replace_rules);
    }

    modified
}

fn replace_string_array(value: &mut serde_json::Value, pointer: &str, label: &str, cn_san_replace_rules: &CnSanReplaceRules) -> bool {
    let mut modified = false;
    if let Some(arr) = value.pointer_mut(pointer).and_then(|v| v.as_array_mut()) {
        for elem in arr.iter_mut() {
            if let Some(s) = elem.as_str() {
                let new_val = cn_san_replace_rules.replace(s);
                if new_val != s {
                    log::info!("Updating cert-manager Certificate {}: {} -> {}", label, s, new_val);
                    *elem = serde_json::Value::String(new_val);
                    modified = true;
                }
            }
        }
    }
    modified
}

#[cfg(test)]
mod tests {
    use super::apply_cn_san_replace_to_certificate;
    use crate::cnsanreplace::{CnSanReplace, CnSanReplaceRules};
    use serde_json::json;

    fn make_rules(pairs: &[(&str, &str)]) -> CnSanReplaceRules {
        CnSanReplaceRules(
            pairs
                .iter()
                .map(|(old, new)| CnSanReplace {
                    old: old.to_string(),
                    new: new.to_string(),
                })
                .collect(),
        )
    }

    fn make_certificate(common_name: &str, dns_names: &[&str]) -> serde_json::Value {
        make_certificate_full(common_name, dns_names, &[], &[], &[])
    }

    fn make_certificate_with_ips(common_name: &str, dns_names: &[&str], ip_addresses: &[&str]) -> serde_json::Value {
        make_certificate_full(common_name, dns_names, ip_addresses, &[], &[])
    }

    fn make_certificate_full(
        common_name: &str,
        dns_names: &[&str],
        ip_addresses: &[&str],
        uris: &[&str],
        email_addresses: &[&str],
    ) -> serde_json::Value {
        let mut spec = json!({
            "commonName": common_name,
            "dnsNames": dns_names,
            "secretName": "test-cert-tls",
            "issuerRef": {
                "name": "test-issuer",
                "kind": "Issuer"
            }
        });
        let obj = spec.as_object_mut().unwrap();
        if !ip_addresses.is_empty() {
            obj.insert("ipAddresses".to_string(), json!(ip_addresses));
        }
        if !uris.is_empty() {
            obj.insert("uris".to_string(), json!(uris));
        }
        if !email_addresses.is_empty() {
            obj.insert("emailAddresses".to_string(), json!(email_addresses));
        }
        json!({
            "apiVersion": "cert-manager.io/v1",
            "kind": "Certificate",
            "metadata": {
                "name": "test-cert",
                "namespace": "default"
            },
            "spec": spec
        })
    }

    #[test]
    fn test_replaces_common_name() {
        let rules = make_rules(&[("seed.example.com", "target.example.com")]);
        let mut cert = make_certificate("seed.example.com", &["other.example.com"]);

        let modified = apply_cn_san_replace_to_certificate(&mut cert, &rules);

        assert!(modified);
        assert_eq!(cert.pointer("/spec/commonName").unwrap().as_str().unwrap(), "target.example.com");
        // dnsNames should be unchanged
        assert_eq!(cert.pointer("/spec/dnsNames/0").unwrap().as_str().unwrap(), "other.example.com");
    }

    #[test]
    fn test_replaces_dns_names() {
        let rules = make_rules(&[("seed.example.com", "target.example.com")]);
        let mut cert = make_certificate("other.example.com", &["seed.example.com", "alt.example.com"]);

        let modified = apply_cn_san_replace_to_certificate(&mut cert, &rules);

        assert!(modified);
        // commonName should be unchanged
        assert_eq!(cert.pointer("/spec/commonName").unwrap().as_str().unwrap(), "other.example.com");
        // First dnsName should be replaced, second unchanged
        assert_eq!(cert.pointer("/spec/dnsNames/0").unwrap().as_str().unwrap(), "target.example.com");
        assert_eq!(cert.pointer("/spec/dnsNames/1").unwrap().as_str().unwrap(), "alt.example.com");
    }

    #[test]
    fn test_replaces_both_common_name_and_dns_names() {
        let rules = make_rules(&[("seed.example.com", "target.example.com")]);
        let mut cert = make_certificate("seed.example.com", &["seed.example.com", "other.example.com"]);

        let modified = apply_cn_san_replace_to_certificate(&mut cert, &rules);

        assert!(modified);
        assert_eq!(cert.pointer("/spec/commonName").unwrap().as_str().unwrap(), "target.example.com");
        assert_eq!(cert.pointer("/spec/dnsNames/0").unwrap().as_str().unwrap(), "target.example.com");
        assert_eq!(cert.pointer("/spec/dnsNames/1").unwrap().as_str().unwrap(), "other.example.com");
    }

    #[test]
    fn test_no_match_returns_unmodified() {
        let rules = make_rules(&[("seed.example.com", "target.example.com")]);
        let mut cert = make_certificate("unrelated.example.com", &["other.example.com"]);
        let original = cert.clone();

        let modified = apply_cn_san_replace_to_certificate(&mut cert, &rules);

        assert!(!modified);
        assert_eq!(cert, original);
    }

    #[test]
    fn test_exact_match_only() {
        // CnSanReplaceRules::replace() does exact string matching, not substring
        let rules = make_rules(&[("seed.example.com", "target.example.com")]);
        let mut cert = make_certificate("prefix.seed.example.com", &["sub.seed.example.com", "seed.example.com.suffix"]);
        let original = cert.clone();

        let modified = apply_cn_san_replace_to_certificate(&mut cert, &rules);

        assert!(!modified);
        assert_eq!(cert, original);
    }

    #[test]
    fn test_multiple_replacement_rules() {
        let rules = make_rules(&[
            ("seed.example.com", "target.example.com"),
            ("api.seed.cluster.local", "api.target.cluster.local"),
        ]);
        let mut cert = make_certificate("seed.example.com", &["api.seed.cluster.local", "other.example.com"]);

        let modified = apply_cn_san_replace_to_certificate(&mut cert, &rules);

        assert!(modified);
        assert_eq!(cert.pointer("/spec/commonName").unwrap().as_str().unwrap(), "target.example.com");
        assert_eq!(
            cert.pointer("/spec/dnsNames/0").unwrap().as_str().unwrap(),
            "api.target.cluster.local"
        );
        assert_eq!(cert.pointer("/spec/dnsNames/1").unwrap().as_str().unwrap(), "other.example.com");
    }

    #[test]
    fn test_no_common_name_field() {
        let rules = make_rules(&[("seed.example.com", "target.example.com")]);
        let mut cert = json!({
            "apiVersion": "cert-manager.io/v1",
            "kind": "Certificate",
            "spec": {
                "dnsNames": ["seed.example.com"],
                "secretName": "test-cert-tls"
            }
        });

        let modified = apply_cn_san_replace_to_certificate(&mut cert, &rules);

        assert!(modified);
        assert!(cert.pointer("/spec/commonName").is_none());
        assert_eq!(cert.pointer("/spec/dnsNames/0").unwrap().as_str().unwrap(), "target.example.com");
    }

    #[test]
    fn test_no_dns_names_field() {
        let rules = make_rules(&[("seed.example.com", "target.example.com")]);
        let mut cert = json!({
            "apiVersion": "cert-manager.io/v1",
            "kind": "Certificate",
            "spec": {
                "commonName": "seed.example.com",
                "secretName": "test-cert-tls"
            }
        });

        let modified = apply_cn_san_replace_to_certificate(&mut cert, &rules);

        assert!(modified);
        assert_eq!(cert.pointer("/spec/commonName").unwrap().as_str().unwrap(), "target.example.com");
        assert!(cert.pointer("/spec/dnsNames").is_none());
    }

    #[test]
    fn test_empty_dns_names_array() {
        let rules = make_rules(&[("seed.example.com", "target.example.com")]);
        let mut cert = make_certificate("seed.example.com", &[]);

        let modified = apply_cn_san_replace_to_certificate(&mut cert, &rules);

        assert!(modified);
        assert_eq!(cert.pointer("/spec/commonName").unwrap().as_str().unwrap(), "target.example.com");
    }

    #[test]
    fn test_empty_rules_returns_unmodified() {
        let rules = make_rules(&[]);
        let mut cert = make_certificate("seed.example.com", &["seed.example.com"]);
        let original = cert.clone();

        let modified = apply_cn_san_replace_to_certificate(&mut cert, &rules);

        assert!(!modified);
        assert_eq!(cert, original);
    }

    #[test]
    fn test_all_dns_names_replaced() {
        let rules = make_rules(&[
            ("a.seed.com", "a.target.com"),
            ("b.seed.com", "b.target.com"),
            ("c.seed.com", "c.target.com"),
        ]);
        let mut cert = make_certificate("other.com", &["a.seed.com", "b.seed.com", "c.seed.com"]);

        let modified = apply_cn_san_replace_to_certificate(&mut cert, &rules);

        assert!(modified);
        let dns_names = cert.pointer("/spec/dnsNames").unwrap().as_array().unwrap();
        assert_eq!(dns_names[0].as_str().unwrap(), "a.target.com");
        assert_eq!(dns_names[1].as_str().unwrap(), "b.target.com");
        assert_eq!(dns_names[2].as_str().unwrap(), "c.target.com");
    }

    #[test]
    fn test_replaces_ip_addresses() {
        let rules = make_rules(&[("10.0.0.1", "10.0.0.2")]);
        let mut cert = make_certificate_with_ips("other.com", &["other.com"], &["10.0.0.1", "192.168.1.100"]);

        let modified = apply_cn_san_replace_to_certificate(&mut cert, &rules);

        assert!(modified);
        let ips = cert.pointer("/spec/ipAddresses").unwrap().as_array().unwrap();
        assert_eq!(ips[0].as_str().unwrap(), "10.0.0.2");
        assert_eq!(ips[1].as_str().unwrap(), "192.168.1.100");
    }

    #[test]
    fn test_replaces_all_fields() {
        let rules = make_rules(&[("seed.example.com", "target.example.com"), ("10.0.0.1", "10.0.0.2")]);
        let mut cert = make_certificate_with_ips("seed.example.com", &["seed.example.com"], &["10.0.0.1"]);

        let modified = apply_cn_san_replace_to_certificate(&mut cert, &rules);

        assert!(modified);
        assert_eq!(cert.pointer("/spec/commonName").unwrap().as_str().unwrap(), "target.example.com");
        assert_eq!(cert.pointer("/spec/dnsNames/0").unwrap().as_str().unwrap(), "target.example.com");
        assert_eq!(cert.pointer("/spec/ipAddresses/0").unwrap().as_str().unwrap(), "10.0.0.2");
    }

    #[test]
    fn test_no_ip_addresses_field() {
        let rules = make_rules(&[("10.0.0.1", "10.0.0.2")]);
        let mut cert = make_certificate("other.com", &["other.com"]);

        let modified = apply_cn_san_replace_to_certificate(&mut cert, &rules);

        assert!(!modified);
        assert!(cert.pointer("/spec/ipAddresses").is_none());
    }

    #[test]
    fn test_ip_no_match_unchanged() {
        let rules = make_rules(&[("10.0.0.1", "10.0.0.2")]);
        let mut cert = make_certificate_with_ips("other.com", &["other.com"], &["192.168.1.100", "172.16.0.1"]);
        let original = cert.clone();

        let modified = apply_cn_san_replace_to_certificate(&mut cert, &rules);

        assert!(!modified);
        assert_eq!(cert, original);
    }

    #[test]
    fn test_replaces_uris() {
        let rules = make_rules(&[("spiffe://seed.cluster.local", "spiffe://target.cluster.local")]);
        let mut cert = make_certificate_full("other.com", &["other.com"], &[], &["spiffe://seed.cluster.local"], &[]);

        let modified = apply_cn_san_replace_to_certificate(&mut cert, &rules);

        assert!(modified);
        assert_eq!(
            cert.pointer("/spec/uris/0").unwrap().as_str().unwrap(),
            "spiffe://target.cluster.local"
        );
    }

    #[test]
    fn test_uri_exact_match_only() {
        let rules = make_rules(&[("spiffe://seed.cluster.local", "spiffe://target.cluster.local")]);
        let mut cert = make_certificate_full(
            "other.com",
            &["other.com"],
            &[],
            &["spiffe://seed.cluster.local/ns/default/sa/myservice"],
            &[],
        );
        let original = cert.clone();

        let modified = apply_cn_san_replace_to_certificate(&mut cert, &rules);

        assert!(!modified);
        assert_eq!(cert, original);
    }

    #[test]
    fn test_replaces_email_addresses() {
        let rules = make_rules(&[("admin@seed.example.com", "admin@target.example.com")]);
        let mut cert = make_certificate_full("other.com", &["other.com"], &[], &[], &["admin@seed.example.com", "user@other.com"]);

        let modified = apply_cn_san_replace_to_certificate(&mut cert, &rules);

        assert!(modified);
        let emails = cert.pointer("/spec/emailAddresses").unwrap().as_array().unwrap();
        assert_eq!(emails[0].as_str().unwrap(), "admin@target.example.com");
        assert_eq!(emails[1].as_str().unwrap(), "user@other.com");
    }

    #[test]
    fn test_replaces_ipv6_addresses() {
        let rules = make_rules(&[("fd00::1", "fd00::2")]);
        let mut cert = make_certificate_with_ips("other.com", &["other.com"], &["fd00::1", "2001:db8::1"]);

        let modified = apply_cn_san_replace_to_certificate(&mut cert, &rules);

        assert!(modified);
        let ips = cert.pointer("/spec/ipAddresses").unwrap().as_array().unwrap();
        assert_eq!(ips[0].as_str().unwrap(), "fd00::2");
        assert_eq!(ips[1].as_str().unwrap(), "2001:db8::1");
    }
}
