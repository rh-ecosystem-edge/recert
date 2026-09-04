use anyhow::{ensure, Context, Result};
use bcder::Oid;
use serde::ser::SerializeStruct;
use std::{self, path::PathBuf, sync::atomic::Ordering::Relaxed};
use x509_certificate::{rfc3280::Name, rfc4519::OID_COMMON_NAME};

use crate::cluster_crypto::{
    crypto_utils::{key_from_file, key_from_pem, SigningKey},
    REDACT_SECRETS,
};

#[derive(Clone)]
pub(crate) struct UseKey {
    pub(crate) key_cert_cn: String,
    pub(crate) signing_key: SigningKey,
}

impl serde::Serialize for UseKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut st = serializer.serialize_struct("UseKey", 3)?;
        st.serialize_field("key_cert_cn", &self.key_cert_cn)?;

        if REDACT_SECRETS.load(Relaxed) {
            st.serialize_field("private_key", "<redacted>")?;
        } else {
            st.serialize_field("private_key", &self.signing_key)?;
        }

        st.end()
    }
}

impl std::fmt::Display for UseKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Using custom private key for CN {}", self.key_cert_cn)
    }
}

impl UseKey {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        let (key_cert_cn, path_or_pem) = split_cn_and_key(value)?;

        Ok(Self {
            key_cert_cn,
            signing_key: if path_or_pem.contains('\n') {
                key_from_pem(&path_or_pem).context("failed to parse PEM string")?
            } else {
                let private_key_path = PathBuf::from(&path_or_pem);
                key_from_file(&private_key_path).context(format!("reading private key from file {}", private_key_path.display()))?
            },
        })
    }
}

fn split_cn_and_key(value: &str) -> Result<(String, String)> {
    if let Some(pem_start) = value.find("-----BEGIN") {
        let cn = value[..pem_start]
            .trim_end()
            .strip_suffix(':')
            .context("expected ':' before PEM block in use-key argument")?
            .trim_end();
        ensure!(!cn.is_empty(), "empty CN in use-key argument");
        return Ok((cn.to_string(), value[pem_start..].to_string()));
    }

    if let Some((cn, path)) = value.rsplit_once(':') {
        ensure!(!cn.is_empty() && !path.is_empty(), "expected CN:path in use-key argument");
        return Ok((cn.to_string(), path.to_string()));
    }

    // TODO: ' ' is legacy, remove eventually
    let (cn, path) = value.split_once(' ').context("expected CN and key path in use-key argument")?;
    ensure!(!cn.is_empty() && !path.is_empty(), "expected CN and key path in use-key argument");
    Ok((cn.to_string(), path.to_string()))
}

#[derive(serde::Serialize)]
pub(crate) struct UseKeyRules(pub Vec<UseKey>);

impl UseKeyRules {
    pub(crate) fn key_file(&self, subject: Name) -> Result<Option<UseKey>> {
        let common_names = subject.iter_by_oid(Oid(OID_COMMON_NAME.as_ref().into())).collect::<Vec<_>>();

        if common_names.is_empty() {
            Ok(None)
        } else {
            ensure!(common_names.len() == 1, "expected exactly one common name, found more");
            let cn = common_names[0].to_string().context("converting CN to string")?;

            Ok(self.0.iter().find(|use_key_rule| use_key_rule.key_cert_cn == cn).cloned())
        }
    }
}

impl std::fmt::Display for UseKeyRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for rule in &self.0 {
            writeln!(f, "{}", rule)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cert::UseCert;

    const RSA_PEM: &str = include_str!("../vendor/pkcs8/tests/examples/rsa2048-priv.pem");
    const CERT_A: &str = include_str!("cluster_crypto/cert_key_pair/testdata/rsa_rfc5280.pem");
    const CERT_B: &str = include_str!("cluster_crypto/cert_key_pair/testdata/rsa_rfc7093.pem");

    fn parse_err(value: &str) -> String {
        UseKey::parse(value).err().expect("parse should fail").to_string()
    }

    #[test]
    fn test_parse_colon_separated_pem() {
        let parsed = UseKey::parse(&format!("my-cn:{RSA_PEM}")).unwrap();
        assert_eq!(parsed.key_cert_cn, "my-cn");
    }

    #[test]
    fn test_parse_rejects_wrong_part_count() {
        assert!(UseKey::parse("only-one-part").is_err());
        assert!(UseKey::parse("").is_err());
    }

    #[test]
    fn test_parse_legacy_space_separator() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.pem");
        std::fs::write(&path, RSA_PEM).unwrap();
        let parsed = UseKey::parse(&format!("my-cn {}", path.display())).unwrap();
        assert_eq!(parsed.key_cert_cn, "my-cn");
    }

    #[test]
    fn test_parse_cn_with_colons_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.pem");
        std::fs::write(&path, RSA_PEM).unwrap();
        let parsed = UseKey::parse(&format!("system:admin:{}", path.display())).unwrap();
        assert_eq!(parsed.key_cert_cn, "system:admin");
    }

    #[test]
    fn test_parse_cn_with_colons_from_pem() {
        let parsed = UseKey::parse(&format!("system:admin:{RSA_PEM}")).unwrap();
        assert_eq!(parsed.key_cert_cn, "system:admin");
    }

    #[test]
    fn test_parse_empty_cn_errors() {
        assert!(parse_err(":-----BEGIN PRIVATE KEY-----").contains("empty CN"));
    }

    #[test]
    fn test_parse_empty_path_errors() {
        assert!(parse_err("my-cn:").contains("expected CN:path"));
    }

    #[test]
    fn test_parse_pem_missing_colon_before_begin() {
        assert!(parse_err("my-cn-----BEGIN PRIVATE KEY-----").contains("expected ':' before PEM block"));
    }

    #[test]
    fn test_key_file_matches_cn() {
        let cert = UseCert::parse(CERT_A).unwrap();
        let key = UseKey::parse(&format!("aggregator-signer:{RSA_PEM}")).unwrap();
        let rules = UseKeyRules(vec![key]);
        let found = rules.key_file(cert.cert.cert.subject_name().clone()).unwrap().unwrap();
        assert_eq!(found.key_cert_cn, "aggregator-signer");
    }

    #[test]
    fn test_key_file_no_match() {
        let other = UseCert::parse(CERT_B).unwrap();
        let key = UseKey::parse(&format!("aggregator-signer:{RSA_PEM}")).unwrap();
        let rules = UseKeyRules(vec![key]);
        assert!(rules.key_file(other.cert.cert.subject_name().clone()).unwrap().is_none());
    }
}
