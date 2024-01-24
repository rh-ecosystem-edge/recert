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
    pub(crate) fn cli_parse(value: &str) -> Result<Self> {
        // TODO: ' ' is legacy, remove eventually
        let parts = if value.contains(':') { value.split(':') } else { value.split(' ') }.collect::<Vec<_>>();

        ensure!(
            parts.len() == 2,
            "expected exactly one ':' in use-key argument, found {}",
            parts.len()
        );

        let key_cert_cn = parts[0].to_string();
        let path_or_pem = parts[1].to_string();

        Ok(Self {
            key_cert_cn,
            signing_key: if path_or_pem.contains('\n') {
                let pem_string = path_or_pem;
                key_from_pem(&pem_string).context("failed to parse PEM string")?
            } else {
                let private_key_path = PathBuf::from(path_or_pem.to_string());
                key_from_file(&private_key_path).context(format!("reading private key from file {}", private_key_path.display()))?
            },
        })
    }
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
