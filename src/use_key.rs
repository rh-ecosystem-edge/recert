use anyhow::{ensure, Context, Result};
use bcder::Oid;
use std::{self, path::PathBuf};
use x509_certificate::{rfc3280::Name, rfc4519::OID_COMMON_NAME};

#[derive(Clone)]
pub(crate) struct UseKey {
    pub(crate) key_cert_cn: String,
    pub(crate) private_key_path: PathBuf,
}

impl std::fmt::Display for UseKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Using private key at {} for CN {}",
            self.private_key_path.display(),
            self.key_cert_cn
        )
    }
}

impl UseKey {
    pub(crate) fn cli_parse(value: &str) -> Result<Self> {
        // TODO: ' ' is legacy, remove eventually
        let parts = if value.contains(':') { value.split(':') } else { value.split(' ') }.collect::<Vec<_>>();

        ensure!(parts.len() == 2, "expected exactly one ':' in use-key argument, found {}", parts.len());

        let key_cert_cn = parts[0].to_string();
        let private_key_path = PathBuf::from(parts[1].to_string());

        Ok(Self {
            key_cert_cn,
            private_key_path,
        })
    }
}

pub(crate) struct UseKeyRules(pub Vec<UseKey>);

impl UseKeyRules {
    pub(crate) fn key_file(&self, subject: Name) -> Result<Option<PathBuf>> {
        let common_names = subject.iter_by_oid(Oid(OID_COMMON_NAME.as_ref().into())).collect::<Vec<_>>();

        if common_names.is_empty() {
            Ok(None)
        } else {
            ensure!(common_names.len() == 1, "expected exactly one common name, found more");
            let cn = common_names[0].to_string().context("converting CN to string")?;

            Ok(self
                .0
                .iter()
                .find(|key| key.key_cert_cn == cn)
                .map(|key| key.private_key_path.clone()))
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
