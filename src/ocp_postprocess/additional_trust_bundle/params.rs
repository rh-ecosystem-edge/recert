use anyhow::{ensure, Context, Result};
use std::path::PathBuf;

#[derive(Clone, serde::Serialize)]
pub(crate) struct ProxyAdditionalTrustBundle {
    pub(crate) configmap_name: String,
    pub(crate) ca_bundle: Option<String>,
}

#[derive(Clone, serde::Serialize)]
pub(crate) struct ProxyAdditionalTrustBundleSet {
    pub(crate) configmap_name: String,
    pub(crate) ca_bundle: String,
}

impl ProxyAdditionalTrustBundle {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        let parts = value.splitn(2, ':').collect::<Vec<_>>();

        ensure!(
            parts.len() == 2,
            "expected two parts separated by ':' in proxy additional trust bundle argument, i.e. '<configmap-name>:<additional-trust-bundle>', found {}",
            parts.len()
        );

        let configmap_name = parts[0].to_string();

        let additional_trust_bundle = match parts[1] {
            "" => None,
            _ => Some(parse_additional_trust_bundle(parts[1]).context("parsing additional trust bundle")?),
        };

        Ok(Self {
            configmap_name,
            ca_bundle: additional_trust_bundle,
        })
    }
}

impl TryFrom<&ProxyAdditionalTrustBundle> for ProxyAdditionalTrustBundleSet {
    type Error = anyhow::Error;

    fn try_from(value: &ProxyAdditionalTrustBundle) -> Result<Self> {
        Ok(Self {
            configmap_name: value.configmap_name.clone(),
            ca_bundle: value.ca_bundle.clone().context("missing additional trust bundle")?,
        })
    }
}

impl ProxyAdditionalTrustBundle {
    pub(crate) fn set_bundle(&self, value: &str) -> ProxyAdditionalTrustBundleSet {
        ProxyAdditionalTrustBundleSet {
            configmap_name: self.configmap_name.clone(),
            ca_bundle: value.to_string(),
        }
    }
}

pub(crate) fn parse_additional_trust_bundle(value: &str) -> Result<String> {
    let bundle = if !value.contains('\n') {
        let path = PathBuf::from(&value);

        ensure!(path.try_exists()?, "additional_trust_bundle must exist");
        ensure!(path.is_file(), "additional_trust_bundle must be a file");

        String::from_utf8(std::fs::read(&path).context("failed to read additional_trust_bundle")?)
            .context("additional_trust_bundle must be valid UTF-8")?
    } else {
        value.to_string()
    };

    let pems = pem::parse_many(bundle.as_bytes()).context("additional_trust_bundle must be valid PEM")?;

    ensure!(!pems.is_empty(), "additional_trust_bundle must contain at least one certificate");

    ensure!(
        pems.iter().all(|pem| pem.tag() == "CERTIFICATE"),
        "additional_trust_bundle must contain only certificates"
    );

    // After parsing, we still return the raw bundle, as OpenShift also preserves the original
    // comments and whitespace in the user's additional trust bundle
    Ok(bundle)
}
