use std::path::PathBuf;

use anyhow::{ensure, Context, Result};
use x509_cert::name::Name;

use crate::cluster_crypto::certificate::{name_attribute_values, Certificate, COMMON_NAME};

#[derive(Clone, serde::Serialize)]
pub(crate) struct UseCert {
    pub(crate) cert: Certificate,
}

impl std::fmt::Display for UseCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Using cert with CN {}", self.cert.subject)
    }
}

impl UseCert {
    pub(crate) fn parse(cert_path_or_pem: &str) -> Result<Self> {
        let pem = pem::parse_many(if cert_path_or_pem.contains('\n') {
            cert_path_or_pem.as_bytes().to_vec()
        } else {
            let path = PathBuf::from(cert_path_or_pem);
            ensure!(path.exists(), "cert file {} does not exist", cert_path_or_pem);
            ensure!(path.is_file(), "cert file {} is not a file", cert_path_or_pem);

            std::fs::read(cert_path_or_pem).context("reading cert file")?
        })
        .context("parsing PEM")?;

        ensure!(pem.len() == 1, "expected exactly one PEM block, found {}", pem.len());
        let pem = &pem[0];
        ensure!(pem.tag() == "CERTIFICATE", "expected CERTIFICATE PEM block, found {}", pem.tag());

        let cert = Certificate::from_der(pem.contents()).context("parsing cert")?;

        Ok(Self { cert })
    }
}

#[derive(serde::Serialize)]
pub(crate) struct UseCertRules(pub Vec<UseCert>);

impl UseCertRules {
    pub(crate) fn get_replacement_cert(&self, candidate_subject: &Name) -> Result<Option<Certificate>> {
        let candidate_cn = if let Some(candidate_cn) = get_cn(candidate_subject)? {
            candidate_cn
        } else {
            // This cert doesn't even have a CN, so it can't possibly match any of our rules
            return Ok(None);
        };

        for rule in &self.0 {
            if get_cn(&rule.cert.tbs().subject)
                .context("getting subject name CN")?
                .context("user provided cert has no CN")?
                == candidate_cn
            {
                return Ok(Some(rule.cert.clone()));
            }
        }

        Ok(None)
    }
}

fn get_cn(subject: &Name) -> Result<Option<String>> {
    let mut common_names = name_attribute_values(subject, COMMON_NAME).context("converting CN to string")?;

    ensure!(common_names.len() <= 1, "expected exactly one common name, found more");
    Ok(common_names.pop())
}

impl std::fmt::Display for UseCertRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for rule in &self.0 {
            writeln!(f, "{}", rule)?;
        }

        Ok(())
    }
}
