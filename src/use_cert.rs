use std::path::PathBuf;

use anyhow::{ensure, Context, Result};
use bcder::Oid;
use x509_certificate::{rfc3280::Name, rfc4519::OID_COMMON_NAME};

use crate::cluster_crypto::certificate::Certificate;

#[derive(Clone)]
pub(crate) struct UseCert {
    pub(crate) cert: Certificate,
}

impl std::fmt::Display for UseCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Using cert with CN {}", self.cert.subject)
    }
}

impl UseCert {
    pub(crate) fn cli_parse(cert_path: &str) -> Result<Self> {
        let path = PathBuf::from(cert_path);
        ensure!(path.exists(), "cert file {} does not exist", cert_path);
        ensure!(path.is_file(), "cert file {} is not a file", cert_path);

        let pem = pem::parse_many(std::fs::read(cert_path).context("reading cert file")?).context("parsing PEM")?;
        ensure!(pem.len() == 1, "expected exactly one PEM block, found {}", pem.len());
        let pem = &pem[0];
        ensure!(pem.tag() == "CERTIFICATE", "expected CERTIFICATE PEM block, found {}", pem.tag());

        let x509_certificate = &x509_certificate::CapturedX509Certificate::from_der(pem.contents()).context("parsing DER")?;
        let cert = Certificate::try_from(x509_certificate).context("parsing cert")?;

        Ok(Self { cert })
    }
}

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
            if get_cn(rule.cert.cert.subject_name())
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
    let common_names = subject.iter_by_oid(Oid(OID_COMMON_NAME.as_ref().into())).collect::<Vec<_>>();

    Ok(if common_names.is_empty() {
        None
    } else {
        ensure!(common_names.len() == 1, "expected exactly one common name, found more");
        let cn = common_names[0].to_string().context("converting CN to string")?;
        Some(cn)
    })
}

impl std::fmt::Display for UseCertRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for rule in &self.0 {
            writeln!(f, "{}", rule)?;
        }

        Ok(())
    }
}
