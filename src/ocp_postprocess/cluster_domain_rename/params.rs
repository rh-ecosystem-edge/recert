use anyhow::{ensure, Result};

#[derive(Clone)]
pub(crate) struct ClusterRenameParameters {
    pub(crate) cluster_name: String,
    pub(crate) cluster_base_domain: String,
}

impl ClusterRenameParameters {
    pub(crate) fn cli_parse(value: &str) -> Result<Self> {
        let parts = value.split(':').collect::<Vec<_>>();

        ensure!(
            parts.len() == 2,
            "expected exactly one ':' in cluster rename argument, found {}",
            parts.len()
        );

        let cluster_name = parts[0].to_string();
        let cluster_base_domain = parts[1].to_string();

        Ok(Self {
            cluster_name,
            cluster_base_domain,
        })
    }

    pub(crate) fn cluster_domain(&self) -> String {
        format!("{}.{}", self.cluster_name, self.cluster_base_domain)
    }
}
