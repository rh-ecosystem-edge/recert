use anyhow::{ensure, Result};

#[derive(Clone, serde::Serialize)]
pub(crate) struct ClusterNamesRename {
    pub(crate) cluster_name: String,
    pub(crate) cluster_base_domain: String,
    pub(crate) infra_id: Option<String>,
}

impl ClusterNamesRename {
    pub(crate) fn cli_parse(value: &str) -> Result<Self> {
        let parts = value.split(':').collect::<Vec<_>>();

        ensure!(
            parts.len() == 2 || parts.len() == 3,
            "expected two or three parts separated by ':' in cluster rename argument, i.e. '<cluster-name>:<cluster-base-domain>:<infra-id> or <cluster-name>:<cluster-base-domain>', found {}",
            parts.len()
        );

        let cluster_name = parts[0].to_string();
        let cluster_base_domain = parts[1].to_string();

        let infra_id = if parts.len() == 3 { Some(parts[2].to_string()) } else { None };

        Ok(Self {
            cluster_name,
            cluster_base_domain,
            infra_id,
        })
    }

    pub(crate) fn cluster_domain(&self) -> String {
        format!("{}.{}", self.cluster_name, self.cluster_base_domain)
    }
}
