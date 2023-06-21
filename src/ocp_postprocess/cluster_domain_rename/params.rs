use anyhow::{self, bail, Result};

#[derive(Clone)]
pub(crate) struct ClusterRenameParameters {
    pub(crate) cluster_name: String,
    pub(crate) cluster_base_domain: String,
}

impl ClusterRenameParameters {
    pub(crate) fn new(cluster_name: String, cluster_base_domain: String) -> Self {
        Self {
            cluster_name,
            cluster_base_domain,
        }
    }

    pub(crate) fn cluster_domain(&self) -> String {
        format!("{}.{}", self.cluster_name, self.cluster_base_domain)
    }
}

impl TryFrom<String> for ClusterRenameParameters {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut parts = value.split(",");

        if parts.clone().count() != 2 {
            bail!("cluster rename must be comma seperated cluster name and cluster base domain");
        }

        let cluster_name = parts.next().unwrap().to_string();
        let cluster_base_domain = parts.next().unwrap().to_string();

        Ok(Self::new(cluster_name, cluster_base_domain))
    }
}

