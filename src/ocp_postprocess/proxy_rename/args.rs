use anyhow::{ensure, Result};

#[derive(Clone, serde::Serialize)]
pub(crate) struct ProxyConfig {
    pub(crate) http_proxy: String,
    pub(crate) https_proxy: String,
    pub(crate) no_proxy: String,
}

#[derive(Clone, serde::Serialize)]
pub(crate) struct Proxy {
    pub(crate) spec_proxy: ProxyConfig,
    pub(crate) status_proxy: ProxyConfig,
}

impl Proxy {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        let parts = value.split('|').collect::<Vec<_>>();

        ensure!(
            parts.len() == 6,
            "expected six parts separated by '|' in proxy argument, i.e. '<http_proxy>|<https_proxy>|<no_proxy>|<status_http_proxy>|<status_https_proxy>|<status_no_proxy>', found {}",
            parts.len()
        );

        let http_proxy = parts[0].to_string();
        let https_proxy = parts[1].to_string();
        let no_proxy = parts[2].to_string();

        let spec_proxy = ProxyConfig {
            http_proxy,
            https_proxy,
            no_proxy,
        };

        let http_proxy = parts[3].to_string();
        let https_proxy = parts[4].to_string();
        let no_proxy = parts[5].to_string();

        let status_proxy = ProxyConfig {
            http_proxy,
            https_proxy,
            no_proxy,
        };

        Ok(Self { spec_proxy, status_proxy })
    }
}
