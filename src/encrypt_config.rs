use std::path::PathBuf;

use anyhow::{ensure, Context, Result};

use crate::encrypt::EncryptionConfiguration;

#[derive(Clone, serde::Serialize)]
pub(crate) struct EncryptionConfig {
    pub(crate) config: EncryptionConfiguration,
}

impl std::fmt::Display for EncryptionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Using encryption configuration {}", self.config.apiVersion)
    }
}

impl EncryptionConfig {
    pub(crate) fn new(config: EncryptionConfiguration) -> Self {
        Self { config }
    }

    pub(crate) fn parse(config_path_or_string: &str) -> Result<Self> {
        // using '{' as it's a JSON formatted string
        let config = EncryptionConfiguration::parse_from_file(if config_path_or_string.contains('{') {
            config_path_or_string.as_bytes().to_vec()
        } else {
            let path = PathBuf::from(config_path_or_string);
            ensure!(
                path.exists(),
                "encryption configuration file {} does not exist",
                config_path_or_string
            );
            ensure!(
                path.is_file(),
                "encryption configuration file {} is not a file",
                config_path_or_string
            );

            std::fs::read(config_path_or_string).context("reading encryption config file")?
        })
        .context("parsing encryption configuration")?;

        Ok(Self { config })
    }
}
