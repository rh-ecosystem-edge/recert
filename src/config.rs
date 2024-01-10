use std::{env, ops::Deref, path::Path};

use crate::{
    cnsanreplace::{CnSanReplace, CnSanReplaceRules},
    ocp_postprocess::cluster_domain_rename::params::ClusterRenameParameters,
    use_cert::{UseCert, UseCertRules},
    use_key::{UseKey, UseKeyRules},
};
use anyhow::{ensure, Context, Result};
use clap::Parser;
use clio::ClioPath;
use serde_yaml::Value;

use self::cli::Cli;

mod cli;

#[derive(Clone, Debug)]
pub(crate) struct ConfigPath(pub(crate) ClioPath);

impl AsRef<ClioPath> for ConfigPath {
    fn as_ref(&self) -> &ClioPath {
        &self.0
    }
}

impl Deref for ConfigPath {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0.path()
    }
}

// Drop in for ClioPath
impl From<ClioPath> for ConfigPath {
    fn from(clio_path: ClioPath) -> Self {
        Self(clio_path)
    }
}

impl serde::Serialize for ConfigPath {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.to_string_lossy().as_ref())
    }
}

/// All the user requested customizations, coalesced into a single struct for convenience
#[derive(serde::Serialize)]
pub(crate) struct Customizations {
    pub(crate) cn_san_replace_rules: CnSanReplaceRules,
    pub(crate) use_key_rules: UseKeyRules,
    pub(crate) use_cert_rules: UseCertRules,
    pub(crate) extend_expiration: bool,
    pub(crate) force_expire: bool,
}

/// All parsed CLI arguments, coalesced into a single struct for convenience
#[derive(serde::Serialize)]
pub(crate) struct RecertConfig {
    pub(crate) dry_run: bool,
    pub(crate) etcd_endpoint: Option<String>,
    pub(crate) static_dirs: Vec<ConfigPath>,
    pub(crate) static_files: Vec<ConfigPath>,
    pub(crate) customizations: Customizations,
    pub(crate) cluster_rename: Option<ClusterRenameParameters>,
    pub(crate) hostname: Option<String>,
    pub(crate) threads: Option<usize>,
    pub(crate) regenerate_server_ssh_keys: Option<ConfigPath>,
    pub(crate) summary_file: Option<ConfigPath>,
    pub(crate) summary_file_clean: Option<ConfigPath>,

    pub(crate) config_file_raw: Option<String>,
    pub(crate) cli_raw: Option<String>,
}

impl RecertConfig {
    pub(crate) fn parse_from_config_file(config_bytes: &[u8]) -> Result<Self> {
        let value: Value = serde_yaml::from_slice(config_bytes)?;

        let dry_run = value
            .get("dry_run")
            .unwrap_or(&Value::Bool(false))
            .as_bool()
            .context("dry_run must be a boolean")?;

        let etcd_endpoint = match value.get("etcd_endpoint") {
            Some(value) => Some(value.as_str().context("etcd_endpoint must be a string")?.to_string()),
            None => None,
        };

        let static_dirs = match value.get("static_dirs") {
            Some(value) => value
                .as_sequence()
                .context("static_dirs must be a sequence")?
                .iter()
                .map(|value| {
                    let clio_path = ClioPath::new(value.as_str().context("static_dirs must be a sequence of strings")?)
                        .context(format!("config dir {}", value.as_str().unwrap()))?;

                    ensure!(clio_path.try_exists()?, format!("static_dir must exist: {}", clio_path));
                    ensure!(clio_path.is_dir(), format!("static_dir must be a directory: {}", clio_path));

                    Ok(ConfigPath::from(clio_path))
                })
                .collect::<Result<Vec<ConfigPath>>>()?,
            None => vec![],
        };

        let static_files = match value.get("static_files") {
            Some(value) => value
                .as_sequence()
                .context("static_files must be a sequence")?
                .iter()
                .map(|value| {
                    let clio_path = ClioPath::new(value.as_str().context("static_files must be a sequence of strings")?)
                        .context(format!("config file {}", value.as_str().unwrap()))?;

                    ensure!(clio_path.try_exists()?, format!("static_file must exist: {}", clio_path));
                    ensure!(clio_path.is_file(), format!("static_file must be a file: {}", clio_path));

                    Ok(ConfigPath::from(clio_path))
                })
                .collect::<Result<Vec<ConfigPath>>>()?,
            None => vec![],
        };

        let cn_san_replace_rules = match value.get("cn_san_replace_rules") {
            Some(value) => CnSanReplaceRules(
                value
                    .as_sequence()
                    .context("cn_san_replace_rules must be a sequence")?
                    .iter()
                    .map(|value| {
                        CnSanReplace::cli_parse(value.as_str().context("cn_san_replace_rules must be a sequence of strings")?)
                            .context(format!("cn_san_replace_rule {}", value.as_str().unwrap()))
                    })
                    .collect::<Result<Vec<CnSanReplace>>>()?,
            ),
            None => CnSanReplaceRules(vec![]),
        };

        let use_key_rules = match value.get("use_key_rules") {
            Some(value) => UseKeyRules(
                value
                    .as_sequence()
                    .context("use_key_rules must be a sequence")?
                    .iter()
                    .map(|value| {
                        UseKey::cli_parse(value.as_str().context("use_key_rules must be a sequence of strings")?)
                            .context(format!("use_key_rule {}", value.as_str().unwrap()))
                    })
                    .collect::<Result<Vec<UseKey>>>()?,
            ),
            None => UseKeyRules(vec![]),
        };

        let use_cert_rules = match value.get("use_cert_rules") {
            Some(value) => UseCertRules(
                value
                    .as_sequence()
                    .context("use_cert_rules must be a sequence")?
                    .iter()
                    .map(|value| {
                        UseCert::cli_parse(value.as_str().context("use_cert_rules must be a sequence of strings")?)
                            .context(format!("use_cert_rule {}", value.as_str().unwrap()))
                    })
                    .collect::<Result<Vec<UseCert>>>()?,
            ),
            None => UseCertRules(vec![]),
        };

        let extend_expiration = value
            .get("extend_expiration")
            .unwrap_or(&Value::Bool(false))
            .as_bool()
            .context("extend_expiration must be a boolean")?;

        let force_expire = value
            .get("force_expire")
            .unwrap_or(&Value::Bool(false))
            .as_bool()
            .context("force_expire must be a boolean")?;

        let cluster_rename = match value.get("cluster_rename") {
            Some(value) => Some(
                ClusterRenameParameters::cli_parse(value.as_str().context("cluster_rename must be a string")?)
                    .context(format!("cluster_rename {}", value.as_str().unwrap()))?,
            ),
            None => None,
        };

        let hostname = match value.get("hostname") {
            Some(value) => Some(value.as_str().context("hostname must be a string")?.to_string()),
            None => None,
        };

        let threads = match value.get("threads") {
            Some(value) => Some(
                value
                    .as_u64()
                    .context("threads must be an integer")?
                    .try_into()
                    .context("threads must be an integer")?,
            ),
            None => None,
        };

        let regenerate_server_ssh_keys = match value.get("regenerate_server_ssh_keys") {
            Some(value) => {
                let clio_path = ConfigPath::from(
                    ClioPath::new(value.as_str().context("regenerate_server_ssh_keys must be a string")?)
                        .context(format!("regenerate_server_ssh_keys {}", value.as_str().unwrap()))?,
                );

                ensure!(clio_path.try_exists()?, "regenerate_server_ssh_keys must exist");
                ensure!(clio_path.is_dir(), "regenerate_server_ssh_keys must be a directory");
                Some(clio_path)
            }
            None => None,
        };

        let summary_file = match value.get("summary_file") {
            Some(value) => Some(ConfigPath::from(
                ClioPath::new(value.as_str().context("summary_file must be a string")?)
                    .context(format!("summary_file {}", value.as_str().unwrap()))?,
            )),
            None => None,
        };

        let summary_file_clean = match value.get("summary_file_clean") {
            Some(value) => Some(ConfigPath::from(
                ClioPath::new(value.as_str().context("summary_file_clean must be a string")?)
                    .context(format!("summary_file_clean {}", value.as_str().unwrap()))?,
            )),
            None => None,
        };

        let recert_config = Self {
            dry_run,
            etcd_endpoint,
            static_dirs,
            static_files,
            customizations: Customizations {
                cn_san_replace_rules,
                use_key_rules,
                use_cert_rules,
                extend_expiration,
                force_expire,
            },
            cluster_rename,
            hostname,
            threads,
            regenerate_server_ssh_keys,
            summary_file,
            summary_file_clean,

            cli_raw: None,
            config_file_raw: Some(String::from_utf8_lossy(config_bytes).to_string()),
        };

        ensure!(
            !(recert_config.customizations.extend_expiration && recert_config.customizations.force_expire),
            "extend_expiration and force_expire are mutually exclusive"
        );

        ensure!(
            !(recert_config.dry_run && recert_config.customizations.force_expire),
            "dry_run and force_expire are mutually exclusive"
        );

        ensure!(
            !(recert_config.dry_run && recert_config.customizations.extend_expiration),
            "dry_run and extend_expiration are mutually exclusive"
        );

        Ok(recert_config)
    }

    pub(crate) fn parse_from_cli(cli: Cli) -> Result<Self> {
        Ok(Self {
            dry_run: cli.dry_run,
            etcd_endpoint: cli.etcd_endpoint,
            static_dirs: cli.static_dir.into_iter().map(ConfigPath::from).collect(),
            static_files: cli.static_file.into_iter().map(ConfigPath::from).collect(),
            customizations: Customizations {
                cn_san_replace_rules: CnSanReplaceRules(cli.cn_san_replace),
                use_key_rules: UseKeyRules(cli.use_key),
                use_cert_rules: UseCertRules(cli.use_cert),
                extend_expiration: cli.extend_expiration,
                force_expire: cli.force_expire,
            },
            cluster_rename: cli.cluster_rename,
            hostname: cli.hostname,
            threads: cli.threads,
            regenerate_server_ssh_keys: cli.regenerate_server_ssh_keys.map(ConfigPath::from),
            summary_file: cli.summary_file.map(ConfigPath::from),
            summary_file_clean: cli.summary_file_clean.map(ConfigPath::from),

            config_file_raw: None,
            cli_raw: Some(serde_json::to_string(&env::args().collect::<Vec<String>>())?),
        })
    }

    pub(crate) fn new() -> Result<RecertConfig> {
        Ok(match std::env::var("RECERT_CONFIG") {
            Ok(var) => {
                let num_args = std::env::args().len();

                ensure!(
                    num_args == 1,
                    "RECERT_CONFIG is set, but there are {num_args} CLI arguments. RECERT_CONFIG is meant to be used with no arguments."
                );

                RecertConfig::parse_from_config_file(&std::fs::read(&var).context(format!("reading RECERT_CONFIG file {}", var))?)
                    .context(format!("parsing RECERT_CONFIG file {}", var))?
            }
            Err(_) => RecertConfig::parse_from_cli(Cli::parse()).context("CLI parsing")?,
        })
    }
}
