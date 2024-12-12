use self::{cli::Cli, path::ConfigPath};
use crate::{
    cluster_crypto::REDACT_SECRETS,
    cnsanreplace::{CnSanReplace, CnSanReplaceRules},
    encrypt_config::EncryptionConfig,
    ocp_postprocess::{
        additional_trust_bundle::params::{parse_additional_trust_bundle, ProxyAdditionalTrustBundle},
        cluster_domain_rename::params::ClusterNamesRename,
        proxy_rename::args::Proxy,
    },
    use_cert::{UseCert, UseCertRules},
    use_key::{UseKey, UseKeyRules},
};
use anyhow::{ensure, Context, Result};
use clap::Parser;
use itertools::Itertools;
use serde::Serialize;
use serde_json::Value;
use std::{env, sync::atomic::Ordering::Relaxed};

#[cfg(test)]
use serde_json::json;

mod cli;
pub(crate) mod path;

/// All the user requested customizations, coalesced into a single struct for convenience
#[derive(serde::Serialize)]
pub(crate) struct CryptoCustomizations {
    pub(crate) dirs: Vec<ConfigPath>,
    pub(crate) files: Vec<ConfigPath>,
    pub(crate) cn_san_replace_rules: CnSanReplaceRules,
    pub(crate) use_key_rules: UseKeyRules,
    pub(crate) use_cert_rules: UseCertRules,
    pub(crate) extend_expiration: bool,
    pub(crate) force_expire: bool,
}

#[derive(serde::Serialize)]
pub(crate) struct ClusterCustomizations {
    pub(crate) dirs: Vec<ConfigPath>,
    pub(crate) files: Vec<ConfigPath>,
    pub(crate) cluster_rename: Option<ClusterNamesRename>,
    pub(crate) hostname: Option<String>,
    pub(crate) ip: Option<String>,
    pub(crate) proxy: Option<Proxy>,
    pub(crate) install_config: Option<String>,
    pub(crate) kubeadmin_password_hash: Option<String>,
    #[serde(serialize_with = "redact")]
    pub(crate) pull_secret: Option<String>,
    pub(crate) user_ca_bundle: Option<String>,
    pub(crate) proxy_trusted_ca_bundle: Option<ProxyAdditionalTrustBundle>,
    pub(crate) machine_network_cidr: Option<String>,
    pub(crate) chrony_config: Option<String>,
}

#[derive(serde::Serialize)]
pub(crate) struct EncryptionCustomizations {
    pub(crate) kube_encryption_config: Option<EncryptionConfig>,
    pub(crate) openshift_encryption_config: Option<EncryptionConfig>,
    pub(crate) oauth_encryption_config: Option<EncryptionConfig>,
}

/// All parsed CLI arguments, coalesced into a single struct for convenience
#[derive(serde::Serialize)]
pub(crate) struct RecertConfig {
    pub(crate) dry_run: bool,
    pub(crate) postprocess_only: bool,
    pub(crate) etcd_endpoint: Option<String>,
    pub(crate) crypto_customizations: CryptoCustomizations,
    pub(crate) cluster_customizations: ClusterCustomizations,
    pub(crate) encryption_customizations: EncryptionCustomizations,
    pub(crate) threads: Option<usize>,
    pub(crate) regenerate_server_ssh_keys: Option<ConfigPath>,
    pub(crate) summary_file: Option<ConfigPath>,
    pub(crate) summary_file_clean: Option<ConfigPath>,
    pub(crate) etcd_defrag: bool,

    #[serde(serialize_with = "config_file_raw_optionally_redacted")]
    pub(crate) config_file_raw: Option<String>,
    pub(crate) cli_raw: Option<String>,
}

// This is a custom serializer for config_file_raw that redacts the entire field incase any of the
// use_key_rule values have a newline in them (as a newline indicates that the user provided raw
// private keys instead of file paths)
//
// A bit hacky but couldn't find a better way to do this
//
// Also redacts the entire field if the config contains a pull secret
fn config_file_raw_optionally_redacted<S: serde::Serializer>(config_file_raw: &Option<String>, serializer: S) -> Result<S::Ok, S::Error> {
    if REDACT_SECRETS.load(Relaxed) {
        if let Some(config_file_raw) = config_file_raw {
            let value: Result<Value, serde_yaml::Error> = serde_yaml::from_slice(config_file_raw.as_bytes());

            match value {
                Ok(value) => {
                    if value.get("pull_secret").is_some() {
                        return "<redacted due to inclusion of pull secret in config>".serialize(serializer);
                    }
                    if let Some(value) = value.get("use_key_rules") {
                        match value.as_array() {
                            Some(seq) => {
                                for value in seq {
                                    match value.as_str() {
                                        Some(value) => {
                                            if value.contains('\n') {
                                                return "<redacted due to inclusion of raw private keys in config>".serialize(serializer);
                                            }
                                        }
                                        None => return "<failed to decode for redaction - non-string use_key rule>".serialize(serializer),
                                    }
                                }
                            }
                            None => return "<failed to decode for redaction - use_key_rules is not an array>".serialize(serializer),
                        }
                    }
                }
                Err(_) => return "<failed to decode for redaction - not valid YAML>".serialize(serializer),
            }
        } else {
            return serializer.serialize_none();
        }
    }

    config_file_raw.serialize(serializer)
}

fn redact<S: serde::Serializer>(value: &Option<String>, serializer: S) -> Result<S::Ok, S::Error> {
    if REDACT_SECRETS.load(Relaxed) {
        "<redacted>".serialize(serializer)
    } else {
        value.serialize(serializer)
    }
}

impl RecertConfig {
    #[cfg(test)]
    fn empty() -> Result<RecertConfig> {
        Ok(RecertConfig {
            dry_run: true,
            etcd_endpoint: None,
            etcd_defrag: false,
            crypto_customizations: CryptoCustomizations {
                dirs: vec![],
                files: vec![],
                cn_san_replace_rules: parse_cs_san_rules(json!([]))?,
                use_key_rules: parse_use_key_rules(json!([]))?,
                use_cert_rules: parse_cert_rules(json!([]))?,
                extend_expiration: false,
                force_expire: false,
            },
            cluster_customizations: ClusterCustomizations {
                dirs: vec![],
                files: vec![],
                cluster_rename: None,
                hostname: None,
                ip: None,
                kubeadmin_password_hash: None,
                pull_secret: None,
                proxy: None,
                install_config: None,
                machine_network_cidr: None,
                user_ca_bundle: None,
                proxy_trusted_ca_bundle: None,
                chrony_config: None,
            },
            encryption_customizations: EncryptionCustomizations {
                kube_encryption_config: None,
                openshift_encryption_config: None,
                oauth_encryption_config: None,
            },
            threads: None,
            regenerate_server_ssh_keys: None,
            summary_file: None,
            summary_file_clean: None,
            config_file_raw: None,
            cli_raw: None,
            postprocess_only: false,
        })
    }

    pub(crate) fn parse_from_config_file(config_bytes: &[u8]) -> Result<Self> {
        let value: Value = serde_yaml::from_slice(config_bytes)?;

        let mut value = value.as_object().context("config file must be a YAML object")?.clone();

        let (crypto_dirs, crypto_files, cluster_customization_dirs, cluster_customization_files) = parse_dir_file_config(&mut value)?;

        let cn_san_replace_rules = match value.remove("cn_san_replace_rules") {
            Some(value) => parse_cs_san_rules(value)?,
            None => CnSanReplaceRules(vec![]),
        };
        let use_key_rules = match value.remove("use_key_rules") {
            Some(value) => parse_use_key_rules(value)?,
            None => UseKeyRules(vec![]),
        };
        let use_cert_rules = match value.remove("use_cert_rules") {
            Some(value) => parse_cert_rules(value)?,
            None => UseCertRules(vec![]),
        };
        let extend_expiration = value
            .remove("extend_expiration")
            .unwrap_or(Value::Bool(false))
            .as_bool()
            .context("extend_expiration must be a boolean")?;
        let force_expire = value
            .remove("force_expire")
            .unwrap_or(Value::Bool(false))
            .as_bool()
            .context("force_expire must be a boolean")?;
        let cluster_rename = match value.remove("cluster_rename") {
            Some(value) => Some(
                ClusterNamesRename::parse(value.as_str().context("cluster_rename must be a string")?).context(format!(
                    "cluster_rename {}",
                    value.as_str().context("cluster_rename must be a string")?
                ))?,
            ),
            None => None,
        };
        let hostname = match value.remove("hostname") {
            Some(value) => Some(value.as_str().context("hostname must be a string")?.to_string()),
            None => None,
        };
        let ip = match value.remove("ip") {
            Some(value) => Some(value.as_str().context("ip must be a string")?.to_string()),
            None => None,
        };
        let pull_secret = match value.remove("pull_secret") {
            Some(value) => Some(value.as_str().context("pull_secret must be a string")?.to_string()),
            None => None,
        };
        let proxy = match value.remove("proxy") {
            Some(value) => Some(
                Proxy::parse(value.as_str().context("proxy must be a string")?)
                    .context(format!("proxy {}", value.as_str().context("proxy must be a string")?))?,
            ),
            None => None,
        };
        let install_config = match value.remove("install_config") {
            Some(value) => Some(value.as_str().context("install_config must be a string")?.to_string()),
            None => None,
        };
        let set_kubeadmin_password_hash = match value.remove("kubeadmin_password_hash") {
            Some(value) => Some(value.as_str().context("set_kubeadmin_password_hash must be a string")?.to_string()),
            None => None,
        };
        let user_ca_bundle = match value.remove("user_ca_bundle") {
            Some(value) => Some(parse_additional_trust_bundle(
                value.as_str().context("additional_trust_bundle must be a string")?,
            )?),
            None => None,
        };
        let proxy_trusted_ca_bundle = match value.remove("proxy_trusted_ca_bundle") {
            Some(value) => Some(
                ProxyAdditionalTrustBundle::parse(value.as_str().context("proxy_trusted_ca_bundle must be a string")?).context(format!(
                    "proxy_trusted_ca_bundle {}",
                    value.as_str().context("proxy_trusted_ca_bundle must be a string")?
                ))?,
            ),
            None => None,
        };
        let machine_network_cidr = match value.remove("machine_network_cidr") {
            Some(value) => Some(value.as_str().context("machine_network_cidr must be a string")?.to_string()),
            None => None,
        };
        let chrony_config = match value.remove("chrony_config") {
            Some(value) => Some(value.as_str().context("chrony_config must be a string")?.to_string()),
            None => None,
        };

        let dry_run = value
            .remove("dry_run")
            .unwrap_or(Value::Bool(false))
            .as_bool()
            .context("dry_run must be a boolean")?;
        let etcd_defrag = value
            .remove("etcd_defrag")
            .unwrap_or(Value::Bool(false))
            .as_bool()
            .context("etcd_defrag must be a boolean")?;
        let etcd_endpoint = match value.remove("etcd_endpoint") {
            Some(value) => Some(value.as_str().context("etcd_endpoint must be a string")?.to_string()),
            None => None,
        };
        let kube_encryption_config = match value.remove("kube_encryption_config") {
            Some(value) => parse_encryption_config(value)?,
            None => None,
        };
        let openshift_encryption_config = match value.remove("openshift_encryption_config") {
            Some(value) => parse_encryption_config(value)?,
            None => None,
        };
        let oauth_encryption_config = match value.remove("oauth_encryption_config") {
            Some(value) => parse_encryption_config(value)?,
            None => None,
        };
        let threads = match value.remove("threads") {
            Some(value) => parse_threads(value)?,
            None => None,
        };
        let regenerate_server_ssh_keys = match value.remove("regenerate_server_ssh_keys") {
            Some(value) => parse_server_ssh_keys(value)?,
            None => None,
        };
        let summary_file = match value.remove("summary_file") {
            Some(value) => parse_summary_file(value)?,
            None => None,
        };
        let summary_file_clean = match value.remove("summary_file_clean") {
            Some(value) => parse_summary_file_clean(value)?,
            None => None,
        };
        let postprocess_only = value
            .remove("postprocess_only")
            .unwrap_or(Value::Bool(false))
            .as_bool()
            .context("postprocess_only must be a boolean")?;

        ensure!(
            value.is_empty(),
            "unknown keys {:?} in config file",
            value.keys().map(|key| key.to_string()).join(", ")
        );

        let crypto_customizations = CryptoCustomizations {
            dirs: crypto_dirs,
            files: crypto_files,
            cn_san_replace_rules,
            use_key_rules,
            use_cert_rules,
            extend_expiration,
            force_expire,
        };

        let cluster_customizations = ClusterCustomizations {
            dirs: cluster_customization_dirs,
            files: cluster_customization_files,
            cluster_rename,
            hostname,
            ip,
            kubeadmin_password_hash: set_kubeadmin_password_hash,
            pull_secret,
            user_ca_bundle,
            proxy_trusted_ca_bundle,
            proxy,
            install_config,
            machine_network_cidr,
            chrony_config,
        };

        let encryption_customizations = EncryptionCustomizations {
            kube_encryption_config,
            openshift_encryption_config,
            oauth_encryption_config,
        };

        let recert_config = Self {
            dry_run,
            etcd_endpoint,
            crypto_customizations,
            cluster_customizations,
            encryption_customizations,
            threads,
            regenerate_server_ssh_keys,
            summary_file,
            summary_file_clean,
            cli_raw: None,
            config_file_raw: Some(String::from_utf8_lossy(config_bytes).to_string()),
            postprocess_only,
            etcd_defrag,
        };

        ensure!(
            !(recert_config.crypto_customizations.extend_expiration && recert_config.crypto_customizations.force_expire),
            "extend_expiration and force_expire are mutually exclusive"
        );

        ensure!(
            !(recert_config.dry_run && recert_config.crypto_customizations.force_expire),
            "dry_run and force_expire are mutually exclusive"
        );

        ensure!(
            !(recert_config.dry_run && recert_config.crypto_customizations.extend_expiration),
            "dry_run and extend_expiration are mutually exclusive"
        );
        ensure!(
            !(recert_config.dry_run && recert_config.etcd_defrag),
            "dry_run and etcd_defrag are mutually exclusive"
        );

        Ok(recert_config)
    }

    pub(crate) fn parse_from_cli(cli: Cli) -> Result<Self> {
        Ok(Self {
            dry_run: cli.dry_run,
            etcd_defrag: cli.etcd_defrag,
            postprocess_only: cli.postprocess_only,
            etcd_endpoint: cli.etcd_endpoint,
            crypto_customizations: CryptoCustomizations {
                dirs: if cli.static_dir.is_empty() {
                    cli.crypto_dir.into_iter().map(ConfigPath::from).collect()
                } else {
                    cli.static_dir.clone().into_iter().map(ConfigPath::from).collect()
                },
                files: if cli.static_file.is_empty() {
                    cli.crypto_file.into_iter().map(ConfigPath::from).collect()
                } else {
                    cli.static_file.clone().into_iter().map(ConfigPath::from).collect()
                },
                cn_san_replace_rules: CnSanReplaceRules(cli.cn_san_replace),
                use_key_rules: UseKeyRules(cli.use_key),
                use_cert_rules: UseCertRules(cli.use_cert),
                extend_expiration: cli.extend_expiration,
                force_expire: cli.force_expire,
            },
            cluster_customizations: ClusterCustomizations {
                dirs: if cli.static_dir.is_empty() {
                    cli.cluster_customization_dir.into_iter().map(ConfigPath::from).collect()
                } else {
                    cli.static_dir.into_iter().map(ConfigPath::from).collect()
                },
                files: if cli.static_file.is_empty() {
                    cli.cluster_customization_file.into_iter().map(ConfigPath::from).collect()
                } else {
                    cli.static_file.into_iter().map(ConfigPath::from).collect()
                },
                cluster_rename: cli.cluster_rename,
                hostname: cli.hostname,
                ip: cli.ip,
                proxy: cli.proxy,
                install_config: cli.install_config,
                kubeadmin_password_hash: cli.kubeadmin_password_hash,
                pull_secret: cli.pull_secret,
                user_ca_bundle: cli.user_ca_bundle,
                proxy_trusted_ca_bundle: cli.proxy_trusted_ca_bundle,
                machine_network_cidr: cli.machine_network_cidr,
                chrony_config: cli.chrony_config,
            },
            encryption_customizations: EncryptionCustomizations {
                kube_encryption_config: cli.kube_encryption_config,
                openshift_encryption_config: cli.openshift_encryption_config,
                oauth_encryption_config: cli.oauth_encryption_config,
            },
            threads: cli.threads,
            regenerate_server_ssh_keys: cli.regenerate_server_ssh_keys.map(ConfigPath::from),
            summary_file: cli.summary_file.map(ConfigPath::from),
            summary_file_clean: cli.summary_file_clean.map(ConfigPath::from),

            config_file_raw: None,
            cli_raw: Some(serde_json::to_string(&env::args().collect::<Vec<String>>())?),
        })
    }

    pub(crate) fn load() -> Result<Self> {
        Ok(match std::env::var("RECERT_CONFIG") {
            Ok(var) => {
                ensure_no_cli_args()?;
                RecertConfig::parse_from_config_file(&std::fs::read(&var).context(format!("reading RECERT_CONFIG file {}", var))?)
                    .context(format!("parsing RECERT_CONFIG file {}", var))?
            }
            Err(_) => RecertConfig::parse_from_cli(Cli::parse()).context("CLI parsing")?,
        })
    }
}

fn ensure_no_cli_args() -> Result<()> {
    let num_args = std::env::args().len();

    ensure!(
        num_args == 1,
        "RECERT_CONFIG is set, but there are {num_args} CLI arguments. RECERT_CONFIG is meant to be used with no arguments."
    );

    Ok(())
}

fn parse_summary_file_clean(value: Value) -> Result<Option<ConfigPath>> {
    Ok(Some(
        ConfigPath::new(value.as_str().context("summary_file_clean must be a string")?).context(format!(
            "summary_file_clean {}",
            value.as_str().context("summary_file_clean must be a string")?
        ))?,
    ))
}

fn parse_summary_file(value: Value) -> Result<Option<ConfigPath>> {
    Ok(Some(
        ConfigPath::new(value.as_str().context("summary_file must be a string")?)
            .context(format!("summary_file {}", value.as_str().context("summary_file must be a string")?))?,
    ))
}

fn parse_server_ssh_keys(value: Value) -> Result<Option<ConfigPath>> {
    let config_path = ConfigPath::new(value.as_str().context("regenerate_server_ssh_keys must be a string")?).context(format!(
        "regenerate_server_ssh_keys {}",
        value.as_str().context("regenerate_server_ssh_keys must be a string")?
    ))?;
    ensure!(config_path.try_exists()?, "regenerate_server_ssh_keys must exist");
    ensure!(config_path.is_dir(), "regenerate_server_ssh_keys must be a directory");
    Ok(Some(config_path))
}

fn parse_threads(value: Value) -> Result<Option<usize>> {
    Ok(Some(
        value
            .as_u64()
            .context("threads must be an integer")?
            .try_into()
            .context("threads must be an integer")?,
    ))
}

fn parse_encryption_config(value: Value) -> Result<Option<EncryptionConfig>> {
    Ok(Some(
        EncryptionConfig::parse(value.as_str().context("encryption_config must be a string")?).context(format!(
            "encryption_config {}",
            value.as_str().context("encryption_config must be a string")?
        ))?,
    ))
}

fn parse_cert_rules(value: Value) -> Result<UseCertRules> {
    Ok(UseCertRules(
        value
            .as_array()
            .context("use_cert_rules must be an array")?
            .iter()
            .map(|value| {
                UseCert::parse(value.as_str().context("use_cert_rules must be an array of strings")?).context(format!(
                    "use_cert_rule {}",
                    value.as_str().context("use_cert_rules must be an array of strings")?
                ))
            })
            .collect::<Result<Vec<UseCert>>>()?,
    ))
}

fn parse_use_key_rules(value: Value) -> Result<UseKeyRules> {
    Ok(UseKeyRules(
        value
            .as_array()
            .context("use_key_rules must be an array")?
            .iter()
            .map(|value| {
                UseKey::parse(value.as_str().context("use_key_rules must be an array of strings")?).context(format!(
                    "use_key_rule {}",
                    value.as_str().context("use_key_rules must be an array of strings")?
                ))
            })
            .collect::<Result<Vec<UseKey>>>()?,
    ))
}

fn parse_cs_san_rules(value: Value) -> Result<CnSanReplaceRules> {
    Ok(CnSanReplaceRules(
        value
            .as_array()
            .context("cn_san_replace_rules must be an array")?
            .iter()
            .map(|value| {
                CnSanReplace::parse(value.as_str().context("cn_san_replace_rules must be an array of strings")?).context(format!(
                    "cn_san_replace_rule {}",
                    value.as_str().context("cn_san_replace_rules must be an array of strings")?
                ))
            })
            .collect::<Result<Vec<CnSanReplace>>>()?,
    ))
}

#[allow(clippy::type_complexity)]
fn parse_dir_file_config(
    value: &mut serde_json::Map<String, Value>,
) -> Result<(Vec<ConfigPath>, Vec<ConfigPath>, Vec<ConfigPath>, Vec<ConfigPath>)> {
    let static_dirs = match value.remove("static_dirs") {
        Some(value) => {
            ensure!(
                value.get("crypto_dirs").is_none(),
                "static_dirs and crypto_dirs are mutually exclusive"
            );
            ensure!(
                value.get("cluster_customization_dirs").is_none(),
                "static_dirs and cluster_customization_dirs are mutually exclusive"
            );
            ensure!(
                value.get("additional_trust_bundle").is_none(),
                "static_dirs and cluster_customization_dirs are mutually exclusive"
            );

            value
                .as_array()
                .context("static_dirs must be an array")?
                .iter()
                .map(|value| {
                    let config_path = ConfigPath::new(value.as_str().context("static_dirs must be an array of strings")?).context(
                        format!("config dir {}", value.as_str().context("static_dirs must be an array of strings")?),
                    )?;

                    ensure!(config_path.try_exists()?, format!("static_dir must exist: {}", config_path));
                    ensure!(config_path.is_dir(), format!("static_dir must be a directory: {}", config_path));

                    Ok(config_path)
                })
                .collect::<Result<Vec<ConfigPath>>>()?
        }
        None => vec![],
    };
    let static_files = match value.remove("static_files") {
        Some(value) => {
            ensure!(
                value.get("crypto_files").is_none(),
                "static_files and crypto_files are mutually exclusive"
            );
            ensure!(
                value.get("cluster_customization_files").is_none(),
                "static_files and cluster_customization_files are mutually exclusive"
            );
            ensure!(
                value.get("additional_trust_bundle").is_none(),
                "static_files and cluster_customization_files are mutually exclusive"
            );

            value
                .as_array()
                .context("static_files must be an array")?
                .iter()
                .map(|value| {
                    let config_path =
                        ConfigPath::new(value.as_str().context("static_files must be an array of strings")?).context(format!(
                            "config file {}",
                            value.as_str().context("static_files must be an array of strings")?
                        ))?;

                    ensure!(config_path.try_exists()?, format!("static_file must exist: {}", config_path));
                    ensure!(config_path.is_file(), format!("static_file must be a file: {}", config_path));

                    Ok(config_path)
                })
                .collect::<Result<Vec<ConfigPath>>>()?
        }
        None => vec![],
    };
    let crypto_dirs = if static_dirs.is_empty() {
        match value.remove("crypto_dirs") {
            Some(value) => value
                .as_array()
                .context("crypto_dirs must be an array")?
                .iter()
                .map(|value| {
                    let config_path = ConfigPath::new(value.as_str().context("crypto_dirs must be an array of strings")?).context(
                        format!("crypto dir {}", value.as_str().context("crypto_dirs must be an array of strings")?),
                    )?;

                    ensure!(config_path.try_exists()?, format!("crypto_dir must exist: {}", config_path));
                    ensure!(config_path.is_dir(), format!("crypto_dir must be a directory: {}", config_path));

                    Ok(config_path)
                })
                .collect::<Result<Vec<ConfigPath>>>()?,
            None => vec![],
        }
    } else {
        static_dirs.clone()
    };
    let crypto_files = if static_files.is_empty() {
        match value.remove("crypto_files") {
            Some(value) => value
                .as_array()
                .context("crypto_files must be an array")?
                .iter()
                .map(|value| {
                    let config_path =
                        ConfigPath::new(value.as_str().context("crypto_files must be an array of strings")?).context(format!(
                            "crypto file {}",
                            value.as_str().context("crypto_files must be an array of strings")?
                        ))?;

                    ensure!(config_path.try_exists()?, format!("crypto_file must exist: {}", config_path));
                    ensure!(config_path.is_file(), format!("crypto_file must be a file: {}", config_path));

                    Ok(config_path)
                })
                .collect::<Result<Vec<ConfigPath>>>()?,
            None => vec![],
        }
    } else {
        static_files.clone()
    };

    let cluster_customization_dirs = if static_dirs.is_empty() {
        match value.remove("cluster_customization_dirs") {
            Some(value) => value
                .as_array()
                .context("cluster_customization_dirs must be an array")?
                .iter()
                .map(|value| {
                    let config_path = ConfigPath::new(value.as_str().context("cluster_customization_dirs must be an array of strings")?)
                        .context(format!(
                            "cluster_customization dir {}",
                            value.as_str().context("cluster_customization_dirs must be an array of strings")?
                        ))?;

                    ensure!(
                        config_path.try_exists()?,
                        format!("cluster_customization_dir must exist: {}", config_path)
                    );
                    ensure!(
                        config_path.is_dir(),
                        format!("cluster_customization_dir must be a directory: {}", config_path)
                    );

                    Ok(config_path)
                })
                .collect::<Result<Vec<ConfigPath>>>()?,
            None => vec![],
        }
    } else {
        static_dirs
    };

    let cluster_customization_files = if static_files.is_empty() {
        match value.remove("cluster_customization_files") {
            Some(value) => value
                .as_array()
                .context("cluster_customization_files must be an array")?
                .iter()
                .map(|value| {
                    let config_path = ConfigPath::new(value.as_str().context("cluster_customization_files must be an array of strings")?)
                        .context(format!(
                        "cluster_customization file {}",
                        value.as_str().context("cluster_customization_files must be an array of strings")?
                    ))?;

                    ensure!(
                        config_path.try_exists()?,
                        format!("cluster_customization_file must exist: {}", config_path)
                    );
                    ensure!(
                        config_path.is_file(),
                        format!("cluster_customization_file must be a file: {}", config_path)
                    );

                    Ok(config_path)
                })
                .collect::<Result<Vec<ConfigPath>>>()?,
            None => vec![],
        }
    } else {
        static_files
    };
    Ok((crypto_dirs, crypto_files, cluster_customization_dirs, cluster_customization_files))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_redact_config_file_raw_private_keys() {
        let raw_config = r#"
use_key_rules:
- /path/to/key
- |
  -----BEGIN RSA PRIVATE KEY-----
  MIIEpAIBAAKCAQEA
"#;

        let mut config = RecertConfig::empty().unwrap();

        config.config_file_raw = Some(raw_config.to_string());

        assert!(serde_json::to_string(&config).unwrap().contains("MIIEpAIBAAKCAQEA"),);
        REDACT_SECRETS.store(true, Relaxed);
        assert!(!serde_json::to_string(&config).unwrap().contains("MIIEpAIBAAKCAQEA"),);
        REDACT_SECRETS.store(false, Relaxed);
    }

    #[test]
    #[serial]
    fn test_redact_config_file_raw_pull_secret() {
        let raw_config = r#"
pull_secret: |
    {"auths": {"cloud.openshift.com": {"auth": "secretsecret", "email": "foo@bar.com"}}}
"#;

        let mut config = RecertConfig::empty().unwrap();

        config.config_file_raw = Some(raw_config.to_string());

        assert!(serde_json::to_string(&config).unwrap().contains("secretsecret"),);
        REDACT_SECRETS.store(true, Relaxed);
        assert!(!serde_json::to_string(&config).unwrap().contains("secretsecret"),);
        REDACT_SECRETS.store(false, Relaxed);
    }

    #[test]
    #[serial]
    fn test_dont_redact_config_file_raw() {
        let raw_config = r#"
use_key_rules:
- /path/to/key
"#;

        let mut config = RecertConfig::empty().unwrap();

        config.config_file_raw = Some(raw_config.to_string());

        assert!(serde_json::to_string(&config).unwrap().contains("/path/to/key"),);
        REDACT_SECRETS.store(true, Relaxed);
        assert!(serde_json::to_string(&config).unwrap().contains("/path/to/key"),);
        REDACT_SECRETS.store(false, Relaxed);
    }

    #[test]
    #[serial]
    fn test_pull_secret_not_serialized() {
        let mut config = RecertConfig::empty().unwrap();

        config.cluster_customizations.pull_secret = Some("woiefjowiefjwioefj".to_string());

        assert!(serde_json::to_string(&config).unwrap().contains("woiefjowiefjwioefj"),);
        REDACT_SECRETS.store(true, Relaxed);
        assert!(!serde_json::to_string(&config).unwrap().contains("woiefjowiefjwioefj"),);
        REDACT_SECRETS.store(false, Relaxed);
    }
}
