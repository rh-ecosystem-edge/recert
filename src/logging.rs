use crate::{
    cluster_crypto::{ClusterCryptoObjects, REDACT_SECRETS},
    config::RecertConfig,
    recert::RunTimes,
};
use anyhow::{bail, Context, Result};
use lazy_static::lazy_static;
use log::{Level, LevelFilter, Metadata, Record};
use std::sync::{atomic::Ordering::Relaxed, Arc, Mutex};

struct RecertLogger;

static LOGGER: RecertLogger = RecertLogger;

pub fn init() -> Result<()> {
    match log::set_logger(&LOGGER) {
        Ok(_) => log::set_max_level(LevelFilter::Info),
        Err(_) => bail!("Logger initalization failed"),
    };

    Ok(())
}

lazy_static! {
    pub(crate) static ref LOG_RECORDS: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
}

impl log::Log for RecertLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        // TODO: Make this configurable
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let log_string = format!(
                "{} - {} - {}:{}: {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.args()
            );

            {
                let mut log_records = match LOG_RECORDS.lock() {
                    Ok(log_records) => log_records,
                    Err(err) => {
                        println!("Failed to lock log records: {}", err);
                        return;
                    }
                };
                log_records.push(log_string.clone());
            }

            println!("{}", log_string);
        }
    }

    fn flush(&self) {}
}

#[derive(serde::Serialize)]
struct Summary {
    cluster_crypto: ClusterCryptoObjects,
    recert_config: RecertConfig,
    logs: Vec<String>,
    run_times: Option<RunTimes>,
}

pub(crate) fn generate_summary(
    recert_config: RecertConfig,
    cluster_crypto: ClusterCryptoObjects,
    run_result: Option<RunTimes>,
) -> Result<()> {
    let logs = match LOG_RECORDS.lock() {
        Ok(logs) => logs.clone(),
        Err(err) => {
            vec![format!("Failed to lock log records: {}", err)]
        }
    };

    let summary = Summary {
        cluster_crypto,
        recert_config,
        logs,
        run_times: run_result,
    };

    if let Some(summary_file) = summary.recert_config.summary_file.clone() {
        let summary_file = summary_file.0.create().context("opening summary file for writing")?;
        serde_yaml::to_writer(summary_file, &summary).context("serializing cluster crypto into summary file")?;
    }

    if let Some(summary_file_clean) = summary.recert_config.summary_file_clean.clone() {
        let summary_file_clean = summary_file_clean.0.create().context("opening summary file for writing")?;

        REDACT_SECRETS.store(true, Relaxed);
        serde_yaml::to_writer(summary_file_clean, &summary).context("serializing cluster crypto into summary file")?;
        REDACT_SECRETS.store(false, Relaxed);
    };
    Ok(())
}
