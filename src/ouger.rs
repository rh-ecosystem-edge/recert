use crate::k8s_etcd;
use anyhow::{ensure, Context, Result};
use k8s_etcd::wait_for_ouger;
use reqwest::Client;
use std::process::{Child, Command};

pub(crate) const OUGER_SERVER_PORT: u16 = 9998;

pub(crate) struct OugerChildProcess(Child);

impl Drop for OugerChildProcess {
    fn drop(&mut self) {
        if let Err(e) = self.0.kill() {
            println!("Could not kill child process: {}", e)
        }
    }
}

pub(crate) async fn launch_ouger_server() -> Result<OugerChildProcess> {
    let ouger_child_process = OugerChildProcess(
        Command::new("ouger_server")
            .args(["--port", &OUGER_SERVER_PORT.to_string()])
            .spawn()?,
    );
    wait_for_ouger().await;
    Ok(ouger_child_process)
}

pub(crate) async fn ouger(ouger_path: &str, raw_etcd_value: &[u8]) -> Result<Vec<u8>> {
    let res = Client::new()
        .post(format!("http://localhost:{OUGER_SERVER_PORT}/{ouger_path}"))
        .body(raw_etcd_value.to_vec())
        .send()
        .await
        .context("ouger server not running")?;

    ensure!(
        res.status().is_success(),
        "ouger server returned non-success status code: {}",
        res.status()
    );
    ensure!(res.content_length().is_some(), "ouger server returned no content length");

    Ok(res.bytes().await?.to_vec())
}
