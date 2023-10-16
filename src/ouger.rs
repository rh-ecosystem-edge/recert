use anyhow::{ensure, Context, Result};
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

async fn wait_for_ouger() {
    let mut tries = 0;
    while tries < 100 {
        if Client::new()
            .get(format!("http://localhost:{OUGER_SERVER_PORT}/healthz"))
            .send()
            .await
            .is_ok()
        {
            return;
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        tries += 1;
    }

    panic!("Ouger server did not start in time");
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
        .context("sending ouger request")?;

    ensure!(
        res.status().is_success(),
        "ouger server returned non-success status code: {}",
        res.status()
    );
    ensure!(res.content_length().is_some(), "ouger server returned no content length");

    Ok(res.bytes().await?.to_vec())
}
