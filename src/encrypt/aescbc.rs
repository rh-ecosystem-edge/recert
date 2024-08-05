use super::transformer::Transformer;
use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

const BLOCK_SIZE: usize = 16;

#[derive(Clone)]
pub(crate) struct AesCbc {
    prefix: String,
    key: String,
}

impl AesCbc {
    pub(crate) fn new(prefix: String, key: String) -> Self {
        Self { prefix, key }
    }
}

#[async_trait]
impl Transformer for AesCbc {
    fn get_prefix(&self) -> String {
        self.prefix.to_string()
    }

    // openssl enc -d -aes-256-cbc \
    //   -K <base64-decoded-key> \
    //   -iv <initialization-vector> \
    //   -in <ciphertext-file> \
    //   -out <plaintext-file>
    async fn decrypt(&self, _etcd_key: String, ciphertext: Vec<u8>) -> Result<Vec<u8>> {
        let (_, cipher_data) = ciphertext.split_at(self.prefix.len());
        ensure!(cipher_data.len() >= BLOCK_SIZE, "data is shorter than the required block size");

        let (iv, data) = cipher_data.split_at(BLOCK_SIZE);
        ensure!(data.len() % BLOCK_SIZE == 0, "invalid block size");

        let key = base64_standard.decode(self.key.as_bytes())?;

        let key_hex = hex::encode(key);
        let iv_hex = hex::encode(iv);

        let mut command = Command::new("openssl")
            .arg("enc")
            .arg("-d")
            .arg("-aes-256-cbc")
            .arg("-K")
            .arg(&key_hex)
            .arg("-iv")
            .arg(&iv_hex)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to spawn openssl")?;

        let stdin_future = async {
            if let Some(mut stdin) = command.stdin.take() {
                stdin.write_all(data).await.context("failed to write to stdin")?;
            }

            Ok::<_, anyhow::Error>(())
        };

        let mut plaintext = Vec::new();
        let mut stderr = Vec::new();

        let stdout_future = async {
            if let Some(mut stdout) = command.stdout.take() {
                stdout.read_to_end(&mut plaintext).await.context("failed to read from stdout")?;
            }

            Ok::<_, anyhow::Error>(())
        };

        let stderr_future = async {
            if let Some(mut stderr_pipe) = command.stderr.take() {
                stderr_pipe.read_to_end(&mut stderr).await.context("failed to read from stderr")?;
            }

            Ok::<_, anyhow::Error>(())
        };

        let (stdin_result, stdout_result, stderr_result) = tokio::join!(stdin_future, stdout_future, stderr_future);

        stdin_result?;
        stdout_result?;
        stderr_result?;

        let status = command.wait().await.context("failed to wait for openssl")?;

        if status.success() {
            Ok(plaintext)
        } else {
            bail!(format!("AES-CBC decryption error: {}", String::from_utf8_lossy(&stderr)));
        }
    }

    // openssl enc -e -aes-256-cbc \
    //   -K <base64-decoded-key> \
    //   -iv <generated-iv> \
    //   -in <plaintext-file> \
    //   -out <ciphertext-file>
    async fn encrypt(&self, _etcd_key: String, plaintext: Vec<u8>) -> Result<Vec<u8>> {
        let (_, data) = plaintext.split_at(self.prefix.len());
        let padding_size = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
        let total_size = self.prefix.len() + BLOCK_SIZE + data.len() + padding_size;

        let mut result = vec![0u8; total_size];
        result[..self.prefix.len()].copy_from_slice(self.prefix.as_bytes());

        OsRng.fill_bytes(&mut result[..BLOCK_SIZE]);
        let binding = result.clone();
        let (iv, _) = binding.split_at(BLOCK_SIZE);

        result[BLOCK_SIZE..BLOCK_SIZE + data.len()].copy_from_slice(data);

        let padding = vec![padding_size as u8; padding_size];
        result[BLOCK_SIZE + data.len()..].copy_from_slice(&padding);

        let key = base64_standard.decode(self.key.as_bytes())?;

        let key_hex = hex::encode(key);
        let iv_hex = hex::encode(iv);

        let mut command = Command::new("openssl")
            .arg("enc")
            .arg("-e")
            .arg("-aes-256-cbc")
            .arg("-K")
            .arg(&key_hex)
            .arg("-iv")
            .arg(&iv_hex)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to spawn openssl")?;

        let stdin_future = async {
            if let Some(mut stdin) = command.stdin.take() {
                stdin.write_all(&result[BLOCK_SIZE..]).await.context("failed to write to stdin")?;
            }

            Ok::<_, anyhow::Error>(())
        };

        let mut ciphertext = Vec::new();
        let mut stderr = Vec::new();

        let stdout_future = async {
            if let Some(mut stdout) = command.stdout.take() {
                stdout.read_to_end(&mut ciphertext).await.context("failed to read from stdout")?;
            }

            Ok::<_, anyhow::Error>(())
        };

        let stderr_future = async {
            if let Some(mut stderr_pipe) = command.stderr.take() {
                stderr_pipe.read_to_end(&mut stderr).await.context("failed to read from stderr")?;
            }

            Ok::<_, anyhow::Error>(())
        };

        let (stdin_result, stdout_result, stderr_result) = tokio::join!(stdin_future, stdout_future, stderr_future);

        stdin_result?;
        stdout_result?;
        stderr_result?;

        let status = command.wait().await.context("failed to wait for openssl")?;

        if status.success() {
            Ok(ciphertext)
        } else {
            bail!(format!("AES-CBC encryption error: {}", String::from_utf8_lossy(&stderr)));
        }
    }
}
