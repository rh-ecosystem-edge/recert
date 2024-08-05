use super::transformer::Transformer;
use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Child;
use tokio::process::Command;

const BLOCK_SIZE: usize = 16;

#[derive(Clone)]
pub(crate) struct AesCbc {
    prefix: String,
    key: Vec<u8>,
}

impl AesCbc {
    pub(crate) fn new(prefix: String, key: Vec<u8>) -> Self {
        Self { prefix, key }
    }

    async fn generate_iv() -> Result<Vec<u8>> {
        let output = Command::new("openssl")
            .arg("rand")
            .arg("16")
            .output()
            .await
            .context("failed to run openssl command")?;

        ensure!(
            output.status.success(),
            format!("openssl command failed with status: {}", output.status)
        );

        Ok(output.stdout)
    }

    async fn run_command_with_stdin(mut cmd: Child, stdin_data: Option<&[u8]>) -> Result<Vec<u8>> {
        let stdin_future = async {
            if let Some(mut stdin) = cmd.stdin.take() {
                if let Some(data) = stdin_data {
                    stdin.write_all(data).await.context("failed to write to stdin")?;
                }
            }
            Ok::<_, anyhow::Error>(())
        };

        let mut stdout_buffer = Vec::new();
        let stdout_future = async {
            if let Some(mut stdout) = cmd.stdout.take() {
                stdout.read_to_end(&mut stdout_buffer).await.context("failed to read from stdout")?;
            }
            Ok::<_, anyhow::Error>(())
        };

        let mut stderr_buffer = Vec::new();
        let stderr_future = async {
            if let Some(mut stderr) = cmd.stderr.take() {
                stderr.read_to_end(&mut stderr_buffer).await.context("failed to read from stderr")?;
            }
            Ok::<_, anyhow::Error>(())
        };

        let (stdin_result, stdout_result, stderr_result) = tokio::join!(stdin_future, stdout_future, stderr_future);

        stdin_result?;
        stdout_result?;
        stderr_result?;

        let status = cmd.wait().await.context("failed to wait for command")?;

        ensure!(
            status.success(),
            format!("Command failed with stderr: {}", String::from_utf8_lossy(&stderr_buffer))
        );

        Ok(stdout_buffer)
    }
}

#[async_trait]
impl Transformer for AesCbc {
    fn get_prefix(&self) -> String {
        self.prefix.to_string()
    }

    async fn decrypt(&self, _etcd_key: String, ciphertext: Vec<u8>) -> Result<Vec<u8>> {
        let (_, cipher_data) = ciphertext.split_at(self.prefix.len());
        ensure!(cipher_data.len() >= BLOCK_SIZE, "data is shorter than the required block size");

        let (iv, data) = cipher_data.split_at(BLOCK_SIZE);
        ensure!(data.len() % BLOCK_SIZE == 0, "invalid block size");

        let cmd = Command::new("openssl")
            .arg("enc")
            .arg("-d")
            .arg("-aes-256-cbc")
            .arg("-K")
            .arg(hex::encode(&self.key))
            .arg("-iv")
            .arg(hex::encode(iv))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to spawn openssl")?;

        let plaintext = Self::run_command_with_stdin(cmd, Some(data))
            .await
            .context("AES-CBC decryption error")?;

        Ok(plaintext)
    }

    async fn encrypt(&self, _etcd_key: String, data: Vec<u8>) -> Result<Vec<u8>> {
        let padding_size = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
        let total_size = data.len() + padding_size;

        let mut plaintext = vec![0u8; total_size];
        plaintext[..data.len()].copy_from_slice(&data);

        // add padding at the end
        for i in 0..padding_size {
            plaintext[data.len() + i] = padding_size as u8;
        }

        let iv = Self::generate_iv().await.context("generating IV")?;

        let cmd = Command::new("openssl")
            .arg("enc")
            .arg("-e")
            .arg("-aes-256-cbc")
            .arg("-nopad")
            .arg("-K")
            .arg(hex::encode(&self.key))
            .arg("-iv")
            .arg(hex::encode(&iv))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to spawn openssl")?;

        let ciphered_data = Self::run_command_with_stdin(cmd, Some(&plaintext))
            .await
            .context("AES-CBC encryption error")?;

        let mut encrypted_data: Vec<u8> = self.prefix.as_bytes().to_vec();
        encrypted_data.extend_from_slice(&iv);
        encrypted_data.extend_from_slice(&ciphered_data);

        Ok(encrypted_data)
    }
}
