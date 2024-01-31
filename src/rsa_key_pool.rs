use super::cluster_crypto::crypto_utils::{generate_rsa_key, generate_rsa_key_async};
use crate::cluster_crypto::crypto_utils::SigningKey;
use anyhow::{Context, Result};
use futures_util::future::join_all;

pub struct RsaKeyPool {
    pub(crate) keys_2048: Vec<SigningKey>,
    pub(crate) keys_4096: Vec<SigningKey>,
}

impl RsaKeyPool {
    pub(crate) async fn fill(num_keys_2048: usize, num_keys_4096: usize) -> Result<Self> {
        Ok(Self {
            keys_2048: join_all(
                (0..num_keys_2048)
                    .map(|_| tokio::spawn(async move { generate_rsa_key_async(2048).await.context("2048 bit RSA keys") }))
                    .collect::<Vec<_>>(),
            )
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?,
            // Also a few 4096 keys
            keys_4096: join_all(
                (0..num_keys_4096)
                    .map(|_| tokio::spawn(async move { generate_rsa_key_async(4096).await.context("4096 bit RSA keys") }))
                    .collect::<Vec<_>>(),
            )
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?,
        })
    }

    pub(crate) fn get(&mut self, size: usize) -> Result<SigningKey> {
        if size == 2048 {
            if let Some(key) = self.keys_2048.pop() {
                return Ok(key);
            }
        }

        if size == 4096 {
            if let Some(key) = self.keys_4096.pop() {
                return Ok(key);
            }
        }

        log::warn!("Cache miss for RSA key of size {size}");

        generate_rsa_key(size)
    }
}
