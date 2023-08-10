use super::cluster_crypto::crypto_utils::{generate_rsa_key, generate_rsa_key_async};
use anyhow::Result;
use futures_util::future::join_all;
use rsa::RsaPrivateKey;
use x509_certificate::InMemorySigningKeyPair;

pub struct RsaKeyPool {
    pub(crate) keys_2048: Vec<(RsaPrivateKey, InMemorySigningKeyPair)>,
    pub(crate) keys_4096: Vec<(RsaPrivateKey, InMemorySigningKeyPair)>,
}

impl RsaKeyPool {
    pub async fn fill(num_keys_2048: usize, num_keys_4096: usize) -> Result<Self> {
        Ok(Self {
            keys_2048: join_all(
                (0..num_keys_2048)
                    .map(|_| tokio::spawn(async move { generate_rsa_key_async(2048).await }))
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
                    .map(|_| tokio::spawn(async move { generate_rsa_key_async(4096).await }))
                    .collect::<Vec<_>>(),
            )
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?,
        })
    }

    pub fn get(&mut self, size: usize) -> Result<(RsaPrivateKey, InMemorySigningKeyPair)> {
        let size = if size != 512 && size != 1024 && size != 2048 && size != 4096 {
            // HACK: If the size is not a power of 2, this is probably not RSA.
            // TODO: Remove this hack once we support non-RSA keys
            4096
        } else {
            size
        };

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

        println!("Cache miss for RSA key of size {}", size);

        Ok(generate_rsa_key(size)?)
    }
}
