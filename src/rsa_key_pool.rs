use super::cluster_crypto::crypto_utils::generate_rsa_key_async;
use anyhow::Result;
use futures_util::future::join_all;
use rsa::RsaPrivateKey;
use x509_certificate::InMemorySigningKeyPair;

pub struct RsaKeyPool {
    pub(crate) keys: Vec<(RsaPrivateKey, InMemorySigningKeyPair)>,
}

impl RsaKeyPool {
    pub async fn fill(num_keys: usize) -> Result<Self> {
        Ok(Self {
            keys: join_all(
                (0..num_keys)
                    .map(|_| tokio::spawn(async move { generate_rsa_key_async().await }))
                    .collect::<Vec<_>>(),
            )
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?,
        })
    }

    pub fn get(&mut self) -> Option<(RsaPrivateKey, InMemorySigningKeyPair)> {
        self.keys.pop()
    }
}
