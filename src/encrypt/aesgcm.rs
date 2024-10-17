use super::transformer::Transformer;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    AeadCore, Aes256Gcm, Key, Nonce,
};
use anyhow::Result;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};

#[derive(Clone)]
pub(crate) struct AesGcm {
    prefix: String,
    key: String,
}

impl AesGcm {
    pub(crate) fn new(prefix: String, key: String) -> Self {
        Self { prefix, key }
    }
}

#[async_trait]
impl Transformer for AesGcm {
    fn get_prefix(&self) -> String {
        self.prefix.to_string()
    }

    async fn decrypt(&self, etcd_key: String, ciphertext: Vec<u8>) -> Result<Vec<u8>> {
        let nonce_size = 12;

        let key = base64_standard.decode(self.key.as_bytes())?;
        let key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(key);

        let (_, nonce_cipher_data) = ciphertext.split_at(self.prefix.len());
        let (nonce_arr, ciphered_data) = nonce_cipher_data.split_at(nonce_size);
        let nonce = Nonce::from_slice(nonce_arr);
        let aad = etcd_key.clone().into_bytes();

        let ciphered = Payload {
            msg: ciphered_data,
            aad: &aad[..],
        };
        let plaintext = cipher.decrypt(nonce, ciphered).map_err(anyhow::Error::msg)?;

        Ok(plaintext)
    }

    async fn encrypt(&self, etcd_key: String, plaintext: Vec<u8>) -> Result<Vec<u8>> {
        let key = base64_standard.decode(self.key.as_bytes())?;
        let key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let aad = etcd_key.clone().into_bytes();
        let payload = Payload {
            msg: &plaintext,
            aad: &aad[..],
        };

        let ciphered_data = cipher.encrypt(&nonce, payload).map_err(anyhow::Error::msg)?;
        let mut encrypted_data: Vec<u8> = self.prefix.as_bytes().to_vec();
        encrypted_data.extend_from_slice(&nonce);
        encrypted_data.extend_from_slice(&ciphered_data);

        Ok(encrypted_data)
    }
}
