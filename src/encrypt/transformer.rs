use anyhow::Result;
use async_trait::async_trait;
use dyn_clone::DynClone;

#[async_trait]
pub(crate) trait Transformer: DynClone {
    fn get_prefix(&self) -> String;

    async fn decrypt(&self, etcd_key: String, ciphertext: Vec<u8>) -> Result<Vec<u8>>;
    async fn encrypt(&self, etcd_key: String, plaintext: Vec<u8>) -> Result<Vec<u8>>;
}

dyn_clone::clone_trait_object!(Transformer);
