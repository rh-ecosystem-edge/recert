use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use bytes::Bytes;
use std::sync::atomic::Ordering::Relaxed;

#[derive(Eq, PartialEq, Clone, Debug, Hash)]
pub(crate) struct SymmetricKey {
    pub(crate) bytes: Bytes,
}

impl SymmetricKey {
    pub(crate) fn new(bytes: Bytes) -> Self {
        Self { bytes }
    }
}

impl serde::Serialize for SymmetricKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if super::REDACT_SECRETS.load(Relaxed) {
            serializer.serialize_str("<redacted>")
        } else {
            serializer.serialize_str(&base64_standard.encode(&self.bytes))
        }
    }
}
