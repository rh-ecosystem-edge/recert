use serde::Serialize;

use super::cert_key_pair::CertKeyPair;
use super::distributed_private_key::DistributedPrivateKey;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::Ordering::Relaxed;

#[derive(Eq, PartialEq, Clone, Debug, Hash)]
pub(crate) struct Jwt {
    pub(crate) str: String,
}

impl Serialize for Jwt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if super::REDACT_SECRETS.load(Relaxed) {
            serializer.serialize_str("<redacted>")
        } else {
            serializer.serialize_str(&self.str)
        }
    }
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub(crate) enum JwtSigner {
    Unknown,
    CertKeyPair(Rc<RefCell<CertKeyPair>>),
    PrivateKey(Rc<RefCell<DistributedPrivateKey>>),
}
