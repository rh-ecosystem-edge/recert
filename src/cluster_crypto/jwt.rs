use super::cert_key_pair::CertKeyPair;
use super::distributed_private_key::DistributedPrivateKey;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Eq, PartialEq, Clone, Debug, Hash)]
pub(crate) struct Jwt {
    pub(crate) str: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum JwtSigner {
    Unknown,
    CertKeyPair(Rc<RefCell<CertKeyPair>>),
    PrivateKey(Rc<RefCell<DistributedPrivateKey>>),
}

