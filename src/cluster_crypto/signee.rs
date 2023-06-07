use x509_certificate::InMemorySigningKeyPair;
use std::{self, fmt::{Formatter, Display}, cell::RefCell, rc::Rc};
use super::{distributed_jwt::DistributedJwt, cert_key_pair::CertKeyPair, keys};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Signee {
    CertKeyPair(Rc<RefCell<CertKeyPair>>),
    Jwt(Rc<RefCell<DistributedJwt>>),
}

impl Display for Signee {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Signee::CertKeyPair(cert_key_pair) => {
                write!(f, "{}", (**cert_key_pair).borrow())
            }
            Signee::Jwt(jwt) => write!(f, "Jwt({})", (**jwt).borrow().locations),
        }
    }
}

impl Signee {
    pub(crate) fn regenerate(&mut self, original_signing_public_key: &keys::PublicKey, new_signing_key: Option<&InMemorySigningKeyPair>) {
        match self {
            Self::CertKeyPair(cert_key_pair) => {
                (**cert_key_pair).borrow_mut().regenerate(new_signing_key);
            }
            Self::Jwt(jwt) => match new_signing_key {
                Some(key_pair) => (**jwt).borrow_mut().regenerate(&original_signing_public_key, key_pair),
                None => {
                    panic!("Cannot regenerate a jwt without a signing key, regenerate may only be called on a signee that is a root cert-key-pair")
                }
            },
        }
    }
}

