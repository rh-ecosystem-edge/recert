use super::{
    cert_key_pair::{CertKeyPair, SerialNumberEdits, SkidEdits},
    distributed_jwt::DistributedJwt,
    keys,
};
use crate::{cnsanreplace::CnSanReplaceRules, use_key::UseKeyRules, rsa_key_pool::RsaKeyPool};
use anyhow::{bail, Context, Result};
use std::{
    self,
    cell::RefCell,
    fmt::{Display, Formatter},
    rc::Rc,
};
use x509_certificate::InMemorySigningKeyPair;

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
    pub(crate) fn regenerate(
        &mut self,
        original_signing_public_key: &keys::PublicKey,
        new_signing_key: Option<&InMemorySigningKeyPair>,
        rsa_key_pool: &mut RsaKeyPool,
        cn_san_replace_rules: &CnSanReplaceRules,
        use_key_rules: &UseKeyRules,
        skid_edits: Option<&mut SkidEdits>,
        serial_number_edits: Option<&mut SerialNumberEdits>,
    ) -> Result<()> {
        match self {
            Self::CertKeyPair(cert_key_pair) => {
                (**cert_key_pair).borrow_mut().regenerate(
                    new_signing_key,
                    rsa_key_pool,
                    cn_san_replace_rules,
                    use_key_rules,
                    skid_edits.context("cert regeneration requires skid edits")?,
                    serial_number_edits.context("cert regeneration requires serial number edits")?,
                )?;
            }
            Self::Jwt(jwt) => match new_signing_key {
                Some(key_pair) => (**jwt).borrow_mut().regenerate(&original_signing_public_key, key_pair)?,
                None => {
                    bail!("Cannot regenerate a jwt without a signing key, regenerate may only be called on a signee that is a root cert-key-pair")
                }
            },
        }

        Ok(())
    }
}
