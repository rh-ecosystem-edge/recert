use super::{
    cert_key_pair::{CertKeyPair, SerialNumberEdits, SkidEdits},
    crypto_utils::SigningKey,
    distributed_jwt::DistributedJwt,
    keys,
};
use crate::{rsa_key_pool::RsaKeyPool, Customizations};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::{self, cell::RefCell, rc::Rc};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Signee {
    CertKeyPair(Rc<RefCell<CertKeyPair>>),
    Jwt(Rc<RefCell<DistributedJwt>>),
}

impl Serialize for Signee {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Signee::CertKeyPair(cert_key_pair) => cert_key_pair.borrow().serialize(serializer),
            Signee::Jwt(jwt) => jwt.borrow().serialize(serializer),
        }
    }
}

impl Signee {
    pub(crate) fn regenerate(
        &mut self,
        original_signing_public_key: &keys::PublicKey,
        new_signing_key: Option<&SigningKey>,
        rsa_key_pool: &mut RsaKeyPool,
        customizations: &Customizations,
        skid_edits: Option<&mut SkidEdits>,
        serial_number_edits: Option<&mut SerialNumberEdits>,
    ) -> Result<()> {
        match self {
            Self::CertKeyPair(cert_key_pair) => {
                (**cert_key_pair).borrow_mut().regenerate(
                    new_signing_key,
                    rsa_key_pool,
                    customizations,
                    skid_edits.context("cert regeneration requires skid edits")?,
                    serial_number_edits.context("cert regeneration requires serial number edits")?,
                )?;
            }
            Self::Jwt(jwt) => match new_signing_key {
                Some(key_pair) => (**jwt).borrow_mut().regenerate(original_signing_public_key, key_pair)?,
                None => {
                    bail!("Cannot regenerate a jwt without a signing key, regenerate may only be called on a signee that is a root cert-key-pair")
                }
            },
        }

        Ok(())
    }
}
