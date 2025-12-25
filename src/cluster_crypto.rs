use self::{
    cert_key_pair::CertKeyPair,
    crypto_objects::DiscoveredCryptoObect,
    crypto_utils::jwt::verify,
    distributed_jwt::DistributedJwt,
    distributed_private_key::DistributedPrivateKey,
    distributed_public_key::DistributedPublicKey,
    keys::{PrivateKey, PublicKey},
    locations::Locations,
};
use crate::{
    cluster_crypto::cert_key_pair::{SerialNumberEdits, SkidEdits},
    cnsanreplace::CnSanReplaceRules,
    config::CryptoCustomizations,
    k8s_etcd::InMemoryK8sEtcd,
    rsa_key_pool::RsaKeyPool,
    rules::KNOWN_MISSING_PRIVATE_KEY_CERTS,
};
use anyhow::{bail, ensure, Context, Result};
use serde::Serialize;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
};
use std::{
    collections::hash_map::Entry::{Occupied, Vacant},
    sync::atomic::AtomicBool,
};
use x509_certificate::X509CertificateError;

mod crypto_objects;
mod distributed_cert;
mod distributed_jwt;
mod distributed_private_key;
mod distributed_public_key;
mod json_crawl;
mod jwt;
mod signee;

pub(crate) mod cert_key_pair;
pub(crate) mod certificate;
pub(crate) mod crypto_utils;
pub(crate) mod keys;
pub(crate) mod locations;
pub(crate) mod pem_utils;
pub(crate) mod scanning;

/// This is the main struct that holds all the crypto objects we've found in the cluster and the
/// locations where we found them, and how they relate to each other.
#[derive(Serialize)]
pub(crate) struct ClusterCryptoObjects {
    /// At the end of the day we're scanning the entire cluster for private keys, public keys
    /// certificates, and jwts. These four hashmaps is where we store all of them. The reason
    /// they're hashmaps and not vectors is because every one of those objects we encounter might
    /// be found in multiple locations. The value types here (Distributed*) hold a list of
    /// locations where the key/cert was found, and the list of locations for each cert/key grows
    /// as we scan more and more resources. The hashmap keys are of-course hashables so we can
    /// easily check if we already encountered the object before.
    #[serde(serialize_with = "hashmap_serialize_just_values", rename(serialize = "standalone_private_keys"))]
    pub(crate) distributed_private_keys: HashMap<PrivateKey, Rc<RefCell<DistributedPrivateKey>>>,
    #[serde(serialize_with = "hashmap_serialize_just_values", rename(serialize = "standalone_public_keys"))]
    pub(crate) distributed_public_keys: HashMap<PublicKey, Rc<RefCell<DistributedPublicKey>>>,
    #[serde(skip_serializing)]
    pub(crate) distributed_certs: HashMap<certificate::Certificate, Rc<RefCell<distributed_cert::DistributedCert>>>,
    #[serde(skip_serializing)]
    pub(crate) distributed_jwts: HashMap<jwt::Jwt, Rc<RefCell<DistributedJwt>>>,

    /// Every time we encounter a private key, we extract the public key
    /// from it and add to this mapping. This will later allow us to easily
    /// associate certificates with their matching private key (which would
    /// otherwise require brute force search).
    #[serde(skip_serializing)]
    pub(crate) public_to_private: HashMap<PublicKey, PrivateKey>,

    /// After collecting all certs and private keys, we go through the list of certs and try to
    /// find a private key that matches the public key of the cert (with the help of
    /// public_to_private) and populate this list of pairs.
    #[serde(serialize_with = "serialize_only_root_pairs")]
    pub(crate) cert_key_pairs: Vec<Rc<RefCell<CertKeyPair>>>,
}

fn serialize_only_root_pairs<S>(pairs: &[Rc<RefCell<CertKeyPair>>], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    pairs
        .iter()
        .filter(|pair| pair.borrow().distributed_cert.borrow().certificate.cert.subject_is_issuer())
        .collect::<Vec<_>>()
        .serialize(serializer)
}

fn hashmap_serialize_just_values<S, K, V>(values: &HashMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    K: serde::Serialize + std::cmp::Eq + std::hash::Hash,
    V: serde::Serialize,
{
    let values: Vec<_> = values.values().collect();
    values.serialize(serializer)
}

// TODO: Find a better way to communicate to the PrivateKey Serialize implementation that it should
// redact the key
pub(crate) static REDACT_SECRETS: AtomicBool = AtomicBool::new(false);

impl ClusterCryptoObjects {
    pub(crate) fn new() -> Self {
        Self {
            distributed_private_keys: HashMap::new(),
            distributed_public_keys: HashMap::new(),
            distributed_certs: HashMap::new(),
            distributed_jwts: HashMap::new(),
            public_to_private: HashMap::new(),
            cert_key_pairs: Vec::new(),
        }
    }

    fn establish_relationships(&mut self) -> Result<()> {
        self.pair_certs_and_keys().context("pairing certs and keys")?;
        self.fill_cert_key_signers().context("filling cert signers")?;
        self.fill_jwt_signers().context("filling JWT signers")?;
        self.fill_signees().context("filling signees")?;
        self.associate_public_keys().context("associating public keys")?;
        Ok(())
    }

    /// Commit all the crypto objects to etcd and disk. This is called after all the crypto
    /// objects have been regenerated so that the newly generated objects are persisted in
    /// etcd and on disk.
    #[allow(clippy::await_holding_refcell_ref)]
    pub(crate) async fn commit_to_etcd_and_disk(&mut self, etcd_client: &InMemoryK8sEtcd) -> Result<()> {
        for cert_key_pair in &self.cert_key_pairs {
            (**cert_key_pair).borrow().commit_to_etcd_and_disk(etcd_client).await?;
        }

        for jwt in self.distributed_jwts.values() {
            (**jwt).borrow().commit_to_etcd_and_disk(etcd_client).await?;
        }

        for private_key in self.distributed_private_keys.values() {
            (**private_key).borrow().commit_to_etcd_and_disk(etcd_client).await?;
        }

        for public_key in self.distributed_public_keys.values() {
            (**public_key).borrow().commit_to_etcd_and_disk(etcd_client).await?;
        }

        Ok(())
    }

    /// Recursively regenerate all the crypto objects. This is done by regenerating the top level
    /// cert-key pairs and standalone private keys, which will in turn regenerate all the objects
    /// that depend on them (signees). Requires that first the crypto objects have been paired and
    /// associated through the other methods.
    fn regenerate_crypto(&mut self, mut rsa_key_pool: RsaKeyPool, crypto_customizations: &CryptoCustomizations) -> Result<()> {
        let mut skid_edits = SkidEdits::new();
        let mut serial_number_edits = SerialNumberEdits::new();

        for cert_key_pair in &self.cert_key_pairs {
            if (**cert_key_pair).borrow().signer.is_some() {
                continue;
            }

            (**cert_key_pair).borrow_mut().regenerate(
                None,
                &mut rsa_key_pool,
                crypto_customizations,
                &mut skid_edits,
                &mut serial_number_edits,
            )?
        }

        for private_key in self.distributed_private_keys.values() {
            (**private_key).borrow_mut().regenerate(&mut rsa_key_pool, crypto_customizations)?
        }

        for public_key in self.distributed_public_keys.values() {
            if (**public_key).borrow().associated {
                // Associated public keys are already regenerated as part of their association
                continue;
            }

            (**public_key).borrow_mut().regenerate_no_private(&mut rsa_key_pool)?
        }

        Ok(())
    }

    fn fill_cert_key_signers(&mut self) -> Result<()> {
        for cert_key_pair in &self.cert_key_pairs {
            let mut true_signing_cert: Option<Rc<RefCell<CertKeyPair>>> = None;
            if !(*(**cert_key_pair).borrow().distributed_cert)
                .borrow()
                .certificate
                .cert
                .subject_is_issuer()
            {
                for potential_signing_cert_key_pair in &self.cert_key_pairs {
                    match (*(**cert_key_pair).borrow().distributed_cert)
                        .borrow()
                        .certificate
                        .cert
                        .verify_signed_by_certificate(
                            &(*(*potential_signing_cert_key_pair).borrow().distributed_cert)
                                .borrow()
                                .certificate
                                .cert,
                        ) {
                        Ok(_) => true_signing_cert = Some(Rc::clone(potential_signing_cert_key_pair)),
                        Err(X509CertificateError::CertificateSignatureVerificationFailed) => {}
                        Err(X509CertificateError::UnsupportedSignatureVerification(..)) => {
                            // This is a hack to get around the fact this lib doesn't support
                            // all signature algorithms yet.
                            if crypto_utils::openssl_is_signed(
                                &(*(*potential_signing_cert_key_pair).borrow().distributed_cert).borrow().certificate,
                                &(*(**cert_key_pair).borrow().distributed_cert).borrow().certificate,
                            )
                            .context("checking signature")?
                            {
                                true_signing_cert = Some(Rc::clone(potential_signing_cert_key_pair));
                            }
                        }
                        unknown_err => unknown_err?,
                    }
                }

                if true_signing_cert.is_none() {
                    log::warn!(
                        "no signing cert found for cert in {}",
                        (*(**cert_key_pair).borrow().distributed_cert).borrow().locations
                    );
                }
            }

            (**cert_key_pair).borrow_mut().signer = true_signing_cert;
        }

        Ok(())
    }

    /// For every jwt, find the private key that signed it (or certificate key pair that signed it,
    /// although rare in OCP) and record it. This will later be used to know how to regenerate the
    /// jwt.
    fn fill_jwt_signers(&mut self) -> Result<()> {
        // Usually it's just one private key signing all the jwts, so to speed things up, we record
        // the last signer and use that as the first guess for the next jwt. This dramatically
        // speeds up the process of finding the signer for each jwt, as trying all private keys is
        // very slow, especially in debug mode without optimizations.
        let mut last_signer: Option<Rc<RefCell<DistributedPrivateKey>>> = None;

        for distributed_jwt in self.distributed_jwts.values() {
            let mut maybe_signer = jwt::JwtSigner::Unknown;

            if let Some(last_signer) = &last_signer {
                if verify(
                    &(**distributed_jwt).borrow().jwt.str,
                    &PublicKey::try_from(&(*last_signer).borrow().key)?,
                )
                .context(format!(
                    "verifying last signer {} for jwt {}",
                    (*last_signer).borrow().locations,
                    (**distributed_jwt).borrow().locations
                ))? {
                    maybe_signer = jwt::JwtSigner::PrivateKey(Rc::clone(last_signer));
                }
            }

            if maybe_signer == jwt::JwtSigner::Unknown {
                for distributed_private_key in self.distributed_private_keys.values() {
                    if verify(
                        &(**distributed_jwt).borrow().jwt.str,
                        &PublicKey::try_from(&(**distributed_private_key).borrow().key)?,
                    )
                    .context(format!(
                        "verifying private key signer {} for jwt {}",
                        (*distributed_private_key).borrow().locations,
                        (**distributed_jwt).borrow().locations
                    ))? {
                        maybe_signer = jwt::JwtSigner::PrivateKey(Rc::clone(distributed_private_key));
                        last_signer = Some(Rc::clone(distributed_private_key));
                        break;
                    }
                }
            }

            if maybe_signer == jwt::JwtSigner::Unknown {
                for cert_key_pair in &self.cert_key_pairs {
                    if let Some(distributed_private_key) = &(**cert_key_pair).borrow().distributed_private_key {
                        if verify(
                            &(**distributed_jwt).borrow().jwt.str,
                            &PublicKey::try_from(&(**distributed_private_key).borrow().key)?,
                        )
                        .context(format!(
                            "verifying cert key pair signer {} for jwt {}",
                            (*distributed_private_key).borrow().locations,
                            (**distributed_jwt).borrow().locations
                        ))? {
                            maybe_signer = jwt::JwtSigner::CertKeyPair(Rc::clone(cert_key_pair));
                            break;
                        }
                    }
                }
            }

            if maybe_signer == jwt::JwtSigner::Unknown {
                log::warn!(
                    "no signer found for jwt in location {}",
                    (**distributed_jwt)
                        .borrow()
                        .clone()
                        .locations
                        .0
                        .into_iter()
                        .next()
                        .context("no locations for jwt")?
                );
            }

            (**distributed_jwt).borrow_mut().signer = maybe_signer;
        }

        Ok(())
    }

    /// For every cert-key pair or private key, find all the crypto objects that depend on it and
    /// record them. This will later be used to know how to regenerate the crypto objects.
    fn fill_signees(&mut self) -> Result<()> {
        for cert_key_pair in &self.cert_key_pairs {
            let mut signees = Vec::new();
            for potential_signee in &self.cert_key_pairs {
                if let Some(potential_signee_signer) = &(**potential_signee).borrow().signer {
                    if (*(**potential_signee_signer).borrow().distributed_cert).borrow().certificate.cert
                        == (*(**cert_key_pair).borrow().distributed_cert).borrow().certificate.cert
                    {
                        signees.push(signee::Signee::CertKeyPair(Rc::clone(potential_signee)));
                    }
                }
            }
            for potential_jwt_signee in self.distributed_jwts.values() {
                match &(*potential_jwt_signee).borrow_mut().signer {
                    // jwt::JwtSigner::Unknown => bail!("JWT has unknown signer"),
                    jwt::JwtSigner::Unknown => (),
                    jwt::JwtSigner::CertKeyPair(jwt_signer_cert_key_pair) => {
                        if jwt_signer_cert_key_pair == cert_key_pair {
                            signees.push(signee::Signee::Jwt(Rc::clone(potential_jwt_signee)));
                        }
                    }
                    jwt::JwtSigner::PrivateKey(_) => {}
                }
            }

            (**cert_key_pair).borrow_mut().signees = signees;
        }

        for distributed_private_key in self.distributed_private_keys.values() {
            for potential_jwt_signee in self.distributed_jwts.values() {
                match &(**potential_jwt_signee).borrow_mut().signer {
                    // jwt::JwtSigner::Unknown => bail!("JWT has unknown signer"),
                    jwt::JwtSigner::Unknown => (),
                    jwt::JwtSigner::CertKeyPair(_cert_key_pair) => {}
                    jwt::JwtSigner::PrivateKey(jwt_signer_distributed_private_key) => {
                        if jwt_signer_distributed_private_key == distributed_private_key {
                            (**distributed_private_key)
                                .borrow_mut()
                                .signees
                                .push(signee::Signee::Jwt(Rc::clone(potential_jwt_signee)));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Find the private key associated with the subject of each certificate and combine them into
    /// a cert-key pair. Also remove the private key from the list of private keys as it is now
    /// part of a cert-key pair, the remaining private keys are considered standalone.
    fn pair_certs_and_keys(&mut self) -> Result<()> {
        let mut paired_cers_to_remove = vec![];
        for (hashable_cert, distributed_cert) in &self.distributed_certs {
            let pair = Rc::new(RefCell::new(cert_key_pair::CertKeyPair {
                distributed_private_key: None,
                distributed_cert: Rc::clone(distributed_cert),
                signer: None,
                signees: Vec::new(),
                associated_public_key: None,
            }));

            let subject_public_key = (**distributed_cert).borrow().certificate.public_key.clone();

            if let Occupied(private_key) = self.public_to_private.entry(subject_public_key.clone()) {
                if let Occupied(distributed_private_key) = self.distributed_private_keys.entry(private_key.get().clone()) {
                    (*pair).borrow_mut().distributed_private_key = Some(Rc::clone(distributed_private_key.get()));

                    // Remove the private key from the pool of private keys as it's now paired with a cert
                    self.distributed_private_keys.remove(private_key.get());
                } else {
                    bail!(
                        "Private key not found for cert {}. The cert was found in {}",
                        (**distributed_cert).borrow().certificate.subject,
                        (**distributed_cert).borrow().locations,
                    );
                }
            } else if KNOWN_MISSING_PRIVATE_KEY_CERTS.iter().any(|known_missing_private_key_cert| {
                known_missing_private_key_cert.is_match(&(**distributed_cert).borrow().certificate.subject)
            }) {
                // This is a known missing private key cert, so we don't need to worry about it not
                // having a private key.
            }
            // else {
            //         // bail!(
            //         //     "Private key not found for cert not in KNOWN_MISSING_PRIVATE_KEY_CERTS, cannot continue, {}. The cert was found in {}",
            //         //     (**distributed_cert).borrow().certificate.subject,
            //         //     (**distributed_cert).borrow().locations,
            //         // );
            //     }

            paired_cers_to_remove.push(hashable_cert.clone());
            self.cert_key_pairs.push(pair);
        }

        for paired_cer_to_remove in paired_cers_to_remove {
            self.distributed_certs.remove(&paired_cer_to_remove);
        }

        Ok(())
    }

    /// Associate public keys with their cert-key pairs or standalone private keys.
    fn associate_public_keys(&mut self) -> Result<()> {
        for cert_key_pair in &self.cert_key_pairs {
            if let Occupied(public_key_entry) = self.distributed_public_keys.entry(
                (*(**cert_key_pair).borrow().distributed_cert)
                    .borrow()
                    .certificate
                    .public_key
                    .clone(),
            ) {
                (*cert_key_pair).borrow_mut().associated_public_key = Some(Rc::clone(public_key_entry.get()));

                (*public_key_entry.get()).borrow_mut().associated = true;
            }
        }

        for distributed_private_key in self.distributed_private_keys.values() {
            let public_part = PublicKey::try_from(&(*distributed_private_key).borrow().key)?;

            if let Occupied(public_key_entry) = self.distributed_public_keys.entry(public_part) {
                (*distributed_private_key).borrow_mut().associated_distributed_public_key = Some(Rc::clone(public_key_entry.get()));
                (*public_key_entry.get()).borrow_mut().associated = true;
            }
        }

        for public_key in self.distributed_public_keys.values() {
            if !(*public_key).borrow().associated {
                // Looks like not always all public keys are associated with a private
                // key/cert-key-pair. Probably because they got rotated and there are some
                // leftovers in etcd/filesystem. So we just warn
                log::warn!(
                    "found a standalone public key not associated with a private key or cert-key-pair, it can be found in these locations: {}. Key will be regenerated anyway.",
                    (*public_key).borrow().locations
                );
            }
        }

        Ok(())
    }

    pub(crate) fn process_objects(
        &mut self,
        discovered_crypto_objects: Vec<DiscoveredCryptoObect>,
        crypto_customizations: &CryptoCustomizations,
        rsa_pool: RsaKeyPool,
    ) -> Result<()> {
        self.register_discovered_crypto_objects(discovered_crypto_objects);
        log::info!(
            "Found {} private keys, {} public keys, {} certificates, and {} JWTs",
            self.distributed_private_keys.len(),
            self.distributed_public_keys.len(),
            self.distributed_certs.len(),
            self.distributed_jwts.len(),
        );

        ensure!(
            !self.distributed_private_keys.is_empty()
                || !self.distributed_public_keys.is_empty()
                || !self.distributed_certs.is_empty()
                || !self.distributed_jwts.is_empty(),
            "Unexpected count of crypto objects found"
        );

        self.establish_relationships().context("establishing relationships")?;
        log::info!("Established relationships between crypto objects");

        if crypto_customizations.ip_change_only {
            self.prune_cert_key_pairs_to_changed_cn_san_trees(&crypto_customizations.cn_san_replace_rules)
                .context("pruning cert-key-pairs to CN/SAN-changed trees")?;
            self.prune_standalone_keys().context("pruning standalone keys")?;
        }

        self.regenerate_crypto(rsa_pool, crypto_customizations)
            .context("regenerating crypto")?;
        log::info!("Regenerated all crypto objects");

        Ok(())
    }

    fn prune_cert_key_pairs_to_changed_cn_san_trees(&mut self, cn_san_replace_rules: &CnSanReplaceRules) -> Result<()> {
        // For each root cert-key-pair tree: if *any* cert in the tree would change if
        // cn_san_replace_rules were applied (CN and/or SAN), keep the *entire* tree.
        let mut keep: HashSet<usize> = HashSet::new();

        let roots: Vec<Rc<RefCell<CertKeyPair>>> = self
            .cert_key_pairs
            .iter()
            .filter(|pair| (**pair).borrow().signer.is_none())
            .cloned()
            .collect();

        // TODO: Improve this flow:
        // don't use two passes and don't use the visted set unless absolutely necessary
        // Consider removing only the roots, but this will mean we can't log
        // easily how many cert-key-pairs were pruned.
        for root in roots {
            let mut visited = HashSet::new();
            let tree_has_change =
                tree_has_change(&root, cn_san_replace_rules, &mut visited).context("checking if tree has CN/SAN changes")?;

            if tree_has_change {
                let mut visited_collect = HashSet::new();
                collect_all_pairs_in_tree(&root, &mut keep, &mut visited_collect);
            }
        }

        let before_count = self.cert_key_pairs.len();
        self.cert_key_pairs.retain(|pair| keep.contains(&(Rc::as_ptr(pair) as usize)));
        let after_count = self.cert_key_pairs.len();

        log::info!(
            "ip-change-only enabled: kept {} cert-key-pairs, pruned {}",
            after_count,
            before_count.saturating_sub(after_count)
        );

        Ok(())
    }

    fn prune_standalone_keys(&mut self) -> Result<()> {
        // When doing an ip-change-only run, we want to minimize churn: only regenerate cert trees
        // that actually change CN/SAN. Standalone keys (private/public) are not part of those trees,
        // so we drop them from the regeneration/commit sets.

        let before_private_count = self.distributed_private_keys.len();
        let before_public_count = self.distributed_public_keys.len();

        // Keep only public keys that are associated with a certificate (cert-key-pair).
        let mut cert_public_keys_to_keep: HashSet<PublicKey> = HashSet::new();
        for cert_key_pair in &self.cert_key_pairs {
            cert_public_keys_to_keep.insert(
                (*(**cert_key_pair).borrow().distributed_cert)
                    .borrow()
                    .certificate
                    .public_key
                    .clone(),
            );
        }

        self.distributed_public_keys
            .retain(|public_key, _| cert_public_keys_to_keep.contains(public_key));
        self.public_to_private
            .retain(|public_key, _| cert_public_keys_to_keep.contains(public_key));

        self.distributed_private_keys.clear();

        let after_public_count = self.distributed_public_keys.len();

        log::info!(
            "ip-change-only enabled: pruned {} standalone private keys and {} standalone public keys",
            before_private_count,
            before_public_count.saturating_sub(after_public_count),
        );

        Ok(())
    }

    fn register_discovered_crypto_objects(&mut self, discovered_crypto_objects: Vec<DiscoveredCryptoObect>) {
        for discovered_crypto_object in discovered_crypto_objects {
            let location = discovered_crypto_object.location.clone();
            self.register_discovered_crypto_object(discovered_crypto_object, location);
        }
    }

    fn register_discovered_crypto_object(&mut self, discovered_crypto_object: DiscoveredCryptoObect, location: locations::Location) {
        match discovered_crypto_object.crypto_object {
            crypto_objects::CryptoObject::PrivateKey(private_part, public_part) => {
                self.register_discovered_private_key(public_part, private_part, &location)
            }
            crypto_objects::CryptoObject::PublicKey(public_key) => self.register_discovered_public_key(public_key, &location),
            crypto_objects::CryptoObject::Certificate(hashable_cert) => self.register_discovered_certificate(hashable_cert, &location),
            crypto_objects::CryptoObject::Jwt(jwt) => self.register_discovered_jwt(jwt, location),
        }
    }

    fn register_discovered_jwt(&mut self, jwt: jwt::Jwt, location: locations::Location) {
        match self.distributed_jwts.entry(jwt.clone()) {
            Vacant(distributed_jwt) => {
                distributed_jwt.insert(Rc::new(RefCell::new(distributed_jwt::DistributedJwt {
                    jwt,
                    jwt_regenerated: None,
                    locations: Locations(vec![location].into_iter().collect()),
                    signer: jwt::JwtSigner::Unknown,
                })));
            }
            Occupied(distributed_jwt) => {
                (**distributed_jwt.get()).borrow_mut().locations.0.insert(location);
            }
        }
    }

    fn register_discovered_certificate(&mut self, hashable_cert: certificate::Certificate, location: &locations::Location) {
        match self.distributed_certs.entry(hashable_cert.clone()) {
            Vacant(distributed_cert) => {
                distributed_cert.insert(Rc::new(RefCell::new(distributed_cert::DistributedCert {
                    certificate: hashable_cert,
                    certificate_regenerated: None,
                    locations: Locations(vec![location.clone()].into_iter().collect()),
                })));
            }
            Occupied(distributed_cert) => {
                (**distributed_cert.get()).borrow_mut().locations.0.insert(location.clone());
            }
        }
    }

    fn register_discovered_public_key(&mut self, public_key: PublicKey, location: &locations::Location) {
        match self.distributed_public_keys.entry(public_key.clone()) {
            Vacant(distributed_public_key_entry) => {
                distributed_public_key_entry.insert(Rc::new(RefCell::new(distributed_public_key::DistributedPublicKey {
                    locations: Locations(vec![location.clone()].into_iter().collect()),
                    key: public_key,
                    key_regenerated: None,
                    associated: false,
                })));
            }

            Occupied(distributed_public_key_entry) => {
                (**distributed_public_key_entry.into_mut())
                    .borrow_mut()
                    .locations
                    .0
                    .insert(location.clone());
            }
        }
    }

    fn register_discovered_private_key(&mut self, public_part: PublicKey, private_part: PrivateKey, location: &locations::Location) {
        self.public_to_private.insert(public_part, private_part.clone());

        match self.distributed_private_keys.entry(private_part.clone()) {
            Vacant(distributed_private_key_entry) => {
                distributed_private_key_entry.insert(Rc::new(RefCell::new(distributed_private_key::DistributedPrivateKey {
                    locations: Locations(vec![location.clone()].into_iter().collect()),
                    key: private_part,
                    key_regenerated: None,
                    signees: vec![],
                    // We don't set the public key here even though we just generated it because
                    // this field is for actual public keys that we find in the wild, not ones we
                    // generate ourselves.
                    associated_distributed_public_key: None,
                })));
            }

            Occupied(distributed_private_key_entry) => {
                (**distributed_private_key_entry.into_mut())
                    .borrow_mut()
                    .locations
                    .0
                    .insert(location.clone());
            }
        }
    }
}

fn tree_has_change(
    pair: &Rc<RefCell<CertKeyPair>>,
    cn_san_replace_rules: &CnSanReplaceRules,
    visited: &mut HashSet<usize>,
) -> Result<bool> {
    let ptr = Rc::as_ptr(pair) as usize;
    if !visited.insert(ptr) {
        return Ok(false);
    }

    let mut has_change = {
        let pair_borrow = pair.borrow();
        let cert_borrow = pair_borrow.distributed_cert.borrow();
        cert_would_change_from_cn_san_replace(&cert_borrow.certificate, cn_san_replace_rules)
            .context("checking whether cert CN/SAN would change")?
    };

    let signees = { pair.borrow().signees.clone() };
    for signee in signees {
        if let signee::Signee::CertKeyPair(child) = &signee {
            if tree_has_change(child, cn_san_replace_rules, visited).context("walking child cert-key-pair")? {
                has_change = true;
            }
        }
    }

    Ok(has_change)
}

fn collect_all_pairs_in_tree(pair: &Rc<RefCell<CertKeyPair>>, out: &mut HashSet<usize>, visited: &mut HashSet<usize>) {
    let ptr = Rc::as_ptr(pair) as usize;
    if !visited.insert(ptr) {
        return;
    }

    out.insert(ptr);

    let signees = { pair.borrow().signees.clone() };
    for signee in signees {
        if let signee::Signee::CertKeyPair(child) = &signee {
            collect_all_pairs_in_tree(&child, out, visited);
        }
    }
}

fn cert_would_change_from_cn_san_replace(cert: &certificate::Certificate, cn_san_replace_rules: &CnSanReplaceRules) -> Result<bool> {
    let x509_cert: &x509_certificate::X509Certificate = &cert.cert;
    let cert_ref: &x509_certificate::rfc5280::Certificate = x509_cert.as_ref();

    let before =
        crate::cluster_crypto::crypto_utils::encode_tbs_cert_to_der(&cert_ref.tbs_certificate).context("encoding original TBS cert")?;
    let mut tbs_after = cert_ref.tbs_certificate.clone();
    crate::cluster_crypto::cert_key_pair::cert_mutations::mutate_cert_cn_san(&mut tbs_after, cn_san_replace_rules)
        .context("mutating TBS CN/SAN")?;
    let after = crate::cluster_crypto::crypto_utils::encode_tbs_cert_to_der(&tbs_after).context("encoding mutated TBS cert")?;

    Ok(before != after)
}
