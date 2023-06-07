use super::{certificate, locations::Locations};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DistributedCert {
    pub(crate) certificate: certificate::Certificate,
    pub(crate) locations: Locations,
}

