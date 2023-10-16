use serde::Serialize;

use super::{certificate, locations::Locations};

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct DistributedCert {
    pub(crate) certificate: certificate::Certificate,
    pub(crate) certificate_regenerated: Option<certificate::Certificate>,
    pub(crate) locations: Locations,
}
