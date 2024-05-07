use crate::json_tools;
use anyhow::{bail, Context, Result};
use lazy_static::lazy_static;
use serde::{ser::SerializeStruct, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Display},
};

lazy_static! {
    static ref SINGULAR_PLURAL_MAP: HashMap<&'static str, &'static str> = {
        HashMap::from([
            ("apiserver", "apiservers"),
            ("servicemonitor", "servicemonitors"),
            ("consolelink", "consolelinks"),
            ("helmchartrepository", "helmchartrepositories"),
            ("controlplanemachineset", "controlplanemachinesets"),
            ("performanceprofile", "performanceprofiles"),
            ("oauth", "oauths"),
            // TODO: This is a weird one, the resource kind is OAuthClient but the keys are e.g.
            // openshift.io/oauth/clients/openshift-challenging-client
            ("oauthclient", "oauth/clients"),
            ("serviceca", "servicecas"),
            ("metal3remediationtemplate", "metal3remediationtemplates"),
            ("prometheus", "prometheuses"),
            ("hostfirmwaresettings", "hostfirmwaresettings"),
            ("hardwaredata", "hardwaredata"),
            ("machineset", "machinesets"),
            ("olmconfig", "olmconfigs"),
            ("egressrouter", "egressrouters"),
            ("installplan", "installplans"),
            ("podnetworkconnectivitycheck", "podnetworkconnectivitychecks"),
            ("dnsrecord", "dnsrecords"),
            ("imagepruner", "imagepruners"),
            ("operatorpki", "operatorpkis"),
            ("cloudcredential", "cloudcredentials"),
            ("controllerconfig", "controllerconfigs"),
            ("imagetagmirrorset", "imagetagmirrorsets"),
            ("preprovisioningimage", "preprovisioningimages"),
            ("clustercsidriver", "clustercsidrivers"),
            ("probe", "probes"),
            ("subscription", "subscriptions"),
            ("proxy", "proxies"),
            ("network", "networks"),
            ("clusterresourcequota", "clusterresourcequotas"),
            ("kubeletconfig", "kubeletconfigs"),
            ("build", "builds"),
            ("imagecontentpolicy", "imagecontentpolicies"),
            ("authentication", "authentications"),
            ("ippool", "ippools"),
            ("kubescheduler", "kubeschedulers"),
            ("bmceventsubscription", "bmceventsubscriptions"),
            ("imagedigestmirrorset", "imagedigestmirrorsets"),
            ("node", "nodes"),
            ("openshiftapiserver", "openshiftapiservers"),
            ("ingresscontroller", "ingresscontrollers"),
            ("machineconfigpool", "machineconfigpools"),
            ("openshiftcontrollermanager", "openshiftcontrollermanagers"),
            ("consoleplugin", "consoleplugins"),
            ("volumesnapshotcontent", "volumesnapshotcontents"),
            ("volumesnapshotclass", "volumesnapshotclasses"),
            ("network", "networks"),
            ("consolenotification", "consolenotifications"),
            ("config", "configs"),
            ("consoleyamlsample", "consoleyamlsamples"),
            ("machinehealthcheck", "machinehealthchecks"),
            ("config", "configs"),
            ("rangeallocation", "rangeallocations"),
            ("machine", "machines"),
            ("credentialsrequest", "credentialsrequests"),
            ("podmonitor", "podmonitors"),
            ("clusterautoscaler", "clusterautoscalers"),
            ("overlappingrangeipreservation", "overlappingrangeipreservations"),
            ("operatorcondition", "operatorconditions"),
            ("operator", "operators"),
            ("dns", "dnses"),
            ("scheduler", "schedulers"),
            ("storage", "storages"),
            ("metal3remediation", "metal3remediations"),
            ("alertmanager", "alertmanagers"),
            ("insightsoperator", "insightsoperators"),
            ("egressip", "egressips"),
            ("consoleexternalloglink", "consoleexternalloglinks"),
            ("console", "consoles"),
            ("volumesnapshot", "volumesnapshots"),
            ("operatorgroup", "operatorgroups"),
            ("machineautoscaler", "machineautoscalers"),
            ("containerruntimeconfig", "containerruntimeconfigs"),
            ("project", "projects"),
            ("kubestorageversionmigrator", "kubestorageversionmigrators"),
            ("firmwareschema", "firmwareschemas"),
            ("config", "configs"),
            ("prometheusrule", "prometheusrules"),
            ("apirequestcount", "apirequestcounts"),
            ("egressqos", "egressqoses"),
            ("imagecontentsourcepolicy", "imagecontentsourcepolicies"),
            ("projecthelmchartrepository", "projecthelmchartrepositories"),
            ("profile", "profiles"),
            ("catalogsource", "catalogsources"),
            ("securitycontextconstraints", "securitycontextconstraints"),
            ("egressfirewall", "egressfirewalls"),
            ("clusterserviceversion", "clusterserviceversions"),
            ("kubeapiserver", "kubeapiservers"),
            ("ingress", "ingresses"),
            ("operatorhub", "operatorhubs"),
            ("alertmanagerconfig", "alertmanagerconfigs"),
            ("featuregate", "featuregates"),
            ("image", "images"),
            ("console", "consoles"),
            ("dns", "dnses"),
            ("kubecontrollermanager", "kubecontrollermanagers"),
            ("consolequickstart", "consolequickstarts"),
            ("machineconfig", "machineconfigs"),
            ("storageversionmigration", "storageversionmigrations"),
            ("provisioning", "provisionings"),
            ("storagestate", "storagestates"),
            ("rolebindingrestriction", "rolebindingrestrictions"),
            ("thanosruler", "thanosrulers"),
            ("baremetalhost", "baremetalhosts"),
            ("clusteroperator", "clusteroperators"),
            ("network-attachment-definition", "network-attachment-definitions"),
            ("infrastructure", "infrastructures"),
            ("consoleclidownload", "consoleclidownloads"),
            ("tuned", "tuneds"),
            ("authentication", "authentications"),
            ("csisnapshotcontroller", "csisnapshotcontrollers"),
            ("clusterversion", "clusterversions"),
            ("etcd", "etcds"),
        ])
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locations(pub(crate) HashSet<Location>);

impl Serialize for Locations {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Sorted
        let mut locations = self.0.iter().collect::<Vec<_>>();

        let k8s_locations = locations
            .iter()
            .filter_map(|location| match location {
                Location::K8s(k8s_location) => Some(k8s_location),
                _ => None,
            })
            .collect::<Vec<_>>();

        let file_locations = locations
            .iter()
            .filter_map(|location| match location {
                Location::Filesystem(file_location) => Some(file_location),
                _ => None,
            })
            .collect::<Vec<_>>();

        locations.sort();

        let mut struct_serializer = serializer.serialize_struct("locations", 2)?;

        struct_serializer.serialize_field("k8s", &k8s_locations)?;
        struct_serializer.serialize_field("filesystem", &file_locations)?;

        struct_serializer.end()
    }
}

impl AsRef<HashSet<Location>> for Locations {
    fn as_ref(&self) -> &HashSet<Location> {
        &self.0
    }
}

impl AsMut<HashSet<Location>> for Locations {
    fn as_mut(&mut self) -> &mut HashSet<Location> {
        &mut self.0
    }
}

impl Display for Locations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let locations = self.0.iter().collect::<Vec<_>>();
        write!(f, "[")?;
        for location in locations {
            write!(f, "{}, ", location)?;
        }
        write!(f, "]")
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub(crate) enum Location {
    K8s(K8sLocation),
    Filesystem(FileLocation),
}

impl Ord for Location {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

impl PartialOrd for Location {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Serialize for Location {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Location::K8s(k8s_location) => k8s_location.serialize(serializer),
            Location::Filesystem(file_location) => file_location.serialize(serializer),
        }
    }
}

impl Location {
    pub fn k8s_yaml(k8s_resource_location: &K8sResourceLocation, yaml_location: &JsonLocation) -> Location {
        Location::K8s(K8sLocation {
            resource_location: k8s_resource_location.clone(),
            yaml_location: yaml_location.clone(),
        })
    }

    pub fn file_yaml(file_path: &str, yaml_location: &JsonLocation) -> Location {
        Location::Filesystem(FileLocation {
            path: file_path.to_string(),
            content_location: FileContentLocation::Yaml(yaml_location.clone()),
        })
    }
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Location::K8s(k8s_location) => write!(f, "k8s:{}:{}", k8s_location.resource_location, k8s_location.yaml_location),
            Location::Filesystem(file_location) => write!(f, "file:{}:{}", file_location.path, file_location.content_location),
        }
    }
}

impl Debug for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::K8s(arg0) => f.debug_tuple("K8s").field(arg0).finish(),
            Self::Filesystem(arg0) => f.debug_tuple("Filesystem").field(arg0).finish(),
        }
    }
}

impl Location {
    pub(crate) fn with_pem_bundle_index(&self, pem_bundle_index: u64) -> Result<Self> {
        Ok(match self {
            Self::K8s(k8s_location) => {
                let mut new_k8s_location = k8s_location.clone();
                new_k8s_location.yaml_location.value = LocationValueType::Pem(PemLocationInfo { pem_bundle_index });
                Self::K8s(new_k8s_location)
            }
            Self::Filesystem(file_location) => match &file_location.content_location {
                FileContentLocation::Raw(location_value_type) => match location_value_type {
                    LocationValueType::Pem(_) => bail!("already has PEM info"),
                    LocationValueType::Jwt => bail!("already has jwt info"),
                    LocationValueType::YetUnknown => {
                        let mut new_file_location = file_location.clone();
                        new_file_location.content_location =
                            FileContentLocation::Raw(LocationValueType::Pem(PemLocationInfo::new(pem_bundle_index)));
                        Self::Filesystem(new_file_location)
                    }
                },
                FileContentLocation::Yaml(yaml_location) => {
                    let mut new_yaml_location = yaml_location.clone();
                    new_yaml_location.value = LocationValueType::Pem(PemLocationInfo::new(pem_bundle_index));
                    let mut new_file_location = file_location.clone();
                    new_file_location.content_location = FileContentLocation::Yaml(new_yaml_location);
                    Self::Filesystem(new_file_location)
                }
            },
        })
    }

    pub(crate) fn with_jwt(&self) -> Result<Self> {
        Ok(match self {
            Self::K8s(k8s_location) => {
                let mut new_k8s_location = k8s_location.clone();
                new_k8s_location.yaml_location.value = LocationValueType::Jwt;
                Self::K8s(new_k8s_location)
            }
            Self::Filesystem(file_location) => match &file_location.content_location {
                FileContentLocation::Raw(location_value_type) => match location_value_type {
                    LocationValueType::Pem(_) => bail!("already has PEM info"),
                    LocationValueType::Jwt => bail!("already has jwt info"),
                    LocationValueType::YetUnknown => {
                        let mut new_file_location = file_location.clone();
                        new_file_location.content_location = FileContentLocation::Raw(LocationValueType::Jwt);
                        Self::Filesystem(new_file_location)
                    }
                },
                FileContentLocation::Yaml(yaml_location) => {
                    let mut new_yaml_location = yaml_location.clone();
                    new_yaml_location.value = LocationValueType::Jwt;
                    let mut new_file_location = file_location.clone();
                    new_file_location.content_location = FileContentLocation::Yaml(new_yaml_location);
                    Self::Filesystem(new_file_location)
                }
            },
        })
    }
}

#[derive(Serialize, Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct PemLocationInfo {
    pub(crate) pem_bundle_index: u64,
}

impl PemLocationInfo {
    fn new(pem_bundle_index: u64) -> Self {
        Self { pem_bundle_index }
    }
}

impl std::fmt::Display for PemLocationInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "in PEM bundle at index {}", self.pem_bundle_index)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct FileLocation {
    pub(crate) path: String,
    pub(crate) content_location: FileContentLocation,
}

impl Serialize for FileLocation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("file: {} {}", self.path, self.content_location))
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) enum FileContentLocation {
    Raw(LocationValueType),
    Yaml(JsonLocation),
}

impl Serialize for FileContentLocation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            FileContentLocation::Raw(location_value_type) => serializer.serialize_str(&format!("{}", location_value_type)),
            FileContentLocation::Yaml(yaml_location) => yaml_location.serialize(serializer),
        }
    }
}

impl std::fmt::Display for FileContentLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileContentLocation::Raw(pem_location_info) => write!(f, "{}", pem_location_info),
            FileContentLocation::Yaml(yaml_location) => write!(f, "{}", yaml_location),
        }
    }
}

#[derive(Serialize, Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) enum LocationValueType {
    Pem(PemLocationInfo),
    Jwt,
    YetUnknown,
}

impl std::fmt::Display for LocationValueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocationValueType::Pem(pem_location_info) => write!(f, "{}", pem_location_info),
            LocationValueType::Jwt => write!(f, "jwt"),
            LocationValueType::YetUnknown => write!(f, "unknown"),
        }
    }
}

#[derive(Serialize, Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) enum FieldEncoding {
    None,
    Base64,
    ByteArray,
    DataUrl,
}

impl Display for FieldEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FieldEncoding::None => write!(f, "without encoding"),
            FieldEncoding::Base64 => write!(f, "encoded as base64"),
            FieldEncoding::DataUrl => write!(f, "encoded as a dataurl"),
            FieldEncoding::ByteArray => write!(f, "encoded as a byte array"),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct JsonLocation {
    pub(crate) json_pointer: String,
    pub(crate) value: LocationValueType,
    pub(crate) encoding: FieldEncoding,
}

impl Serialize for JsonLocation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{}", self))
    }
}

impl JsonLocation {
    pub fn new(prefix: &str, key: &str, encoding: FieldEncoding) -> Self {
        JsonLocation {
            json_pointer: format!("{}/{}", prefix, key.to_string().replace('/', "~1")),
            value: LocationValueType::YetUnknown,
            encoding,
        }
    }
}

impl std::fmt::Display for JsonLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}, {}, {}", self.json_pointer, self.encoding, self.value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct K8sResourceLocation {
    pub(crate) namespace: Option<String>,
    pub(crate) kind: String,
    pub(crate) apiversion: String,
    pub(crate) name: String,
}

impl Serialize for K8sResourceLocation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.namespace {
            Some(namespace) => serializer.serialize_str(&format!("{}/{}/{}:{}", self.apiversion, self.kind, namespace, self.name)),
            None => serializer.serialize_str(&format!("{}/{}/{}", self.apiversion, self.kind, self.name)),
        }
    }
}

impl K8sResourceLocation {
    pub(crate) fn new(namespace: Option<&str>, kind: &str, name: &str, apiversion: &str) -> Self {
        Self {
            namespace: namespace.map(|namespace| namespace.to_string()),
            kind: kind.to_string(),
            name: name.to_string(),
            apiversion: apiversion.to_string(),
        }
    }

    pub(crate) fn as_etcd_key(&self) -> String {
        let apiversion_first_component = self.apiversion.as_str().split('/').next();

        let is_openshift = matches!(self.apiversion.as_str(), "route.openshift.io/v1" | "oauth.openshift.io/v1");

        format!(
            "/{}/{}{}/{}{}",
            if is_openshift { "openshift.io" } else { "kubernetes.io" },
            match apiversion_first_component {
                Some(apiversion_first_component_value) => {
                    match apiversion_first_component_value {
                        "operator.openshift.io"
                        | "monitoring.coreos.com"
                        | "apiregistration.k8s.io"
                        | "machineconfiguration.openshift.io"
                        | "config.openshift.io"
                        | "console.openshift.io" => {
                            format!("{}/", apiversion_first_component_value)
                        }
                        _ => "".to_string(),
                    }
                }
                None => "".to_string(),
            },
            SINGULAR_PLURAL_MAP
                .get(self.kind.to_lowercase().as_str())
                .unwrap_or(&format!("{}s", self.kind.to_lowercase()).as_str()),
            match &self.namespace {
                Some(namespace) => format!("{}/", namespace),
                None => "".to_string(),
            },
            self.name,
        )
    }
}

impl TryFrom<&serde_json::Value> for K8sResourceLocation {
    type Error = anyhow::Error;
    fn try_from(value: &serde_json::Value) -> Result<Self> {
        let namespace = match json_tools::read_metadata_string_field(value, "namespace") {
            Some(namespace) => match namespace.as_str() {
                "" => None,
                _ => Some(namespace),
            },
            None => None,
        };

        Ok(Self {
            namespace,
            kind: json_tools::read_string_field(value, "kind").context("missing kind field")?,
            name: json_tools::read_metadata_string_field(value, "name").context("missing name field")?,
            apiversion: json_tools::read_string_field(value, "apiVersion").context("missing apiversion field")?,
        })
    }
}

impl std::hash::Hash for K8sResourceLocation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.namespace.hash(state);
        self.kind.hash(state);
        self.name.hash(state);
    }
}

impl std::fmt::Display for K8sResourceLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}:{}",
            self.kind,
            self.namespace.clone().unwrap_or("cluster-scoped".to_string()),
            self.name
        )
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct K8sLocation {
    pub(crate) resource_location: K8sResourceLocation,
    pub(crate) yaml_location: JsonLocation,
}

impl Serialize for K8sLocation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("k8s: {} {}", self.resource_location, self.yaml_location))
    }
}

impl std::fmt::Display for K8sLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}:{}",
            self.resource_location, self.yaml_location.json_pointer, self.yaml_location.value
        )
    }
}
