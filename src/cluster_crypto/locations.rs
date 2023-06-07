use std::{
    collections::HashSet,
    fmt::{Debug, Display},
};

use serde_json::Value;

use crate::json_tools;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locations(pub(crate) HashSet<Location>);

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

impl Location {
    pub fn k8s_yaml(k8s_resource_location: &K8sResourceLocation, yaml_location: &YamlLocation) -> Location {
        Location::K8s(K8sLocation {
            resource_location: k8s_resource_location.clone(),
            yaml_location: yaml_location.clone(),
        })
    }

    pub fn file_yaml(file_path: &str, yaml_location: &YamlLocation) -> Location {
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
    pub(crate) fn with_pem_bundle_index(&self, pem_bundle_index: u64) -> Self {
        match self {
            Self::K8s(k8s_location) => {
                let mut new_k8s_location = k8s_location.clone();
                new_k8s_location.yaml_location.value = LocationValueType::Pem(PemLocationInfo { pem_bundle_index });
                Self::K8s(new_k8s_location)
            }
            Self::Filesystem(file_location) => match &file_location.content_location {
                FileContentLocation::Raw(location_value_type) => match location_value_type {
                    LocationValueType::Pem(_) => panic!("Already has PEM info"),
                    LocationValueType::Jwt => panic!("Already has JWT info"),
                    LocationValueType::Unknown => {
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
        }
    }

    pub(crate) fn with_jwt(&self) -> Self {
        match self {
            Self::K8s(k8s_location) => {
                let mut new_k8s_location = k8s_location.clone();
                new_k8s_location.yaml_location.value = LocationValueType::Jwt;
                Self::K8s(new_k8s_location)
            }
            Self::Filesystem(file_location) => match &file_location.content_location {
                FileContentLocation::Raw(location_value_type) => match location_value_type {
                    LocationValueType::Pem(_) => panic!("Already has PEM info"),
                    LocationValueType::Jwt => panic!("Already has JWT info"),
                    LocationValueType::Unknown => {
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
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
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
        write!(f, ":pem{}", self.pem_bundle_index)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct FileLocation {
    pub(crate) path: String,
    pub(crate) content_location: FileContentLocation,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) enum FileContentLocation {
    Raw(LocationValueType),
    Yaml(YamlLocation),
}

impl std::fmt::Display for FileContentLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileContentLocation::Raw(pem_location_info) => write!(f, "{}", pem_location_info),
            FileContentLocation::Yaml(yaml_location) => write!(f, "{}", yaml_location),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) enum LocationValueType {
    Pem(PemLocationInfo),
    Jwt,
    Unknown,
}

impl std::fmt::Display for LocationValueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocationValueType::Pem(pem_location_info) => write!(f, "{}", pem_location_info),
            LocationValueType::Jwt => write!(f, ":jwt"),
            LocationValueType::Unknown => panic!("Cannot display unknown location value type"),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) enum FieldEncoding {
    None,
    Base64,
    DataUrl,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct YamlLocation {
    pub(crate) json_pointer: String,
    pub(crate) value: LocationValueType,
    pub(crate) encoding: FieldEncoding,
}

impl YamlLocation {
    pub fn new(prefix: &str, key: &str, encoding: FieldEncoding) -> Self {
        YamlLocation {
            json_pointer: format!("{}/{}", prefix, key.to_string().replace("/", "~1")),
            value: LocationValueType::Unknown,
            encoding,
        }
    }
}

impl std::fmt::Display for YamlLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, ":{}{}", self.json_pointer, self.value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct K8sResourceLocation {
    pub(crate) namespace: Option<String>,
    pub(crate) kind: String,
    pub(crate) apiversion: String,
    pub(crate) name: String,
}

impl K8sResourceLocation {
    pub(crate) fn new(namespace: Option<&str>, kind: &str, name: &str, apiversion: &str) -> Self {
        Self {
            namespace: if let Some(namespace) = namespace {
                Some(namespace.to_string())
            } else {
                None
            },
            kind: kind.to_string(),
            name: name.to_string(),
            apiversion: apiversion.to_string(),
        }
    }
}

impl From<&Value> for K8sResourceLocation {
    fn from(value: &Value) -> Self {
        Self {
            namespace: json_tools::read_metadata_string_field(value, "namespace"),
            kind: json_tools::read_string_field(value, "kind").unwrap(),
            name: json_tools::read_metadata_string_field(value, "name").unwrap(),
            apiversion: json_tools::read_string_field(value, "apiVersion")
                .expect(format!("Missing apiversion field in {}", value).as_str()),
        }
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
    pub(crate) yaml_location: YamlLocation,
}

impl K8sResourceLocation {
    pub(crate) fn as_etcd_key(&self) -> String {
        let apiversion_first_component = self.apiversion.as_str().split('/').next();

        format!(
            "/kubernetes.io/{}{}s/{}{}",
            match apiversion_first_component {
                Some(apiversion_first_component_value) => {
                    match apiversion_first_component_value {
                        "apiregistration.k8s.io" => format!("{}/", apiversion_first_component_value),
                        "machineconfiguration.openshift.io" => format!("{}/", apiversion_first_component_value),
                        _ => "".to_string(),
                    }
                }
                None => "".to_string(),
            },
            self.kind.to_lowercase(),
            match self.namespace {
                Some(_) => format!("{}/", self.namespace.as_ref().unwrap()),
                None => "".to_string(),
            },
            self.name,
        )
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
