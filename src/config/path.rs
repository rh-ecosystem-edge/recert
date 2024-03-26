use anyhow::Result;
use clio::ClioPath;
use std::{ops::Deref, path::Path};

#[derive(Clone, Debug)]
pub(crate) struct ConfigPath(pub(crate) ClioPath);

impl std::fmt::Display for ConfigPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.to_string_lossy().fmt(f)
    }
}

impl AsRef<ClioPath> for ConfigPath {
    fn as_ref(&self) -> &ClioPath {
        &self.0
    }
}

impl Deref for ConfigPath {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0.path()
    }
}

impl From<ClioPath> for ConfigPath {
    fn from(clio_path: ClioPath) -> Self {
        Self(clio_path)
    }
}

impl ConfigPath {
    pub(crate) fn new(path: &str) -> Result<Self> {
        Ok(Self(ClioPath::new(path)?))
    }
}

impl serde::Serialize for ConfigPath {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.to_string_lossy().as_ref())
    }
}
