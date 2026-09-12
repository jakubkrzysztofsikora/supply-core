use crate::domain::*;
use anyhow::Result;
use chrono::{DateTime, Utc};
use semver::{Version, VersionReq};
use std::path::Path;

pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}
pub trait VulnerabilitySource: Send + Sync {
    fn query(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &Version,
    ) -> Result<Vec<VulnerabilityFinding>>;
}
pub trait MetadataStore: Send + Sync {
    fn save_decision(&self, decision: &Decision) -> Result<()>;
    fn put_frozen(&self, artifact: FrozenArtifact) -> Result<()>;
    fn get_frozen(&self, name: &str, version: &Version) -> Result<Option<FrozenArtifact>>;
    fn latest_frozen_satisfying(
        &self,
        name: &str,
        requested: Option<&VersionReq>,
    ) -> Result<Option<FrozenArtifact>>;
    fn latest_frozen(&self, name: &str) -> Result<Option<FrozenArtifact>> {
        self.latest_frozen_satisfying(name, None)
    }
}
pub trait ArtifactStore: Send + Sync {
    fn put(&self, name: &str, version: &Version, bytes: &[u8]) -> Result<String>;
    /// Resolve a frozen artifact for `(name, version)`. Returns the
    /// canonical on-disk path inside the store root, or `None` if no
    /// such artifact exists. The store validates `name` and confines
    /// the resulting path to its artifact directory.
    fn resolve(&self, name: &str, version: &Version) -> Result<Option<String>>;
    /// Read an artifact into memory, rejecting paths outside the store's
    /// artifact directory. Callers normally obtain paths from `resolve`
    /// or `put`; this API does not track path provenance.
    fn read(&self, path: &str) -> Result<Vec<u8>>;
}
pub trait Hasher: Send + Sync {
    fn sha256(&self, bytes: &[u8]) -> String;
    fn verify_npm_integrity(&self, bytes: &[u8], integrity: &str) -> bool;
}
pub trait UpstreamNpmRegistry: Send + Sync {
    fn metadata(&self, package: &str) -> Result<serde_json::Value>;
    fn tarball(&self, url: &str) -> Result<Vec<u8>>;
}
pub trait UpstreamPyPiRegistry: Send + Sync {
    fn release(&self, package: &str, version: &str) -> Result<serde_json::Value>;
}
pub trait UpstreamNuGetRegistry: Send + Sync {
    fn release(&self, package: &str, version: &str) -> Result<serde_json::Value>;
}
pub trait WorkflowReader: Send + Sync {
    fn read(&self, root: &Path) -> Result<Vec<(String, String)>>;
}
