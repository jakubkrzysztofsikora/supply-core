use crate::application::ledger::EngineReport;
use crate::domain::*;
use anyhow::Result;
use chrono::{DateTime, Utc};
use node_semver::Range;
use std::{io::Read, path::Path};

pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}
pub trait VulnerabilitySource: Send + Sync {
    fn query(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &PackageVersionId,
    ) -> Result<Vec<VulnerabilityFinding>>;
    fn query_version(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
    ) -> Result<Vec<VulnerabilityFinding>> {
        let version = PackageVersionId::parse(&ecosystem, version)?;
        self.query(ecosystem, name, &version)
    }
}
pub trait MetadataStore: Send + Sync {
    fn save_decision(&self, decision: &Decision) -> Result<()>;
    fn put_frozen(&self, artifact: FrozenArtifact) -> Result<()>;
    fn get_frozen(&self, key: &ArtifactKey) -> Result<Option<FrozenArtifact>>;
    fn latest_frozen_satisfying(
        &self,
        source: &str,
        ecosystem: &Ecosystem,
        name: &str,
        requested: Option<&Range>,
    ) -> Result<Option<FrozenArtifact>>;
    fn latest_frozen(
        &self,
        source: &str,
        ecosystem: &Ecosystem,
        name: &str,
    ) -> Result<Option<FrozenArtifact>> {
        self.latest_frozen_satisfying(source, ecosystem, name, None)
    }
    fn save_content_finding(&self, finding: &ContentFinding) -> Result<()>;
    fn content_finding(
        &self,
        ecosystem: &Ecosystem,
        name: &str,
        version: &PackageVersionId,
    ) -> Result<Option<ContentFinding>>;
}
pub trait ContentScanner: Send + Sync {
    fn scan_archive(
        &self,
        ecosystem: &Ecosystem,
        archive: &mut std::fs::File,
        archive_path: &Path,
        name: &str,
        version: &PackageVersionId,
    ) -> Result<EngineReport>;
}
pub struct StoredArtifact {
    pub sha256: String,
    pub path: String,
    pub file: std::fs::File,
}
pub trait ArtifactStore: Send + Sync {
    fn put(&self, reader: &mut dyn Read, max_bytes: u64) -> Result<StoredArtifact>;
    fn map(&self, key: &ArtifactKey, sha256: &str) -> Result<()>;
    fn resolve(&self, key: &ArtifactKey) -> Result<Option<String>>;
    fn open(&self, key: &ArtifactKey) -> Result<Option<std::fs::File>>;
    fn import_legacy(&self, key: &ArtifactKey, expected_sha256: &str) -> Result<String>;
}
pub trait Hasher: Send + Sync {
    fn verified_npm_reader(
        &self,
        reader: Box<dyn Read + Send>,
        integrity: &str,
    ) -> Result<Box<dyn Read + Send>>;
}
pub trait UpstreamNpmRegistry: Send + Sync {
    fn metadata(&self, package: &str) -> Result<serde_json::Value>;
    fn tarball(&self, url: &str) -> Result<Box<dyn Read + Send>>;
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
