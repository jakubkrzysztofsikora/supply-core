use crate::domain::*;
use crate::ports::*;
use anyhow::Result;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct PackageEvaluator<'a> {
    pub policy: &'a Policy,
    pub clock: &'a dyn Clock,
    pub vulns: &'a dyn VulnerabilitySource,
    pub metadata: &'a dyn MetadataStore,
}
impl<'a> PackageEvaluator<'a> {
    /// `requested` is the client's semver range (e.g. `^1.2.0`). Fallback
    /// serves the latest frozen version satisfying it; `None` allows any.
    pub fn evaluate(
        &self,
        version: &PackageVersion,
        requested: Option<&VersionReq>,
    ) -> Result<Decision> {
        let name = &version.package.name;
        if self.policy.npm.deny_packages.contains(name) {
            return Ok(Decision::block(
                name,
                Some(version.version.to_string()),
                "package is denylisted",
            ));
        }
        if self.policy.npm.require_integrity && version.integrity.is_none() {
            return self.fallback_or_block(
                name,
                &version.version,
                requested,
                "package version is missing npm integrity",
            );
        }
        let findings = self.vulns.query(Ecosystem::Npm, name, &version.version)?;
        if let Some(reason) = blocks_vulnerability(&findings, &self.policy.vulnerabilities) {
            return self.fallback_or_block(name, &version.version, requested, reason);
        }
        if is_version_quarantined(
            version.published_at,
            self.clock.now(),
            &self.policy.quarantine,
        ) {
            return self.fallback_or_block(
                name,
                &version.version,
                requested,
                "package version is inside quarantine window",
            );
        }
        Ok(Decision::allow(name.clone(), version.version.to_string()))
    }
    fn fallback_or_block(
        &self,
        name: &str,
        requested_version: &Version,
        requested: Option<&VersionReq>,
        reason: impl Into<String>,
    ) -> Result<Decision> {
        let reason = reason.into();
        if self.policy.npm.fallback_to_frozen {
            if let Some(frozen) = self.metadata.latest_frozen_satisfying(name, requested)? {
                return Ok(Decision::fallback(
                    name,
                    requested_version.to_string(),
                    frozen.version.to_string(),
                    reason,
                ));
            }
        }
        Ok(Decision::block(
            name,
            Some(requested_version.to_string()),
            reason,
        ))
    }
}

pub struct IngestService<'a> {
    pub policy: &'a Policy,
    pub registry: &'a dyn UpstreamNpmRegistry,
    pub hasher: &'a dyn Hasher,
    pub artifacts: &'a dyn ArtifactStore,
    pub metadata: &'a dyn MetadataStore,
    pub clock: &'a dyn Clock,
}
impl<'a> IngestService<'a> {
    /// Fetch tarball bytes and freeze them only after dist.integrity verifies.
    /// Fail closed: missing integrity, unreachable tarball, or byte mismatch
    /// never produces a frozen artifact.
    pub fn freeze_verified(&self, version: &PackageVersion) -> Result<FrozenArtifact> {
        let name = &version.package.name;
        let url = version
            .tarball_url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("no tarball url for {name}"))?;
        let integrity = version.integrity.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "no dist.integrity for {name}@{}: refusing to freeze unverified bytes",
                version.version
            )
        })?;
        let bytes = self.registry.tarball(url)?;
        if self.policy.npm.require_integrity && !self.hasher.verify_npm_integrity(&bytes, integrity)
        {
            anyhow::bail!(
                "integrity mismatch for {name}@{}: registry bytes do not match dist.integrity",
                version.version
            );
        }
        let sha256 = self.hasher.sha256(&bytes);
        if let Some(existing) = self.metadata.get_frozen(name, &version.version)? {
            if existing.sha256 != sha256 {
                anyhow::bail!(
                    "registry immutability violation: {name}@{} already frozen with different bytes",
                    version.version
                );
            }
            return Ok(existing);
        }
        let path = self.artifacts.put(name, &version.version, &bytes)?;
        let artifact = FrozenArtifact {
            package: version.package.clone(),
            version: version.version.clone(),
            sha256: self.hasher.sha256(&bytes),
            integrity: Some(integrity.to_string()),
            path,
            frozen_at: self.clock.now(),
        };
        self.metadata.put_frozen(artifact.clone())?;
        Ok(artifact)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowScanReport {
    pub findings: Vec<Decision>,
    pub references: Vec<GitHubActionReference>,
}
impl WorkflowScanReport {
    pub fn is_blocking(&self) -> bool {
        self.findings
            .iter()
            .any(|d| matches!(d.status, DecisionStatus::Block))
    }
}

pub struct GitHubActionsScanner<'a> {
    pub policy: &'a Policy,
    pub reader: &'a dyn WorkflowReader,
}
impl<'a> GitHubActionsScanner<'a> {
    pub fn scan(&self, root: &Path) -> Result<WorkflowScanReport> {
        let mut refs = vec![];
        let mut findings = vec![];
        for (file, body) in self.reader.read(root)? {
            for (idx, line) in body.lines().enumerate() {
                if let Some(raw) = extract_uses(line) {
                    let pin_kind = classify_action_ref(&raw);
                    let reference = GitHubActionReference {
                        raw: raw.clone(),
                        file: file.clone(),
                        line: idx + 1,
                        pin_kind: pin_kind.clone(),
                    };
                    let mut block = None;
                    match pin_kind {
                        ActionPinKind::FullSha => {}
                        ActionPinKind::Local if self.policy.github_actions.allow_local_actions => {}
                        ActionPinKind::TagOrBranch
                            if self.policy.github_actions.require_full_sha_pin =>
                        {
                            block = Some(
                                "GitHub Action is not pinned to a full 40-character commit SHA",
                            )
                        }
                        ActionPinKind::Docker => block = Some(
                            "Docker actions are not immutable unless image digests are enforced",
                        ),
                        ActionPinKind::Unknown => {
                            block = Some("GitHub Action reference could not be classified")
                        }
                        _ => {}
                    }
                    if let Some(reason) = block {
                        findings.push(Decision::block(
                            raw.clone(),
                            None,
                            format!("{reason} at {file}:{}", idx + 1),
                        ));
                    }
                    refs.push(reference);
                }
            }
        }
        Ok(WorkflowScanReport {
            findings,
            references: refs,
        })
    }
}
fn extract_uses(line: &str) -> Option<String> {
    let s = line.trim().trim_start_matches('-').trim();
    let rest = s.strip_prefix("uses:")?.trim();
    if let Some(quote) = rest.chars().next().filter(|c| *c == '"' || *c == '\'') {
        let inner = rest.strip_prefix(quote)?.strip_suffix(quote)?;
        return Some(inner.to_string());
    }
    let value = rest.split_once(" #").map(|(v, _)| v).unwrap_or(rest);
    Some(value.trim().to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use chrono::{DateTime, Duration, Utc};
    use std::{path::Path, sync::Mutex};

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }
    struct M(Mutex<Option<FrozenArtifact>>);
    impl MetadataStore for M {
        fn save_decision(&self, _: &Decision) -> Result<()> {
            Ok(())
        }
        fn latest_frozen_satisfying(
            &self,
            _: &str,
            requested: Option<&VersionReq>,
        ) -> Result<Option<FrozenArtifact>> {
            let frozen = self
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("lock poisoned"))?
                .clone();
            Ok(frozen.filter(|a| requested.is_none_or(|r| r.matches(&a.version))))
        }
        fn get_frozen(&self, _: &str, version: &Version) -> Result<Option<FrozenArtifact>> {
            let frozen = self
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("lock poisoned"))?
                .clone();
            Ok(frozen.filter(|a| a.version == *version))
        }
        fn put_frozen(&self, _: FrozenArtifact) -> Result<()> {
            Ok(())
        }
    }
    fn frozen(version: &str) -> FrozenArtifact {
        FrozenArtifact {
            package: PackageCoordinate {
                ecosystem: Ecosystem::Npm,
                name: "left-pad".into(),
            },
            version: Version::parse(version).unwrap(),
            sha256: "x".into(),
            integrity: None,
            path: "p".into(),
            frozen_at: Utc::now(),
        }
    }
    fn package(published: Option<DateTime<Utc>>) -> PackageVersion {
        PackageVersion {
            package: PackageCoordinate {
                ecosystem: Ecosystem::Npm,
                name: "left-pad".into(),
            },
            version: Version::parse("2.0.0").unwrap(),
            published_at: published,
            integrity: Some("sha512-x".into()),
            tarball_url: None,
        }
    }
    fn evaluator<'a>(
        policy: &'a Policy,
        clock: &'a FixedClock,
        metadata: &'a dyn MetadataStore,
    ) -> PackageEvaluator<'a> {
        PackageEvaluator {
            policy,
            clock,
            vulns: &NoVulns,
            metadata,
        }
    }
    struct NoVulns;
    impl VulnerabilitySource for NoVulns {
        fn query(&self, _: Ecosystem, _: &str, _: &Version) -> Result<Vec<VulnerabilityFinding>> {
            Ok(vec![])
        }
    }
    #[test]
    fn quarantine_falls_back_to_frozen() -> Result<()> {
        let now = Utc::now();
        let p = Policy::default();
        let c = FixedClock(now);
        let m = M(Mutex::new(Some(frozen("1.0.0"))));
        let e = evaluator(&p, &c, &m);
        let d = e.evaluate(&package(Some(now - Duration::days(2))), None)?;
        assert_eq!(d.status, DecisionStatus::Fallback);
        assert_eq!(d.served_version.as_deref(), Some("1.0.0"));
        Ok(())
    }
    #[test]
    fn missing_published_at_is_quarantined() -> Result<()> {
        let now = Utc::now();
        let p = Policy::default();
        let c = FixedClock(now);
        let m = M(Mutex::new(None));
        let e = evaluator(&p, &c, &m);
        let d = e.evaluate(&package(None), None)?;
        assert_eq!(d.status, DecisionStatus::Block);
        assert!(d.reasons[0].contains("quarantine"));
        Ok(())
    }
    #[test]
    fn denylisted_blocks_even_with_frozen_available() -> Result<()> {
        let now = Utc::now();
        let mut p = Policy::default();
        p.npm.deny_packages = vec!["left-pad".into()];
        let c = FixedClock(now);
        let m = M(Mutex::new(Some(frozen("1.0.0"))));
        let e = evaluator(&p, &c, &m);
        let d = e.evaluate(&package(Some(now - Duration::days(30))), None)?;
        assert_eq!(d.status, DecisionStatus::Block);
        assert!(d.reasons[0].contains("denylisted"));
        Ok(())
    }
    #[test]
    fn old_version_allows() -> Result<()> {
        let now = Utc::now();
        let p = Policy::default();
        let c = FixedClock(now);
        let m = M(Mutex::new(None));
        let e = evaluator(&p, &c, &m);
        let d = e.evaluate(&package(Some(now - Duration::days(30))), None)?;
        assert_eq!(d.status, DecisionStatus::Allow);
        Ok(())
    }
    #[test]
    fn range_aware_fallback_picks_latest_satisfying() -> Result<()> {
        let now = Utc::now();
        let p = Policy::default();
        let c = FixedClock(now);
        let store = crate::adapters::storage::MemoryMetadataStore::default();
        store.put_frozen(frozen("1.0.0"))?;
        store.put_frozen(frozen("1.5.0"))?;
        let quarantined = package(Some(now - Duration::days(2)));
        let e = evaluator(&p, &c, &store);
        let caret_one = VersionReq::parse("^1.0.0")?;
        let d = e.evaluate(&quarantined, Some(&caret_one))?;
        assert_eq!(d.status, DecisionStatus::Fallback);
        assert_eq!(d.served_version.as_deref(), Some("1.5.0"));
        let caret_two = VersionReq::parse("^2.0.0")?;
        let d = e.evaluate(&quarantined, Some(&caret_two))?;
        assert_eq!(
            d.status,
            DecisionStatus::Block,
            "no frozen version satisfies ^2.0.0: must block, not serve wrong major"
        );
        Ok(())
    }
    struct Reg(Vec<u8>);
    impl UpstreamNpmRegistry for Reg {
        fn metadata(&self, _: &str) -> Result<serde_json::Value> {
            Ok(serde_json::json!({}))
        }
        fn tarball(&self, _: &str) -> Result<Vec<u8>> {
            Ok(self.0.clone())
        }
    }
    struct MemStore;
    impl ArtifactStore for MemStore {
        fn put(&self, _: &str, _: &Version, _: &[u8]) -> Result<String> {
            Ok("p".into())
        }
        fn get(&self, _: &str) -> Result<Vec<u8>> {
            Ok(vec![])
        }
    }
    fn sri_sha512(bytes: &[u8]) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use sha2::Digest;
        format!("sha512-{}", STANDARD.encode(sha2::Sha512::digest(bytes)))
    }
    fn ingest_into(
        policy: &Policy,
        store: &crate::adapters::storage::MemoryMetadataStore,
        bytes: Vec<u8>,
        integrity: String,
    ) -> Result<FrozenArtifact> {
        use crate::adapters::crypto::ShaHasher;
        let pv = PackageVersion {
            package: PackageCoordinate {
                ecosystem: Ecosystem::Npm,
                name: "left-pad".into(),
            },
            version: Version::parse("1.3.0")?,
            published_at: None,
            integrity: Some(integrity),
            tarball_url: Some("http://registry/t.tgz".into()),
        };
        let hasher = ShaHasher;
        IngestService {
            policy,
            registry: &Reg(bytes),
            hasher: &hasher,
            artifacts: &MemStore,
            metadata: store,
            clock: &FixedClock(Utc::now()),
        }
        .freeze_verified(&pv)
    }
    #[test]
    fn republish_same_version_conflicting_bytes_rejected() -> Result<()> {
        let p = Policy::default();
        let store = crate::adapters::storage::MemoryMetadataStore::default();
        let good = b"good bytes".to_vec();
        let first = ingest_into(&p, &store, good.clone(), sri_sha512(&good))?;
        assert_eq!(first.sha256.len(), 64);
        let idempotent = ingest_into(&p, &store, good.clone(), sri_sha512(&good))?;
        assert_eq!(
            idempotent.sha256, first.sha256,
            "same bytes re-freeze is idempotent"
        );
        let evil = b"evil payload".to_vec();
        let republished = ingest_into(&p, &store, evil.clone(), sri_sha512(&evil));
        let err = republished.unwrap_err().to_string();
        assert!(
            err.contains("immutability violation"),
            "expected immutability violation, got: {err}"
        );
        Ok(())
    }
    struct R(Vec<(String, String)>);
    impl WorkflowReader for R {
        fn read(&self, _: &Path) -> Result<Vec<(String, String)>> {
            Ok(self.0.clone())
        }
    }
    #[test]
    fn scans_unpinned_actions() -> Result<()> {
        let s = GitHubActionsScanner {
            policy: &Policy::default(),
            reader: &R(vec![(
                ".github/workflows/ci.yml".into(),
                "steps:\n - uses: actions/checkout@v4".into(),
            )]),
        };
        let r = s.scan(Path::new("."))?;
        assert!(r.is_blocking());
        Ok(())
    }
    #[test]
    fn sha_pinned_action_with_comment_allows() -> Result<()> {
        let body = format!(
            "steps:\n  - uses: a/b@{} # v1.2.3\n  - uses: \"a/c@{}\"",
            "0".repeat(40),
            "1".repeat(40)
        );
        let s = GitHubActionsScanner {
            policy: &Policy::default(),
            reader: &R(vec![(".github/workflows/ci.yml".into(), body)]),
        };
        let r = s.scan(Path::new("."))?;
        assert!(!r.is_blocking());
        assert_eq!(r.references.len(), 2);
        Ok(())
    }
}
