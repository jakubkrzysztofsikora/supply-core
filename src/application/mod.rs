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
                // Frozen bytes are immutable, but vulnerability knowledge changes.
                let findings = self.vulns.query(Ecosystem::Npm, name, &frozen.version)?;
                if let Some(fallback_reason) =
                    blocks_vulnerability(&findings, &self.policy.vulnerabilities)
                {
                    return Ok(Decision::block(
                        name,
                        Some(requested_version.to_string()),
                        format!(
                            "{reason}; frozen fallback {} blocked: {fallback_reason}",
                            frozen.version
                        ),
                    ));
                }
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
    /// Locations in the same order as findings; absent in older serialized reports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finding_locations: Vec<GitHubActionReference>,
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
        let mut finding_locations = vec![];
        for (file, body) in self.reader.read(root)? {
            for (raw, line) in extract_uses(&body)
                .map_err(|error| anyhow::anyhow!("invalid workflow {file}: {error}"))?
            {
                let pin_kind = classify_action_ref(&raw);
                let reference = GitHubActionReference {
                    raw: raw.clone(),
                    file: file.clone(),
                    line,
                    pin_kind: pin_kind.clone(),
                };
                let mut block = None;
                match pin_kind {
                    ActionPinKind::FullSha => {}
                    ActionPinKind::Local if self.policy.github_actions.allow_local_actions => {}
                    ActionPinKind::Local => {
                        block = Some("Local GitHub Actions are disallowed by policy")
                    }
                    ActionPinKind::TagOrBranch
                        if self.policy.github_actions.require_full_sha_pin =>
                    {
                        block =
                            Some("GitHub Action is not pinned to a full 40-character commit SHA")
                    }
                    ActionPinKind::Docker => {
                        block = Some(
                            "Docker actions are not immutable unless image digests are enforced",
                        )
                    }
                    ActionPinKind::Unknown => {
                        block = Some("GitHub Action reference could not be classified")
                    }
                    _ => {}
                }
                if let Some(reason) = block {
                    finding_locations.push(reference.clone());
                    findings.push(Decision::block(
                        raw.clone(),
                        None,
                        if line == 0 {
                            format!("{reason} at {file}")
                        } else {
                            format!("{reason} at {file}:{line}")
                        },
                    ));
                }
                refs.push(reference);
            }
        }
        Ok(WorkflowScanReport {
            findings,
            references: refs,
            finding_locations,
        })
    }
}
/// Extract all parsed YAML `uses` occurrences, including repeated values.
/// Line 0 means unknown: serde_norway's value tree does not retain source spans.
/// Raw text matching cannot safely locate folded scalars, aliases, or repeated
/// values inside comments and run blocks, so it never gates security findings.
pub fn extract_uses(body: &str) -> Result<Vec<(String, usize)>> {
    let root = serde_norway::from_str::<serde_norway::Value>(body)?;
    let mut out = Vec::new();
    walk_value(&root, &mut out);
    Ok(out.into_iter().map(|value| (value, 0)).collect())
}
fn walk_value(v: &serde_norway::Value, out: &mut Vec<String>) {
    use serde_norway::Value;
    match v {
        Value::Mapping(map) => {
            for (k, val) in map.iter() {
                let key_is_uses = matches!(k, Value::String(s) if s == "uses");
                if key_is_uses {
                    if let Value::String(s) = val {
                        out.push(s.clone());
                    }
                    continue;
                }
                walk_value(val, out);
            }
        }
        Value::Sequence(seq) => {
            for item in seq.iter() {
                walk_value(item, out);
            }
        }
        Value::Tagged(t) => walk_value(&t.value, out),
        _ => {}
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineScanReport {
    pub findings: Vec<Decision>,
    pub references: Vec<PipelineReference>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finding_locations: Vec<PipelineReference>,
}
impl PipelineScanReport {
    pub fn is_blocking(&self) -> bool {
        self.findings
            .iter()
            .any(|d| matches!(d.status, DecisionStatus::Block))
    }
}

pub struct AzurePipelinesScanner<'a> {
    pub policy: &'a Policy,
    pub reader: &'a dyn WorkflowReader,
}
impl<'a> AzurePipelinesScanner<'a> {
    pub fn scan(&self, root: &Path) -> Result<PipelineScanReport> {
        let mut refs = vec![];
        let mut findings = vec![];
        let mut finding_locations = vec![];
        for (file, body) in self.reader.read(root)? {
            for (raw, kind, line) in extract_pipeline_references(&body)
                .map_err(|error| anyhow::anyhow!("invalid pipeline {file}: {error}"))?
            {
                let pin_kind = classify_pipeline_ref(&raw, &kind);
                let reference = PipelineReference {
                    raw: raw.clone(),
                    file: file.clone(),
                    line,
                    kind: kind.clone(),
                    pin_kind: pin_kind.clone(),
                };
                let mut block = None;
                match kind {
                    PipelineRefKind::Task => {
                        let is_allowed = self
                            .policy
                            .azure_pipelines
                            .allowed_unpinned_tasks
                            .iter()
                            .any(|p| p == &raw);
                        if !is_allowed {
                            match pin_kind {
                                ActionPinKind::TaskVersion | ActionPinKind::FullSha => {}
                                ActionPinKind::Unknown
                                    if self.policy.azure_pipelines.require_task_version =>
                                {
                                    block = Some(
                                        "Azure DevOps task is missing a version specifier (e.g. @1, @2)",
                                    );
                                }
                                _ => {}
                            }
                        }
                    }
                    PipelineRefKind::Checkout => {
                        let is_allowed = self
                            .policy
                            .azure_pipelines
                            .allowed_unpinned_checkouts
                            .iter()
                            .any(|p| p == &raw);
                        if !is_allowed {
                            match pin_kind {
                                ActionPinKind::Local => {}
                                ActionPinKind::FullSha => {}
                                ActionPinKind::TagOrBranch | ActionPinKind::Unknown
                                    if self.policy.azure_pipelines.require_full_sha_pin =>
                                {
                                    block = Some(
                                        "External repository checkout is not pinned to a full 40-character commit SHA",
                                    );
                                }
                                _ => {}
                            }
                        }
                    }
                    PipelineRefKind::Template => match pin_kind {
                        ActionPinKind::Local
                            if self.policy.azure_pipelines.allow_local_templates => {}
                        ActionPinKind::Local => {
                            block = Some("Local pipeline templates are disallowed by policy");
                        }
                        ActionPinKind::FullSha => {}
                        ActionPinKind::TagOrBranch | ActionPinKind::Unknown
                            if self.policy.azure_pipelines.require_full_sha_pin =>
                        {
                            block = Some(
                                "External pipeline template repository is not pinned to a full 40-character commit SHA",
                            );
                        }
                        _ => {}
                    },
                    PipelineRefKind::Repository => {
                        let is_allowed = self
                            .policy
                            .azure_pipelines
                            .allowed_unpinned_repositories
                            .iter()
                            .any(|p| p == &raw);
                        if !is_allowed {
                            match pin_kind {
                                ActionPinKind::FullSha => {}
                                ActionPinKind::TagOrBranch | ActionPinKind::Unknown
                                    if self.policy.azure_pipelines.require_full_sha_pin =>
                                {
                                    block = Some(
                                        "Repository resource is not pinned to a full 40-character commit SHA",
                                    );
                                }
                                _ => {}
                            }
                        }
                    }
                    PipelineRefKind::Action => match pin_kind {
                        ActionPinKind::FullSha => {}
                        ActionPinKind::Local
                            if self.policy.github_actions.allow_local_actions => {}
                        ActionPinKind::Local => {
                            block = Some("Local GitHub Actions are disallowed by policy");
                        }
                        ActionPinKind::TagOrBranch
                            if self.policy.github_actions.require_full_sha_pin =>
                        {
                            block = Some(
                                "GitHub Action is not pinned to a full 40-character commit SHA",
                            );
                        }
                        ActionPinKind::Docker => {
                            block = Some(
                                "Docker actions are not immutable unless image digests are enforced",
                            );
                        }
                        ActionPinKind::Unknown => {
                            block = Some("GitHub Action reference could not be classified");
                        }
                        _ => {}
                    },
                }
                if let Some(reason) = block {
                    finding_locations.push(reference.clone());
                    findings.push(Decision::block(
                        raw.clone(),
                        None,
                        if line == 0 {
                            format!("{reason} at {file}")
                        } else {
                            format!("{reason} at {file}:{line}")
                        },
                    ));
                }
                refs.push(reference);
            }
        }
        Ok(PipelineScanReport {
            findings,
            references: refs,
            finding_locations,
        })
    }
}

pub fn extract_pipeline_references(body: &str) -> Result<Vec<(String, PipelineRefKind, usize)>> {
    let root = serde_norway::from_str::<serde_norway::Value>(body)?;
    let mut out = Vec::new();
    walk_pipeline_value(&root, &mut out);
    let mut located = Vec::new();
    for (raw, kind) in out {
        let line = find_pipeline_ref_line(body, &raw, &kind);
        located.push((raw, kind, line));
    }
    Ok(located)
}

fn walk_pipeline_value(v: &serde_norway::Value, out: &mut Vec<(String, PipelineRefKind)>) {
    use serde_norway::Value;
    match v {
        Value::Mapping(map) => {
            for (k, val) in map.iter() {
                if let Value::String(key_str) = k {
                    match key_str.as_str() {
                        "task" => {
                            if let Value::String(s) = val {
                                out.push((s.clone(), PipelineRefKind::Task));
                            }
                            continue;
                        }
                        "checkout" => {
                            if let Value::String(s) = val {
                                out.push((s.clone(), PipelineRefKind::Checkout));
                            }
                            continue;
                        }
                        "template" => {
                            if let Value::String(s) = val {
                                out.push((s.clone(), PipelineRefKind::Template));
                            }
                            continue;
                        }
                        "uses" => {
                            if let Value::String(s) = val {
                                out.push((s.clone(), PipelineRefKind::Action));
                            }
                            continue;
                        }
                        "repositories" => {
                            if let Value::Sequence(seq) = val {
                                for item in seq {
                                    if let Value::Mapping(repo_map) = item {
                                        let repo_val = repo_map.get("repository").and_then(|v| {
                                            if let Value::String(s) = v {
                                                Some(s.clone())
                                            } else {
                                                None
                                            }
                                        });
                                        let ref_val = repo_map.get("ref").and_then(|v| {
                                            if let Value::String(s) = v {
                                                Some(s.clone())
                                            } else {
                                                None
                                            }
                                        });
                                        if let Some(name) = repo_val {
                                            if let Some(r) = ref_val {
                                                out.push((
                                                    format!("{name}@{r}"),
                                                    PipelineRefKind::Repository,
                                                ));
                                            } else {
                                                out.push((name, PipelineRefKind::Repository));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                walk_pipeline_value(val, out);
            }
        }
        Value::Sequence(seq) => {
            for item in seq.iter() {
                walk_pipeline_value(item, out);
            }
        }
        Value::Tagged(t) => walk_pipeline_value(&t.value, out),
        _ => {}
    }
}

fn find_pipeline_ref_line(body: &str, raw: &str, kind: &PipelineRefKind) -> usize {
    let keyword = match kind {
        PipelineRefKind::Task => "task:",
        PipelineRefKind::Checkout => "checkout:",
        PipelineRefKind::Template => "template:",
        PipelineRefKind::Repository => "repository:",
        PipelineRefKind::Action => "uses:",
    };
    let target = if let PipelineRefKind::Repository = kind {
        if let Some((repo, _)) = raw.split_once('@') {
            repo
        } else {
            raw
        }
    } else {
        raw
    };
    for (idx, line) in body.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if trimmed.contains(keyword) && trimmed.contains(target) {
            return idx + 1;
        }
    }
    0
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
    fn frozen_fallback_is_rechecked_for_vulnerabilities() -> Result<()> {
        struct Source {
            fail: bool,
            queried: Mutex<Vec<Version>>,
        }
        impl VulnerabilitySource for Source {
            fn query(
                &self,
                _: Ecosystem,
                _: &str,
                version: &Version,
            ) -> Result<Vec<VulnerabilityFinding>> {
                self.queried.lock().unwrap().push(version.clone());
                if version.major != 1 {
                    return Ok(vec![]);
                }
                if self.fail {
                    anyhow::bail!("OSV unavailable for fallback");
                }
                Ok(vec![VulnerabilityFinding {
                    source: "OSV".into(),
                    id: "TEST-FROZEN".into(),
                    severity: Severity::High,
                    summary: "new advisory".into(),
                }])
            }
        }
        let now = Utc::now();
        let policy = Policy::default();
        let clock = FixedClock(now);
        let metadata = M(Mutex::new(Some(frozen("1.0.0"))));
        for fail in [false, true] {
            let source = Source {
                fail,
                queried: Mutex::new(vec![]),
            };
            let evaluator = PackageEvaluator {
                policy: &policy,
                clock: &clock,
                vulns: &source,
                metadata: &metadata,
            };
            let result = evaluator.evaluate(&package(Some(now)), None);
            if fail {
                assert!(result.is_err(), "fallback query errors must fail closed");
            } else {
                let decision = result?;
                assert_eq!(decision.status, DecisionStatus::Block);
                assert!(decision.reasons[0].contains("TEST-FROZEN"));
            }
            assert_eq!(
                *source.queried.lock().unwrap(),
                vec![Version::new(2, 0, 0), Version::new(1, 0, 0)]
            );
        }
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
        fn resolve(&self, _: &str, _: &Version) -> Result<Option<String>> {
            Ok(Some("p".into()))
        }
        fn read(&self, _: &str) -> Result<Vec<u8>> {
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

    // ----- adversarial parser tests (see docs/adversarial-review.md) -----

    fn scan_str(body: &str) -> WorkflowScanReport {
        GitHubActionsScanner {
            policy: &Policy::default(),
            reader: &R(vec![(".github/workflows/ci.yml".into(), body.into())]),
        }
        .scan(Path::new("."))
        .unwrap()
    }

    #[test]
    fn flow_mapping_uses_is_detected() {
        let body = "steps:\n  - { uses: actions/checkout@v4 }\n";
        let r = scan_str(body);
        assert!(r.is_blocking());
        assert_eq!(r.references.len(), 1);
        assert_eq!(r.references[0].raw, "actions/checkout@v4");
    }

    #[test]
    fn quoted_uses_with_trailing_comment_is_detected() {
        let body = "steps:\n  - uses: \"actions/checkout@main\" # pinned\n";
        let r = scan_str(body);
        assert!(r.is_blocking());
        assert_eq!(r.references.len(), 1);
        assert_eq!(r.references[0].raw, "actions/checkout@main");
    }

    #[test]
    fn space_before_colon_uses_is_detected() {
        let body = "steps:\n  - uses : actions/checkout@v4\n";
        let r = scan_str(body);
        assert!(r.is_blocking());
        assert_eq!(r.references.len(), 1);
    }

    #[test]
    fn run_block_with_literal_uses_text_is_ignored() {
        let body = "steps:\n  - run: |\n      echo \"uses: actions/checkout@v4\"\n";
        let r = scan_str(body);
        assert!(!r.is_blocking());
        assert_eq!(r.references.len(), 0);
    }

    #[test]
    fn mixed_block_and_flow_and_quoted_in_one_file() {
        let sha = "0".repeat(40);
        let body = format!(
            "steps:\n  - uses: actions/checkout@v4\n  - {{ uses: actions/setup-node@v4 }}\n  - uses: \"actions/setup-python@{}\" # pinned\n",
            sha
        );
        let r = scan_str(&body);
        assert_eq!(r.references.len(), 3);
        assert!(r.is_blocking());
    }

    #[test]
    fn malformed_yaml_returns_error() {
        let body = "steps:\n  - uses: actions/checkout@v4\n  oops: [unclosed\n";
        let error = GitHubActionsScanner {
            policy: &Policy::default(),
            reader: &R(vec![(".github/workflows/ci.yml".into(), body.into())]),
        }
        .scan(Path::new("."))
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("invalid workflow .github/workflows/ci.yml"));
    }

    #[test]
    fn quoted_key_and_flow_extra_key_are_detected() {
        for body in [
            "steps:\n  - 'uses': actions/checkout@v4\n",
            "steps:\n  - { uses: actions/checkout@v4, name: checkout }\n",
        ] {
            let report = scan_str(body);
            assert!(report.is_blocking());
            assert_eq!(report.references.len(), 1);
            assert_eq!(report.references[0].raw, "actions/checkout@v4");
        }
    }

    #[test]
    fn folded_and_escaped_scalars_are_detected() {
        for body in [
            "steps:\n  - uses: >-\n      actions/checkout@v4\n",
            "steps:\n  - uses: \"actions/checkout@\\u00764\"\n",
        ] {
            let report = scan_str(body);
            assert!(report.is_blocking());
            assert_eq!(report.references[0].raw, "actions/checkout@v4");
            assert_eq!(report.references[0].line, 0);
        }
    }

    #[test]
    fn repeated_references_are_preserved_without_matching_run_text() {
        let report = scan_str("steps:\n  - run: |\n      uses: actions/checkout@v4\n  - uses: actions/checkout@v4\n  - uses: actions/checkout@v4\n");
        assert_eq!(report.references.len(), 2);
        assert_eq!(report.findings.len(), 2);
        assert!(report
            .finding_locations
            .iter()
            .all(|reference| reference.line == 0));
    }

    #[test]
    fn local_actions_policy_is_enforced() -> Result<()> {
        let mut policy = Policy::default();
        let reader = R(vec![(
            "ci.yml".into(),
            "steps:\n  - uses: ./local-action\n".into(),
        )]);
        policy.github_actions.allow_local_actions = true;
        assert!(!GitHubActionsScanner {
            policy: &policy,
            reader: &reader
        }
        .scan(Path::new("."))?
        .is_blocking());
        policy.github_actions.allow_local_actions = false;
        let report = GitHubActionsScanner {
            policy: &policy,
            reader: &reader,
        }
        .scan(Path::new("."))?;
        assert!(report.is_blocking());
        assert!(report.findings[0].reasons[0].contains("Local GitHub Actions are disallowed"));
        Ok(())
    }

    #[test]
    fn azure_scanner_passes_versioned_tasks_and_local_templates() -> Result<()> {
        let policy = Policy::default();
        let body = r#"
steps:
  - checkout: self
  - checkout: none
  - task: UseNode@1
  - task: AzureCLI@2
  - template: ../templates/build.yml
"#;
        let reader = R(vec![("pipelines/pr.yml".into(), body.into())]);
        let scanner = AzurePipelinesScanner {
            policy: &policy,
            reader: &reader,
        };
        let report = scanner.scan(Path::new("."))?;
        assert!(!report.is_blocking());
        assert_eq!(report.references.len(), 5);
        Ok(())
    }

    #[test]
    fn azure_scanner_blocks_unversioned_tasks() -> Result<()> {
        let policy = Policy::default();
        let body = "steps:\n  - task: AzureCLI\n";
        let reader = R(vec![("pipelines/pr.yml".into(), body.into())]);
        let report = AzurePipelinesScanner {
            policy: &policy,
            reader: &reader,
        }
        .scan(Path::new("."))?;
        assert!(report.is_blocking());
        assert!(report.findings[0].reasons[0].contains("missing a version specifier"));
        Ok(())
    }

    #[test]
    fn azure_scanner_blocks_unpinned_external_checkouts() -> Result<()> {
        let policy = Policy::default();
        let body = "steps:\n  - checkout: git://Circit/release-notes-generator\n";
        let reader = R(vec![("pipelines/core-main.yml".into(), body.into())]);
        let report = AzurePipelinesScanner {
            policy: &policy,
            reader: &reader,
        }
        .scan(Path::new("."))?;
        assert!(report.is_blocking());
        assert!(report.findings[0].reasons[0].contains("External repository checkout is not pinned"));
        assert_eq!(report.references[0].line, 2);
        Ok(())
    }

    #[test]
    fn azure_scanner_allows_pinned_external_checkouts() -> Result<()> {
        let policy = Policy::default();
        let sha = "0".repeat(40);
        let body = format!("steps:\n  - checkout: git://Circit/release-notes-generator@{}\n", sha);
        let reader = R(vec![("pipelines/core-main.yml".into(), body)]);
        let report = AzurePipelinesScanner {
            policy: &policy,
            reader: &reader,
        }
        .scan(Path::new("."))?;
        assert!(!report.is_blocking());
        Ok(())
    }

    #[test]
    fn azure_scanner_respects_allowed_unpinned_checkouts() -> Result<()> {
        let mut policy = Policy::default();
        policy
            .azure_pipelines
            .allowed_unpinned_checkouts
            .push("git://Circit/release-notes-generator".into());
        let body = "steps:\n  - checkout: git://Circit/release-notes-generator\n";
        let reader = R(vec![("pipelines/core-main.yml".into(), body.into())]);
        let report = AzurePipelinesScanner {
            policy: &policy,
            reader: &reader,
        }
        .scan(Path::new("."))?;
        assert!(!report.is_blocking());
        Ok(())
    }

    #[test]
    fn azure_scanner_blocks_unpinned_repositories_and_templates() -> Result<()> {
        let policy = Policy::default();
        let body = r#"
resources:
  repositories:
    - repository: common
      type: git
      name: Circit/common
      ref: refs/heads/main
steps:
  - template: build.yml@common
"#;
        let reader = R(vec![("pipelines/ci.yml".into(), body.into())]);
        let report = AzurePipelinesScanner {
            policy: &policy,
            reader: &reader,
        }
        .scan(Path::new("."))?;
        assert!(report.is_blocking());
        assert_eq!(report.findings.len(), 2);
        Ok(())
    }
}
