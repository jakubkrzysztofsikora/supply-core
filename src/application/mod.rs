use crate::domain::*;
use crate::ports::*;
use anyhow::Result;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub mod scanner;

pub struct PackageEvaluator<'a> {
    pub policy: &'a Policy,
    pub clock: &'a dyn Clock,
    pub vulns: &'a dyn VulnerabilitySource,
    pub metadata: &'a dyn MetadataStore,
}
struct EcosystemPolicy<'p> {
    require_integrity: bool,
    fallback_to_frozen: bool,
    deny: &'p [String],
}
impl<'a> PackageEvaluator<'a> {
    fn ecosystem_policy(&self, ecosystem: &Ecosystem) -> EcosystemPolicy<'_> {
        match ecosystem {
            Ecosystem::Npm => EcosystemPolicy {
                require_integrity: self.policy.npm.require_integrity,
                fallback_to_frozen: self.policy.npm.fallback_to_frozen,
                deny: &self.policy.npm.deny_packages,
            },
            Ecosystem::PyPi => EcosystemPolicy {
                require_integrity: self.policy.pip.require_integrity,
                fallback_to_frozen: self.policy.pip.fallback_to_frozen,
                deny: &[],
            },
            Ecosystem::NuGet => EcosystemPolicy {
                require_integrity: self.policy.nuget.require_integrity,
                fallback_to_frozen: self.policy.nuget.fallback_to_frozen,
                deny: &[],
            },
            _ => EcosystemPolicy {
                require_integrity: true,
                fallback_to_frozen: true,
                deny: &[],
            },
        }
    }
    /// `requested` is the client's semver range (e.g. `^1.2.0`). Fallback
    /// serves the latest frozen version satisfying it; `None` allows any.
    pub fn evaluate(
        &self,
        version: &PackageVersion,
        requested: Option<&VersionReq>,
    ) -> Result<Decision> {
        let name = &version.package.name;
        let ecosystem = version.package.ecosystem.clone();
        let ecosystem_policy = self.ecosystem_policy(&ecosystem);
        if ecosystem_policy.deny.contains(name) {
            return Ok(Decision::block(
                name,
                Some(version.version.to_string()),
                "package is denylisted",
            ));
        }
        if ecosystem_policy.require_integrity && version.integrity.is_none() {
            return self.fallback_or_block(
                &ecosystem,
                name,
                &version.version,
                requested,
                "package version is missing integrity",
            );
        }
        let mut review_warning = None;
        if self.policy.quarantine_scanner.enabled {
            if let Some(finding) =
                self.metadata
                    .content_finding(&ecosystem, name, &version.version)?
            {
                if finding.score >= self.policy.quarantine_scanner.block_score {
                    return self.fallback_or_block(
                        &ecosystem,
                        name,
                        &version.version,
                        requested,
                        format!(
                            "content scan: {} [{}]",
                            finding.summary,
                            finding.rules.join(", ")
                        ),
                    );
                }
                if finding.score >= self.policy.quarantine_scanner.review_score {
                    review_warning = Some(format!(
                        "content scan review (score {}): {} [{}]",
                        finding.score,
                        finding.summary,
                        finding.rules.join(", ")
                    ));
                }
            }
        }
        let findings = self
            .vulns
            .query(ecosystem.clone(), name, &version.version)?;
        if let Some(reason) = self.vulnerability_reason(&findings) {
            return self.fallback_or_block(&ecosystem, name, &version.version, requested, reason);
        }
        if is_version_quarantined(
            version.published_at,
            self.clock.now(),
            &self.policy.quarantine,
        ) {
            return self.fallback_or_block(
                &ecosystem,
                name,
                &version.version,
                requested,
                "package version is inside quarantine window",
            );
        }
        let mut decision = Decision::allow(name.clone(), version.version.to_string());
        if let Some(warning) = review_warning {
            decision.warnings.push(warning);
        }
        Ok(decision)
    }
    fn vulnerability_reason(&self, findings: &[VulnerabilityFinding]) -> Option<String> {
        if self.policy.quarantine.cve_keeps_quarantined {
            strongest_vulnerability(findings)
        } else {
            blocks_vulnerability(findings, &self.policy.vulnerabilities)
        }
    }
    fn fallback_or_block(
        &self,
        ecosystem: &Ecosystem,
        name: &str,
        requested_version: &Version,
        requested: Option<&VersionReq>,
        reason: impl Into<String>,
    ) -> Result<Decision> {
        let reason = reason.into();
        let ecosystem_policy = self.ecosystem_policy(ecosystem);
        if ecosystem_policy.fallback_to_frozen {
            if let Some(frozen) = self
                .metadata
                .latest_frozen_satisfying(ecosystem, name, requested)?
            {
                // Frozen bytes are immutable, but vulnerability knowledge changes.
                let findings = self.vulns.query(ecosystem.clone(), name, &frozen.version)?;
                if let Some(fallback_reason) = self.vulnerability_reason(&findings) {
                    return Ok(Decision::block(
                        name,
                        Some(requested_version.to_string()),
                        format!(
                            "{reason}; frozen fallback {} blocked: {fallback_reason}",
                            frozen.version
                        ),
                    ));
                }
                if self.policy.quarantine_scanner.enabled {
                    if let Some(finding) =
                        self.metadata
                            .content_finding(ecosystem, name, &frozen.version)?
                    {
                        if finding.score >= self.policy.quarantine_scanner.block_score {
                            return Ok(Decision::block(
                                name,
                                Some(requested_version.to_string()),
                                format!(
                                    "{reason}; frozen fallback {} blocked: content scan {}",
                                    frozen.version, finding.summary
                                ),
                            ));
                        }
                    }
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
        if let Some(existing) =
            self.metadata
                .get_frozen(&version.package.ecosystem, name, &version.version)?
        {
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

pub fn extract_dockerfile_from(content: &str) -> Vec<(String, usize)> {
    let mut references = Vec::new();
    for (index, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        let Some(prefix) = line.get(..4) else {
            continue;
        };
        if !prefix.eq_ignore_ascii_case("FROM") {
            continue;
        }
        if line
            .as_bytes()
            .get(4)
            .is_some_and(|byte| !byte.is_ascii_whitespace())
        {
            continue;
        }
        let image = line
            .get(4..)
            .unwrap_or("")
            .split_whitespace()
            .find(|token| !token.starts_with('-') && !token.is_empty());
        if let Some(image) = image {
            references.push((image.to_string(), index + 1));
        }
    }
    references
}

pub fn extract_compose_images(content: &str) -> Vec<(String, usize)> {
    let mut references = Vec::new();
    for (index, raw_line) in content.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        let Some(value) = line.strip_prefix("image:") else {
            continue;
        };
        let value = value.trim().trim_matches(['"', '\'']);
        if !value.is_empty() {
            references.push((value.to_string(), index + 1));
        }
    }
    references
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DockerImageReference {
    pub raw: String,
    pub file: String,
    pub line: usize,
    pub pin_kind: ImagePinKind,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DockerScanReport {
    pub references: Vec<DockerImageReference>,
    pub findings: Vec<Decision>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finding_locations: Vec<DockerImageReference>,
}
impl DockerScanReport {
    pub fn is_blocking(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| matches!(finding.status, DecisionStatus::Block))
    }
}

pub struct DockerScanner<'a> {
    pub policy: &'a Policy,
}
impl<'a> DockerScanner<'a> {
    pub fn scan(&self, root: &Path) -> Result<DockerScanReport> {
        const SKIP: &[&str] = &[
            "node_modules",
            "target",
            ".git",
            "vendor",
            "dist",
            "build",
            ".venv",
            "venv",
            "__pycache__",
            ".next",
            ".cache",
            ".worktrees",
            "worktrees",
            ".claude",
        ];
        let mut references = Vec::new();
        let mut findings = Vec::new();
        let mut finding_locations = Vec::new();
        let walker = walkdir::WalkDir::new(root)
            .max_depth(8)
            .into_iter()
            .filter_entry(|entry| {
                !(entry.file_type().is_dir()
                    && SKIP.contains(&entry.file_name().to_string_lossy().as_ref()))
            });
        for entry in walker.filter_map(|entry| entry.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let lower = name.to_ascii_lowercase();
            let is_dockerfile = name.starts_with("Dockerfile") || lower.ends_with(".dockerfile");
            let is_compose = (lower.starts_with("docker-compose")
                || lower == "compose.yml"
                || lower == "compose.yaml")
                && (lower.ends_with(".yml") || lower.ends_with(".yaml"));
            if !is_dockerfile && !is_compose {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            let extracted = if is_dockerfile {
                extract_dockerfile_from(&content)
            } else {
                extract_compose_images(&content)
            };
            let file = entry
                .path()
                .strip_prefix(root)
                .unwrap_or(entry.path())
                .display()
                .to_string();
            for (raw, line) in extracted {
                if raw == "scratch" {
                    continue;
                }
                let pin_kind = classify_image_ref(&raw);
                if self.policy.docker.require_digest_pin {
                    let block = match pin_kind {
                        ImagePinKind::Digest => None,
                        ImagePinKind::InvalidDigest => {
                            Some("container image digest is not a valid sha256 digest")
                        }
                        ImagePinKind::Unresolved => {
                            Some("container image reference is not statically resolvable")
                        }
                        _ => Some("container image is not pinned to a sha256 digest"),
                    };
                    if let Some(reason) = block {
                        let reference = DockerImageReference {
                            raw: raw.clone(),
                            file: file.clone(),
                            line,
                            pin_kind: pin_kind.clone(),
                        };
                        finding_locations.push(reference);
                        findings.push(Decision::block(
                            raw.clone(),
                            None,
                            format!("{reason} at {file}:{line}"),
                        ));
                    }
                }
                references.push(DockerImageReference {
                    raw,
                    file: file.clone(),
                    line,
                    pin_kind,
                });
            }
        }
        Ok(DockerScanReport {
            references,
            findings,
            finding_locations,
        })
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
                        ActionPinKind::Local if self.policy.github_actions.allow_local_actions => {}
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
            ecosystem: &Ecosystem,
            _: &str,
            requested: Option<&VersionReq>,
        ) -> Result<Option<FrozenArtifact>> {
            let frozen = self
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("lock poisoned"))?
                .clone();
            Ok(frozen.filter(|a| {
                a.package.ecosystem == *ecosystem && requested.is_none_or(|r| r.matches(&a.version))
            }))
        }
        fn get_frozen(
            &self,
            ecosystem: &Ecosystem,
            _: &str,
            version: &Version,
        ) -> Result<Option<FrozenArtifact>> {
            let frozen = self
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("lock poisoned"))?
                .clone();
            Ok(frozen.filter(|a| a.package.ecosystem == *ecosystem && a.version == *version))
        }
        fn save_content_finding(&self, _: &ContentFinding) -> Result<()> {
            Ok(())
        }
        fn content_finding(
            &self,
            _: &Ecosystem,
            _: &str,
            _: &Version,
        ) -> Result<Option<ContentFinding>> {
            Ok(None)
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
    struct VersionedVulns;
    impl VulnerabilitySource for VersionedVulns {
        fn query(
            &self,
            _: Ecosystem,
            _: &str,
            version: &Version,
        ) -> Result<Vec<VulnerabilityFinding>> {
            if version.major == 2 {
                Ok(vec![VulnerabilityFinding {
                    source: "OSV".into(),
                    id: "GHSA-medium".into(),
                    severity: Severity::Medium,
                    summary: "medium advisory".into(),
                }])
            } else {
                Ok(vec![])
            }
        }
    }
    struct MediumVulns;
    impl VulnerabilitySource for MediumVulns {
        fn query(&self, _: Ecosystem, _: &str, _: &Version) -> Result<Vec<VulnerabilityFinding>> {
            Ok(vec![VulnerabilityFinding {
                source: "OSV".into(),
                id: "GHSA-medium".into(),
                severity: Severity::Medium,
                summary: "medium advisory".into(),
            }])
        }
    }
    #[test]
    fn cve_is_never_released_after_quarantine_window() -> Result<()> {
        let now = Utc::now();
        let p = Policy::default();
        let c = FixedClock(now);
        let m = M(Mutex::new(None));
        let e = PackageEvaluator {
            policy: &p,
            clock: &c,
            vulns: &MediumVulns,
            metadata: &m,
        };
        let d = e.evaluate(&package(Some(now - Duration::days(30))), None)?;
        assert_eq!(
            d.status,
            DecisionStatus::Block,
            "a version with a known CVE must never age out of quarantine"
        );
        assert!(d.reasons[0].contains("GHSA-medium"));
        Ok(())
    }
    #[test]
    fn cve_version_falls_back_to_clean_frozen() -> Result<()> {
        let now = Utc::now();
        let p = Policy::default();
        let c = FixedClock(now);
        let m = M(Mutex::new(Some(frozen("1.0.0"))));
        let e = PackageEvaluator {
            policy: &p,
            clock: &c,
            vulns: &VersionedVulns,
            metadata: &m,
        };
        let d = e.evaluate(&package(Some(now - Duration::days(30))), None)?;
        assert_eq!(d.status, DecisionStatus::Fallback);
        assert_eq!(d.served_version.as_deref(), Some("1.0.0"));
        Ok(())
    }
    #[test]
    fn frozen_fallback_with_medium_cve_is_rejected() -> Result<()> {
        let now = Utc::now();
        let p = Policy::default();
        let c = FixedClock(now);
        let m = M(Mutex::new(Some(frozen("1.0.0"))));
        let e = PackageEvaluator {
            policy: &p,
            clock: &c,
            vulns: &MediumVulns,
            metadata: &m,
        };
        let d = e.evaluate(&package(Some(now - Duration::days(30))), None)?;
        assert_eq!(d.status, DecisionStatus::Block);
        assert!(d.reasons[0].contains("GHSA-medium"));
        Ok(())
    }
    #[test]
    fn docker_scan_skips_worktree_copies() -> Result<()> {
        let dir = tempfile::tempdir()?;
        std::fs::create_dir_all(dir.path().join(".worktrees/old"))?;
        std::fs::write(
            dir.path().join(".worktrees/old/Dockerfile"),
            "FROM alpine:3.20\n",
        )?;
        std::fs::write(dir.path().join("Dockerfile"), "FROM debian:12\n")?;
        let p = Policy::default();
        let report = DockerScanner { policy: &p }.scan(dir.path())?;
        assert_eq!(report.references.len(), 1);
        assert!(!report.references[0].file.contains(".worktrees"));
        Ok(())
    }
    #[test]
    fn dockerfile_extraction_handles_unicode_lines() {
        let refs = extract_dockerfile_from("— em dash\n# — pinned base\nFROM alpine:3.20\n");
        assert_eq!(refs, vec![("alpine:3.20".to_string(), 3)]);
    }
    #[test]
    fn dockerfile_references_are_classified_and_blocked() -> Result<()> {
        let dir = tempfile::tempdir()?;
        std::fs::write(
            dir.path().join("Dockerfile"),
            "FROM alpine:3.20\nFROM ghcr.io/org/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nFROM ubuntu\nFROM scratch\nCOPY x /x\n",
        )?;
        let p = Policy::default();
        let report = DockerScanner { policy: &p }.scan(dir.path())?;
        assert_eq!(report.references.len(), 3);
        assert_eq!(report.findings.len(), 2);
        assert!(report
            .findings
            .iter()
            .all(|finding| finding.reasons.join(" ").contains("digest")));
        Ok(())
    }
    #[test]
    fn compose_images_are_scanned() -> Result<()> {
        let dir = tempfile::tempdir()?;
        std::fs::write(
            dir.path().join("docker-compose.yml"),
            "services:\n  web:\n    image: nginx:1.27\n  db:\n    image: redis@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n  queue:\n    image: ${BASE_IMAGE}:latest\n",
        )?;
        let p = Policy::default();
        let report = DockerScanner { policy: &p }.scan(dir.path())?;
        assert_eq!(report.references.len(), 3);
        assert_eq!(report.findings.len(), 2);
        Ok(())
    }
    #[test]
    fn docker_policy_can_be_disabled() -> Result<()> {
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join("Dockerfile"), "FROM alpine:3.20\n")?;
        let mut p = Policy::default();
        p.docker.require_digest_pin = false;
        let report = DockerScanner { policy: &p }.scan(dir.path())?;
        assert_eq!(report.references.len(), 1);
        assert!(report.findings.is_empty());
        Ok(())
    }
    #[test]
    fn pip_integrity_policy_is_ecosystem_scoped() -> Result<()> {
        let now = Utc::now();
        let mut p = Policy::default();
        p.pip.require_integrity = false;
        let c = FixedClock(now);
        let m = M(Mutex::new(None));
        let e = PackageEvaluator {
            policy: &p,
            clock: &c,
            vulns: &NoVulns,
            metadata: &m,
        };
        let pv = PackageVersion {
            package: PackageCoordinate {
                ecosystem: Ecosystem::PyPi,
                name: "requests".into(),
            },
            version: Version::parse("2.32.3").unwrap(),
            published_at: Some(now - Duration::days(30)),
            integrity: None,
            tarball_url: None,
        };
        let d = e.evaluate(&pv, None)?;
        assert_eq!(
            d.status,
            DecisionStatus::Allow,
            "pip policy, not npm policy, must decide pip integrity"
        );
        Ok(())
    }
    struct OnlyPyPiVulns;
    impl VulnerabilitySource for OnlyPyPiVulns {
        fn query(
            &self,
            ecosystem: Ecosystem,
            _: &str,
            _: &Version,
        ) -> Result<Vec<VulnerabilityFinding>> {
            if ecosystem == Ecosystem::PyPi {
                Ok(vec![VulnerabilityFinding {
                    source: "OSV".into(),
                    id: "GHSA-pip".into(),
                    severity: Severity::Medium,
                    summary: "pip advisory".into(),
                }])
            } else {
                Ok(vec![])
            }
        }
    }
    #[test]
    fn vulnerability_query_uses_package_ecosystem() -> Result<()> {
        let now = Utc::now();
        let p = Policy::default();
        let c = FixedClock(now);
        let m = M(Mutex::new(None));
        let e = PackageEvaluator {
            policy: &p,
            clock: &c,
            vulns: &OnlyPyPiVulns,
            metadata: &m,
        };
        let pv = PackageVersion {
            package: PackageCoordinate {
                ecosystem: Ecosystem::PyPi,
                name: "requests".into(),
            },
            version: Version::parse("2.32.3").unwrap(),
            published_at: Some(now - Duration::days(30)),
            integrity: Some("sha256-abc".into()),
            tarball_url: None,
        };
        let d = e.evaluate(&pv, None)?;
        assert_eq!(d.status, DecisionStatus::Block);
        assert!(d.reasons[0].contains("GHSA-pip"));
        Ok(())
    }
    fn finding(score: u8) -> ContentFinding {
        ContentFinding {
            ecosystem: Ecosystem::Npm,
            package: "left-pad".into(),
            version: Version::parse("2.0.0").unwrap(),
            source: "static-heuristics".into(),
            score,
            rules: vec!["install-script-network".into()],
            summary: "postinstall script posts environment to a webhook".into(),
        }
    }
    struct FindingM {
        frozen: Mutex<Option<FrozenArtifact>>,
        finding: Mutex<Option<ContentFinding>>,
    }
    impl MetadataStore for FindingM {
        fn save_decision(&self, _: &Decision) -> Result<()> {
            Ok(())
        }
        fn put_frozen(&self, _: FrozenArtifact) -> Result<()> {
            Ok(())
        }
        fn latest_frozen_satisfying(
            &self,
            ecosystem: &Ecosystem,
            _: &str,
            requested: Option<&VersionReq>,
        ) -> Result<Option<FrozenArtifact>> {
            let frozen = self
                .frozen
                .lock()
                .map_err(|_| anyhow::anyhow!("lock poisoned"))?
                .clone();
            Ok(frozen.filter(|a| {
                a.package.ecosystem == *ecosystem && requested.is_none_or(|r| r.matches(&a.version))
            }))
        }
        fn get_frozen(
            &self,
            ecosystem: &Ecosystem,
            _: &str,
            version: &Version,
        ) -> Result<Option<FrozenArtifact>> {
            let frozen = self
                .frozen
                .lock()
                .map_err(|_| anyhow::anyhow!("lock poisoned"))?
                .clone();
            Ok(frozen.filter(|a| a.package.ecosystem == *ecosystem && a.version == *version))
        }
        fn save_content_finding(&self, finding: &ContentFinding) -> Result<()> {
            *self
                .finding
                .lock()
                .map_err(|_| anyhow::anyhow!("lock poisoned"))? = Some(finding.clone());
            Ok(())
        }
        fn content_finding(
            &self,
            ecosystem: &Ecosystem,
            _: &str,
            version: &Version,
        ) -> Result<Option<ContentFinding>> {
            let finding = self
                .finding
                .lock()
                .map_err(|_| anyhow::anyhow!("lock poisoned"))?
                .clone();
            Ok(finding.filter(|f| f.ecosystem == *ecosystem && f.version == *version))
        }
    }
    #[test]
    fn content_finding_blocks_high_score_when_scanner_enabled() -> Result<()> {
        let now = Utc::now();
        let mut p = Policy::default();
        p.quarantine_scanner.enabled = true;
        let c = FixedClock(now);
        let m = FindingM {
            frozen: Mutex::new(None),
            finding: Mutex::new(Some(finding(9))),
        };
        let e = PackageEvaluator {
            policy: &p,
            clock: &c,
            vulns: &NoVulns,
            metadata: &m,
        };
        let d = e.evaluate(&package(Some(now - Duration::days(30))), None)?;
        assert_eq!(d.status, DecisionStatus::Block);
        assert!(d.reasons[0].contains("content scan"), "{:?}", d.reasons);
        assert!(d.reasons[0].contains("install-script-network"));
        Ok(())
    }
    #[test]
    fn content_finding_is_ignored_when_scanner_disabled() -> Result<()> {
        let now = Utc::now();
        let p = Policy::default();
        let c = FixedClock(now);
        let m = FindingM {
            frozen: Mutex::new(None),
            finding: Mutex::new(Some(finding(9))),
        };
        let e = PackageEvaluator {
            policy: &p,
            clock: &c,
            vulns: &NoVulns,
            metadata: &m,
        };
        let d = e.evaluate(&package(Some(now - Duration::days(30))), None)?;
        assert_eq!(d.status, DecisionStatus::Allow);
        Ok(())
    }
    #[test]
    fn content_finding_review_score_warns_but_allows() -> Result<()> {
        let now = Utc::now();
        let mut p = Policy::default();
        p.quarantine_scanner.enabled = true;
        let c = FixedClock(now);
        let m = FindingM {
            frozen: Mutex::new(None),
            finding: Mutex::new(Some(finding(5))),
        };
        let e = PackageEvaluator {
            policy: &p,
            clock: &c,
            vulns: &NoVulns,
            metadata: &m,
        };
        let d = e.evaluate(&package(Some(now - Duration::days(30))), None)?;
        assert_eq!(d.status, DecisionStatus::Allow);
        assert!(
            d.warnings.iter().any(|warning| warning.contains("review")),
            "{:?}",
            d.warnings
        );
        Ok(())
    }
    #[test]
    fn content_finding_blocks_frozen_fallback() -> Result<()> {
        let now = Utc::now();
        let mut p = Policy::default();
        p.quarantine_scanner.enabled = true;
        let c = FixedClock(now);
        let mut frozen_finding = finding(9);
        frozen_finding.version = Version::parse("1.0.0").unwrap();
        let m = FindingM {
            frozen: Mutex::new(Some(frozen("1.0.0"))),
            finding: Mutex::new(Some(frozen_finding)),
        };
        let e = PackageEvaluator {
            policy: &p,
            clock: &c,
            vulns: &NoVulns,
            metadata: &m,
        };
        let d = e.evaluate(&package(Some(now - Duration::days(2))), None)?;
        assert_eq!(d.status, DecisionStatus::Block);
        assert!(d.reasons[0].contains("frozen fallback"), "{:?}", d.reasons);
        Ok(())
    }
    #[test]
    fn cve_permanence_can_be_disabled_by_policy() -> Result<()> {
        let now = Utc::now();
        let mut p = Policy::default();
        p.quarantine.cve_keeps_quarantined = false;
        let c = FixedClock(now);
        let m = M(Mutex::new(None));
        let e = PackageEvaluator {
            policy: &p,
            clock: &c,
            vulns: &MediumVulns,
            metadata: &m,
        };
        let d = e.evaluate(&package(Some(now - Duration::days(30))), None)?;
        assert_eq!(
            d.status,
            DecisionStatus::Allow,
            "with the strict rule disabled only block_severities applies"
        );
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
        assert!(
            report.findings[0].reasons[0].contains("External repository checkout is not pinned")
        );
        assert_eq!(report.references[0].line, 2);
        Ok(())
    }

    #[test]
    fn azure_scanner_allows_pinned_external_checkouts() -> Result<()> {
        let policy = Policy::default();
        let sha = "0".repeat(40);
        let body = format!(
            "steps:\n  - checkout: git://Circit/release-notes-generator@{}\n",
            sha
        );
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
