use crate::domain::*;
use crate::ports::*;
use anyhow::Result;
#[cfg(test)]
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub mod ai_scanner;
pub mod detonation;
pub mod image_scanner;
pub mod ledger;
pub mod packages;
pub mod scanner;

#[derive(Debug, Clone, Copy)]
pub enum VersionSelection<'a> {
    Exact,
    NpmRange(&'a node_semver::Range),
}
pub struct PackageEvaluator<'a> {
    pub policy: &'a Policy,
    pub clock: &'a dyn Clock,
    pub vulns: &'a dyn VulnerabilitySource,
    pub metadata: &'a dyn MetadataStore,
    pub ledger: ledger::LedgerRecorder,
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
    pub fn evaluate(
        &self,
        version: &PackageVersion,
        requested: VersionSelection<'_>,
    ) -> Result<Decision> {
        let mut decision = self.evaluate_decision(version, requested)?;
        self.ledger
            .record_evaluation(version, self.policy, &decision, self.clock.now())
            .map_err(|error| error.context(ledger::LedgerRecordingError))?;
        decision.warnings.push(ledger::LEDGER_PENDING.to_string());
        Ok(decision)
    }
    fn evaluate_decision(
        &self,
        version: &PackageVersion,
        requested: VersionSelection<'_>,
    ) -> Result<Decision> {
        let version_text = version.version.to_string();
        self.evaluate_with_version(version, requested, &version_text, None)
    }
    pub(crate) fn evaluate_with_version_string(
        &self,
        version: &PackageVersion,
        requested: VersionSelection<'_>,
        version_text: &str,
    ) -> Result<Decision> {
        self.evaluate_with_version(version, requested, version_text, Some(version_text))
    }
    fn evaluate_with_version(
        &self,
        version: &PackageVersion,
        requested: VersionSelection<'_>,
        version_text: &str,
        query_version_text: Option<&str>,
    ) -> Result<Decision> {
        let name = &version.package.name;
        let ecosystem = version.package.ecosystem.clone();
        let ecosystem_policy = self.ecosystem_policy(&ecosystem);
        if ecosystem_policy.deny.contains(name) {
            return Ok(Decision::block(
                name,
                Some(version_text.to_string()),
                "package is denylisted",
            ));
        }
        if ecosystem_policy.require_integrity && version.integrity.is_none() {
            if let Some(query_version_text) = query_version_text {
                let findings =
                    self.vulns
                        .query_version(ecosystem.clone(), name, query_version_text)?;
                if let Some(reason) = self.vulnerability_reason(&findings) {
                    return self.fallback_or_block(version, requested, version_text, reason);
                }
            }
            return self.fallback_or_block(
                version,
                requested,
                version_text,
                "package version is missing integrity",
            );
        }
        let mut review_warning = None;
        if self.policy.quarantine_scanner.enabled {
            if let Some(finding) =
                self.metadata
                    .content_finding(&ecosystem, name, &version.version)?
            {
                let Some(score) = finding.score.filter(|_| !finding.scan_incomplete) else {
                    return self.fallback_or_block(
                        version,
                        requested,
                        version_text,
                        format!("content scan incomplete: {}", finding.summary),
                    );
                };
                if score >= self.policy.quarantine_scanner.block_score.into() {
                    return self.fallback_or_block(
                        version,
                        requested,
                        version_text,
                        format!(
                            "content scan: {} [{}]",
                            finding.summary,
                            finding.rules.join(", ")
                        ),
                    );
                }
                if score >= self.policy.quarantine_scanner.review_score.into() {
                    review_warning = Some(format!(
                        "content scan review (score {score}): {} [{}]",
                        finding.summary,
                        finding.rules.join(", ")
                    ));
                }
            }
        }
        let findings = if let Some(query_version_text) = query_version_text {
            self.vulns
                .query_version(ecosystem.clone(), name, query_version_text)?
        } else {
            self.vulns
                .query(ecosystem.clone(), name, &version.version)?
        };
        if let Some(reason) = self.vulnerability_reason(&findings) {
            return self.fallback_or_block(version, requested, version_text, reason);
        }
        if is_version_quarantined(
            version.published_at,
            self.clock.now(),
            &self.policy.quarantine,
        ) {
            return self.fallback_or_block(
                version,
                requested,
                version_text,
                "package version is inside quarantine window",
            );
        }
        let mut decision = Decision::allow(name.clone(), version_text.to_string());
        if let Some(warning) = review_warning {
            decision.warnings.push(warning);
        }
        Ok(decision)
    }
    fn vulnerability_reason(&self, findings: &[VulnerabilityFinding]) -> Option<String> {
        strongest_osv_vulnerability(findings).or_else(|| {
            if self.policy.quarantine.cve_keeps_quarantined {
                strongest_vulnerability(findings)
            } else {
                blocks_vulnerability(findings, &self.policy.vulnerabilities)
            }
        })
    }
    fn fallback_or_block(
        &self,
        version: &PackageVersion,
        requested: VersionSelection<'_>,
        requested_version_text: &str,
        reason: impl Into<String>,
    ) -> Result<Decision> {
        let name = &version.package.name;
        let ecosystem = &version.package.ecosystem;
        let reason = reason.into();
        let ecosystem_policy = self.ecosystem_policy(ecosystem);
        let requested_range = match requested {
            VersionSelection::Exact => {
                return Ok(Decision::block(
                    name,
                    Some(requested_version_text.to_string()),
                    reason,
                ));
            }
            VersionSelection::NpmRange(range) => range,
        };
        if ecosystem_policy.fallback_to_frozen {
            let Some(tarball_url) = version.tarball_url.as_deref() else {
                return Ok(Decision::block(
                    name,
                    Some(requested_version_text.to_string()),
                    format!("{reason}; registry source cannot be derived for frozen fallback"),
                ));
            };
            let source = match ArtifactKey::source_from_tarball_url(tarball_url) {
                Ok(source) => source,
                Err(_) => {
                    return Ok(Decision::block(
                        name,
                        Some(requested_version_text.to_string()),
                        format!("{reason}; registry source cannot be derived for frozen fallback"),
                    ));
                }
            };
            if let Some(frozen) = self.metadata.latest_frozen_satisfying(
                &source,
                ecosystem,
                name,
                Some(requested_range),
            )? {
                let findings = self.vulns.query(ecosystem.clone(), name, &frozen.version)?;
                if let Some(fallback_reason) = self.vulnerability_reason(&findings) {
                    return Ok(Decision::block(
                        name,
                        Some(requested_version_text.to_string()),
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
                        if finding.scan_incomplete || finding.score.is_none() {
                            return Ok(Decision::block(
                                name,
                                Some(requested_version_text.to_string()),
                                format!(
                                    "{reason}; frozen fallback {} blocked: content scan incomplete: {}",
                                    frozen.version, finding.summary
                                ),
                            ));
                        }
                        if finding.score.is_some_and(|score| {
                            score >= self.policy.quarantine_scanner.block_score.into()
                        }) {
                            return Ok(Decision::block(
                                name,
                                Some(requested_version_text.to_string()),
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
                    requested_version_text.to_string(),
                    frozen.version.to_string(),
                    reason,
                ));
            }
        }
        Ok(Decision::block(
            name,
            Some(requested_version_text.to_string()),
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
    pub ledger: ledger::LedgerRecorder,
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
        let key =
            ArtifactKey::from_tarball_url(url, &version.package.ecosystem, name, &version.version)?;
        let integrity = version.integrity.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "no dist.integrity for {name}@{}: refusing to freeze unverified bytes",
                version.version
            )
        })?;
        let existing = self.metadata.get_frozen(&key)?;
        let upstream = self.registry.tarball(url)?;
        let mut verified = self.hasher.verified_npm_reader(upstream, integrity)?;
        let stored = self.artifacts.put(
            verified.as_mut(),
            crate::application::scanner::MAX_COMPRESSED_ARCHIVE_BYTES,
        )?;
        if let Some(existing) = existing {
            if existing.sha256 != stored.sha256 {
                anyhow::bail!(
                    "registry immutability violation: {name}@{} already frozen with different bytes",
                    version.version
                );
            }
            if existing.path != stored.path {
                anyhow::bail!("frozen metadata path does not match its indexed artifact");
            }
            self.artifacts.map(&key, &stored.sha256)?;
            self.ledger.record_discovered(&existing, self.clock.now())?;
            return Ok(existing);
        }
        self.artifacts.map(&key, &stored.sha256)?;
        let artifact = FrozenArtifact {
            key,
            package: version.package.clone(),
            version: version.version.clone(),
            sha256: stored.sha256,
            integrity: Some(integrity.to_string()),
            path: stored.path,
            frozen_at: self.clock.now(),
        };
        self.metadata.put_frozen(artifact.clone())?;
        self.ledger.record_discovered(&artifact, self.clock.now())?;
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
    pub files: Vec<String>,
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
        let mut extracted = vec![];
        let mut files = Vec::new();
        for (file, body) in self.reader.read(root)? {
            let file_refs = extract_pipeline_references(&body)
                .map_err(|error| anyhow::anyhow!("invalid pipeline {file}: {error}"))?;
            files.push(file.clone());
            extracted.push((file, file_refs));
        }
        files.sort();
        files.dedup();
        let pinned_aliases = sha_pinned_repository_aliases(&extracted);
        for (file, file_refs) in extracted {
            for (raw, kind, line) in file_refs {
                let pin_kind = resolve_repository_alias(
                    &raw,
                    &kind,
                    classify_pipeline_ref(&raw, &kind),
                    &pinned_aliases,
                );
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
            files,
            findings,
            references: refs,
            finding_locations,
        })
    }
}

type ExtractedPipelineRefs = Vec<(String, Vec<(String, PipelineRefKind, usize)>)>;

fn sha_pinned_repository_aliases(extracted: &ExtractedPipelineRefs) -> HashSet<String> {
    let mut aliases: HashMap<&str, bool> = HashMap::new();
    for (raw, kind, _) in extracted.iter().flat_map(|(_, refs)| refs) {
        if *kind != PipelineRefKind::Repository {
            continue;
        }
        let alias = raw.split_once('@').map_or(raw.as_str(), |(alias, _)| alias);
        let is_pinned = classify_pipeline_ref(raw, kind) == ActionPinKind::FullSha;
        aliases
            .entry(alias)
            .and_modify(|all_pinned| *all_pinned &= is_pinned)
            .or_insert(is_pinned);
    }
    aliases
        .into_iter()
        .filter(|(_, all_pinned)| *all_pinned)
        .map(|(alias, _)| alias.to_string())
        .collect()
}

fn resolve_repository_alias(
    raw: &str,
    kind: &PipelineRefKind,
    pin_kind: ActionPinKind,
    pinned_aliases: &HashSet<String>,
) -> ActionPinKind {
    if pin_kind != ActionPinKind::TagOrBranch {
        return pin_kind;
    }
    let alias = match kind {
        PipelineRefKind::Template => raw.rsplit_once('@').map(|(_, alias)| alias),
        PipelineRefKind::Checkout if !raw.contains('@') && !raw.contains("://") => Some(raw),
        _ => None,
    };
    match alias {
        Some(alias) if pinned_aliases.contains(alias) => ActionPinKind::FullSha,
        _ => pin_kind,
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
    fn npm_version(raw: &str) -> PackageVersionId {
        PackageVersionId::parse(&Ecosystem::Npm, raw).unwrap()
    }

    fn pypi_version(raw: &str) -> PackageVersionId {
        PackageVersionId::parse(&Ecosystem::PyPi, raw).unwrap()
    }

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
            source: &str,
            ecosystem: &Ecosystem,
            _: &str,
            requested: Option<&node_semver::Range>,
        ) -> Result<Option<FrozenArtifact>> {
            let frozen = self
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("lock poisoned"))?
                .clone();
            Ok(frozen.filter(|artifact| {
                artifact.key.source == source
                    && artifact.key.ecosystem == *ecosystem
                    && requested.is_none_or(|range| artifact.version.satisfies_npm_range(range))
            }))
        }
        fn get_frozen(&self, key: &ArtifactKey) -> Result<Option<FrozenArtifact>> {
            let frozen = self
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("lock poisoned"))?
                .clone();
            Ok(frozen.filter(|artifact| artifact.key == *key))
        }
        fn save_content_finding(&self, _: &ContentFinding) -> Result<()> {
            Ok(())
        }
        fn content_finding(
            &self,
            _: &Ecosystem,
            _: &str,
            _: &PackageVersionId,
        ) -> Result<Option<ContentFinding>> {
            Ok(None)
        }
        fn put_frozen(&self, _: FrozenArtifact) -> Result<()> {
            Ok(())
        }
    }
    fn frozen(version: &str) -> FrozenArtifact {
        let version = npm_version(version);
        FrozenArtifact {
            key: ArtifactKey {
                source: "https://registry.example".into(),
                ecosystem: Ecosystem::Npm,
                name: "left-pad".into(),
                filename: format!("left-pad-{version}.tgz"),
                version: version.clone(),
            },
            package: PackageCoordinate {
                ecosystem: Ecosystem::Npm,
                name: "left-pad".into(),
            },
            version,
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
            version: npm_version("2.0.0"),
            published_at: published,
            integrity: Some("sha512-x".into()),
            tarball_url: Some("https://registry.example/left-pad/-/left-pad-2.0.0.tgz".into()),
        }
    }
    fn evaluator<'a>(
        policy: &'a Policy,
        clock: &'a FixedClock,
        metadata: &'a dyn MetadataStore,
    ) -> Result<PackageEvaluator<'a>> {
        Ok(PackageEvaluator {
            policy,
            clock,
            vulns: &NoVulns,
            metadata,
            ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
        })
    }
    struct NoVulns;
    impl VulnerabilitySource for NoVulns {
        fn query(
            &self,
            _: Ecosystem,
            _: &str,
            _: &PackageVersionId,
        ) -> Result<Vec<VulnerabilityFinding>> {
            Ok(vec![])
        }
    }
    #[test]
    fn quarantine_falls_back_to_frozen() -> Result<()> {
        let now = Utc::now();
        let p = Policy::default();
        let c = FixedClock(now);
        let m = M(Mutex::new(Some(frozen("1.0.0"))));
        let e = evaluator(&p, &c, &m)?;
        let d = e.evaluate(
            &package(Some(now - Duration::days(2))),
            VersionSelection::NpmRange(&node_semver::Range::parse("*")?),
        )?;
        assert_eq!(d.status, DecisionStatus::Fallback);
        assert!(d
            .warnings
            .iter()
            .any(|warning| warning == ledger::LEDGER_PENDING));
        let jobs = e.ledger.pending_jobs(10)?;
        assert_eq!(jobs.len(), 1);
        let payload: serde_json::Value = serde_json::from_slice(&jobs[0].payload)?;
        assert_eq!(payload["operation"], "evaluate_version");
        assert_eq!(payload["scope"], "complete");
        assert_eq!(d.served_version.as_deref(), Some("1.0.0"));
        Ok(())
    }

    #[test]
    fn legacy_findings_block_until_rescanned() -> Result<()> {
        let now = Utc::now();
        let legacy = ContentFinding {
            ecosystem: Ecosystem::Npm,
            package: "left-pad".into(),
            version: npm_version("2.0.0"),
            source: "guarddog".into(),
            score: Some(rust_decimal::Decimal::from(6)),
            scan_incomplete: false,
            rules: vec![],
            summary: "legacy finding".into(),
            detected_at: now,
        };
        let mut legacy_json = serde_json::to_value(legacy)?;
        legacy_json
            .as_object_mut()
            .unwrap()
            .remove("scan_incomplete");
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("findings.jsonl");
        std::fs::write(&path, format!("{legacy_json}\n"))?;

        let store = crate::adapters::storage::MemoryMetadataStore::default();
        assert_eq!(
            crate::adapters::storage::FindingFile::new(&path).load_into(&store)?,
            1
        );
        let mut policy = Policy::default();
        policy.quarantine_scanner.enabled = true;
        let clock = FixedClock(now);
        let evaluator = evaluator(&policy, &clock, &store)?;
        let decision = evaluator.evaluate(
            &package(Some(now - Duration::days(30))),
            VersionSelection::Exact,
        )?;

        assert_eq!(decision.status, DecisionStatus::Block);
        assert!(decision
            .reasons
            .iter()
            .any(|reason| reason.contains("content scan incomplete")));
        Ok(())
    }
    #[test]
    fn evaluator_marks_ledger_append_failure() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("ledger.sqlite");
        let recorder = crate::application::ledger::LedgerRecorder::open(&path)?;
        rusqlite::Connection::open(&path)?.execute_batch(
            "CREATE TRIGGER reject_ledger_events
             BEFORE INSERT ON ledger_events
             BEGIN
                 SELECT RAISE(ABORT, 'injected ledger failure');
             END;",
        )?;
        let policy = Policy::default();
        let clock = FixedClock(Utc::now());
        let metadata = M(Mutex::new(None));
        let evaluator = PackageEvaluator {
            policy: &policy,
            clock: &clock,
            vulns: &NoVulns,
            metadata: &metadata,
            ledger: recorder,
        };
        let error = evaluator
            .evaluate(
                &package(Some(clock.now() - Duration::days(30))),
                VersionSelection::Exact,
            )
            .unwrap_err();
        assert!(error
            .downcast_ref::<crate::application::ledger::LedgerRecordingError>()
            .is_some());
        Ok(())
    }
    #[test]
    fn frozen_fallback_is_rechecked_for_vulnerabilities() -> Result<()> {
        struct Source {
            fail: bool,
            queried: Mutex<Vec<PackageVersionId>>,
        }
        impl VulnerabilitySource for Source {
            fn query(
                &self,
                _: Ecosystem,
                _: &str,
                version: &PackageVersionId,
            ) -> Result<Vec<VulnerabilityFinding>> {
                self.queried.lock().unwrap().push(version.clone());
                if version.canonical() != "1.0.0" {
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
                    aliases: vec![],
                    modified: None,
                    withdrawn: None,
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
                ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
            };
            let result = evaluator.evaluate(
                &package(Some(now)),
                VersionSelection::NpmRange(&node_semver::Range::parse("*")?),
            );
            if fail {
                assert!(result.is_err(), "fallback query errors must fail closed");
            } else {
                let decision = result?;
                assert_eq!(decision.status, DecisionStatus::Block);
                assert!(decision.reasons[0].contains("TEST-FROZEN"));
            }
            assert_eq!(
                *source.queried.lock().unwrap(),
                vec![npm_version("2.0.0"), npm_version("1.0.0")]
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
            version: &PackageVersionId,
        ) -> Result<Vec<VulnerabilityFinding>> {
            if version.canonical() == "2.0.0" {
                Ok(vec![VulnerabilityFinding {
                    source: "OSV".into(),
                    id: "GHSA-medium".into(),
                    severity: Severity::Medium,
                    summary: "medium advisory".into(),
                    aliases: vec![],
                    modified: None,
                    withdrawn: None,
                }])
            } else {
                Ok(vec![])
            }
        }
    }
    struct MediumVulns;
    impl VulnerabilitySource for MediumVulns {
        fn query(
            &self,
            _: Ecosystem,
            _: &str,
            _: &PackageVersionId,
        ) -> Result<Vec<VulnerabilityFinding>> {
            Ok(vec![VulnerabilityFinding {
                source: "OSV".into(),
                id: "GHSA-medium".into(),
                severity: Severity::Medium,
                summary: "medium advisory".into(),
                aliases: vec![],
                modified: None,
                withdrawn: None,
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
            ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
        };
        let d = e.evaluate(
            &package(Some(now - Duration::days(30))),
            VersionSelection::Exact,
        )?;
        assert_eq!(
            d.status,
            DecisionStatus::Block,
            "a version with a known CVE must never age out of quarantine"
        );
        assert!(d.reasons[0].contains("GHSA-medium"));
        Ok(())
    }
    #[test]
    fn withdrawn_osv_advisory_does_not_block_version() -> Result<()> {
        struct WithdrawnVulns;
        impl VulnerabilitySource for WithdrawnVulns {
            fn query(
                &self,
                _: Ecosystem,
                _: &str,
                _: &PackageVersionId,
            ) -> Result<Vec<VulnerabilityFinding>> {
                Ok(vec![VulnerabilityFinding {
                    source: "OSV".into(),
                    id: "GHSA-withdrawn".into(),
                    aliases: vec!["CVE-2026-1234".into()],
                    severity: Severity::Critical,
                    summary: "withdrawn advisory".into(),
                    modified: None,
                    withdrawn: Some("2026-10-13T10:30:00Z".parse()?),
                }])
            }
        }

        let now = Utc::now();
        let policy = Policy::default();
        let clock = FixedClock(now);
        let metadata = M(Mutex::new(None));
        let decision = PackageEvaluator {
            policy: &policy,
            clock: &clock,
            vulns: &WithdrawnVulns,
            metadata: &metadata,
            ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
        }
        .evaluate(
            &package(Some(now - Duration::days(30))),
            VersionSelection::Exact,
        )?;

        assert_eq!(decision.status, DecisionStatus::Allow);
        Ok(())
    }

    #[test]
    fn active_osv_findings_block_even_when_severity_policy_is_disabled() -> Result<()> {
        let now = Utc::now();
        let mut policy = Policy::default();
        policy.quarantine.cve_keeps_quarantined = false;
        policy.vulnerabilities.block_severities.clear();
        let clock = FixedClock(now);
        let metadata = M(Mutex::new(None));
        let evaluator = PackageEvaluator {
            policy: &policy,
            clock: &clock,
            vulns: &MediumVulns,
            metadata: &metadata,
            ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
        };

        let decision = evaluator.evaluate(
            &package(Some(now - Duration::days(30))),
            VersionSelection::Exact,
        )?;

        assert_eq!(decision.status, DecisionStatus::Block);
        assert!(decision.reasons[0].contains("GHSA-medium"));
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
            ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
        };
        let d = e.evaluate(
            &package(Some(now - Duration::days(30))),
            VersionSelection::NpmRange(&node_semver::Range::parse("*")?),
        )?;
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
            ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
        };
        let d = e.evaluate(
            &package(Some(now - Duration::days(30))),
            VersionSelection::NpmRange(&node_semver::Range::parse("*")?),
        )?;
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
            ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
        };
        let pv = PackageVersion {
            package: PackageCoordinate {
                ecosystem: Ecosystem::PyPi,
                name: "requests".into(),
            },
            version: pypi_version("2.32.3"),
            published_at: Some(now - Duration::days(30)),
            integrity: None,
            tarball_url: None,
        };
        let d = e.evaluate(&pv, VersionSelection::Exact)?;
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
            _: &PackageVersionId,
        ) -> Result<Vec<VulnerabilityFinding>> {
            if ecosystem == Ecosystem::PyPi {
                Ok(vec![VulnerabilityFinding {
                    source: "OSV".into(),
                    id: "GHSA-pip".into(),
                    severity: Severity::Medium,
                    summary: "pip advisory".into(),
                    aliases: vec![],
                    modified: None,
                    withdrawn: None,
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
            ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
        };
        let pv = PackageVersion {
            package: PackageCoordinate {
                ecosystem: Ecosystem::PyPi,
                name: "requests".into(),
            },
            version: pypi_version("2.32.3"),
            published_at: Some(now - Duration::days(30)),
            integrity: Some("sha256-abc".into()),
            tarball_url: None,
        };
        let d = e.evaluate(&pv, VersionSelection::Exact)?;
        assert_eq!(d.status, DecisionStatus::Block);
        assert!(d.reasons[0].contains("GHSA-pip"));
        Ok(())
    }
    fn finding(score: Decimal) -> ContentFinding {
        ContentFinding {
            ecosystem: Ecosystem::Npm,
            package: "left-pad".into(),
            version: npm_version("2.0.0"),
            source: "static-heuristics".into(),
            score: Some(score),
            scan_incomplete: false,
            rules: vec!["install-script-network".into()],
            summary: "postinstall script posts environment to a webhook".into(),
            detected_at: chrono::Utc::now(),
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
            source: &str,
            ecosystem: &Ecosystem,
            _: &str,
            requested: Option<&node_semver::Range>,
        ) -> Result<Option<FrozenArtifact>> {
            let frozen = self
                .frozen
                .lock()
                .map_err(|_| anyhow::anyhow!("lock poisoned"))?
                .clone();
            Ok(frozen.filter(|artifact| {
                artifact.key.source == source
                    && artifact.key.ecosystem == *ecosystem
                    && requested.is_none_or(|range| artifact.version.satisfies_npm_range(range))
            }))
        }
        fn get_frozen(&self, key: &ArtifactKey) -> Result<Option<FrozenArtifact>> {
            let frozen = self
                .frozen
                .lock()
                .map_err(|_| anyhow::anyhow!("lock poisoned"))?
                .clone();
            Ok(frozen.filter(|artifact| artifact.key == *key))
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
            version: &PackageVersionId,
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
    fn pypi_content_finding_blocks_pip_evaluation() -> Result<()> {
        use crate::adapters::storage::MemoryMetadataStore;
        let store = MemoryMetadataStore::default();
        store.save_content_finding(&ContentFinding {
            ecosystem: Ecosystem::PyPi,
            package: "evil".into(),
            version: pypi_version("1.0.0"),
            source: "static-heuristics".into(),
            score: Some(Decimal::from(9)),
            scan_incomplete: false,
            rules: vec!["env-exfiltration".into()],
            summary: "exfiltrates the environment".into(),
            detected_at: Utc::now(),
        })?;
        let mut policy = Policy::default();
        policy.quarantine_scanner.enabled = true;
        let now = Utc::now();
        let clock = FixedClock(now);
        let evaluator = PackageEvaluator {
            policy: &policy,
            clock: &clock,
            vulns: &NoVulns,
            metadata: &store,
            ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
        };
        let pv = PackageVersion {
            package: PackageCoordinate {
                ecosystem: Ecosystem::PyPi,
                name: "evil".into(),
            },
            version: pypi_version("1.0.0"),
            published_at: Some(now - Duration::days(30)),
            integrity: Some("sha256-x".into()),
            tarball_url: None,
        };
        let decision = evaluator.evaluate(&pv, VersionSelection::Exact)?;
        assert_eq!(decision.status, DecisionStatus::Block);
        Ok(())
    }
    fn malicious_archive() -> Result<Vec<u8>> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for (path, content) in [
            (
                "package.json",
                r#"{"name":"left-pad","scripts":{"postinstall":"node beacon.js"}}"#,
            ),
            (
                "beacon.js",
                "const https = require('node:https'); https.get('https://discord.com/api/webhooks/1/x');\n",
            ),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_cksum();
            builder.append_data(&mut header, format!("package/{path}"), content.as_bytes())?;
        }
        Ok(builder.into_inner()?.finish()?)
    }

    #[test]
    fn malicious_archive_blocks_without_provenance_evidence() -> Result<()> {
        use crate::adapters::storage::MemoryMetadataStore;
        use crate::application::scanner::scan_archive_bytes;

        let bytes = malicious_archive()?;
        let store = MemoryMetadataStore::default();
        let now = Utc::now();
        let version = npm_version("2.0.0");
        let scratch = tempfile::tempdir()?;
        let finding = scan_archive_bytes(
            &store,
            &crate::application::ledger::LedgerRecorder::open_in_memory()?,
            &Ecosystem::Npm,
            "left-pad",
            &version,
            &bytes,
            scratch.path(),
        )?;
        assert!(finding.is_some());
        let finding = store
            .content_finding(&Ecosystem::Npm, "left-pad", &version)?
            .unwrap_or_else(|| panic!("finding was persisted"));
        assert!(!finding
            .rules
            .iter()
            .any(|rule| rule == "provenance-attested"));
        assert!(!finding.summary.contains("provenance"));

        let mut policy = Policy::default();
        policy.quarantine_scanner.enabled = true;
        let clock = FixedClock(now);
        let evaluator = PackageEvaluator {
            policy: &policy,
            clock: &clock,
            vulns: &NoVulns,
            metadata: &store,
            ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
        };
        let decision = evaluator.evaluate(
            &package(Some(now - Duration::days(30))),
            VersionSelection::Exact,
        )?;
        assert_eq!(decision.status, DecisionStatus::Block);
        assert!(
            decision.reasons[0].contains("content scan"),
            "{:?}",
            decision.reasons
        );
        Ok(())
    }
    #[test]
    fn malicious_archive_blocks_through_store_and_evaluator() -> Result<()> {
        use crate::adapters::storage::MemoryMetadataStore;
        use crate::application::scanner::scan_archive_bytes;

        let bytes = malicious_archive()?;
        let store = MemoryMetadataStore::default();
        let now = Utc::now();
        let version = npm_version("2.0.0");
        let scratch = tempfile::tempdir()?;
        let finding = scan_archive_bytes(
            &store,
            &crate::application::ledger::LedgerRecorder::open_in_memory()?,
            &Ecosystem::Npm,
            "left-pad",
            &version,
            &bytes,
            scratch.path(),
        )?;
        assert!(finding.is_some());
        let mut policy = Policy::default();
        policy.quarantine_scanner.enabled = true;
        let clock = FixedClock(now);
        let evaluator = PackageEvaluator {
            policy: &policy,
            clock: &clock,
            vulns: &NoVulns,
            metadata: &store,
            ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
        };
        let decision = evaluator.evaluate(
            &package(Some(now - Duration::days(30))),
            VersionSelection::Exact,
        )?;
        assert_eq!(decision.status, DecisionStatus::Block);
        assert!(
            decision.reasons[0].contains("content scan"),
            "{:?}",
            decision.reasons
        );
        Ok(())
    }
    #[test]
    fn content_finding_blocks_high_score_when_scanner_enabled() -> Result<()> {
        let now = Utc::now();
        let mut p = Policy::default();
        p.quarantine_scanner.enabled = true;
        let c = FixedClock(now);
        let m = FindingM {
            frozen: Mutex::new(None),
            finding: Mutex::new(Some(finding(Decimal::from(9)))),
        };
        let e = PackageEvaluator {
            policy: &p,
            clock: &c,
            vulns: &NoVulns,
            metadata: &m,
            ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
        };
        let d = e.evaluate(
            &package(Some(now - Duration::days(30))),
            VersionSelection::Exact,
        )?;
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
            finding: Mutex::new(Some(finding(Decimal::from(9)))),
        };
        let e = PackageEvaluator {
            policy: &p,
            clock: &c,
            vulns: &NoVulns,
            metadata: &m,
            ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
        };
        let d = e.evaluate(
            &package(Some(now - Duration::days(30))),
            VersionSelection::Exact,
        )?;
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
            finding: Mutex::new(Some(finding(Decimal::new(79, 1)))),
        };
        let e = PackageEvaluator {
            policy: &p,
            clock: &c,
            vulns: &NoVulns,
            metadata: &m,
            ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
        };
        let d = e.evaluate(
            &package(Some(now - Duration::days(30))),
            VersionSelection::Exact,
        )?;
        assert_eq!(d.status, DecisionStatus::Allow);
        assert!(
            d.warnings.iter().any(|warning| warning.contains("review")),
            "{:?}",
            d.warnings
        );
        Ok(())
    }
    #[test]
    fn incomplete_content_scan_blocks_without_a_score() -> Result<()> {
        let now = Utc::now();
        let mut policy = Policy::default();
        policy.quarantine_scanner.enabled = true;
        let clock = FixedClock(now);
        let mut incomplete = finding(Decimal::ZERO);
        incomplete.score = None;
        incomplete.scan_incomplete = true;
        incomplete.rules = vec!["scan-incomplete".into()];
        let metadata = FindingM {
            frozen: Mutex::new(None),
            finding: Mutex::new(Some(incomplete)),
        };
        let evaluator = PackageEvaluator {
            policy: &policy,
            clock: &clock,
            vulns: &NoVulns,
            metadata: &metadata,
            ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
        };
        let decision = evaluator.evaluate(
            &package(Some(now - Duration::days(30))),
            VersionSelection::Exact,
        )?;
        assert_eq!(decision.status, DecisionStatus::Block);
        assert!(decision.reasons[0].contains("scan incomplete"));
        Ok(())
    }
    #[test]
    fn content_finding_blocks_frozen_fallback() -> Result<()> {
        let now = Utc::now();
        let mut p = Policy::default();
        p.quarantine_scanner.enabled = true;
        let c = FixedClock(now);
        let mut frozen_finding = finding(Decimal::from(9));
        frozen_finding.version = npm_version("1.0.0");
        let m = FindingM {
            frozen: Mutex::new(Some(frozen("1.0.0"))),
            finding: Mutex::new(Some(frozen_finding)),
        };
        let e = PackageEvaluator {
            policy: &p,
            clock: &c,
            vulns: &NoVulns,
            metadata: &m,
            ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
        };
        let d = e.evaluate(
            &package(Some(now - Duration::days(2))),
            VersionSelection::NpmRange(&node_semver::Range::parse("*")?),
        )?;
        assert_eq!(d.status, DecisionStatus::Block);
        assert!(d.reasons[0].contains("frozen fallback"), "{:?}", d.reasons);
        Ok(())
    }
    #[test]
    fn missing_published_at_is_quarantined() -> Result<()> {
        let now = Utc::now();
        let p = Policy::default();
        let c = FixedClock(now);
        let m = M(Mutex::new(None));
        let e = evaluator(&p, &c, &m)?;
        let d = e.evaluate(&package(None), VersionSelection::Exact)?;
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
        let e = evaluator(&p, &c, &m)?;
        let d = e.evaluate(
            &package(Some(now - Duration::days(30))),
            VersionSelection::Exact,
        )?;
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
        let e = evaluator(&p, &c, &m)?;
        let d = e.evaluate(
            &package(Some(now - Duration::days(30))),
            VersionSelection::Exact,
        )?;
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
        let e = evaluator(&p, &c, &store)?;
        let caret_one = node_semver::Range::parse("^1.0.0")?;
        let d = e.evaluate(&quarantined, VersionSelection::NpmRange(&caret_one))?;
        assert_eq!(d.status, DecisionStatus::Fallback);
        assert_eq!(d.served_version.as_deref(), Some("1.5.0"));
        let caret_two = node_semver::Range::parse("^2.0.0")?;
        let d = e.evaluate(&quarantined, VersionSelection::NpmRange(&caret_two))?;
        assert_eq!(
            d.status,
            DecisionStatus::Block,
            "no frozen version satisfies ^2.0.0: must block, not serve wrong major"
        );
        Ok(())
    }

    #[test]
    fn exact_pin_does_not_return_a_different_frozen_version() -> Result<()> {
        let now = Utc::now();
        let policy = Policy::default();
        let clock = FixedClock(now);
        let store = crate::adapters::storage::MemoryMetadataStore::default();
        store.put_frozen(frozen("1.0.0"))?;
        let decision = evaluator(&policy, &clock, &store)?.evaluate(
            &package(Some(now - Duration::days(2))),
            VersionSelection::Exact,
        )?;
        assert_eq!(decision.status, DecisionStatus::Block);
        assert_eq!(decision.served_version, None);
        Ok(())
    }
    struct Reg(Vec<u8>);
    impl UpstreamNpmRegistry for Reg {
        fn metadata(&self, _: &str) -> Result<serde_json::Value> {
            Ok(serde_json::json!({}))
        }
        fn tarball(&self, _: &str) -> Result<Box<dyn std::io::Read + Send>> {
            Ok(Box::new(std::io::Cursor::new(self.0.clone())))
        }
    }
    struct MemStore;
    impl ArtifactStore for MemStore {
        fn put(
            &self,
            reader: &mut dyn std::io::Read,
            max_bytes: u64,
        ) -> Result<crate::ports::StoredArtifact> {
            use sha2::{Digest, Sha256};
            use std::io::{Seek, SeekFrom, Write};

            let mut file = tempfile::tempfile()?;
            let mut hasher = Sha256::new();
            let mut size = 0u64;
            let mut buffer = [0u8; 8192];
            loop {
                let count = reader.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                size = size
                    .checked_add(u64::try_from(count)?)
                    .ok_or_else(|| anyhow::anyhow!("artifact size overflow"))?;
                anyhow::ensure!(size <= max_bytes, "artifact exceeds its size limit");
                hasher.update(&buffer[..count]);
                file.write_all(&buffer[..count])?;
            }
            file.seek(SeekFrom::Start(0))?;
            Ok(crate::ports::StoredArtifact {
                sha256: hex::encode(hasher.finalize()),
                path: "p".into(),
                file,
            })
        }
        fn map(&self, _: &ArtifactKey, _: &str) -> Result<()> {
            Ok(())
        }
        fn resolve(&self, _: &ArtifactKey) -> Result<Option<String>> {
            Ok(Some("p".into()))
        }
        fn open(&self, _: &ArtifactKey) -> Result<Option<std::fs::File>> {
            Ok(None)
        }
        fn import_legacy(&self, _: &ArtifactKey, _: &str) -> Result<String> {
            Ok("p".into())
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
        ledger: &crate::application::ledger::LedgerRecorder,
        bytes: Vec<u8>,
        integrity: String,
    ) -> Result<FrozenArtifact> {
        use crate::adapters::crypto::ShaHasher;
        let pv = PackageVersion {
            package: PackageCoordinate {
                ecosystem: Ecosystem::Npm,
                name: "left-pad".into(),
            },
            version: npm_version("1.3.0"),
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
            ledger: ledger.clone(),
        }
        .freeze_verified(&pv)
    }
    #[test]
    fn republish_same_version_conflicting_bytes_rejected() -> Result<()> {
        let p = Policy::default();
        let store = crate::adapters::storage::MemoryMetadataStore::default();
        let ledger = crate::application::ledger::LedgerRecorder::open_in_memory()?;
        let good = b"good bytes".to_vec();
        let first = ingest_into(&p, &store, &ledger, good.clone(), sri_sha512(&good))?;
        assert_eq!(first.sha256.len(), 64);
        let idempotent = ingest_into(&p, &store, &ledger, good.clone(), sri_sha512(&good))?;
        assert_eq!(
            idempotent.sha256, first.sha256,
            "same bytes re-freeze is idempotent"
        );
        let jobs = ledger.pending_jobs(10)?;
        assert_eq!(jobs.len(), 2);
        assert!(jobs.iter().all(|job| {
            let payload: serde_json::Value = serde_json::from_slice(&job.payload).unwrap();
            payload["operation"] == "evaluate_version" && payload["scope"] == "complete"
        }));
        let evil = b"evil payload".to_vec();
        let republished = ingest_into(&p, &store, &ledger, evil.clone(), sri_sha512(&evil));
        let err = republished.unwrap_err().to_string();
        assert!(
            err.contains("immutability violation"),
            "expected immutability violation, got: {err}"
        );
        Ok(())
    }
    #[test]
    fn integrity_is_enforced_when_policy_flag_is_disabled() -> Result<()> {
        let mut policy = Policy::default();
        policy.npm.require_integrity = false;
        let store = crate::adapters::storage::MemoryMetadataStore::default();
        let ledger = crate::application::ledger::LedgerRecorder::open_in_memory()?;
        let bytes = b"package bytes".to_vec();
        let error = ingest_into(
            &policy,
            &store,
            &ledger,
            bytes,
            sri_sha512(b"different bytes"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("npm integrity mismatch"));
        let key = ArtifactKey::from_tarball_url(
            "http://registry/t.tgz",
            &Ecosystem::Npm,
            "left-pad",
            &PackageVersionId::parse(&Ecosystem::Npm, "1.3.0")?,
        )?;
        assert!(store.get_frozen(&key)?.is_none());
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
    fn azure_scan_reports_root_entrypoint_and_empty_pipeline_files() -> Result<()> {
        let root = tempfile::tempdir()?;
        let pipelines = root.path().join("pipelines");
        std::fs::create_dir_all(&pipelines)?;
        std::fs::write(pipelines.join("empty.yml"), "steps: []\n")?;
        let entrypoint = root.path().join("ai-orchestrator-ci.yml");
        std::fs::write(
            &entrypoint,
            "steps:\n  - checkout: git://example/repository\n",
        )?;
        let policy = Policy::default();
        let reader = crate::adapters::azure_devops::FsAzurePipelineReader;

        let blocked = AzurePipelinesScanner {
            policy: &policy,
            reader: &reader,
        }
        .scan(root.path())?;
        assert!(blocked.is_blocking());
        assert!(blocked
            .references
            .iter()
            .any(|reference| reference.file == "ai-orchestrator-ci.yml"));
        assert_eq!(
            serde_json::to_value(&blocked)?["files"],
            serde_json::json!(["ai-orchestrator-ci.yml", "pipelines/empty.yml"])
        );

        let pinned = "steps:\n  - checkout: git://example/repository@0000000000000000000000000000000000000000\n";
        std::fs::write(entrypoint, pinned)?;
        let allowed = AzurePipelinesScanner {
            policy: &policy,
            reader: &reader,
        }
        .scan(root.path())?;
        assert!(!allowed.is_blocking());
        assert_eq!(allowed.references.len(), 1);
        assert_eq!(
            serde_json::to_value(&allowed)?["files"],
            serde_json::json!(["ai-orchestrator-ci.yml", "pipelines/empty.yml"])
        );
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

    fn scan_azure(files: Vec<(&str, String)>) -> Result<PipelineScanReport> {
        let policy = Policy::default();
        let reader = R(files
            .into_iter()
            .map(|(file, body)| (file.to_string(), body))
            .collect());
        AzurePipelinesScanner {
            policy: &policy,
            reader: &reader,
        }
        .scan(Path::new("."))
    }

    fn shared_repository_resource(alias: &str, reference: &str) -> String {
        format!(
            "resources:\n  repositories:\n    - repository: {alias}\n      type: git\n      name: Circit/circit-app\n      ref: {reference}\n"
        )
    }

    #[test]
    fn azure_scanner_allows_sha_pinned_repository_resource() -> Result<()> {
        let body = shared_repository_resource("circitapp", &"a".repeat(40));
        let report = scan_azure(vec![("ci.yml", body)])?;
        assert!(!report.is_blocking(), "{:?}", report.findings);
        Ok(())
    }

    #[test]
    fn azure_scanner_allows_templates_and_checkouts_of_sha_pinned_alias() -> Result<()> {
        let body = format!(
            "{}steps:\n  - checkout: circitapp\n  - template: pipelines/templates/gitleaks-scan.yml@circitapp\n",
            shared_repository_resource("circitapp", &"a".repeat(40))
        );
        let report = scan_azure(vec![("ci.yml", body)])?;
        assert!(!report.is_blocking(), "{:?}", report.findings);
        Ok(())
    }

    #[test]
    fn azure_scanner_resolves_alias_declared_in_root_pipeline_for_nested_template() -> Result<()> {
        let root = format!(
            "{}stages:\n  - template: pipelines/stages/ci.yml\n",
            shared_repository_resource("circitapp", &"b".repeat(40))
        );
        let nested = "jobs:\n  - job: Gates\n    steps:\n      - template: pipelines/templates/gitleaks-scan.yml@circitapp\n".to_string();
        let report = scan_azure(vec![("ci.yml", root), ("pipelines/stages/ci.yml", nested)])?;
        assert!(!report.is_blocking(), "{:?}", report.findings);
        Ok(())
    }

    #[test]
    fn azure_scanner_blocks_template_when_any_alias_declaration_is_unpinned() -> Result<()> {
        let pinned = format!(
            "{}steps:\n  - template: a.yml@circitapp\n",
            shared_repository_resource("circitapp", &"c".repeat(40))
        );
        let unpinned = format!(
            "{}steps:\n  - checkout: circitapp\n",
            shared_repository_resource("circitapp", "refs/heads/develop")
        );
        let report = scan_azure(vec![("a.yml", pinned), ("b.yml", unpinned)])?;
        let blocked: Vec<_> = report
            .finding_locations
            .iter()
            .map(|r| (r.file.as_str(), r.kind.clone()))
            .collect();
        assert_eq!(
            blocked,
            vec![
                ("a.yml", PipelineRefKind::Template),
                ("b.yml", PipelineRefKind::Repository),
                ("b.yml", PipelineRefKind::Checkout),
            ]
        );
        Ok(())
    }

    #[test]
    fn azure_scanner_blocks_template_of_undeclared_alias() -> Result<()> {
        let report = scan_azure(vec![(
            "ci.yml",
            "steps:\n  - template: a.yml@circitapp\n".to_string(),
        )])?;
        assert!(report.is_blocking());
        Ok(())
    }
}
