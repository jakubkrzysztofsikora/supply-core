use chrono::{DateTime, Utc};
use semver::Version;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    Npm,
    PyPi,
    NuGet,
    DockerImage,
    GitHubActions,
    AzurePipelines,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackageCoordinate {
    pub ecosystem: Ecosystem,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageVersion {
    pub package: PackageCoordinate,
    pub version: Version,
    pub published_at: Option<DateTime<Utc>>,
    pub integrity: Option<String>,
    pub tarball_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenArtifact {
    pub package: PackageCoordinate,
    pub version: Version,
    pub sha256: String,
    pub integrity: Option<String>,
    pub path: String,
    pub frozen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}
impl Severity {
    pub fn rank(&self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub source: String,
    pub id: String,
    pub severity: Severity,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionStatus {
    Allow,
    Warn,
    Block,
    Quarantine,
    Fallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub status: DecisionStatus,
    pub package: String,
    pub requested_version: Option<String>,
    pub served_version: Option<String>,
    pub reasons: Vec<String>,
    pub warnings: Vec<String>,
}
impl Decision {
    pub fn allow(package: impl Into<String>, version: impl Into<String>) -> Self {
        let version = version.into();
        Self {
            status: DecisionStatus::Allow,
            package: package.into(),
            requested_version: Some(version.clone()),
            served_version: Some(version),
            reasons: vec![],
            warnings: vec![],
        }
    }
    pub fn fallback(
        package: impl Into<String>,
        requested: impl Into<String>,
        served: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            status: DecisionStatus::Fallback,
            package: package.into(),
            requested_version: Some(requested.into()),
            served_version: Some(served.into()),
            reasons: vec![],
            warnings: vec![reason.into()],
        }
    }
    pub fn block(
        package: impl Into<String>,
        requested: Option<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            status: DecisionStatus::Block,
            package: package.into(),
            requested_version: requested,
            served_version: None,
            reasons: vec![reason.into()],
            warnings: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct QuarantinePolicy {
    pub enabled: bool,
    pub minimum_age_days: i64,
    pub cve_keeps_quarantined: bool,
}
impl Default for QuarantinePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            minimum_age_days: 7,
            cve_keeps_quarantined: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VulnerabilityPolicy {
    pub block_severities: Vec<Severity>,
}
impl Default for VulnerabilityPolicy {
    fn default() -> Self {
        Self {
            block_severities: vec![Severity::High, Severity::Critical],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImagePinKind {
    Digest,
    InvalidDigest,
    Tag,
    Latest,
    MissingTag,
    Unresolved,
}

pub fn classify_image_ref(raw: &str) -> ImagePinKind {
    let trimmed = raw.trim().trim_matches(['"', '\'']);
    if trimmed.is_empty() || trimmed.contains('$') {
        return ImagePinKind::Unresolved;
    }
    if let Some((_, digest)) = trimmed.split_once('@') {
        let valid = digest
            .strip_prefix("sha256:")
            .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()));
        return if valid {
            ImagePinKind::Digest
        } else {
            ImagePinKind::InvalidDigest
        };
    }
    let last_slash = trimmed.rfind('/');
    let last_colon = trimmed.rfind(':');
    match last_colon {
        Some(colon) if last_slash.is_none_or(|slash| colon > slash) => {
            match &trimmed[colon + 1..] {
                "" => ImagePinKind::MissingTag,
                "latest" => ImagePinKind::Latest,
                _ => ImagePinKind::Tag,
            }
        }
        _ => ImagePinKind::MissingTag,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PipPolicy {
    pub require_integrity: bool,
    pub fallback_to_frozen: bool,
}
impl Default for PipPolicy {
    fn default() -> Self {
        Self {
            require_integrity: true,
            fallback_to_frozen: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NuGetPolicy {
    pub require_integrity: bool,
    pub fallback_to_frozen: bool,
}
impl Default for NuGetPolicy {
    fn default() -> Self {
        Self {
            require_integrity: true,
            fallback_to_frozen: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerPolicy {
    pub require_digest_pin: bool,
}
impl Default for DockerPolicy {
    fn default() -> Self {
        Self {
            require_digest_pin: true,
        }
    }
}

fn default_detected_at() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentFinding {
    pub ecosystem: Ecosystem,
    pub package: String,
    pub version: Version,
    pub source: String,
    pub score: u8,
    pub rules: Vec<String>,
    pub summary: String,
    #[serde(default = "default_detected_at")]
    pub detected_at: chrono::DateTime<chrono::Utc>,
}
impl ContentFinding {
    /// OSV-shaped record, ready to attach to an `ossf/malicious-packages`
    /// contribution or a GitHub advisory.
    pub fn to_osv(&self) -> serde_json::Value {
        let ecosystem = match self.ecosystem {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPi => "PyPI",
            Ecosystem::NuGet => "NuGet",
            _ => "unknown",
        };
        let sanitized = |raw: &str| -> String {
            raw.chars()
                .map(|character| {
                    if character.is_ascii_alphanumeric() {
                        character.to_ascii_uppercase()
                    } else {
                        '-'
                    }
                })
                .collect()
        };
        serde_json::json!({
            "schema_version": "1.7.0",
            "id": format!(
                "SUPPLY-{}-{}",
                sanitized(&self.package),
                sanitized(&self.version.to_string())
            ),
            "modified": self.detected_at.to_rfc3339(),
            "summary": self.summary,
            "details": format!(
                "rules: {}; source: {}",
                self.rules.join(", "),
                self.source
            ),
            "affected": [{
                "package": { "ecosystem": ecosystem, "name": self.package },
                "versions": [self.version.to_string()]
            }],
            "references": []
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct QuarantineScannerPolicy {
    pub enabled: bool,
    pub review_score: u8,
    pub block_score: u8,
}
impl Default for QuarantineScannerPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            review_score: 4,
            block_score: 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NpmPolicy {
    pub require_integrity: bool,
    pub fallback_to_frozen: bool,
    pub deny_packages: Vec<String>,
}
impl Default for NpmPolicy {
    fn default() -> Self {
        Self {
            require_integrity: true,
            fallback_to_frozen: true,
            deny_packages: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GitHubActionsPolicy {
    pub require_full_sha_pin: bool,
    pub allow_local_actions: bool,
}
impl Default for GitHubActionsPolicy {
    fn default() -> Self {
        Self {
            require_full_sha_pin: true,
            allow_local_actions: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AzurePipelinesPolicy {
    pub require_task_version: bool,
    pub require_full_sha_pin: bool,
    pub allow_local_templates: bool,
    pub allowed_unpinned_checkouts: Vec<String>,
    pub allowed_unpinned_tasks: Vec<String>,
    pub allowed_unpinned_repositories: Vec<String>,
}
impl Default for AzurePipelinesPolicy {
    fn default() -> Self {
        Self {
            require_task_version: true,
            require_full_sha_pin: true,
            allow_local_templates: true,
            allowed_unpinned_checkouts: vec![],
            allowed_unpinned_tasks: vec![],
            allowed_unpinned_repositories: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ServerPolicy {
    pub service_url: String,
    pub allow_fallback: bool,
    pub force_official: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Policy {
    #[serde(default)]
    pub server: ServerPolicy,
    #[serde(default)]
    pub quarantine: QuarantinePolicy,
    #[serde(default)]
    pub vulnerabilities: VulnerabilityPolicy,
    #[serde(default)]
    pub npm: NpmPolicy,
    #[serde(default)]
    pub pip: PipPolicy,
    #[serde(default)]
    pub nuget: NuGetPolicy,
    #[serde(default)]
    pub docker: DockerPolicy,
    #[serde(default)]
    pub quarantine_scanner: QuarantineScannerPolicy,
    #[serde(default)]
    pub github_actions: GitHubActionsPolicy,
    #[serde(default)]
    pub azure_pipelines: AzurePipelinesPolicy,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionPinKind {
    FullSha,
    TagOrBranch,
    Local,
    Docker,
    TaskVersion,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHubActionReference {
    pub raw: String,
    pub file: String,
    pub line: usize,
    pub pin_kind: ActionPinKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipelineRefKind {
    Action,
    Task,
    Checkout,
    Template,
    Repository,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineReference {
    pub raw: String,
    pub file: String,
    pub line: usize,
    pub kind: PipelineRefKind,
    pub pin_kind: ActionPinKind,
}

pub fn classify_action_ref(raw: &str) -> ActionPinKind {
    if raw.starts_with("./") {
        return ActionPinKind::Local;
    }
    if raw.starts_with("docker://") {
        return ActionPinKind::Docker;
    }
    let Some((_, reference)) = raw.rsplit_once('@') else {
        return ActionPinKind::Unknown;
    };
    if reference.len() == 40 && reference.chars().all(|c| c.is_ascii_hexdigit()) {
        ActionPinKind::FullSha
    } else {
        ActionPinKind::TagOrBranch
    }
}

pub fn classify_pipeline_ref(raw: &str, kind: &PipelineRefKind) -> ActionPinKind {
    match kind {
        PipelineRefKind::Task => {
            if let Some((_, version)) = raw.rsplit_once('@') {
                if !version.is_empty() {
                    if version.len() == 40 && version.chars().all(|c| c.is_ascii_hexdigit()) {
                        ActionPinKind::FullSha
                    } else {
                        ActionPinKind::TaskVersion
                    }
                } else {
                    ActionPinKind::Unknown
                }
            } else {
                ActionPinKind::Unknown
            }
        }
        PipelineRefKind::Checkout => {
            if raw == "self" || raw == "none" {
                ActionPinKind::Local
            } else if let Some((_, reference)) = raw.rsplit_once('@') {
                if reference.len() == 40 && reference.chars().all(|c| c.is_ascii_hexdigit()) {
                    ActionPinKind::FullSha
                } else {
                    ActionPinKind::TagOrBranch
                }
            } else {
                ActionPinKind::TagOrBranch
            }
        }
        PipelineRefKind::Template => {
            if let Some((_, suffix)) = raw.rsplit_once('@') {
                if suffix.len() == 40 && suffix.chars().all(|c| c.is_ascii_hexdigit()) {
                    ActionPinKind::FullSha
                } else {
                    ActionPinKind::TagOrBranch
                }
            } else {
                ActionPinKind::Local
            }
        }
        PipelineRefKind::Repository => {
            let trimmed = raw
                .strip_prefix("refs/heads/")
                .or_else(|| raw.strip_prefix("refs/tags/"))
                .unwrap_or(raw);
            if trimmed.len() == 40 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                ActionPinKind::FullSha
            } else if !trimmed.is_empty() {
                ActionPinKind::TagOrBranch
            } else {
                ActionPinKind::Unknown
            }
        }
        PipelineRefKind::Action => classify_action_ref(raw),
    }
}

pub fn is_version_quarantined(
    published_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    policy: &QuarantinePolicy,
) -> bool {
    policy.enabled
        && match published_at {
            Some(p) => now.signed_duration_since(p).num_days() < policy.minimum_age_days,
            None => true,
        }
}

fn severity_word(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

pub fn strongest_vulnerability(findings: &[VulnerabilityFinding]) -> Option<String> {
    findings
        .iter()
        .max_by_key(|f| (f.severity.rank(), f.id.as_str()))
        .map(|f| {
            format!(
                "{} vulnerability {} from {}",
                severity_word(&f.severity),
                f.id,
                f.source
            )
        })
}

pub fn blocks_vulnerability(
    findings: &[VulnerabilityFinding],
    policy: &VulnerabilityPolicy,
) -> Option<String> {
    let min_rank = policy.block_severities.iter().map(Severity::rank).min()?;
    findings
        .iter()
        .filter(|f| f.severity.rank() >= min_rank)
        .max_by_key(|f| (f.severity.rank(), f.id.as_str()))
        .map(|f| {
            format!(
                "{} vulnerability {} from {}",
                severity_word(&f.severity),
                f.id,
                f.source
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    #[test]
    fn classifies_actions() {
        assert_eq!(
            classify_action_ref("actions/checkout@v4"),
            ActionPinKind::TagOrBranch
        );
        assert_eq!(
            classify_action_ref("./.github/actions/x"),
            ActionPinKind::Local
        );
        assert_eq!(
            classify_action_ref("docker://node:20"),
            ActionPinKind::Docker
        );
        assert_eq!(
            classify_action_ref("a/b@0123456789abcdef0123456789abcdef01234567"),
            ActionPinKind::FullSha
        );
    }
    #[test]
    fn quarantine_by_age() {
        let now = Utc::now();
        assert!(is_version_quarantined(
            Some(now - Duration::days(2)),
            now,
            &QuarantinePolicy {
                enabled: true,
                minimum_age_days: 7,
                cve_keeps_quarantined: true
            }
        ));
        assert!(!is_version_quarantined(
            Some(now - Duration::days(8)),
            now,
            &QuarantinePolicy {
                enabled: true,
                minimum_age_days: 7,
                cve_keeps_quarantined: true
            }
        ));
    }
    #[test]
    fn content_finding_serializes_to_osv_record() {
        let finding = ContentFinding {
            ecosystem: Ecosystem::Npm,
            package: "evil-pkg".into(),
            version: Version::parse("1.2.3").unwrap_or_else(|_| panic!("valid semver")),
            source: "static-heuristics".into(),
            score: 9,
            rules: vec!["install-script-network".into()],
            summary: "postinstall beacon".into(),
            detected_at: chrono::Utc::now(),
        };
        let record = finding.to_osv();
        assert_eq!(record["id"], "SUPPLY-EVIL-PKG-1-2-3");
        assert!(
            record["modified"]
                .as_str()
                .is_some_and(|modified| modified.contains('T')),
            "OSV records need an RFC3339 modified timestamp"
        );
        assert_eq!(record["affected"][0]["package"]["ecosystem"], "npm");
        assert_eq!(record["affected"][0]["package"]["name"], "evil-pkg");
        assert_eq!(record["affected"][0]["versions"][0], "1.2.3");
        assert_eq!(record["summary"], "postinstall beacon");
        assert!(record["details"]
            .as_str()
            .is_some_and(|details| details.contains("install-script-network")));
    }
    #[test]
    fn scanner_policy_defaults_are_disabled() {
        let p = Policy::default();
        assert!(!p.quarantine_scanner.enabled);
        assert_eq!(p.quarantine_scanner.review_score, 4);
        assert_eq!(p.quarantine_scanner.block_score, 8);
    }
    #[test]
    fn classifies_image_references() {
        let pinned = format!("nginx@sha256:{}", "a".repeat(64));
        assert_eq!(classify_image_ref(&pinned), ImagePinKind::Digest);
        assert_eq!(
            classify_image_ref("nginx@sha256:deadbeef"),
            ImagePinKind::InvalidDigest
        );
        assert_eq!(classify_image_ref("nginx:1.27-alpine"), ImagePinKind::Tag);
        assert_eq!(classify_image_ref("nginx:latest"), ImagePinKind::Latest);
        assert_eq!(classify_image_ref("nginx"), ImagePinKind::MissingTag);
        assert_eq!(
            classify_image_ref("ghcr.io/org/app@sha256:abc123"),
            ImagePinKind::InvalidDigest
        );
        assert_eq!(
            classify_image_ref("localhost:5000/app:1.2"),
            ImagePinKind::Tag
        );
        assert_eq!(classify_image_ref("$BASE_IMAGE"), ImagePinKind::Unresolved);
        assert_eq!(
            classify_image_ref("${BASE_IMAGE}:1"),
            ImagePinKind::Unresolved
        );
    }
    #[test]
    fn ecosystem_policies_have_secure_defaults() {
        let p = Policy::default();
        assert!(p.pip.require_integrity);
        assert!(p.pip.fallback_to_frozen);
        assert!(p.nuget.require_integrity);
        assert!(p.nuget.fallback_to_frozen);
        assert!(p.docker.require_digest_pin);
    }
    #[test]
    fn strongest_vulnerability_is_order_independent() {
        let finding = |id: &str| VulnerabilityFinding {
            source: "OSV".into(),
            id: id.into(),
            severity: Severity::Medium,
            summary: "x".into(),
        };
        let forward = vec![finding("GHSA-a"), finding("GHSA-b")];
        let reverse = vec![finding("GHSA-b"), finding("GHSA-a")];
        assert_eq!(
            strongest_vulnerability(&forward),
            strongest_vulnerability(&reverse)
        );
    }
    #[test]
    fn vuln_threshold() {
        let f = vec![VulnerabilityFinding {
            source: "OSV".into(),
            id: "GHSA-x".into(),
            severity: Severity::High,
            summary: "x".into(),
        }];
        assert!(blocks_vulnerability(&f, &VulnerabilityPolicy::default()).is_some());
    }
    #[test]
    fn classifies_pipeline_refs() {
        assert_eq!(
            classify_pipeline_ref("AzureCLI@2", &PipelineRefKind::Task),
            ActionPinKind::TaskVersion
        );
        assert_eq!(
            classify_pipeline_ref("UseNode@1.2.3", &PipelineRefKind::Task),
            ActionPinKind::TaskVersion
        );
        assert_eq!(
            classify_pipeline_ref("AzureCLI", &PipelineRefKind::Task),
            ActionPinKind::Unknown
        );
        assert_eq!(
            classify_pipeline_ref("self", &PipelineRefKind::Checkout),
            ActionPinKind::Local
        );
        assert_eq!(
            classify_pipeline_ref("none", &PipelineRefKind::Checkout),
            ActionPinKind::Local
        );
        assert_eq!(
            classify_pipeline_ref(
                "git://Circit/release-notes-generator",
                &PipelineRefKind::Checkout
            ),
            ActionPinKind::TagOrBranch
        );
        assert_eq!(
            classify_pipeline_ref(
                "git://Circit/repo@0123456789abcdef0123456789abcdef01234567",
                &PipelineRefKind::Checkout
            ),
            ActionPinKind::FullSha
        );
        assert_eq!(
            classify_pipeline_ref("../templates/bicep.yml", &PipelineRefKind::Template),
            ActionPinKind::Local
        );
        assert_eq!(
            classify_pipeline_ref("template.yml@common-templates", &PipelineRefKind::Template),
            ActionPinKind::TagOrBranch
        );
        assert_eq!(
            classify_pipeline_ref(
                "template.yml@common@0123456789abcdef0123456789abcdef01234567",
                &PipelineRefKind::Template
            ),
            ActionPinKind::FullSha
        );
        assert_eq!(
            classify_pipeline_ref(
                "0123456789abcdef0123456789abcdef01234567",
                &PipelineRefKind::Repository
            ),
            ActionPinKind::FullSha
        );
        assert_eq!(
            classify_pipeline_ref("refs/heads/main", &PipelineRefKind::Repository),
            ActionPinKind::TagOrBranch
        );
    }
}
