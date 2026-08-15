use chrono::{DateTime, Utc};
use semver::Version;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    Npm,
    GitHubActions,
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
pub struct QuarantinePolicy {
    pub enabled: bool,
    pub minimum_age_days: i64,
}
impl Default for QuarantinePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            minimum_age_days: 7,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Policy {
    pub quarantine: QuarantinePolicy,
    pub vulnerabilities: VulnerabilityPolicy,
    pub npm: NpmPolicy,
    pub github_actions: GitHubActionsPolicy,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionPinKind {
    FullSha,
    TagOrBranch,
    Local,
    Docker,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHubActionReference {
    pub raw: String,
    pub file: String,
    pub line: usize,
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

pub fn blocks_vulnerability(
    findings: &[VulnerabilityFinding],
    policy: &VulnerabilityPolicy,
) -> Option<String> {
    let min_rank = policy.block_severities.iter().map(Severity::rank).min()?;
    findings
        .iter()
        .find(|f| f.severity.rank() >= min_rank)
        .map(|f| {
            format!(
                "{} vulnerability {} from {}",
                match f.severity {
                    Severity::Critical => "critical",
                    Severity::High => "high",
                    Severity::Medium => "medium",
                    Severity::Low => "low",
                },
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
                minimum_age_days: 7
            }
        ));
        assert!(!is_version_quarantined(
            Some(now - Duration::days(8)),
            now,
            &QuarantinePolicy {
                enabled: true,
                minimum_age_days: 7
            }
        ));
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
}
