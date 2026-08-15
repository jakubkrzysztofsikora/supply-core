use crate::domain::*;
use crate::ports::*;
use anyhow::Result;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct PackageEvaluator<'a> {
    pub policy: &'a Policy,
    pub clock: &'a dyn Clock,
    pub vulns: &'a dyn VulnerabilitySource,
    pub metadata: &'a dyn MetadataStore,
}
impl<'a> PackageEvaluator<'a> {
    pub fn evaluate(&self, version: &PackageVersion) -> Result<Decision> {
        let name = &version.package.name;
        if self.policy.npm.deny_packages.contains(name) {
            return self.fallback_or_block(name, &version.version, "package is denylisted");
        }
        if self.policy.npm.require_integrity && version.integrity.is_none() {
            return self.fallback_or_block(
                name,
                &version.version,
                "package version is missing npm integrity",
            );
        }
        let findings = self.vulns.query(Ecosystem::Npm, name, &version.version)?;
        if let Some(reason) = blocks_vulnerability(&findings, &self.policy.vulnerabilities) {
            return self.fallback_or_block(name, &version.version, reason);
        }
        if is_version_quarantined(
            version.published_at,
            self.clock.now(),
            &self.policy.quarantine,
        ) {
            return self.fallback_or_block(
                name,
                &version.version,
                "package version is inside quarantine window",
            );
        }
        Ok(Decision::allow(name.clone(), version.version.to_string()))
    }
    fn fallback_or_block(
        &self,
        name: &str,
        requested: &Version,
        reason: impl Into<String>,
    ) -> Result<Decision> {
        let reason = reason.into();
        if self.policy.npm.fallback_to_frozen {
            if let Some(frozen) = self.metadata.latest_frozen(name)? {
                return Ok(Decision::fallback(
                    name,
                    requested.to_string(),
                    frozen.version.to_string(),
                    reason,
                ));
            }
        }
        Ok(Decision::block(name, Some(requested.to_string()), reason))
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
    let rest = s
        .strip_prefix("uses:")?
        .trim()
        .trim_matches('"')
        .trim_matches('\'');
    Some(rest.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::{path::Path, sync::Mutex};
    struct C;
    impl Clock for C {
        fn now(&self) -> chrono::DateTime<Utc> {
            Utc::now()
        }
    }
    struct V(Vec<VulnerabilityFinding>);
    impl VulnerabilitySource for V {
        fn query(&self, _: Ecosystem, _: &str, _: &Version) -> Result<Vec<VulnerabilityFinding>> {
            Ok(self.0.clone())
        }
    }
    struct M(Mutex<Option<FrozenArtifact>>);
    impl MetadataStore for M {
        fn save_decision(&self, _: &Decision) -> Result<()> {
            Ok(())
        }
        fn latest_frozen(&self, _: &str) -> Result<Option<FrozenArtifact>> {
            Ok(self
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("lock poisoned"))?
                .clone())
        }
        fn put_frozen(&self, _: FrozenArtifact) -> Result<()> {
            Ok(())
        }
    }
    #[test]
    fn falls_back_instead_of_error() -> Result<()> {
        let p = Policy::default();
        let m = M(Mutex::new(Some(FrozenArtifact {
            package: PackageCoordinate {
                ecosystem: Ecosystem::Npm,
                name: "left-pad".into(),
            },
            version: Version::parse("1.0.0")?,
            sha256: "x".into(),
            integrity: None,
            path: "p".into(),
            frozen_at: Utc::now(),
        })));
        let e = PackageEvaluator {
            policy: &p,
            clock: &C,
            vulns: &V(vec![]),
            metadata: &m,
        };
        let v = PackageVersion {
            package: PackageCoordinate {
                ecosystem: Ecosystem::Npm,
                name: "left-pad".into(),
            },
            version: Version::parse("2.0.0")?,
            published_at: Some(Utc::now()),
            integrity: Some("sha512-x".into()),
            tarball_url: None,
        };
        let d = e.evaluate(&v)?;
        assert_eq!(d.status, DecisionStatus::Fallback);
        assert_eq!(d.served_version.as_deref(), Some("1.0.0"));
        Ok(())
    }
    struct R;
    impl WorkflowReader for R {
        fn read(&self, _: &Path) -> Result<Vec<(String, String)>> {
            Ok(vec![(
                ".github/workflows/ci.yml".into(),
                "steps:\n - uses: actions/checkout@v4".into(),
            )])
        }
    }
    #[test]
    fn scans_unpinned_actions() -> Result<()> {
        let s = GitHubActionsScanner {
            policy: &Policy::default(),
            reader: &R,
        };
        let r = s.scan(Path::new("."))?;
        assert!(r.is_blocking());
        Ok(())
    }
}
