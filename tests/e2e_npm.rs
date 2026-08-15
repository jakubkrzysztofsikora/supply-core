#![allow(clippy::unwrap_used)]

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use semver::Version;
use supply_core::adapters::crypto::ShaHasher;
use supply_core::adapters::npm::{package_version_from_metadata, HttpNpmRegistry};
use supply_core::adapters::osv::NoopVulnerabilitySource;
use supply_core::adapters::storage::{FsArtifactStore, MemoryMetadataStore};
use supply_core::application::PackageEvaluator;
use supply_core::domain::{DecisionStatus, FrozenArtifact, Policy};
use supply_core::ports::{ArtifactStore, Clock, Hasher, MetadataStore, UpstreamNpmRegistry};

struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

struct FixedClock(DateTime<Utc>);
impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

/// Full real-registry flow per docs/e2e-npm-plan.md: fetch → evaluate →
/// verify integrity → freeze → quarantine fallback → denylist block.
#[test]
#[ignore = "hits registry.npmjs.org"]
fn left_pad_end_to_end() -> Result<()> {
    let name = "left-pad";
    let version = Version::parse("1.3.0")?;
    let registry = HttpNpmRegistry::default();

    let metadata = registry
        .metadata(name)
        .context("step 1: fetch registry metadata")?;
    let pv = package_version_from_metadata(&metadata, name, &version)
        .context("step 2: map metadata to domain")?;
    let published_at = pv
        .published_at
        .context("step 2: publish time missing from registry metadata")?;

    let store = MemoryMetadataStore::default();
    let policy = Policy::default();
    let allow = PackageEvaluator {
        policy: &policy,
        clock: &SystemClock,
        vulns: &NoopVulnerabilitySource,
        metadata: &store,
    }
    .evaluate(&pv)
    .context("step 3: evaluate for allow")?;
    assert_eq!(
        allow.status,
        DecisionStatus::Allow,
        "2018 publish date must clear the 7-day quarantine"
    );

    let tarball_url = pv
        .tarball_url
        .clone()
        .context("step 4: tarball url missing")?;
    let integrity = pv.integrity.clone().context("step 5: integrity missing")?;
    let bytes = registry
        .tarball(&tarball_url)
        .context("step 4: fetch tarball")?;

    let hasher = ShaHasher;
    assert!(
        hasher.verify_npm_integrity(&bytes, &integrity),
        "step 5: sha512 integrity must match real registry bytes"
    );

    let dir = tempfile::tempdir()?;
    let artifacts = FsArtifactStore {
        root: dir.path().to_path_buf(),
    };
    let path = artifacts
        .put(name, &version, &bytes)
        .context("step 6: freeze artifact")?;
    let frozen = FrozenArtifact {
        package: pv.package.clone(),
        version: version.clone(),
        sha256: hasher.sha256(&bytes),
        integrity: Some(integrity.clone()),
        path,
        frozen_at: Utc::now(),
    };
    store.put_frozen(frozen).context("step 6: record frozen")?;
    assert_eq!(store.latest_frozen(name)?.unwrap().version, version);

    let quarantined_clock = FixedClock(published_at + Duration::days(2));
    let fallback = PackageEvaluator {
        policy: &policy,
        clock: &quarantined_clock,
        vulns: &NoopVulnerabilitySource,
        metadata: &store,
    }
    .evaluate(&pv)
    .context("step 7: evaluate quarantine fallback")?;
    assert_eq!(fallback.status, DecisionStatus::Fallback);
    assert_eq!(fallback.served_version.as_deref(), Some("1.3.0"));

    let mut denied_policy = Policy::default();
    denied_policy.npm.deny_packages = vec![name.to_string()];
    let denied = PackageEvaluator {
        policy: &denied_policy,
        clock: &SystemClock,
        vulns: &NoopVulnerabilitySource,
        metadata: &store,
    }
    .evaluate(&pv)
    .context("step 8: evaluate denylist block")?;
    assert_eq!(
        denied.status,
        DecisionStatus::Block,
        "denylist must never serve, even with frozen copy available"
    );

    Ok(())
}
