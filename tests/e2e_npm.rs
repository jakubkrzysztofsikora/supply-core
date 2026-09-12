#![allow(clippy::unwrap_used)]

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use semver::Version;
use supply_core::adapters::crypto::ShaHasher;
use supply_core::adapters::npm::{package_version_from_metadata, HttpNpmRegistry};
use supply_core::adapters::osv::NoopVulnerabilitySource;
use supply_core::adapters::storage::{FsArtifactStore, MemoryMetadataStore};
use supply_core::application::{IngestService, PackageEvaluator};
use supply_core::domain::{DecisionStatus, Ecosystem, FrozenArtifact, PackageVersion, Policy};
use supply_core::ports::{Clock, MetadataStore, UpstreamNpmRegistry};

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

/// Corrupts the first tarball byte: simulates upstream tamper
/// (compromised mirror, MITM, hijacked maintainer re-publish).
struct TamperRegistry<'a> {
    inner: &'a HttpNpmRegistry,
}
impl UpstreamNpmRegistry for TamperRegistry<'_> {
    fn metadata(&self, package: &str) -> Result<serde_json::Value> {
        self.inner.metadata(package)
    }
    fn tarball(&self, url: &str) -> Result<Vec<u8>> {
        let mut bytes = self.inner.tarball(url)?;
        if let Some(first) = bytes.first_mut() {
            *first ^= 0xff;
        }
        Ok(bytes)
    }
}

fn fixture(registry: &HttpNpmRegistry) -> Result<PackageVersion> {
    let name = "left-pad";
    let metadata = registry.metadata(name).context("fetch registry metadata")?;
    package_version_from_metadata(&metadata, name, &Version::parse("1.3.0")?)
        .context("map metadata to domain")
}

/// Full real-registry flow per docs/e2e-npm-plan.md: fetch → evaluate →
/// verified freeze → quarantine fallback → denylist block.
#[test]
#[ignore = "hits registry.npmjs.org"]
fn left_pad_end_to_end() -> Result<()> {
    let name = "left-pad";
    let version = Version::parse("1.3.0")?;
    let registry = HttpNpmRegistry::new()?;
    let pv = fixture(&registry)?;
    let published_at = pv
        .published_at
        .context("publish time missing from registry metadata")?;

    let store = MemoryMetadataStore::default();
    let policy = Policy::default();
    let allow = PackageEvaluator {
        policy: &policy,
        clock: &SystemClock,
        vulns: &NoopVulnerabilitySource,
        metadata: &store,
    }
    .evaluate(&pv, None)
    .context("evaluate for allow")?;
    assert_eq!(
        allow.status,
        DecisionStatus::Allow,
        "2018 publish date must clear the 7-day quarantine"
    );

    let dir = tempfile::tempdir()?;
    let artifacts = FsArtifactStore {
        root: dir.path().to_path_buf(),
    };
    let hasher = ShaHasher;
    let frozen: FrozenArtifact = IngestService {
        policy: &policy,
        registry: &registry,
        hasher: &hasher,
        artifacts: &artifacts,
        metadata: &store,
        clock: &SystemClock,
    }
    .freeze_verified(&pv)
    .context("verified freeze of real tarball")?;
    assert_eq!(frozen.version, version);
    assert_eq!(
        store.latest_frozen(&Ecosystem::Npm, name)?.unwrap().version,
        version
    );

    let quarantined_clock = FixedClock(published_at + Duration::days(2));
    let fallback = PackageEvaluator {
        policy: &policy,
        clock: &quarantined_clock,
        vulns: &NoopVulnerabilitySource,
        metadata: &store,
    }
    .evaluate(&pv, None)
    .context("evaluate quarantine fallback")?;
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
    .evaluate(&pv, None)
    .context("evaluate denylist block")?;
    assert_eq!(
        denied.status,
        DecisionStatus::Block,
        "denylist must never serve, even with frozen copy available"
    );

    Ok(())
}

/// 0-day simulation per docs/e2e-npm-plan.md: a brand-new version with no
/// advisory yet (noop vuln source = CVE-less malware case). The quarantine
/// window must catch it, the frozen copy must rescue the build, tampered
/// upstream bytes must never freeze, and a 0-day with no frozen fallback
/// must hard-block.
#[test]
#[ignore = "hits registry.npmjs.org"]
fn zero_day_update_quarantined_tamper_blocked() -> Result<()> {
    let registry = HttpNpmRegistry::new()?;
    let known_good = fixture(&registry)?;

    let dir = tempfile::tempdir()?;
    let artifacts = FsArtifactStore {
        root: dir.path().to_path_buf(),
    };
    let policy = Policy::default();
    let hasher = ShaHasher;
    let store = MemoryMetadataStore::default();
    let ingest = IngestService {
        policy: &policy,
        registry: &registry,
        hasher: &hasher,
        artifacts: &artifacts,
        metadata: &store,
        clock: &SystemClock,
    };
    ingest
        .freeze_verified(&known_good)
        .context("baseline freeze of known-good 1.3.0")?;

    // 0-day: version 9.9.9 published 2 days ago. Vuln source is a noop:
    // exactly the "no CVE assigned yet" supply-chain attack window.
    let zero_day = PackageVersion {
        package: known_good.package.clone(),
        version: Version::parse("9.9.9")?,
        published_at: Some(Utc::now() - Duration::days(2)),
        integrity: known_good.integrity.clone(),
        tarball_url: known_good.tarball_url.clone(),
    };

    // Tampered upstream (compromised mirror): verified ingest must refuse.
    let tamper_ingest = IngestService {
        policy: &policy,
        registry: &TamperRegistry { inner: &registry },
        hasher: &hasher,
        artifacts: &artifacts,
        metadata: &store,
        clock: &SystemClock,
    };
    let tampered = tamper_ingest.freeze_verified(&known_good);
    assert!(
        tampered.is_err(),
        "integrity mismatch must never produce a frozen artifact"
    );
    assert!(tampered
        .unwrap_err()
        .to_string()
        .contains("integrity mismatch"));

    // Quarantine catches the 0-day; frozen 1.3.0 rescues the build.
    // Range-aware: ^1.0.0 satisfied by frozen 1.3.0; ^9.0.0 must block.
    let caret_one = semver::VersionReq::parse("^1.0.0")?;
    let decision = PackageEvaluator {
        policy: &policy,
        clock: &SystemClock,
        vulns: &NoopVulnerabilitySource,
        metadata: &store,
    }
    .evaluate(&zero_day, Some(&caret_one))
    .context("evaluate 0-day")?;
    assert_eq!(
        decision.status,
        DecisionStatus::Fallback,
        "0-day inside quarantine window must fall back"
    );
    assert_eq!(decision.served_version.as_deref(), Some("1.3.0"));
    assert!(decision.warnings.iter().any(|w| w.contains("quarantine")));

    let caret_nine = semver::VersionReq::parse("^9.0.0")?;
    let unsatisfiable = PackageEvaluator {
        policy: &policy,
        clock: &SystemClock,
        vulns: &NoopVulnerabilitySource,
        metadata: &store,
    }
    .evaluate(&zero_day, Some(&caret_nine))?;
    assert_eq!(
        unsatisfiable.status,
        DecisionStatus::Block,
        "range not satisfied by any frozen version must block, not serve wrong major"
    );

    // Same 0-day with nothing frozen: hard block, no silent allow.
    let empty_store = MemoryMetadataStore::default();
    let blocked = PackageEvaluator {
        policy: &policy,
        clock: &SystemClock,
        vulns: &NoopVulnerabilitySource,
        metadata: &empty_store,
    }
    .evaluate(&zero_day, None)?;
    assert_eq!(
        blocked.status,
        DecisionStatus::Block,
        "0-day with no frozen fallback must block"
    );

    // After the quarantine window expires (30 days), the same version
    // is allowed — the cooldown is the only CVE-less control.
    let aged_clock = FixedClock(Utc::now() + Duration::days(30));
    let aged = PackageEvaluator {
        policy: &policy,
        clock: &aged_clock,
        vulns: &NoopVulnerabilitySource,
        metadata: &empty_store,
    }
    .evaluate(&zero_day, None)?;
    assert_eq!(aged.status, DecisionStatus::Allow);

    Ok(())
}

/// Registry immutability: compromised mirror re-publishing the same
/// version with different (self-consistently hashed) bytes must be
/// rejected against the frozen ledger.
#[test]
#[ignore = "hits registry.npmjs.org"]
fn same_version_republish_detected() -> Result<()> {
    let registry = HttpNpmRegistry::new()?;
    let pv = fixture(&registry)?;

    let dir = tempfile::tempdir()?;
    let artifacts = FsArtifactStore {
        root: dir.path().to_path_buf(),
    };
    let policy = Policy::default();
    let hasher = ShaHasher;
    let store = MemoryMetadataStore::default();
    let baseline = IngestService {
        policy: &policy,
        registry: &registry,
        hasher: &hasher,
        artifacts: &artifacts,
        metadata: &store,
        clock: &SystemClock,
    }
    .freeze_verified(&pv)
    .context("baseline freeze of real 1.3.0")?;

    // Attacker mirror serves different bytes for the same version, with
    // an integrity string matching those bytes — so sha512 alone would
    // pass; only the frozen-ledger conflict detects the re-publish.
    let tamper = TamperRegistry { inner: &registry };
    let tampered_bytes = tamper.tarball(pv.tarball_url.as_deref().unwrap())?;
    let mut republish = pv.clone();
    republish.integrity = Some(sri_sha512(&tampered_bytes));
    let conflict = IngestService {
        policy: &policy,
        registry: &tamper,
        hasher: &hasher,
        artifacts: &artifacts,
        metadata: &store,
        clock: &SystemClock,
    }
    .freeze_verified(&republish);
    let err = conflict.unwrap_err().to_string();
    assert!(
        err.contains("immutability violation"),
        "expected immutability violation, got: {err}"
    );
    assert_eq!(
        store
            .latest_frozen(&Ecosystem::Npm, "left-pad")?
            .unwrap()
            .sha256,
        baseline.sha256,
        "ledger must keep original bytes after refused re-publish"
    );
    Ok(())
}

fn sri_sha512(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use sha2::Digest;
    format!("sha512-{}", STANDARD.encode(sha2::Sha512::digest(bytes)))
}
