use crate::{
    adapters::{npm, nuget},
    application::{PackageEvaluator, VersionSelection},
    domain::{DecisionStatus, Ecosystem, PackageVersionId},
    ports::Clock,
};
use anyhow::{Context, Result};
use base64::Engine;
use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

#[derive(Serialize)]
pub struct PackageScanInput {
    pub path: String,
    pub sha256: String,
}
#[derive(Serialize)]
pub struct PackageScanEntry {
    pub ecosystem: String,
    pub source: String,
    pub name: String,
    pub locked_version: String,
    pub status: String,
    pub reasons: Vec<String>,
    pub warnings: Vec<String>,
    pub originating_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_attestation: Option<String>,
}
#[derive(Serialize)]
pub struct PackageScanReport {
    pub inputs: Vec<PackageScanInput>,
    pub packages: Vec<PackageScanEntry>,
    pub errors: Vec<String>,
    pub complete: bool,
}

#[derive(Clone)]
struct Locked {
    ecosystem: Ecosystem,
    source: String,
    source_identity: String,
    name: String,
    version: String,
    integrity: Option<String>,
    archive_hash: Option<String>,
    in_bundle: bool,
    origins: BTreeSet<String>,
    metadata: serde_json::Value,
}

type NpmMetadataCache = BTreeMap<(PathBuf, String, String, String), serde_json::Value>;
type LockedKey = (String, String, String, String, String, String, String);

pub fn scan(
    npm_locks: &[PathBuf],
    nuget_locks: &[PathBuf],
    nuget_packages: Option<&Path>,
    policy: &crate::domain::Policy,
    osv_cache: Option<&Path>,
) -> Result<(PackageScanReport, i32)> {
    let mut report = PackageScanReport {
        inputs: Vec::new(),
        packages: Vec::new(),
        errors: Vec::new(),
        complete: false,
    };
    if npm_locks.is_empty() && nuget_locks.is_empty() {
        report
            .errors
            .push("at least one lockfile is required".into());
    }
    if !nuget_locks.is_empty() && nuget_packages.is_none() {
        report
            .errors
            .push("--nuget-packages is required with NuGet lockfiles".into());
    }
    let mut locks: BTreeMap<LockedKey, Locked> = BTreeMap::new();
    let mut npm_sources = BTreeMap::new();
    let mut npm_metadata = NpmMetadataCache::new();
    for path in npm_locks {
        match read_npm_lock(path, &mut report, &mut npm_sources, &mut npm_metadata) {
            Ok(found) => {
                for lock in found {
                    insert_lock(&mut locks, lock);
                }
            }
            Err(error) => report.errors.push(format!("{}: {error:#}", path.display())),
        }
    }
    if let Some(cache) = nuget_packages {
        for path in nuget_locks {
            match read_nuget_lock(path, cache, &mut report) {
                Ok(found) => {
                    for lock in found {
                        insert_lock(&mut locks, lock);
                    }
                }
                Err(error) => report.errors.push(format!("{}: {error:#}", path.display())),
            }
        }
    }
    if locks.is_empty() {
        if report.errors.is_empty() {
            report
                .errors
                .push("no registry package resolutions found".into());
        }
        return Ok((report, 1));
    }
    let clock = ScanClock;
    let metadata_store = crate::adapters::storage::MemoryMetadataStore::default();
    let cache = osv_cache.map(Path::to_path_buf).unwrap_or_else(|| {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".local/share/supply-core/osv-cache")
    });
    let transport = match crate::adapters::osv::ReqwestOsvTransport::new() {
        Ok(transport) => Box::new(transport),
        Err(error) => {
            report
                .errors
                .push(format!("cannot initialize OSV transport: {error:#}"));
            return Ok((report, 1));
        }
    };
    let vulnerabilities =
        crate::adapters::osv::OsvVulnerabilitySource::new(transport).with_cache(cache);
    let evaluator = PackageEvaluator {
        policy,
        clock: &clock,
        vulns: &vulnerabilities,
        metadata: &metadata_store,
        ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
    };
    let mut flagged = false;
    for mut lock in locks.into_values() {
        let attestation = match attest_nuget_hash(&mut lock, &policy.nuget.first_party_packages) {
            Ok(attestation) => attestation,
            Err(error) => {
                report
                    .errors
                    .push(format!("{}@{}: {error:#}", lock.name, lock.version));
                continue;
            }
        };
        match assess(&lock, &evaluator) {
            Ok(decision) => {
                let is_flagged =
                    decision.status != DecisionStatus::Allow || !decision.warnings.is_empty();
                flagged |= is_flagged;
                report.packages.push(PackageScanEntry {
                    ecosystem: if lock.ecosystem == Ecosystem::Npm {
                        "npm"
                    } else {
                        "nuget"
                    }
                    .into(),
                    source: lock.source,
                    name: lock.name,
                    locked_version: lock.version,
                    status: format!(
                        "{:?}",
                        if is_flagged && decision.status == DecisionStatus::Allow {
                            DecisionStatus::Warn
                        } else {
                            decision.status
                        }
                    )
                    .to_lowercase(),
                    reasons: decision.reasons,
                    warnings: decision.warnings,
                    originating_paths: lock.origins.into_iter().collect(),
                    hash_attestation: attestation.map(str::to_string),
                });
            }
            Err(error) => report
                .errors
                .push(format!("{}@{}: {error:#}", lock.name, lock.version)),
        }
    }
    report.complete = report.errors.is_empty() && !report.packages.is_empty();
    let status = if !report.complete {
        1
    } else if flagged {
        2
    } else {
        0
    };
    Ok((report, status))
}

fn insert_lock(locks: &mut BTreeMap<LockedKey, Locked>, lock: Locked) {
    let registry_hash = lock
        .metadata
        .get("packageHash")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let registry_algorithm = lock
        .metadata
        .get("packageHashAlgorithm")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("sha512")
        .to_ascii_lowercase();
    let key = (
        format!("{:?}", lock.ecosystem),
        lock.source_identity.clone(),
        lock.name.clone(),
        lock.version.clone(),
        lock.integrity.clone().unwrap_or_default(),
        lock.archive_hash.clone().unwrap_or_default(),
        format!("{registry_algorithm}:{registry_hash}"),
    );
    if let Some(existing) = locks.get_mut(&key) {
        existing.origins.extend(lock.origins);
    } else {
        locks.insert(key, lock);
    }
}

struct ScanClock;
impl Clock for ScanClock {
    fn now(&self) -> chrono::DateTime<Utc> {
        Utc::now()
    }
}

fn read_npm_lock(
    path: &Path,
    report: &mut PackageScanReport,
    scopes: &mut BTreeMap<PathBuf, BTreeMap<String, String>>,
    metadata_cache: &mut NpmMetadataCache,
) -> Result<Vec<Locked>> {
    let bytes = fs::read(path).context("cannot read npm lockfile")?;
    report.inputs.push(input(path, &bytes));
    let json: serde_json::Value =
        serde_json::from_slice(&bytes).context("malformed npm lock JSON")?;
    let lock_version = json
        .get("lockfileVersion")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    if lock_version != 2 && lock_version != 3 {
        anyhow::bail!("unsupported npm lockfileVersion {lock_version}");
    }
    let packages = json
        .get("packages")
        .and_then(serde_json::Value::as_object)
        .context("npm lock has no packages object")?;
    let cwd = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .to_path_buf();
    let mut found = Vec::new();
    let mut local_count = 0;
    for (key, entry) in packages {
        if key.is_empty() {
            continue;
        }
        let resolved = entry.get("resolved").and_then(|v| v.as_str()).unwrap_or("");
        let link = entry.get("link").and_then(|v| v.as_bool()).unwrap_or(false);
        let in_bundle = entry
            .get("inBundle")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !key.contains("node_modules/")
            || (link && !in_bundle)
            || (resolved.starts_with("file:") && !in_bundle)
        {
            local_count += 1;
            continue;
        }
        let Some(name) = entry
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| name_from_node_modules_path(key))
        else {
            anyhow::bail!("cannot resolve npm package identity for {key}");
        };
        let version = entry
            .get("version")
            .and_then(|v| v.as_str())
            .context("npm registry entry missing version")?;
        if in_bundle {
            PackageVersionId::parse(&Ecosystem::Npm, version)
                .context("unsupported bundled npm version")?;
            found.push(Locked {
                source_identity: "bundled".into(),
                ecosystem: Ecosystem::Npm,
                source: "bundled".into(),
                name: name.clone(),
                version: version.into(),
                integrity: None,
                archive_hash: None,
                in_bundle: true,
                origins: BTreeSet::from([path.display().to_string()]),
                metadata: serde_json::Value::Null,
            });
            report.errors.push(format!(
                "bundled npm package {name}@{version} cannot be independently verified"
            ));
            continue;
        }
        if resolved.starts_with("git+")
            || resolved.starts_with("git:")
            || resolved.starts_with("file://")
        {
            anyhow::bail!("unsupported npm source for {key}");
        }
        let integrity = entry
            .get("integrity")
            .and_then(|v| v.as_str())
            .context("npm registry entry missing integrity")?;
        let scope = if name.starts_with('@') {
            name.split('/').next().unwrap_or("@invalid").to_string()
        } else {
            String::new()
        };
        let registries = scopes.entry(cwd.clone()).or_default();
        let registry = if let Some(value) = registries.get(&scope) {
            value.clone()
        } else {
            let value = npm::configured_registry(&name, &cwd)?;
            registries.insert(scope, value.clone());
            value
        };
        let source = npm::validate_locked_registry_source(
            (!resolved.is_empty()).then_some(resolved),
            &registry,
            &name,
        )?;
        let cache_key = (
            cwd.clone(),
            registry.clone(),
            name.clone(),
            version.to_string(),
        );
        let metadata = if let Some(metadata) = metadata_cache.get(&cache_key) {
            metadata.clone()
        } else {
            let metadata = npm::exact_metadata(&name, version, &cwd)?;
            metadata_cache.insert(cache_key, metadata.clone());
            metadata
        };
        let parsed = PackageVersionId::parse(&Ecosystem::Npm, version)
            .context("unsupported npm locked version")?;
        let package = npm::package_version_from_metadata(&metadata, &name, &parsed)?;
        if package.published_at.is_none() {
            anyhow::bail!("npm publication time missing for {name}@{version}");
        }
        if !npm_integrity_matches(
            integrity,
            package.integrity.as_deref(),
            metadata
                .get("dist")
                .and_then(|dist| dist.get("shasum"))
                .and_then(serde_json::Value::as_str),
        )? {
            anyhow::bail!("npm integrity mismatch for {name}@{version}");
        }
        found.push(Locked {
            ecosystem: Ecosystem::Npm,
            source_identity: registry.clone(),
            source,
            name,
            version: version.into(),
            integrity: Some(integrity.into()),
            archive_hash: None,
            in_bundle: false,
            origins: BTreeSet::from([path.display().to_string()]),
            metadata,
        });
    }
    if local_count > 0 {
        report.packages.push(PackageScanEntry {
            ecosystem: "npm".into(),
            source: "local".into(),
            name: "workspace/file links".into(),
            locked_version: "local".into(),
            status: "not-applicable".into(),
            reasons: Vec::new(),
            warnings: Vec::new(),
            originating_paths: vec![path.display().to_string()],
            hash_attestation: None,
        });
    }
    if found.is_empty() && local_count == 0 {
        report.packages.push(PackageScanEntry {
            ecosystem: "npm".into(),
            source: "lockfile".into(),
            name: "no registry package dependencies".into(),
            locked_version: "none".into(),
            status: "not-applicable".into(),
            reasons: Vec::new(),
            warnings: Vec::new(),
            originating_paths: vec![path.display().to_string()],
            hash_attestation: None,
        });
    }
    Ok(found)
}

fn npm_integrity_matches(
    locked_integrity: &str,
    registry_integrity: Option<&str>,
    registry_shasum: Option<&str>,
) -> Result<bool> {
    let locked = parse_npm_integrity(locked_integrity)?;
    let mut registry = registry_integrity
        .map(parse_npm_integrity)
        .transpose()?
        .unwrap_or_default();
    if let Some(shasum) = registry_shasum {
        let digest = hex::decode(shasum).context("invalid npm registry shasum")?;
        anyhow::ensure!(digest.len() == 20, "invalid npm registry shasum length");
        registry.entry("sha1".into()).or_default().push(digest);
    }
    let algorithm = ["sha512", "sha384", "sha256", "sha1"]
        .into_iter()
        .find(|algorithm| locked.contains_key(*algorithm))
        .context("npm lock integrity contains no supported digest algorithm")?;
    let registry_digests = registry.get(algorithm).with_context(|| {
        format!("registry metadata does not provide locked SRI algorithm {algorithm}")
    })?;
    Ok(locked[algorithm]
        .iter()
        .all(|locked_digest| registry_digests.contains(locked_digest)))
}

fn parse_npm_integrity(integrity: &str) -> Result<BTreeMap<String, Vec<Vec<u8>>>> {
    let mut digests = BTreeMap::new();
    for token in integrity.split_ascii_whitespace() {
        let (algorithm, encoded) = token.split_once('-').context("malformed npm SRI token")?;
        let algorithm = algorithm.to_ascii_lowercase();
        let digest_length = match algorithm.as_str() {
            "sha1" => 20,
            "sha256" => 32,
            "sha384" => 48,
            "sha512" => 64,
            _ => continue,
        };
        let encoded = encoded
            .split_once('?')
            .map_or(encoded, |(digest, _)| digest);
        let digest = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .context("invalid npm SRI digest")?;
        anyhow::ensure!(
            digest.len() == digest_length,
            "invalid npm SRI digest length for {algorithm}"
        );
        digests
            .entry(algorithm)
            .or_insert_with(Vec::new)
            .push(digest);
    }
    Ok(digests)
}

fn name_from_node_modules_path(path: &str) -> Option<String> {
    let after = path.rsplit_once("node_modules/")?.1;
    if let Some(scoped) = after.strip_prefix('@') {
        let (scope, name) = scoped.split_once('/')?;
        Some(format!("@{scope}/{name}"))
    } else {
        Some(after.split('/').next()?.into())
    }
}

fn validated_nuget_source(source: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(source).context("invalid NuGet source")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        anyhow::bail!("NuGet source must be an HTTPS URL without credentials or query data");
    }
    Ok(url)
}

fn read_nuget_lock(
    path: &Path,
    cache: &Path,
    report: &mut PackageScanReport,
) -> Result<Vec<Locked>> {
    let bytes = fs::read(path).context("cannot read NuGet lockfile")?;
    report.inputs.push(input(path, &bytes));
    let content = std::str::from_utf8(&bytes).context("NuGet lock is not UTF-8")?;
    let (pins, gaps) = nuget::parse_packages_lock(content)?;
    if !gaps.is_empty() {
        anyhow::bail!("incomplete NuGet lock: {}", gaps.join("; "));
    }
    if pins.is_empty() {
        report.packages.push(PackageScanEntry {
            ecosystem: "nuget".into(),
            source: "lockfile".into(),
            name: "no registry package dependencies".into(),
            locked_version: "none".into(),
            status: "not-applicable".into(),
            reasons: Vec::new(),
            warnings: Vec::new(),
            originating_paths: vec![path.display().to_string()],
            hash_attestation: None,
        });
    }
    let mut found = Vec::new();
    for pin in pins {
        let hash = pin
            .content_hash
            .context("NuGet lock entry missing contentHash")?;
        let package_dir = cache
            .join(pin.name.to_lowercase())
            .join(pin.version.to_lowercase());
        let info: serde_json::Value = serde_json::from_slice(
            &fs::read(package_dir.join(".nupkg.metadata"))
                .context("missing NuGet .nupkg.metadata")?,
        )
        .context("invalid NuGet cache metadata")?;
        let source = info
            .get("source")
            .and_then(|v| v.as_str())
            .context("NuGet cache metadata lacks source")?;
        let source_url = validated_nuget_source(source)?;
        let package_file = package_dir.join(format!(
            "{}.{}.nupkg",
            pin.name.to_lowercase(),
            pin.version.to_lowercase()
        ));
        let package_bytes =
            fs::read(&package_file).context("missing restored NuGet package bytes")?;
        let actual_archive_hash =
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&package_bytes));
        let actual_content_hash = nuget::package_content_hash(&package_bytes)?;
        let cached_content_hash = info
            .get("contentHash")
            .and_then(|value| value.as_str())
            .context("NuGet cache metadata lacks contentHash")?;
        let lock_hash = hash
            .strip_prefix("sha512-")
            .or_else(|| hash.strip_prefix("SHA512-"))
            .unwrap_or(&hash);
        if cached_content_hash != lock_hash {
            anyhow::bail!(
                "NuGet cache contentHash does not match lock contentHash for {} {}",
                pin.name,
                pin.version
            );
        }
        if actual_content_hash != lock_hash {
            anyhow::bail!(
                "NuGet package bytes do not match lock contentHash for {} {}",
                pin.name,
                pin.version
            );
        }
        let cached_archive_hash = fs::read_to_string(package_file.with_extension("nupkg.sha512"))
            .context("missing restored NuGet archive checksum")?;
        if actual_archive_hash != cached_archive_hash.trim() {
            anyhow::bail!(
                "NuGet package archive checksum does not match restored bytes for {} {}",
                pin.name,
                pin.version
            );
        }
        let token = if source_url.host_str() == Some("pkgs.dev.azure.com")
            || source_url.host_str() == Some("circit.pkgs.visualstudio.com")
        {
            std::env::var("SUPPLY_NUGET_TOKEN").ok()
        } else {
            None
        };
        let source = source_url.to_string();
        let metadata =
            nuget::release_from_source(&source, &pin.name, &pin.version, token.as_deref())?;
        let source_identity = hex::encode(Sha256::digest(source.as_bytes()));
        found.push(Locked {
            ecosystem: Ecosystem::NuGet,
            source_identity,
            source,
            name: pin.name,
            version: pin.version,
            integrity: Some(hash),
            archive_hash: Some(actual_archive_hash),
            in_bundle: false,
            origins: BTreeSet::from([path.display().to_string()]),
            metadata,
        });
    }
    Ok(found)
}

const NUGET_ORG_INDEX: &str = "https://api.nuget.org/v3/index.json";

fn attest_nuget_hash(
    lock: &mut Locked,
    first_party: &[crate::domain::FirstPartyNuGetPackages],
) -> Result<Option<&'static str>> {
    if lock.ecosystem != Ecosystem::NuGet {
        return Ok(None);
    }
    let (name, version) = (lock.name.clone(), lock.version.clone());
    let (metadata, attestation) = attested_nuget_metadata(
        &lock.metadata,
        &name,
        &lock.source,
        first_party,
        &|| nuget::release_from_source(NUGET_ORG_INDEX, &name, &version, None),
        &|| nuget::package_id_exists_on_source(NUGET_ORG_INDEX, &name),
    )?;
    lock.metadata = metadata;
    Ok(Some(attestation))
}

fn same_source(left: &str, right: &str) -> bool {
    match (reqwest::Url::parse(left), reqwest::Url::parse(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

// Azure Artifacts attests no package hash. Mirrored packages take nuget.org's catalog hash,
// so the feed cannot vouch for itself. A first-party package is one whose id matches a
// policy prefix AND was restored from that entry's exact feed; a prefixed id from any
// other source is refused outright. No version of a first-party id may exist on nuget.org
// (dependency confusion), and it is held to the lockfile contentHash plus the bytes the
// feed serves.
fn attested_nuget_metadata(
    metadata: &serde_json::Value,
    name: &str,
    source: &str,
    first_party: &[crate::domain::FirstPartyNuGetPackages],
    upstream: &dyn Fn() -> Result<serde_json::Value>,
    id_exists_upstream: &dyn Fn() -> Result<bool>,
) -> Result<(serde_json::Value, &'static str)> {
    let lowered = name.to_ascii_lowercase();
    let claimed: Vec<_> = first_party
        .iter()
        .filter(|entry| {
            !entry.prefix.is_empty() && lowered.starts_with(&entry.prefix.to_ascii_lowercase())
        })
        .collect();
    let trusted = claimed
        .iter()
        .any(|entry| same_source(&entry.source, source));
    if !claimed.is_empty() && !trusted {
        anyhow::bail!(
            "package {name} uses a first-party prefix but was restored from {source}, not a trusted first-party feed"
        );
    }
    if !metadata["packageHash"].is_null() {
        return Ok((metadata.clone(), "registry-catalog"));
    }
    let Some(feed_hash) = metadata["feedContentHash"].as_str() else {
        return Ok((metadata.clone(), "none"));
    };
    let mut attested = metadata.clone();
    if trusted {
        let exists = id_exists_upstream()
            .context("cannot confirm first-party package id is absent from nuget.org")?;
        if exists {
            anyhow::bail!(
                "first-party package id {name} exists on nuget.org; refusing feed-only attestation"
            );
        }
        attested["packageHash"] = serde_json::Value::String(feed_hash.to_string());
        attested["packageHashAlgorithm"] = serde_json::Value::String("SHA512".into());
        return Ok((attested, "first-party-feed-bytes"));
    }
    let upstream_metadata =
        upstream().context("cannot attest mirrored package against nuget.org")?;
    let Some(upstream_hash) = upstream_metadata["packageHash"].as_str() else {
        anyhow::bail!("mirrored package {name} has no nuget.org catalog hash; cannot attest");
    };
    attested["packageHash"] = serde_json::Value::String(upstream_hash.to_string());
    attested["packageHashAlgorithm"] = upstream_metadata["packageHashAlgorithm"].clone();
    if !upstream_metadata["published"].is_null() {
        attested["published"] = upstream_metadata["published"].clone();
    }
    Ok((attested, "upstream-catalog"))
}

fn assess(lock: &Locked, evaluator: &PackageEvaluator<'_>) -> Result<crate::domain::Decision> {
    let version = PackageVersionId::parse(&lock.ecosystem, &lock.version)?;
    if lock.in_bundle {
        let package = crate::domain::PackageVersion {
            package: crate::domain::PackageCoordinate {
                ecosystem: lock.ecosystem.clone(),
                name: lock.name.clone(),
            },
            version,
            published_at: None,
            integrity: None,
            tarball_url: None,
        };
        return evaluator.evaluate_with_version_string(
            &package,
            VersionSelection::Exact,
            &lock.version,
        );
    }
    let package = if lock.ecosystem == Ecosystem::Npm {
        let mut value = npm::package_version_from_metadata(&lock.metadata, &lock.name, &version)?;
        value.integrity = lock.integrity.clone();
        value
    } else {
        nuget::package_version_from_nuget(
            &lock.metadata,
            &lock.name,
            &version,
            lock.integrity.as_deref(),
            lock.archive_hash.as_deref(),
        )?
    };
    if package.published_at.is_none() {
        anyhow::bail!("registry publication time missing");
    }
    evaluator.evaluate_with_version_string(&package, VersionSelection::Exact, &lock.version)
}

fn input(path: &Path, bytes: &[u8]) -> PackageScanInput {
    PackageScanInput {
        path: path.display().to_string(),
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[derive(Default)]
    struct CapturedVersions(std::sync::Mutex<Vec<String>>);

    impl crate::ports::VulnerabilitySource for CapturedVersions {
        fn query(
            &self,
            _: Ecosystem,
            _: &str,
            version: &PackageVersionId,
        ) -> Result<Vec<crate::domain::VulnerabilityFinding>> {
            self.0
                .lock()
                .map_err(|_| anyhow::anyhow!("captured version mutex poisoned"))?
                .push(version.to_string());
            Ok(Vec::new())
        }

        fn query_version(
            &self,
            _: Ecosystem,
            _: &str,
            version: &str,
        ) -> Result<Vec<crate::domain::VulnerabilityFinding>> {
            self.0
                .lock()
                .map_err(|_| anyhow::anyhow!("captured version mutex poisoned"))?
                .push(version.to_string());
            Ok(Vec::new())
        }
    }

    #[test]
    fn package_names_are_recovered_from_nested_node_modules_paths() {
        assert_eq!(
            name_from_node_modules_path("node_modules/@circit/editor/node_modules/lodash"),
            Some("lodash".into())
        );
        assert_eq!(
            name_from_node_modules_path("node_modules/@circit/editor"),
            Some("@circit/editor".into())
        );
        assert_eq!(name_from_node_modules_path("node_modules/@circit"), None);
    }

    #[test]
    fn local_npm_dependencies_are_recorded_without_registry_lookup() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let lock_path = directory.path().join("package-lock.json");
        let bytes = serde_json::to_vec(&serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "workspace"},
                "node_modules/local": {"link": true, "resolved": "packages/local"},
                "packages/local": {"name": "local", "version": "1.0.0"},
                "node_modules/local-copy": {"resolved": "file:../local-copy", "version": "1.0.0"}
            }
        }))?;
        fs::write(&lock_path, &bytes)?;

        let mut report = PackageScanReport {
            inputs: Vec::new(),
            packages: Vec::new(),
            errors: Vec::new(),
            complete: false,
        };
        let locks = read_npm_lock(
            &lock_path,
            &mut report,
            &mut BTreeMap::new(),
            &mut BTreeMap::new(),
        )?;

        assert!(locks.is_empty());
        assert_eq!(report.inputs.len(), 1);
        assert_eq!(report.inputs[0].sha256, hex::encode(Sha256::digest(&bytes)));
        assert_eq!(report.packages.len(), 1);
        assert_eq!(report.packages[0].source, "local");
        assert_eq!(report.packages[0].status, "not-applicable");
        assert_eq!(
            report.packages[0].originating_paths,
            vec![lock_path.display().to_string()]
        );
        assert!(report.errors.is_empty());
        Ok(())
    }
    #[test]
    fn bundled_npm_dependencies_are_not_silently_skipped() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let lock_path = directory.path().join("package-lock.json");
        fs::write(
            &lock_path,
            serde_json::json!({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "workspace"},
                    "node_modules/bundled": {
                        "name": "bundled",
                        "version": "1.0.0",
                        "inBundle": true
                    }
                }
            })
            .to_string(),
        )?;
        let mut report = PackageScanReport {
            inputs: Vec::new(),
            packages: Vec::new(),
            errors: Vec::new(),
            complete: false,
        };

        let locks = read_npm_lock(
            &lock_path,
            &mut report,
            &mut BTreeMap::new(),
            &mut BTreeMap::new(),
        )?;

        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].name, "bundled");
        assert_eq!(locks[0].version, "1.0.0");
        assert!(report.errors.iter().any(|error| error.contains("bundled")));
        assert!(report
            .packages
            .iter()
            .all(|entry| entry.name != "workspace/file links"));
        let policy = crate::domain::Policy::default();
        let clock = ScanClock;
        let metadata = crate::adapters::storage::MemoryMetadataStore::default();
        let vulns = CapturedVersions::default();
        let evaluator = PackageEvaluator {
            policy: &policy,
            clock: &clock,
            vulns: &vulns,
            metadata: &metadata,
            ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
        };
        let decision = assess(&locks[0], &evaluator)?;

        assert_eq!(*vulns.0.lock().unwrap(), vec!["1.0.0"]);
        assert_eq!(decision.status, DecisionStatus::Block);
        assert!(decision
            .reasons
            .iter()
            .any(|reason| reason.contains("missing integrity")));
        Ok(())
    }

    #[test]
    fn unsupported_npm_sources_fail_before_registry_lookup() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let lock_path = directory.path().join("package-lock.json");
        fs::write(
            &lock_path,
            serde_json::json!({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/fixture": {
                        "version": "1.0.0",
                        "resolved": "git+https://example.test/fixture.git#commit",
                        "integrity": "sha512-fixture"
                    }
                }
            })
            .to_string(),
        )?;

        let mut report = PackageScanReport {
            inputs: Vec::new(),
            packages: Vec::new(),
            errors: Vec::new(),
            complete: false,
        };
        let error = match read_npm_lock(
            &lock_path,
            &mut report,
            &mut BTreeMap::new(),
            &mut BTreeMap::new(),
        ) {
            Ok(_) => anyhow::bail!("unsupported Git dependency was accepted"),
            Err(error) => error,
        };

        assert!(format!("{error:#}").contains("unsupported npm source"));
        assert_eq!(report.inputs.len(), 1);
        assert!(report.packages.is_empty());
        Ok(())
    }

    #[test]
    fn nuget_locks_require_restored_cache_metadata() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let lock_path = directory.path().join("packages.lock.json");
        let package_cache = directory.path().join("packages");
        fs::create_dir_all(package_cache.join("example").join("1.0.0"))?;
        fs::write(
            &lock_path,
            serde_json::json!({
                "version": 1,
                "dependencies": {
                    "net10.0": {
                        "Example": {
                            "type": "Direct",
                            "requested": "1.0.0",
                            "resolved": "1.0.0",
                            "contentHash": "sha512-fixture"
                        }
                    }
                }
            })
            .to_string(),
        )?;

        let mut report = PackageScanReport {
            inputs: Vec::new(),
            packages: Vec::new(),
            errors: Vec::new(),
            complete: false,
        };
        let error = match read_nuget_lock(&lock_path, &package_cache, &mut report) {
            Ok(_) => anyhow::bail!("lock without restored package metadata was accepted"),
            Err(error) => error,
        };

        assert!(format!("{error:#}").contains("missing NuGet .nupkg.metadata"));
        assert_eq!(report.inputs.len(), 1);
        assert!(report.packages.is_empty());
        Ok(())
    }

    #[test]
    fn dependency_free_nuget_lock_is_reported_as_not_applicable() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let lock_path = directory.path().join("packages.lock.json");
        fs::write(
            &lock_path,
            serde_json::json!({"version":1,"dependencies":{}}).to_string(),
        )?;
        let mut report = PackageScanReport {
            inputs: Vec::new(),
            packages: Vec::new(),
            errors: Vec::new(),
            complete: false,
        };

        let locks = read_nuget_lock(&lock_path, &directory.path().join("packages"), &mut report)?;

        assert!(locks.is_empty());
        assert!(report.errors.is_empty());
        assert_eq!(report.inputs.len(), 1);
        assert_eq!(report.packages.len(), 1);
        assert_eq!(report.packages[0].status, "not-applicable");
        assert_eq!(report.packages[0].name, "no registry package dependencies");
        Ok(())
    }

    #[test]
    fn local_only_npm_scan_is_incomplete_without_registry_resolutions() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let lock_path = directory.path().join("package-lock.json");
        fs::write(
            &lock_path,
            serde_json::json!({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "workspace"},
                    "node_modules/local": {"link": true, "resolved": "packages/local"},
                    "packages/local": {"name": "local", "version": "1.0.0"}
                }
            })
            .to_string(),
        )?;

        let (report, status) = scan(
            std::slice::from_ref(&lock_path),
            &[],
            None,
            &crate::domain::Policy::default(),
            None,
        )?;

        assert_eq!(status, 1);
        assert!(!report.complete);
        assert!(report
            .errors
            .iter()
            .any(|error| error == "no registry package resolutions found"));
        assert_eq!(report.packages.len(), 1);
        assert_eq!(report.packages[0].status, "not-applicable");
        Ok(())
    }

    #[test]
    fn dependency_free_nuget_scan_is_incomplete_without_osv() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let lock_path = directory.path().join("packages.lock.json");
        let package_cache = directory.path().join("packages");
        fs::create_dir_all(&package_cache)?;
        fs::write(
            &lock_path,
            serde_json::json!({"version":1,"dependencies":{}}).to_string(),
        )?;

        let (report, status) = scan(
            &[],
            std::slice::from_ref(&lock_path),
            Some(&package_cache),
            &crate::domain::Policy::default(),
            None,
        )?;

        assert_eq!(status, 1);
        assert!(!report.complete);
        assert!(report
            .errors
            .iter()
            .any(|error| error == "no registry package resolutions found"));
        assert_eq!(report.packages.len(), 1);
        assert_eq!(report.packages[0].status, "not-applicable");
        Ok(())
    }

    #[test]
    fn empty_package_scan_fails_before_network_initialization() -> Result<()> {
        let (report, status) = scan(&[], &[], None, &crate::domain::Policy::default(), None)?;

        assert_eq!(status, 1);
        assert!(!report.complete);
        assert!(report.packages.is_empty());
        assert!(report
            .errors
            .iter()
            .any(|error| error == "at least one lockfile is required"));
        Ok(())
    }
    #[test]
    fn nuget_same_origin_archives_with_different_bytes_are_assessed_independently() -> Result<()> {
        let make_lock = |feed_url: &str, archive_hash: &str, package_hash: &str| Locked {
            ecosystem: Ecosystem::NuGet,
            source: "https://pkgs.dev.azure.com".into(),
            source_identity: feed_url.into(),
            name: "Example".into(),
            version: "1.0.0".into(),
            integrity: Some("sha512-lock".into()),
            archive_hash: Some(archive_hash.into()),
            in_bundle: false,
            origins: BTreeSet::new(),
            metadata: serde_json::json!({
                "listed": true,
                "published": "2020-01-01T00:00:00Z",
                "packageHash": package_hash,
                "packageHashAlgorithm": "SHA512"
            }),
        };
        let mut locks = BTreeMap::new();
        insert_lock(
            &mut locks,
            make_lock(
                "https://pkgs.dev.azure.com/org/_packaging/feed-one/nuget/v3/index.json",
                "archive-one",
                "archive-one",
            ),
        );
        insert_lock(
            &mut locks,
            make_lock(
                "https://pkgs.dev.azure.com/org/_packaging/feed-two/nuget/v3/index.json",
                "archive-two",
                "registry-mismatch",
            ),
        );

        assert_eq!(locks.len(), 2);
        let policy = crate::domain::Policy::default();
        let clock = ScanClock;
        let metadata = crate::adapters::storage::MemoryMetadataStore::default();
        let vulns = CapturedVersions::default();
        let evaluator = PackageEvaluator {
            policy: &policy,
            clock: &clock,
            vulns: &vulns,
            metadata: &metadata,
            ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
        };
        let valid = locks
            .values()
            .find(|lock| lock.archive_hash.as_deref() == Some("archive-one"))
            .context("first NuGet archive was merged away")?;
        let mismatched = locks
            .values()
            .find(|lock| lock.archive_hash.as_deref() == Some("archive-two"))
            .context("second NuGet archive was merged away")?;

        assert!(assess(valid, &evaluator).is_ok());
        assert!(assess(mismatched, &evaluator).is_err());
        Ok(())
    }
    #[test]
    fn npm_integrity_rejects_unregistered_digests_for_strongest_algorithm() -> Result<()> {
        let authorized = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode([0_u8; 64])
        );
        let unregistered = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode([1_u8; 64])
        );
        let locked = format!("{authorized} {unregistered}");

        assert!(!npm_integrity_matches(&locked, Some(&authorized), None)?);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn npm_sha1_lock_integrity_matches_registry_shasum() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        static NPM_PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = NPM_PATH_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("npm test path lock poisoned"))?;
        let directory = tempfile::tempdir()?;
        let bin = directory.path().join("bin");
        fs::create_dir_all(&bin)?;
        let registry_integrity = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode([0_u8; 64])
        );
        let metadata = serde_json::json!({
            "dist": {
                "integrity": registry_integrity,
                "shasum": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
            },
            "time": "2020-01-01T00:00:00Z"
        });
        let npm = bin.join("npm");
        fs::write(
            &npm,
            format!(
                "#!/bin/sh\nif [ \"$1\" = \"config\" ]; then\n  printf '%s\\n' 'https://registry.npmjs.org/'\nelif [ \"$1\" = \"view\" ]; then\n  printf '%s\\n' '{}'\nelse\n  exit 1\nfi\n",
                metadata
            ),
        )?;
        let mut permissions = fs::metadata(&npm)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&npm, permissions)?;
        let lock_path = directory.path().join("package-lock.json");
        fs::write(
            &lock_path,
            serde_json::json!({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "fixture"},
                    "node_modules/fixture": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz",
                        "integrity": "sha1-2jmj7l5rSw0yVb/vlWAYkK/YBwk="
                    }
                }
            })
            .to_string(),
        )?;
        let old_path = std::env::var_os("PATH");
        let mut paths = vec![bin];
        if let Some(old_path) = old_path.as_deref() {
            paths.extend(std::env::split_paths(old_path));
        }
        let new_path = std::env::join_paths(paths)?;
        std::env::set_var("PATH", new_path);
        let mut report = PackageScanReport {
            inputs: Vec::new(),
            packages: Vec::new(),
            errors: Vec::new(),
            complete: false,
        };
        let result = read_npm_lock(
            &lock_path,
            &mut report,
            &mut BTreeMap::new(),
            &mut BTreeMap::new(),
        );
        if let Some(old_path) = old_path {
            std::env::set_var("PATH", old_path);
        } else {
            std::env::remove_var("PATH");
        }

        let locks = result?;
        assert_eq!(locks.len(), 1);
        Ok(())
    }

    #[test]
    fn nuget_source_keeps_feed_path_and_rejects_url_credentials() -> Result<()> {
        let source = validated_nuget_source(
            "https://pkgs.dev.azure.com/Circit/Project/_packaging/FeedA/nuget/v3/index.json",
        )?;
        let other_feed = validated_nuget_source(
            "https://pkgs.dev.azure.com/Circit/Project/_packaging/FeedB/nuget/v3/index.json",
        )?;

        assert_eq!(
            source.as_str(),
            "https://pkgs.dev.azure.com/Circit/Project/_packaging/FeedA/nuget/v3/index.json"
        );
        assert_ne!(source.as_str(), other_feed.as_str());
        assert!(validated_nuget_source(
            "https://user:password@pkgs.dev.azure.com/Circit/Project/_packaging/FeedA/nuget/v3/index.json"
        )
        .is_err());
        assert!(validated_nuget_source(
            "https://pkgs.dev.azure.com/Circit/Project/_packaging/FeedA/nuget/v3/index.json?token=secret"
        )
        .is_err());
        assert!(validated_nuget_source(
            "https://pkgs.dev.azure.com/Circit/Project/_packaging/FeedA/nuget/v3/index.json#secret"
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn nuget_four_component_version_is_assessed_without_truncation() -> Result<()> {
        let lock = Locked {
            ecosystem: Ecosystem::NuGet,
            source: "https://api.nuget.org/v3/index.json".into(),
            source_identity: "https://api.nuget.org/v3/index.json".into(),
            name: "Example".into(),
            version: "1.2.3.4".into(),
            integrity: Some("sha512-fixture".into()),
            archive_hash: None,
            in_bundle: false,
            origins: BTreeSet::new(),
            metadata: serde_json::json!({
                "listed": true,
                "published": "2020-01-01T00:00:00Z"
            }),
        };
        let policy = crate::domain::Policy::default();
        let clock = ScanClock;
        let metadata = crate::adapters::storage::MemoryMetadataStore::default();
        let vulns = CapturedVersions::default();
        let evaluator = PackageEvaluator {
            policy: &policy,
            clock: &clock,
            vulns: &vulns,
            metadata: &metadata,
            ledger: crate::application::ledger::LedgerRecorder::open_in_memory()?,
        };

        let decision = assess(&lock, &evaluator)?;

        assert_eq!(decision.requested_version.as_deref(), Some("1.2.3.4"));
        assert_eq!(decision.served_version.as_deref(), Some("1.2.3.4"));
        assert_eq!(*vulns.0.lock().unwrap(), vec!["1.2.3.4"]);
        Ok(())
    }

    const BACKEND: &str =
        "https://pkgs.dev.azure.com/Circit/Circit/_packaging/Backend/nuget/v3/index.json";
    const OTHER_FEED: &str =
        "https://pkgs.dev.azure.com/Circit/Circit/_packaging/Other/nuget/v3/index.json";
    const NUGET_ORG: &str = "https://api.nuget.org/v3/index.json";

    fn first_party() -> Vec<crate::domain::FirstPartyNuGetPackages> {
        vec![crate::domain::FirstPartyNuGetPackages {
            prefix: "Circit.".to_string(),
            source: BACKEND.to_string(),
        }]
    }

    fn no_upstream_release() -> Result<serde_json::Value> {
        anyhow::bail!("upstream release must not be consulted")
    }

    fn no_id_lookup() -> Result<bool> {
        anyhow::bail!("id lookup must not be consulted")
    }

    #[test]
    fn catalog_hash_is_used_as_is() -> Result<()> {
        let metadata = serde_json::json!({ "packageHash": "CATALOG", "feedContentHash": "FEED" });
        let (attested, label) = attested_nuget_metadata(
            &metadata,
            "Any.Package",
            NUGET_ORG,
            &first_party(),
            &no_upstream_release,
            &no_id_lookup,
        )?;
        assert_eq!(attested["packageHash"], "CATALOG");
        assert_eq!(label, "registry-catalog");
        Ok(())
    }

    #[test]
    fn mirrored_package_takes_hash_and_age_from_nuget_org_not_the_feed() -> Result<()> {
        let metadata =
            serde_json::json!({ "feedContentHash": "FEED", "published": "2026-11-19T16:00:00Z" });
        let (attested, label) = attested_nuget_metadata(
            &metadata,
            "Microsoft.Extensions.Http",
            BACKEND,
            &first_party(),
            &|| {
                Ok(serde_json::json!({
                    "packageHash": "UPSTREAM",
                    "packageHashAlgorithm": "SHA512",
                    "published": "2026-02-10T18:55:00Z"
                }))
            },
            &no_id_lookup,
        )?;
        assert_eq!(attested["packageHash"], "UPSTREAM");
        assert_eq!(attested["published"], "2026-02-10T18:55:00Z");
        assert_eq!(label, "upstream-catalog");
        Ok(())
    }

    #[test]
    fn mirrored_package_without_an_upstream_hash_is_an_error() {
        let metadata = serde_json::json!({ "feedContentHash": "FEED" });
        assert!(attested_nuget_metadata(
            &metadata,
            "Some.Mirrored",
            BACKEND,
            &first_party(),
            &|| Ok(serde_json::json!({ "packageHash": null })),
            &no_id_lookup,
        )
        .is_err());
        assert!(attested_nuget_metadata(
            &metadata,
            "Some.Mirrored",
            BACKEND,
            &first_party(),
            &|| anyhow::bail!("HTTP 404"),
            &no_id_lookup,
        )
        .is_err());
    }

    #[test]
    fn first_party_package_needs_id_absence_from_nuget_org() -> Result<()> {
        let metadata = serde_json::json!({ "feedContentHash": "FEED" });
        let (attested, label) = attested_nuget_metadata(
            &metadata,
            "circit.evidence",
            BACKEND,
            &first_party(),
            &no_upstream_release,
            &|| Ok(false),
        )?;
        assert_eq!(attested["packageHash"], "FEED");
        assert_eq!(label, "first-party-feed-bytes");

        let confused = attested_nuget_metadata(
            &metadata,
            "Circit.Evidence",
            BACKEND,
            &first_party(),
            &no_upstream_release,
            &|| Ok(true),
        );
        assert!(format!("{:#}", confused.unwrap_err()).contains("exists on nuget.org"));

        let unreachable = attested_nuget_metadata(
            &metadata,
            "Circit.Evidence",
            BACKEND,
            &first_party(),
            &no_upstream_release,
            &|| anyhow::bail!("service index rejected request"),
        );
        assert!(format!("{:#}", unreachable.unwrap_err()).contains("cannot confirm"));
        Ok(())
    }

    #[test]
    fn first_party_prefix_from_any_other_source_is_refused() {
        let feed_only = serde_json::json!({ "feedContentHash": "FEED" });
        let with_catalog = serde_json::json!({ "packageHash": "CATALOG" });
        for (metadata, source) in [(&feed_only, OTHER_FEED), (&with_catalog, NUGET_ORG)] {
            let error = attested_nuget_metadata(
                metadata,
                "Circit.Evidence",
                source,
                &first_party(),
                &no_upstream_release,
                &|| Ok(false),
            )
            .unwrap_err();
            assert!(
                format!("{error:#}").contains("not a trusted first-party feed"),
                "{source}: {error:#}"
            );
        }
    }

    #[test]
    fn feed_identity_is_compared_exactly_not_by_host_or_prefix() {
        let feed_only = serde_json::json!({ "feedContentHash": "FEED" });
        for lookalike in [
            "https://pkgs.dev.azure.com/Circit/Circit/_packaging/Backend2/nuget/v3/index.json",
            "https://pkgs.dev.azure.com/Circit/Other/_packaging/Backend/nuget/v3/index.json",
            "http://pkgs.dev.azure.com/Circit/Circit/_packaging/Backend/nuget/v3/index.json",
            "not a url",
        ] {
            assert!(
                attested_nuget_metadata(
                    &feed_only,
                    "Circit.Evidence",
                    lookalike,
                    &first_party(),
                    &no_upstream_release,
                    &|| Ok(false),
                )
                .is_err(),
                "{lookalike} must not be trusted"
            );
        }
    }

    #[test]
    fn no_first_party_entries_means_nothing_is_first_party() {
        let metadata = serde_json::json!({ "feedContentHash": "FEED" });
        let result = attested_nuget_metadata(
            &metadata,
            "Circit.Evidence",
            BACKEND,
            &[],
            &|| Ok(serde_json::json!({ "packageHash": "UPSTREAM" })),
            &no_id_lookup,
        );
        assert_eq!(result.unwrap().0["packageHash"], "UPSTREAM");
    }
}
