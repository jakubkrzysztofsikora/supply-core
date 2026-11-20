use crate::application::ledger::{
    engine_finding_id, Coverage, EngineFinding, EngineReport, MAX_ENGINE_FINDINGS,
};
use crate::domain::{ContentFinding, Ecosystem, PackageVersionId};
use crate::ports::ContentScanner;
use anyhow::{Context, Result};
use chrono::Utc;
use rust_decimal::Decimal;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_MAX_OUTPUT: usize = 8 * 1024 * 1024;
const DRAIN_GRACE: Duration = Duration::from_secs(2);
const OSSGADGET_UPSTREAM_COMMIT: &str = "4063457b40211c25b41d56465d41783f2d42c5c1";
const OSSGADGET_MANIFEST: &str = "supply-ossgadget-manifest.json";
const OSSGADGET_COVERAGE_ENV: &str = "SUPPLY_OSSGADGET_COVERAGE_PATH";
const SCANNER_MEMORY_LIMIT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Archive scanners copy the input and unpack members; outside large scans
/// both are bounded by the 64 MiB compressed and expanded archive caps.
const ARCHIVE_SCANNER_FILE_SIZE_LIMIT_BYTES: u64 = 64 * 1024 * 1024;
/// .NET reserves its GC region range up front; with the region range and heap
/// bounded below, OSSGadget starts and scans within this address space.
const OSSGADGET_MEMORY_LIMIT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// OSSGadget scans single-threaded; a 1.5 MB package already takes about a minute.
const OSSGADGET_TIMEOUT: Duration = Duration::from_secs(480);
#[cfg(target_os = "linux")]
const OSSGADGET_GC_REGION_RANGE: &str = "40000000";
#[cfg(target_os = "linux")]
const OSSGADGET_GC_HEAP_HARD_LIMIT: &str = "30000000";

fn scanner_memory_limit_supported() -> bool {
    cfg!(target_os = "linux")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// `command <ecosystem> <archive>` with `{"score","rules","summary"}` JSON.
    Normalized,
    /// `command <ecosystem> scan <archive> --output-format json`, GuardDog v3.
    GuardDog,
}

fn scanner_args(format: ReportFormat, ecosystem: &Ecosystem, archive: &Path) -> Vec<String> {
    let archive = archive.to_string_lossy().to_string();
    match format {
        ReportFormat::Normalized => vec![ecosystem_label(ecosystem).to_string(), archive],
        ReportFormat::GuardDog => vec![
            ecosystem_label(ecosystem).to_string(),
            "scan".to_string(),
            archive,
            "--output-format".to_string(),
            "json".to_string(),
        ],
    }
}

/// Maps a real GuardDog v3 report (risk_score/results/errors) into a finding.
pub fn finding_from_guarddog(
    payload: &serde_json::Value,
    ecosystem: &Ecosystem,
    name: &str,
    version: &PackageVersionId,
) -> Result<Option<ContentFinding>> {
    if let Some(errors) = payload.get("errors") {
        match errors.as_object() {
            Some(map) if map.is_empty() => {}
            Some(map) => {
                anyhow::bail!(
                    "guarddog reported scan errors: {}",
                    serde_json::to_string(map)?
                );
            }
            None => anyhow::bail!("guarddog report has a malformed errors field"),
        }
    }
    let score_text = payload
        .get("risk_score")
        .and_then(|risk| risk.get("score"))
        .and_then(serde_json::Value::as_number)
        .context("guarddog report is missing risk_score.score")?
        .to_string();
    let score = Decimal::from_str_exact(&score_text)
        .or_else(|_| Decimal::from_scientific(&score_text))
        .context("guarddog risk score is not an exact decimal")?;
    if score < Decimal::new(0, 0) || score > Decimal::new(10, 0) {
        anyhow::bail!("guarddog risk score is outside [0, 10]");
    }
    if score.is_zero() {
        return Ok(None);
    }
    let results = payload
        .get("results")
        .and_then(|results| results.as_object());
    let mut rules: Vec<String> = results
        .map(|results| {
            results
                .iter()
                .filter(|(_, hits)| hits.as_array().is_some_and(|hits| !hits.is_empty()))
                .map(|(rule, _)| rule.clone())
                .collect()
        })
        .unwrap_or_default();
    rules.sort();
    let label = payload
        .get("risk_score")
        .and_then(|risk| risk.get("label"))
        .and_then(|label| label.as_str())
        .unwrap_or("risk");
    let top_message = results
        .and_then(|results| {
            let threat = results
                .iter()
                .filter(|(rule, _)| rule.starts_with("threat-"))
                .find_map(|(_, hits)| first_message(hits));
            threat.or_else(|| results.values().find_map(first_message))
        })
        .unwrap_or("guarddog flagged this package");
    Ok(Some(ContentFinding {
        ecosystem: ecosystem.clone(),
        package: name.to_string(),
        version: version.clone(),
        source: "guarddog".to_string(),
        score: Some(score),
        scan_incomplete: false,
        rules,
        summary: format!("{label}: {top_message}"),
        detected_at: Utc::now(),
    }))
}

fn first_message(hits: &serde_json::Value) -> Option<&str> {
    hits.as_array()?.first()?.get("message")?.as_str()
}

#[derive(Debug)]
struct OssGadgetLocation {
    path: Option<String>,
}

#[derive(Debug)]
struct OssGadgetSarifFinding {
    rule_id: String,
    location: Option<OssGadgetLocation>,
}

#[derive(Debug)]
struct OssGadgetSarif {
    rules: std::collections::BTreeSet<String>,
    findings: Vec<OssGadgetSarifFinding>,
    diagnostics: usize,
    malformed_results: usize,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifLog {
    version: String,
    #[serde(default)]
    runs: Vec<SarifRun>,
}

#[derive(serde::Deserialize)]
struct SarifRun {
    tool: Option<SarifTool>,
    #[serde(default)]
    results: Vec<SarifResult>,
    #[serde(default)]
    invocations: Vec<SarifInvocation>,
}

#[derive(serde::Deserialize)]
struct SarifTool {
    driver: Option<SarifDriver>,
}

#[derive(serde::Deserialize)]
struct SarifDriver {
    rules: Option<Vec<SarifRule>>,
}

#[derive(serde::Deserialize)]
struct SarifRule {
    id: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: Option<String>,
    rule: Option<SarifRule>,
    #[serde(default)]
    locations: Vec<SarifLocation>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: Option<SarifPhysicalLocation>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    address: Option<SarifAddress>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifAddress {
    fully_qualified_name: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifInvocation {
    execution_successful: Option<bool>,
    #[serde(default)]
    tool_execution_notifications: Vec<SarifNotification>,
    #[serde(default)]
    tool_configuration_notifications: Vec<SarifNotification>,
}

#[derive(serde::Deserialize)]
struct SarifNotification {
    message: Option<SarifMessage>,
}

#[derive(serde::Deserialize)]
struct SarifMessage {
    text: Option<String>,
}

fn parse_ossgadget_sarif(payload: &str) -> Result<OssGadgetSarif> {
    let report: SarifLog = serde_json::from_str(payload).context("invalid OSSGadget SARIF")?;
    anyhow::ensure!(
        report.version == "2.1.0",
        "unsupported OSSGadget SARIF version"
    );
    anyhow::ensure!(!report.runs.is_empty(), "OSSGadget SARIF has no runs");
    let mut parsed = OssGadgetSarif {
        rules: std::collections::BTreeSet::new(),
        findings: Vec::new(),
        diagnostics: 0,
        malformed_results: 0,
    };
    for run in report.runs {
        if let Some(rules) = run
            .tool
            .and_then(|tool| tool.driver)
            .and_then(|driver| driver.rules)
        {
            for rule in rules {
                if let Some(id) = rule.id.filter(|id| !id.trim().is_empty()) {
                    parsed.rules.insert(id);
                }
            }
        }
        for result in run.results {
            let Some(rule_id) = result
                .rule_id
                .or_else(|| result.rule.and_then(|rule| rule.id))
                .filter(|rule_id| !rule_id.trim().is_empty())
            else {
                parsed.malformed_results += 1;
                continue;
            };
            let location = result.locations.iter().find_map(|location| {
                let physical = location.physical_location.as_ref()?;
                Some(OssGadgetLocation {
                    path: physical
                        .address
                        .as_ref()
                        .and_then(|address| address.fully_qualified_name.clone()),
                })
            });
            parsed
                .findings
                .push(OssGadgetSarifFinding { rule_id, location });
        }
        for invocation in run.invocations {
            parsed.diagnostics += invocation
                .tool_execution_notifications
                .iter()
                .filter(|notification| {
                    notification
                        .message
                        .as_ref()
                        .and_then(|message| message.text.as_ref())
                        .is_some()
                })
                .count();
            parsed.diagnostics += invocation
                .tool_configuration_notifications
                .iter()
                .filter(|notification| {
                    notification
                        .message
                        .as_ref()
                        .and_then(|message| message.text.as_ref())
                        .is_some()
                })
                .count();
            parsed.diagnostics += usize::from(invocation.execution_successful == Some(false));
        }
    }
    Ok(parsed)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OssGadgetCoverage {
    version: u32,
    scanned_paths: Vec<String>,
    skipped_paths: Vec<OssGadgetSkippedPath>,
    diagnostics: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OssGadgetSkippedPath {
    path: String,
    reason: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OssGadgetInstallManifest {
    format_version: u32,
    upstream_commit: String,
    binary_sha256: String,
    rule_bundle_sha256: String,
}

pub struct OssGadgetScanner {
    command: PathBuf,
    rule_bundle_sha256: String,
    bundle_rules: std::collections::BTreeSet<String>,
    timeout: Duration,
    max_output_bytes: usize,
}

/// Rule IDs declared by the attested rule files; OSSGadget's SARIF names rules
/// per result without listing them in the driver.
fn ossgadget_rule_ids(rules: &Path) -> Result<std::collections::BTreeSet<String>> {
    #[derive(serde::Deserialize)]
    struct RuleFileEntry {
        id: String,
    }
    let mut ids = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(rules)? {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let (bytes, truncated) = read_capped(File::open(&path)?, 16 * 1024 * 1024);
        anyhow::ensure!(!truncated, "OSSGadget rule file exceeds size limit");
        let entries: Vec<RuleFileEntry> =
            serde_json::from_slice(&bytes).context("invalid OSSGadget rule file")?;
        ids.extend(entries.into_iter().map(|entry| entry.id));
    }
    anyhow::ensure!(!ids.is_empty(), "OSSGadget rule bundle declares no rules");
    Ok(ids)
}

impl OssGadgetScanner {
    pub fn from_env() -> Result<Self> {
        let command =
            std::env::var_os("OSSGADGET_BIN").context("OSSGADGET_BIN is not configured")?;
        let command = resolve_executable(Path::new(&command))?;
        let install_root = command
            .parent()
            .context("OSSGADGET_BIN has no parent directory")?;
        let manifest_path = std::env::var_os("OSSGADGET_MANIFEST")
            .map(PathBuf::from)
            .unwrap_or_else(|| install_root.join(OSSGADGET_MANIFEST));
        let (manifest_bytes, truncated) = read_capped(File::open(&manifest_path)?, 16 * 1024);
        anyhow::ensure!(!truncated, "OSSGadget install manifest exceeds size limit");
        let manifest: OssGadgetInstallManifest = serde_json::from_slice(&manifest_bytes)
            .context("invalid OSSGadget install manifest")?;
        let rules = install_root.join("Resources/BackdoorRules");
        verify_ossgadget_installation(&command, &rules, &manifest)?;
        let bundle_rules = ossgadget_rule_ids(&rules)?;
        Ok(Self {
            command,
            rule_bundle_sha256: manifest.rule_bundle_sha256,
            bundle_rules,
            timeout: OSSGADGET_TIMEOUT,
            max_output_bytes: DEFAULT_MAX_OUTPUT,
        })
    }

    pub fn unavailable_report(
        input_sha256: &str,
        expected_inputs: u64,
        reason: &str,
    ) -> EngineReport {
        EngineReport {
            source: "ossgadget".to_string(),
            version: None,
            rule_bundle_sha256: None,
            database_sha256: None,
            input_sha256: Some(input_sha256.to_string()),
            expected_inputs,
            processed_inputs: 0,
            coverage: Coverage::Unknown,
            findings: Vec::new(),
            reason: Some(reason.to_string()),
        }
    }
    fn partial_report(
        &self,
        input_sha256: &str,
        expected_inputs: u64,
        reason: &str,
    ) -> Result<EngineReport> {
        let report = EngineReport {
            source: "ossgadget".to_string(),
            version: Some(OSSGADGET_UPSTREAM_COMMIT.to_string()),
            rule_bundle_sha256: Some(self.rule_bundle_sha256.clone()),
            database_sha256: None,
            input_sha256: Some(input_sha256.to_string()),
            expected_inputs,
            processed_inputs: 0,
            coverage: Coverage::Partial,
            findings: Vec::new(),
            reason: Some(reason.to_string()),
        };
        report.validate()?;
        Ok(report)
    }

    pub fn scan(
        &self,
        package_root: &Path,
        expected_paths: &std::collections::BTreeSet<String>,
        inventory_complete: bool,
        input_sha256: &str,
    ) -> Result<EngineReport> {
        let expected_inputs = u64::try_from(expected_paths.len())?;
        if !scanner_memory_limit_supported() {
            return self.partial_report(
                input_sha256,
                expected_inputs,
                "scanner_memory_limit_unavailable",
            );
        }
        #[cfg(unix)]
        if ensure_unprivileged(unsafe { libc::geteuid() }).is_err() {
            return self.partial_report(input_sha256, expected_inputs, "scanner_privileged");
        }
        let runner = match sandbox_runner() {
            Ok(runner) => runner,
            Err(_) => {
                return self.partial_report(
                    input_sha256,
                    expected_inputs,
                    "scanner_sandbox_unavailable",
                )
            }
        };
        let package_root = std::fs::canonicalize(package_root)?;
        anyhow::ensure!(
            std::fs::symlink_metadata(&package_root)?
                .file_type()
                .is_dir(),
            "OSSGadget input is not a real directory"
        );
        let scratch_parent = package_root
            .parent()
            .context("OSSGadget input has no parent")?;
        let scratch = ScannerScratch::new(scratch_parent)?;
        let sarif_path = scratch.path.join("ossgadget.sarif");
        let coverage_path = scratch.path.join("coverage.json");
        let guest_sarif_path = if cfg!(target_os = "macos") {
            sarif_path.clone()
        } else {
            PathBuf::from("/tmp/ossgadget.sarif")
        };
        let guest_coverage_path = if cfg!(target_os = "macos") {
            coverage_path.clone()
        } else {
            PathBuf::from("/tmp/coverage.json")
        };
        let install_root = self
            .command
            .parent()
            .context("OSSGadget executable has no install directory")?;
        let command = match ossgadget_sandbox_command(
            &runner,
            &self.command,
            install_root,
            &package_root,
            &scratch.path,
            &guest_sarif_path,
            &guest_coverage_path,
        ) {
            Ok(command) => command,
            Err(_) => {
                return self.partial_report(
                    input_sha256,
                    expected_inputs,
                    "scanner_sandbox_unavailable",
                )
            }
        };
        let execution = run_bounded_command(
            command,
            None,
            self.timeout,
            self.max_output_bytes,
            self.max_output_bytes as u64,
            OSSGADGET_MEMORY_LIMIT_BYTES,
            "ossgadget",
        )
        .ok();
        let execution_succeeded = execution
            .as_ref()
            .is_some_and(|output| output.status.success());
        let mut output_complete = execution.as_ref().is_none_or(|output| output.complete);
        let (sarif_bytes, sarif_truncated) = read_optional_report(&sarif_path)?;
        let (coverage_bytes, coverage_truncated) = read_optional_report(&coverage_path)?;
        output_complete &= !sarif_truncated && !coverage_truncated;
        let sarif = sarif_bytes
            .filter(|_| !sarif_truncated)
            .and_then(|bytes| std::str::from_utf8(&bytes).ok().map(str::to_string))
            .and_then(|text| parse_ossgadget_sarif(&text).ok());
        let coverage = coverage_bytes
            .filter(|_| !coverage_truncated)
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
        let guest_root = if cfg!(target_os = "macos") {
            package_root.as_path()
        } else {
            Path::new("/scan/package")
        };
        ossgadget_engine_report(
            OssGadgetReportContext {
                input_sha256,
                rule_bundle_sha256: &self.rule_bundle_sha256,
                bundle_rules: &self.bundle_rules,
                package_root: &package_root,
                guest_root,
                expected_paths,
                inventory_complete,
                execution_succeeded,
                output_complete,
            },
            sarif,
            coverage,
        )
    }
}

fn verify_ossgadget_installation(
    command: &Path,
    rules: &Path,
    manifest: &OssGadgetInstallManifest,
) -> Result<()> {
    anyhow::ensure!(
        manifest.format_version == 1 && manifest.upstream_commit == OSSGADGET_UPSTREAM_COMMIT,
        "OSSGadget installation is not pinned to the required upstream commit"
    );
    anyhow::ensure!(
        sha256_path(command)? == manifest.binary_sha256,
        "OSSGadget executable digest does not match its manifest"
    );
    anyhow::ensure!(
        sha256_directory(rules)? == manifest.rule_bundle_sha256,
        "OSSGadget rule bundle digest does not match its manifest"
    );
    Ok(())
}

fn sha256_path(path: &Path) -> Result<String> {
    hash_file(&mut File::open(path)?)
}

fn sha256_directory(root: &Path) -> Result<String> {
    fn collect(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                collect(root, &entry.path(), files)?;
            } else if file_type.is_file() {
                files.push(entry.path());
                anyhow::ensure!(files.len() <= 10_000, "rule bundle has too many files");
            } else {
                anyhow::bail!("rule bundle contains a non-regular file");
            }
        }
        let _ = root;
        Ok(())
    }

    anyhow::ensure!(
        std::fs::symlink_metadata(root)?.file_type().is_dir(),
        "rule bundle is not a real directory"
    );
    let mut files = Vec::new();
    collect(root, root, &mut files)?;
    let mut entries = files
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(root)?
                .to_str()
                .context("rule path is not UTF-8")?
                .replace('\\', "/");
            let normalized = normalize_relative_path(&relative).context("rule path is invalid")?;
            Ok((normalized, path))
        })
        .collect::<Result<Vec<_>>>()?;
    entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
    let mut bundle_hasher = Sha256::new();
    let mut total_bytes = 0_u64;
    for (normalized, path) in entries {
        let mut file = File::open(&path)?;
        let mut content_hasher = Sha256::new();
        let mut size = 0_u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            size = size.saturating_add(count as u64);
            total_bytes = total_bytes.saturating_add(count as u64);
            anyhow::ensure!(
                total_bytes <= 64 * 1024 * 1024,
                "rule bundle exceeds size limit"
            );
            content_hasher.update(&buffer[..count]);
        }
        bundle_hasher.update((normalized.len() as u64).to_be_bytes());
        bundle_hasher.update(normalized.as_bytes());
        bundle_hasher.update(size.to_be_bytes());
        bundle_hasher.update(content_hasher.finalize());
    }
    Ok(hex::encode(bundle_hasher.finalize()))
}

fn normalize_relative_path(path: &str) -> Option<String> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') {
        return None;
    }
    let mut components = Vec::new();
    for component in Path::new(path).components() {
        match component {
            std::path::Component::Normal(component) => {
                components.push(component.to_str()?);
            }
            _ => return None,
        }
    }
    (!components.is_empty()).then(|| components.join("/"))
}

fn ossgadget_coverage_matches(
    coverage: &OssGadgetCoverage,
    expected_paths: &std::collections::BTreeSet<String>,
) -> bool {
    if coverage.version != 1 || !coverage.diagnostics.is_empty() {
        return false;
    }
    let mut scanned = std::collections::BTreeSet::new();
    for path in &coverage.scanned_paths {
        let Some(path) = normalize_relative_path(path) else {
            return false;
        };
        if !scanned.insert(path) {
            return false;
        }
    }
    for entry in &coverage.skipped_paths {
        let Some(path) = normalize_relative_path(&entry.path) else {
            return false;
        };
        if !expected_paths.contains(&path) || entry.reason.is_empty() {
            return false;
        }
    }
    coverage.skipped_paths.is_empty() && &scanned == expected_paths
}

fn ossgadget_scanned_paths(
    coverage: &OssGadgetCoverage,
) -> Option<std::collections::BTreeSet<String>> {
    let mut scanned = std::collections::BTreeSet::new();
    for path in &coverage.scanned_paths {
        if !scanned.insert(normalize_relative_path(path)?) {
            return None;
        }
    }
    Some(scanned)
}

fn normalize_sarif_path(path: &str, root: &Path, guest_root: &Path) -> Option<String> {
    if path.contains('\\') {
        return None;
    }
    let path = Path::new(path);
    let relative = if path.is_absolute() {
        path.strip_prefix(root)
            .or_else(|_| path.strip_prefix(guest_root))
            .ok()?
    } else {
        // OSSGadget reports the guest root without its leading slash.
        guest_root
            .strip_prefix("/")
            .ok()
            .and_then(|guest| path.strip_prefix(guest).ok())
            .unwrap_or(path)
    };
    normalize_relative_path(relative.to_str()?)
}

struct OssGadgetReportContext<'a> {
    input_sha256: &'a str,
    rule_bundle_sha256: &'a str,
    bundle_rules: &'a std::collections::BTreeSet<String>,
    package_root: &'a Path,
    guest_root: &'a Path,
    expected_paths: &'a std::collections::BTreeSet<String>,
    inventory_complete: bool,
    execution_succeeded: bool,
    output_complete: bool,
}

fn path_within_inventory(path: &str, expected_paths: &std::collections::BTreeSet<String>) -> bool {
    expected_paths.contains(path)
        || path
            .match_indices('/')
            .any(|(index, _)| expected_paths.contains(&path[..index]))
}

fn ossgadget_engine_report(
    context: OssGadgetReportContext<'_>,
    sarif: Option<OssGadgetSarif>,
    coverage: Option<OssGadgetCoverage>,
) -> Result<EngineReport> {
    let OssGadgetReportContext {
        input_sha256,
        rule_bundle_sha256,
        bundle_rules,
        package_root,
        guest_root,
        expected_paths,
        inventory_complete,
        execution_succeeded,
        output_complete,
    } = context;
    let mut findings = Vec::new();
    let mut finding_ids = std::collections::HashSet::new();
    let mut finding_limit_exceeded = false;
    let mut location_outside_inventory = false;
    let rules_complete = sarif.as_ref().is_some_and(|sarif| {
        sarif.malformed_results == 0
            && sarif.findings.iter().all(|finding| {
                sarif.rules.contains(&finding.rule_id) || bundle_rules.contains(&finding.rule_id)
            })
    });
    if let Some(sarif) = &sarif {
        for finding in &sarif.findings {
            let path = finding
                .location
                .as_ref()
                .and_then(|location| location.path.as_deref())
                .map(|path| normalize_sarif_path(path, package_root, guest_root));
            if let Some(path) = &path {
                if path
                    .as_ref()
                    .is_none_or(|path| !path_within_inventory(path, expected_paths))
                {
                    location_outside_inventory = true;
                }
            }
            let member = path
                .as_ref()
                .and_then(|path| path.as_deref())
                .unwrap_or("unknown");
            let rule = safe_code(&finding.rule_id);
            let id = engine_finding_id("ossgadget", &rule, member, "all-matches")?;
            if !finding_ids.insert(id.clone()) {
                continue;
            }
            if findings.len() == MAX_ENGINE_FINDINGS {
                finding_limit_exceeded = true;
                continue;
            }
            findings.push(EngineFinding {
                id,
                rule,
                summary: "potential backdoor pattern matched; review required".to_string(),
                location: None,
                native_severity: None,
                policy_score: Some(Decimal::from(4)),
            });
        }
    }
    let scanned_count = coverage
        .as_ref()
        .and_then(ossgadget_scanned_paths)
        .map(|paths| paths.intersection(expected_paths).count())
        .unwrap_or_default();
    let coverage_matches = coverage
        .as_ref()
        .is_some_and(|coverage| ossgadget_coverage_matches(coverage, expected_paths));
    let diagnostics = sarif.as_ref().is_some_and(|sarif| sarif.diagnostics > 0)
        || coverage
            .as_ref()
            .is_some_and(|coverage| !coverage.diagnostics.is_empty());
    let reason = if !output_complete {
        Some("output_limit")
    } else if !execution_succeeded {
        Some("scanner_execution_failed")
    } else if sarif.is_none() {
        Some("invalid_report")
    } else if !rules_complete {
        Some("missing_rules")
    } else if !inventory_complete {
        Some("input_inventory_incomplete")
    } else if location_outside_inventory {
        Some("input_coverage_mismatch")
    } else if coverage.is_none() {
        Some("coverage_report_missing")
    } else if diagnostics {
        Some("scanner_reported_errors")
    } else if !coverage_matches {
        Some("input_coverage_mismatch")
    } else if finding_limit_exceeded {
        Some("finding_limit")
    } else {
        None
    };
    let engine_report = EngineReport {
        source: "ossgadget".to_string(),
        version: Some("4063457b40211c25b41d56465d41783f2d42c5c1".to_string()),
        rule_bundle_sha256: Some(rule_bundle_sha256.to_string()),
        database_sha256: None,
        input_sha256: Some(input_sha256.to_string()),
        expected_inputs: u64::try_from(expected_paths.len())?,
        processed_inputs: u64::try_from(scanned_count)?,
        coverage: if reason.is_none() {
            Coverage::Complete
        } else {
            Coverage::Partial
        },
        findings,
        reason: reason.map(str::to_string),
    };
    engine_report.validate()?;
    Ok(engine_report)
}

fn kill_process_group(pid: i32) {
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
}

/// Runs an external analyzer against a package archive and expects a
/// normalized JSON report on stdout: `{"score": 0-10, "rules": [...],
/// "summary": "..."}`. This keeps the firewall engine independent of any
/// single tool's output schema; GuardDog, for example, can be wrapped by a
/// small script that prints this shape.
pub struct CommandScanner {
    pub command: PathBuf,
    pub source: String,
    pub timeout: Duration,
    pub max_output_bytes: usize,
    pub format: ReportFormat,
    pub revision: EngineRevision,
}

/// Whether a scanner's engine version and rule bundle were verified for this run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineRevision {
    Unknown,
    Unverified,
    Attested {
        version: String,
        rule_bundle_sha256: String,
    },
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardDogInstallManifest {
    format_version: u32,
    guarddog_version: String,
    executable_sha256: String,
    package_dir: String,
    package_sha256: String,
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn verify_guarddog_installation(command: &Path, manifest_path: &Path) -> Result<EngineRevision> {
    let (manifest_bytes, truncated) = read_capped(File::open(manifest_path)?, 16 * 1024);
    anyhow::ensure!(!truncated, "GuardDog install manifest exceeds size limit");
    let manifest: GuardDogInstallManifest =
        serde_json::from_slice(&manifest_bytes).context("invalid GuardDog install manifest")?;
    anyhow::ensure!(
        manifest.format_version == 1,
        "unsupported GuardDog manifest format"
    );
    anyhow::ensure!(
        !manifest.guarddog_version.is_empty()
            && manifest.guarddog_version.len() <= 64
            && manifest
                .guarddog_version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte)),
        "GuardDog manifest version is invalid"
    );
    anyhow::ensure!(
        is_sha256_hex(&manifest.executable_sha256) && is_sha256_hex(&manifest.package_sha256),
        "GuardDog manifest digests are invalid"
    );
    anyhow::ensure!(
        sha256_path(command)? == manifest.executable_sha256,
        "GuardDog executable digest does not match its manifest"
    );
    let package_dir = normalize_relative_path(&manifest.package_dir)
        .context("GuardDog manifest package_dir is invalid")?;
    let package_root = manifest_path
        .parent()
        .context("GuardDog manifest has no parent directory")?
        .join(package_dir);
    anyhow::ensure!(
        sha256_directory(&package_root)? == manifest.package_sha256,
        "GuardDog package digest does not match its manifest"
    );
    Ok(EngineRevision::Attested {
        version: manifest.guarddog_version,
        rule_bundle_sha256: manifest.package_sha256,
    })
}

impl CommandScanner {
    pub fn new(command: impl Into<PathBuf>, source: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            source: source.into(),
            timeout: DEFAULT_TIMEOUT,
            max_output_bytes: DEFAULT_MAX_OUTPUT,
            format: ReportFormat::Normalized,
            revision: EngineRevision::Unknown,
        }
    }

    pub fn guarddog(command: impl Into<PathBuf>) -> Self {
        Self {
            command: command.into(),
            source: "guarddog".to_string(),
            timeout: DEFAULT_TIMEOUT,
            max_output_bytes: DEFAULT_MAX_OUTPUT,
            format: ReportFormat::GuardDog,
            revision: EngineRevision::Unknown,
        }
    }

    /// Attests the engine revision from an install manifest; any mismatch leaves
    /// the scanner `Unverified`, so its reports stay partial.
    pub fn with_guarddog_manifest(mut self, manifest_path: &Path) -> Self {
        self.revision = resolve_executable(&self.command)
            .and_then(|command| verify_guarddog_installation(&command, manifest_path))
            .unwrap_or(EngineRevision::Unverified);
        self
    }

    pub fn with_format(mut self, format: ReportFormat) -> Self {
        self.format = format;
        self
    }

    pub fn with_limits(mut self, timeout: Duration, max_output_bytes: usize) -> Self {
        self.timeout = timeout;
        self.max_output_bytes = max_output_bytes;
        self
    }

    fn run(
        &self,
        ecosystem: &Ecosystem,
        archive: &mut File,
        archive_path: &Path,
    ) -> Result<String> {
        #[cfg(unix)]
        ensure_unprivileged(unsafe { libc::geteuid() })?;

        let runner = sandbox_runner()?;
        self.run_with_runner(ecosystem, archive, archive_path, &runner)
    }

    fn run_with_runner(
        &self,
        ecosystem: &Ecosystem,
        archive: &mut File,
        archive_path: &Path,
        runner: &Path,
    ) -> Result<String> {
        if !runner.is_file() {
            anyhow::bail!("scanner sandbox runner not found: {}", runner.display());
        }
        let scanner = resolve_executable(&self.command)?;
        let scratch_parent = archive_path
            .parent()
            .context("scanner archive has no parent")?;
        let scratch_parent = std::fs::canonicalize(scratch_parent)?;
        let scratch = ScannerScratch::new(&scratch_parent)?;
        let archive_in_sandbox = Path::new(if cfg!(target_os = "macos") {
            "/dev/fd/0"
        } else {
            "/scan/archive"
        });
        let command = sandbox_command(
            runner,
            &scanner,
            self.format,
            ecosystem,
            archive_in_sandbox,
            &scratch.path,
        )?;
        archive.seek(SeekFrom::Start(0))?;
        let archive_fd = archive.try_clone()?;
        let output = run_bounded_command(
            command,
            Some(archive_fd),
            self.timeout,
            self.max_output_bytes,
            ARCHIVE_SCANNER_FILE_SIZE_LIMIT_BYTES,
            SCANNER_MEMORY_LIMIT_BYTES,
            &self.command.display().to_string(),
        )?;
        if !output.complete {
            anyhow::bail!(
                "{} output exceeded {} bytes",
                self.command.display(),
                self.max_output_bytes
            );
        }
        if !output.status.success() {
            anyhow::bail!(
                "{} exited with {}: {}",
                self.command.display(),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

pub(crate) struct BoundedCommandOutput {
    pub(crate) status: std::process::ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) complete: bool,
}

pub(crate) struct SandboxMount {
    pub(crate) host_path: PathBuf,
    pub(crate) sandbox_path: PathBuf,
}

struct ToolRunOptions<'a> {
    environment: &'a [(std::ffi::OsString, std::ffi::OsString)],
    timeout: Duration,
    output_limit: usize,
    file_size_limit: u64,
    memory_limit: u64,
    allow_network: bool,
}

pub(crate) fn run_isolated_tool_with_env(
    scanner_path: &Path,
    arguments: &[std::ffi::OsString],
    mounts: &[SandboxMount],
    scratch_path: &Path,
    environment: &[(std::ffi::OsString, std::ffi::OsString)],
    timeout: Duration,
    output_limit: usize,
) -> Result<BoundedCommandOutput> {
    run_isolated_tool_with_network_and_env(
        scanner_path,
        arguments,
        mounts,
        scratch_path,
        ToolRunOptions {
            environment,
            timeout,
            output_limit,
            file_size_limit: output_limit as u64,
            memory_limit: SCANNER_MEMORY_LIMIT_BYTES,
            allow_network: false,
        },
    )
}

pub(crate) fn run_isolated_image_tool(
    scanner_path: &Path,
    arguments: &[std::ffi::OsString],
    mounts: &[SandboxMount],
    scratch_path: &Path,
    timeout: Duration,
    output_limit: usize,
) -> Result<BoundedCommandOutput> {
    run_isolated_tool_with_network_and_env(
        scanner_path,
        arguments,
        mounts,
        scratch_path,
        ToolRunOptions {
            environment: &[
                ("GOMEMLIMIT".into(), "384MiB".into()),
                ("GOMAXPROCS".into(), "2".into()),
            ],
            timeout,
            output_limit,
            file_size_limit: 2 * 1024 * 1024 * 1024,
            // Trivy mmaps the CVE and Java databases. Leave room in the
            // address space for the mappings without growing the Go heap.
            memory_limit: 16 * 1024 * 1024 * 1024,
            allow_network: false,
        },
    )
}

pub(crate) fn run_networked_isolated_tool(
    scanner_path: &Path,
    arguments: &[std::ffi::OsString],
    scratch_path: &Path,
    timeout: Duration,
    output_limit: usize,
) -> Result<BoundedCommandOutput> {
    run_isolated_tool_with_network_and_env(
        scanner_path,
        arguments,
        &[],
        scratch_path,
        ToolRunOptions {
            environment: &[],
            timeout,
            output_limit,
            file_size_limit: output_limit as u64,
            memory_limit: SCANNER_MEMORY_LIMIT_BYTES,
            allow_network: true,
        },
    )
}

fn run_isolated_tool_with_network_and_env(
    scanner_path: &Path,
    arguments: &[std::ffi::OsString],
    mounts: &[SandboxMount],
    scratch_path: &Path,
    options: ToolRunOptions<'_>,
) -> Result<BoundedCommandOutput> {
    let ToolRunOptions {
        environment,
        timeout,
        output_limit,
        file_size_limit,
        memory_limit,
        allow_network,
    } = options;
    if !scanner_memory_limit_supported() {
        anyhow::bail!("scanner_memory_limit_unavailable");
    }
    #[cfg(unix)]
    ensure_unprivileged(unsafe { libc::geteuid() })?;

    let runner = sandbox_runner()?;
    let scanner = resolve_executable(scanner_path)?;
    let scratch = std::fs::canonicalize(scratch_path)?;
    anyhow::ensure!(
        std::fs::symlink_metadata(&scratch)?.file_type().is_dir(),
        "scanner scratch is not a real directory"
    );
    let mounts = canonical_sandbox_mounts(mounts, &scratch)?;
    let command = isolated_tool_command(
        &runner,
        &scanner,
        arguments,
        &mounts,
        &scratch,
        allow_network,
        environment,
    )?;
    run_bounded_command(
        command,
        None,
        timeout,
        output_limit,
        file_size_limit,
        memory_limit,
        &scanner.display().to_string(),
    )
}

fn canonical_sandbox_mounts(
    mounts: &[SandboxMount],
    scratch_path: &Path,
) -> Result<Vec<SandboxMount>> {
    let scratch_metadata = std::fs::symlink_metadata(scratch_path)?;
    anyhow::ensure!(
        scratch_metadata.file_type().is_dir(),
        "scanner scratch is not a real directory"
    );
    let scratch = std::fs::canonicalize(scratch_path)?;
    #[cfg(unix)]
    let scratch_inodes = sandbox_tree_inodes(&scratch)?;
    let mut result = Vec::with_capacity(mounts.len());
    for mount in mounts {
        let metadata = std::fs::symlink_metadata(&mount.host_path)?;
        anyhow::ensure!(
            metadata.file_type().is_file() || metadata.file_type().is_dir(),
            "scanner input is not a regular file or directory"
        );
        let host_path = std::fs::canonicalize(&mount.host_path)?;
        anyhow::ensure!(
            !paths_overlap(&host_path, &scratch),
            "scanner input overlaps writable scratch"
        );
        anyhow::ensure!(
            mount.sandbox_path.is_absolute()
                && mount.sandbox_path.starts_with("/scan")
                && mount.sandbox_path.components().all(|component| matches!(
                    component,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )),
            "scanner input path is not confined to /scan"
        );
        anyhow::ensure!(
            mount.sandbox_path != Path::new("/scan"),
            "scanner input path cannot replace /scan"
        );
        anyhow::ensure!(
            !result.iter().any(|previous: &SandboxMount| {
                previous.sandbox_path == mount.sandbox_path
                    || previous.sandbox_path.starts_with(&mount.sandbox_path)
                    || mount.sandbox_path.starts_with(&previous.sandbox_path)
            }),
            "scanner input mounts overlap"
        );
        for entry in walkdir::WalkDir::new(&host_path).follow_links(false) {
            let entry = entry?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() {
                if let Ok(target) = std::fs::canonicalize(path) {
                    anyhow::ensure!(
                        !paths_overlap(&target, &scratch),
                        "scanner input contains an alias to writable scratch"
                    );
                }
                continue;
            }
            #[cfg(unix)]
            anyhow::ensure!(
                !scratch_inodes.contains(&(metadata.dev(), metadata.ino())),
                "scanner input aliases writable scratch"
            );
        }
        result.push(SandboxMount {
            host_path,
            sandbox_path: mount.sandbox_path.clone(),
        });
    }
    Ok(result)
}

fn paths_overlap(first: &Path, second: &Path) -> bool {
    first.starts_with(second) || second.starts_with(first)
}

#[cfg(unix)]
fn sandbox_tree_inodes(root: &Path) -> Result<std::collections::HashSet<(u64, u64)>> {
    let mut inodes = std::collections::HashSet::new();
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if !metadata.file_type().is_symlink() {
            inodes.insert((metadata.dev(), metadata.ino()));
        }
    }
    Ok(inodes)
}

fn run_bounded_command(
    mut command: Command,
    stdin: Option<File>,
    timeout: Duration,
    output_limit: usize,
    file_size_limit: u64,
    memory_limit: u64,
    label: &str,
) -> Result<BoundedCommandOutput> {
    install_resource_limits(&mut command, timeout, file_size_limit, memory_limit)?;
    let mut child = command
        .stdin(stdin.map(Stdio::from).unwrap_or_else(Stdio::null))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run {label}"))?;
    let pid = child.id() as i32;
    let stdout = child.stdout.take().context("scanner stdout missing")?;
    let stderr = child.stderr.take().context("scanner stderr missing")?;
    let (out_tx, out_rx) = std::sync::mpsc::channel();
    let (err_tx, err_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = out_tx.send(read_capped(stdout, output_limit));
    });
    std::thread::spawn(move || {
        let _ = err_tx.send(read_capped(stderr, output_limit));
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            kill_process_group(pid);
            let _ = child.wait();
            anyhow::bail!("{label} timed out after {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let drain_deadline = deadline.min(Instant::now() + DRAIN_GRACE);
    let (stdout, stdout_truncated) =
        match out_rx.recv_timeout(drain_deadline.saturating_duration_since(Instant::now())) {
            Ok(result) => result,
            Err(_) => {
                kill_process_group(pid);
                anyhow::bail!("{label} timed out while draining scanner output");
            }
        };
    let (stderr, stderr_truncated) =
        match err_rx.recv_timeout(drain_deadline.saturating_duration_since(Instant::now())) {
            Ok(result) => result,
            Err(_) => {
                kill_process_group(pid);
                anyhow::bail!("{label} timed out while draining scanner output");
            }
        };
    Ok(BoundedCommandOutput {
        status,
        stdout,
        stderr,
        complete: !stdout_truncated && !stderr_truncated,
    })
}
fn install_resource_limits(
    command: &mut Command,
    timeout: Duration,
    file_size_limit: u64,
    memory_limit: u64,
) -> Result<()> {
    if !scanner_memory_limit_supported() {
        anyhow::bail!("scanner_memory_limit_unavailable");
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let cpu_limit = timeout
            .as_secs()
            .saturating_add(u64::from(timeout.subsec_nanos() > 0))
            .max(1) as libc::rlim_t;
        let memory_limit = memory_limit as libc::rlim_t;
        let file_size_limit = file_size_limit as libc::rlim_t;
        command.process_group(0);
        unsafe {
            command.pre_exec(move || {
                for (resource, limit) in [
                    (libc::RLIMIT_CPU, cpu_limit),
                    (libc::RLIMIT_AS, memory_limit),
                    (libc::RLIMIT_FSIZE, file_size_limit),
                ] {
                    let limits = libc::rlimit {
                        rlim_cur: limit,
                        rlim_max: limit,
                    };
                    if libc::setrlimit(resource, &limits) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (command, timeout, file_size_limit, memory_limit);
    }
    Ok(())
}

struct ScannerScratch {
    path: PathBuf,
}

impl ScannerScratch {
    fn new(parent: &Path) -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_nanos();
        let path = parent.join(format!(
            ".supply-core-scanner-{}-{nanos}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = std::fs::DirBuilder::new();
        builder
            .mode(0o700)
            .create(&path)
            .context("failed to create scanner scratch")?;
        let mut scratch = Self { path };
        scratch.path = std::fs::canonicalize(&scratch.path)?;
        Ok(scratch)
    }
}

impl Drop for ScannerScratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
#[cfg(unix)]
fn ensure_unprivileged(effective_uid: libc::uid_t) -> Result<()> {
    anyhow::ensure!(
        effective_uid != 0,
        "scanner must run with an unprivileged effective UID"
    );
    Ok(())
}

fn sandbox_runner() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let runner = PathBuf::from("/usr/bin/sandbox-exec");
        if runner.is_file() {
            return Ok(runner);
        }
        anyhow::bail!("macOS Seatbelt runner is unavailable");
    }
    #[cfg(target_os = "linux")]
    {
        for runner in ["/usr/bin/bwrap", "/bin/bwrap"] {
            let runner = PathBuf::from(runner);
            if runner.is_file() {
                return Ok(runner);
            }
        }
        anyhow::bail!("Linux scanner sandbox requires bubblewrap");
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    anyhow::bail!("scanner sandbox is unsupported on this platform")
}

fn resolve_executable(command: &Path) -> Result<PathBuf> {
    if command.is_absolute() || command.components().count() > 1 {
        return std::fs::canonicalize(command)
            .with_context(|| format!("scanner executable not found: {}", command.display()));
    }
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        let candidate = directory.join(command);
        if candidate.is_file() {
            return std::fs::canonicalize(&candidate).with_context(|| {
                format!(
                    "failed to resolve scanner executable: {}",
                    command.display()
                )
            });
        }
    }
    anyhow::bail!("scanner executable not found: {}", command.display())
}

fn virtual_environment_root(path: &Path) -> Option<PathBuf> {
    let mut directory = path.parent();
    while let Some(candidate) = directory {
        if candidate.join("pyvenv.cfg").is_file() || candidate.join("conda-meta").is_dir() {
            return Some(candidate.to_path_buf());
        }
        directory = candidate.parent();
    }
    None
}

fn scanner_runtime_paths(scanner: &Path) -> Vec<PathBuf> {
    let mut paths = vec![scanner.to_path_buf()];
    if let Some(root) = virtual_environment_root(scanner) {
        paths.push(root);
    }
    let mut prefix = [0_u8; 512];
    if let Ok(mut file) = File::open(scanner) {
        if let Ok(length) = file.read(&mut prefix) {
            if prefix[..length].starts_with(b"#!") {
                let end = prefix[..length]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .unwrap_or(length);
                if let Ok(line) = std::str::from_utf8(&prefix[2..end]) {
                    if let Some(interpreter) = line.split_whitespace().next() {
                        let interpreter = PathBuf::from(interpreter);
                        if let Some(root) = virtual_environment_root(&interpreter) {
                            paths.push(root);
                        }
                        if let Ok(interpreter) = std::fs::canonicalize(interpreter) {
                            if let Some(root) = virtual_environment_root(&interpreter) {
                                paths.push(root);
                            }
                            paths.push(interpreter);
                        }
                    }
                }
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

fn scanner_path_environment(scanner: &Path, runtime: &[PathBuf]) -> Result<std::ffi::OsString> {
    let mut paths = Vec::new();
    if let Some(parent) = scanner.parent() {
        paths.push(parent.to_path_buf());
    }
    for root in runtime {
        let bin = root.join("bin");
        if bin.is_dir() {
            paths.push(bin);
        }
    }
    paths.extend([
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
        PathBuf::from("/usr/sbin"),
        PathBuf::from("/sbin"),
    ]);
    std::env::join_paths(paths).context("failed to build scanner PATH")
}

fn sandbox_command(
    runner: &Path,
    scanner: &Path,
    format: ReportFormat,
    ecosystem: &Ecosystem,
    archive: &Path,
    scratch: &Path,
) -> Result<Command> {
    #[cfg(target_os = "macos")]
    {
        macos_sandbox_command(runner, scanner, format, ecosystem, archive, scratch)
    }
    #[cfg(target_os = "linux")]
    {
        linux_sandbox_command(runner, scanner, format, ecosystem, archive, scratch)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (runner, scanner, format, ecosystem, archive, scratch);
        anyhow::bail!("scanner sandbox is unsupported on this platform")
    }
}

fn isolated_tool_command(
    runner: &Path,
    scanner: &Path,
    arguments: &[std::ffi::OsString],
    mounts: &[SandboxMount],
    scratch: &Path,
    allow_network: bool,
    environment: &[(std::ffi::OsString, std::ffi::OsString)],
) -> Result<Command> {
    #[cfg(target_os = "macos")]
    {
        macos_isolated_tool_command(
            runner,
            scanner,
            arguments,
            mounts,
            scratch,
            allow_network,
            environment,
        )
    }
    #[cfg(target_os = "linux")]
    {
        linux_isolated_tool_command(
            runner,
            scanner,
            arguments,
            mounts,
            scratch,
            allow_network,
            environment,
        )
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (
            runner,
            scanner,
            arguments,
            mounts,
            scratch,
            allow_network,
            environment,
        );
        anyhow::bail!("scanner sandbox is unsupported on this platform")
    }
}

#[cfg(target_os = "macos")]
fn macos_isolated_tool_command(
    runner: &Path,
    scanner: &Path,
    arguments: &[std::ffi::OsString],
    mounts: &[SandboxMount],
    scratch: &Path,
    allow_network: bool,
    environment: &[(std::ffi::OsString, std::ffi::OsString)],
) -> Result<Command> {
    let runtime = scanner_runtime_paths(scanner);
    let inputs = mounts
        .iter()
        .map(|mount| mount.host_path.as_path())
        .collect::<Vec<_>>();
    let profile = macos_sandbox_profile(scanner, &runtime, &inputs, scratch, allow_network)?;
    let mut command = Command::new(runner);
    command
        .env_clear()
        .env("HOME", scratch)
        .env("TMPDIR", scratch)
        .env("TMP", scratch)
        .env("TEMP", scratch)
        .env("XDG_CACHE_HOME", scratch.join(".cache"))
        .env("PATH", scanner_path_environment(scanner, &runtime)?)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .current_dir(scratch)
        .arg("-p")
        .arg(profile)
        .arg(scanner)
        .args(arguments);
    for (key, value) in environment {
        command.env(key, value);
    }
    Ok(command)
}

#[cfg(target_os = "linux")]
fn linux_isolated_tool_command(
    runner: &Path,
    scanner: &Path,
    arguments: &[std::ffi::OsString],
    mounts: &[SandboxMount],
    scratch: &Path,
    allow_network: bool,
    environment: &[(std::ffi::OsString, std::ffi::OsString)],
) -> Result<Command> {
    let runtime = scanner_runtime_paths(scanner);
    let system_roots = ["/usr", "/bin", "/sbin", "/lib", "/lib64"];
    let ca_bundle = if allow_network {
        Some(linux_system_ca_bundle()?)
    } else {
        None
    };
    let mut command = Command::new(runner);
    command
        .env_clear()
        .args(["--die-with-parent", "--new-session", "--unshare-all"]);
    if allow_network {
        command.arg("--share-net");
    }
    command.args(["--tmpfs", "/"]);

    let mut runtime_mounts = Vec::new();
    for path in &runtime {
        if system_roots
            .iter()
            .any(|root| path.starts_with(Path::new(root)))
            || runtime
                .iter()
                .any(|root| root != path && root.is_dir() && path.starts_with(root))
        {
            continue;
        }
        runtime_mounts.push(path);
    }
    let mut directories = std::collections::BTreeSet::new();
    for path in &runtime_mounts {
        add_mount_parents(&mut directories, path)?;
    }
    for mount in mounts {
        add_mount_parents(&mut directories, &mount.sandbox_path)?;
    }
    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by_key(|path| path.components().count());
    for directory in directories {
        command.arg("--dir").arg(directory);
    }
    for root in system_roots {
        let root = Path::new(root);
        if root.exists() {
            command.arg("--ro-bind").arg(root).arg(root);
        }
    }
    for path in runtime_mounts {
        command.arg("--ro-bind").arg(path).arg(path);
    }
    command
        .args(["--proc", "/proc", "--dev", "/dev", "--bind"])
        .arg(scratch)
        .args(["/tmp"]);
    if let Some(ca_bundle) = &ca_bundle {
        anyhow::ensure!(
            !paths_overlap(ca_bundle, scratch),
            "network CA bundle overlaps writable scratch"
        );
        command
            .arg("--ro-bind")
            .arg(ca_bundle)
            .arg("/tmp/.supply-core-ca-bundle.pem");
    }
    for mount in mounts {
        command
            .arg("--ro-bind")
            .arg(&mount.host_path)
            .arg(&mount.sandbox_path);
    }
    command
        .args([
            "--remount-ro",
            "/",
            "--chdir",
            "/tmp",
            "--clearenv",
            "--setenv",
            "HOME",
            "/tmp",
            "--setenv",
            "TMPDIR",
            "/tmp",
            "--setenv",
            "TMP",
            "/tmp",
            "--setenv",
            "TEMP",
            "/tmp",
            "--setenv",
            "XDG_CACHE_HOME",
            "/tmp/.cache",
            "--setenv",
            "LANG",
            "C",
            "--setenv",
            "LC_ALL",
            "C",
            "--setenv",
            "PYTHONDONTWRITEBYTECODE",
            "1",
            "--setenv",
            "PATH",
        ])
        .arg(scanner_path_environment(scanner, &runtime)?);
    if ca_bundle.is_some() {
        command.args([
            "--setenv",
            "SSL_CERT_FILE",
            "/tmp/.supply-core-ca-bundle.pem",
        ]);
    }
    for (key, value) in environment {
        command.arg("--setenv").arg(key).arg(value);
    }
    command.arg("--").arg(scanner).args(arguments);
    Ok(command)
}
#[cfg(target_os = "linux")]
fn linux_system_ca_bundle() -> Result<PathBuf> {
    if let Some(configured) = std::env::var_os("SSL_CERT_FILE") {
        if let Ok(path) = std::fs::canonicalize(PathBuf::from(configured)) {
            if let Ok(metadata) = std::fs::metadata(&path) {
                if metadata.is_file() && metadata.len() > 0 {
                    return Ok(path);
                }
            }
        }
    }

    for candidate in [
        Path::new("/etc/ssl/certs/ca-certificates.crt"),
        Path::new("/etc/pki/tls/certs/ca-bundle.crt"),
        Path::new("/etc/ssl/ca-bundle.pem"),
        Path::new("/etc/pki/tls/cacert.pem"),
        Path::new("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"),
        Path::new("/etc/ssl/cert.pem"),
    ] {
        let Ok(path) = std::fs::canonicalize(candidate) else {
            continue;
        };
        let Ok(metadata) = std::fs::metadata(&path) else {
            continue;
        };
        if metadata.is_file() && metadata.len() > 0 {
            return Ok(path);
        }
    }
    anyhow::bail!("system_ca_bundle_unavailable")
}

#[cfg(target_os = "linux")]
fn add_mount_parents(
    directories: &mut std::collections::BTreeSet<PathBuf>,
    path: &Path,
) -> Result<()> {
    let mut parent = path.parent();
    while let Some(directory) = parent {
        if directory == Path::new("/") {
            break;
        }
        if !directory.starts_with("/scan")
            && ["/usr", "/bin", "/sbin", "/lib", "/lib64"]
                .iter()
                .any(|root| directory.starts_with(Path::new(root)))
        {
            break;
        }
        directories.insert(directory.to_path_buf());
        parent = directory.parent();
    }
    Ok(())
}

fn ossgadget_sandbox_command(
    runner: &Path,
    scanner: &Path,
    install_root: &Path,
    package_root: &Path,
    scratch: &Path,
    sarif_path: &Path,
    coverage_path: &Path,
) -> Result<Command> {
    #[cfg(target_os = "macos")]
    {
        macos_ossgadget_sandbox_command(
            runner,
            scanner,
            install_root,
            package_root,
            scratch,
            sarif_path,
            coverage_path,
        )
    }
    #[cfg(target_os = "linux")]
    {
        linux_ossgadget_sandbox_command(
            runner,
            scanner,
            install_root,
            package_root,
            scratch,
            sarif_path,
            coverage_path,
        )
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (
            runner,
            scanner,
            install_root,
            package_root,
            scratch,
            sarif_path,
            coverage_path,
        );
        anyhow::bail!("scanner sandbox is unsupported on this platform")
    }
}

#[cfg(target_os = "macos")]
fn macos_ossgadget_sandbox_command(
    runner: &Path,
    scanner: &Path,
    install_root: &Path,
    package_root: &Path,
    scratch: &Path,
    sarif_path: &Path,
    coverage_path: &Path,
) -> Result<Command> {
    let mut runtime = scanner_runtime_paths(scanner);
    runtime.push(install_root.to_path_buf());
    runtime.sort();
    runtime.dedup();
    let profile = macos_sandbox_profile(scanner, &runtime, &[package_root], scratch, false)?;
    let path = scanner_path_environment(scanner, &runtime)?;
    let mut command = Command::new(runner);
    command
        .env_clear()
        .env("HOME", scratch)
        .env("TMPDIR", scratch)
        .env("TMP", scratch)
        .env("TEMP", scratch)
        .env("XDG_CACHE_HOME", scratch.join(".cache"))
        .env("PATH", path)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env(OSSGADGET_COVERAGE_ENV, coverage_path)
        .current_dir(scratch)
        .arg("-p")
        .arg(profile)
        .arg(scanner)
        .args(["detect-backdoor", "--format", "sarifv2", "--output-file"])
        .arg(sarif_path)
        .args(["--download-directory"])
        .arg(scratch)
        .arg("--single-threaded")
        .arg(package_root);
    Ok(command)
}

#[cfg(target_os = "linux")]
fn linux_ossgadget_sandbox_command(
    runner: &Path,
    scanner: &Path,
    install_root: &Path,
    package_root: &Path,
    scratch: &Path,
    sarif_path: &Path,
    coverage_path: &Path,
) -> Result<Command> {
    let mut runtime = scanner_runtime_paths(scanner);
    runtime.push(install_root.to_path_buf());
    runtime.sort();
    runtime.dedup();
    let system_roots = ["/usr", "/bin", "/sbin", "/lib", "/lib64"];
    let mut command = Command::new(runner);
    command.env_clear().args([
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--tmpfs",
        "/",
    ]);
    for root in system_roots {
        let root = Path::new(root);
        if root.exists() {
            command.arg("--ro-bind").arg(root).arg(root);
        }
    }
    for path in &runtime {
        if system_roots
            .iter()
            .any(|root| path.starts_with(Path::new(root)))
            || runtime
                .iter()
                .any(|root| root != path && root.is_dir() && path.starts_with(root))
        {
            continue;
        }
        command.arg("--ro-bind").arg(path).arg(path);
    }
    command
        .args(["--proc", "/proc", "--dev", "/dev", "--bind"])
        .arg(scratch)
        .args(["/tmp", "--dir", "/scan", "--ro-bind"])
        .arg(package_root)
        .arg("/scan/package")
        .args([
            "--remount-ro",
            "/",
            "--chdir",
            "/tmp",
            "--clearenv",
            "--setenv",
            "HOME",
            "/tmp",
            "--setenv",
            "TMPDIR",
            "/tmp",
            "--setenv",
            "TMP",
            "/tmp",
            "--setenv",
            "TEMP",
            "/tmp",
        ])
        .arg("--setenv")
        .arg(OSSGADGET_COVERAGE_ENV)
        .arg(coverage_path)
        .args([
            "--setenv",
            "DOTNET_GCRegionRange",
            OSSGADGET_GC_REGION_RANGE,
        ])
        .args([
            "--setenv",
            "DOTNET_GCHeapHardLimit",
            OSSGADGET_GC_HEAP_HARD_LIMIT,
        ])
        // W^X double-maps JIT code through a growing file that RLIMIT_FSIZE kills.
        .args(["--setenv", "DOTNET_EnableWriteXorExecute", "0"])
        .arg("--setenv")
        .arg("PATH")
        .arg(scanner_path_environment(scanner, &runtime)?)
        .args([
            "--setenv",
            "LANG",
            "C",
            "--setenv",
            "LC_ALL",
            "C",
            "--setenv",
            "PYTHONDONTWRITEBYTECODE",
            "1",
            "--",
        ])
        .arg(scanner)
        .args(["detect-backdoor", "--format", "sarifv2", "--output-file"])
        .arg(sarif_path)
        .args([
            "--download-directory",
            "/tmp",
            "--single-threaded",
            "/scan/package",
        ]);
    Ok(command)
}

#[cfg(target_os = "macos")]
fn macos_sandbox_command(
    runner: &Path,
    scanner: &Path,
    format: ReportFormat,
    ecosystem: &Ecosystem,
    archive: &Path,
    scratch: &Path,
) -> Result<Command> {
    let runtime = scanner_runtime_paths(scanner);
    let profile = macos_sandbox_profile(scanner, &runtime, &[archive], scratch, false)?;
    let path = scanner_path_environment(scanner, &runtime)?;
    let mut command = Command::new(runner);
    command
        .env_clear()
        .env("HOME", scratch)
        .env("TMPDIR", scratch)
        .env("TMP", scratch)
        .env("TEMP", scratch)
        .env("XDG_CACHE_HOME", scratch.join(".cache"))
        .env("PATH", path)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .current_dir(scratch)
        .arg("-p")
        .arg(profile)
        .arg(scanner);
    for argument in scanner_args(format, ecosystem, archive) {
        command.arg(argument);
    }
    Ok(command)
}

#[cfg(target_os = "linux")]
fn linux_sandbox_command(
    runner: &Path,
    scanner: &Path,
    format: ReportFormat,
    ecosystem: &Ecosystem,
    archive: &Path,
    scratch: &Path,
) -> Result<Command> {
    let runtime = scanner_runtime_paths(scanner);
    let system_roots = ["/usr", "/bin", "/sbin", "/lib", "/lib64"];
    let mut command = Command::new(runner);
    command.env_clear().args([
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--tmpfs",
        "/",
    ]);
    for root in system_roots {
        let root = Path::new(root);
        if root.exists() {
            command.arg("--ro-bind").arg(root).arg(root);
        }
    }
    for path in &runtime {
        if system_roots
            .iter()
            .any(|root| path.starts_with(Path::new(root)))
            || runtime
                .iter()
                .any(|root| root != path && root.is_dir() && path.starts_with(root))
        {
            continue;
        }
        command.arg("--ro-bind").arg(path).arg(path);
    }
    command
        .args(["--proc", "/proc", "--dev", "/dev", "--bind"])
        .arg(scratch)
        .args(["/tmp", "--dir", "/scan", "--ro-bind", "/proc/self/fd/0"])
        .arg(archive);
    // GuardDog's pygit2 dependency aborts at import when OpenSSL's default CA
    // paths are unreadable, so a public bundle is mounted even without network.
    let ca_bundle = linux_system_ca_bundle()
        .ok()
        .filter(|bundle| !paths_overlap(bundle, scratch));
    if let Some(ca_bundle) = &ca_bundle {
        command
            .arg("--ro-bind")
            .arg(ca_bundle)
            .arg("/tmp/.supply-core-ca-bundle.pem");
    }
    command.args(["--remount-ro", "/", "--chdir", "/tmp", "--clearenv"]);
    command
        .args(["--setenv", "HOME", "/tmp", "--setenv", "TMPDIR", "/tmp"])
        .args(["--setenv", "TMP", "/tmp", "--setenv", "TEMP", "/tmp"]);
    if ca_bundle.is_some() {
        command.args([
            "--setenv",
            "SSL_CERT_FILE",
            "/tmp/.supply-core-ca-bundle.pem",
        ]);
    }
    command
        .arg("--setenv")
        .arg("PATH")
        .arg(scanner_path_environment(scanner, &runtime)?)
        .args([
            "--setenv",
            "LANG",
            "C",
            "--setenv",
            "LC_ALL",
            "C",
            "--setenv",
            "PYTHONDONTWRITEBYTECODE",
            "1",
            "--",
        ])
        .arg(scanner);
    for argument in scanner_args(format, ecosystem, Path::new("/scan/archive")) {
        command.arg(argument);
    }
    Ok(command)
}

#[cfg(target_os = "macos")]
fn macos_sandbox_profile(
    scanner: &Path,
    runtime: &[PathBuf],
    inputs: &[&Path],
    scratch: &Path,
    allow_network: bool,
) -> Result<String> {
    let network_rule = if allow_network {
        "(allow network*)\n"
    } else {
        "(deny network*)\n"
    };
    let mut profile = format!(
        "(version 1)\n(deny default)\n(allow process*)\n(allow sysctl-read)\n{network_rule}"
    );
    for root in ["/System", "/usr", "/bin", "/sbin", "/opt/homebrew"] {
        let root = Path::new(root);
        if root.is_dir() {
            append_seatbelt_rule(&mut profile, "file-read*", "subpath", root)?;
        }
    }
    for path in runtime {
        let filter = if path.is_dir() { "subpath" } else { "literal" };
        append_seatbelt_rule(&mut profile, "file-read*", filter, path)?;
    }
    append_seatbelt_rule(&mut profile, "file-read*", "literal", scanner)?;
    for input in inputs {
        let input_filter = if input.is_dir() { "subpath" } else { "literal" };
        append_seatbelt_rule(&mut profile, "file-read*", input_filter, input)?;
    }
    append_seatbelt_rule(&mut profile, "file-read*", "subpath", scratch)?;
    append_seatbelt_rule(&mut profile, "file-write*", "subpath", scratch)?;
    let dev_null = Path::new("/dev/null");
    append_seatbelt_rule(&mut profile, "file-read*", "literal", dev_null)?;
    append_seatbelt_rule(&mut profile, "file-write*", "literal", dev_null)?;
    append_seatbelt_rule(
        &mut profile,
        "file-read*",
        "literal",
        Path::new("/dev/zero"),
    )?;
    for path in std::iter::once(scanner)
        .chain(runtime.iter().map(PathBuf::as_path))
        .chain(inputs.iter().copied())
        .chain([scratch])
    {
        append_parent_metadata(&mut profile, path)?;
    }
    Ok(profile)
}

#[cfg(target_os = "macos")]
fn append_parent_metadata(profile: &mut String, path: &Path) -> Result<()> {
    let mut parent = path.parent();
    while let Some(directory) = parent {
        append_seatbelt_rule(profile, "file-read-metadata", "literal", directory)?;
        parent = directory.parent();
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn append_seatbelt_rule(
    profile: &mut String,
    operation: &str,
    filter: &str,
    path: &Path,
) -> Result<()> {
    profile.push_str(&format!(
        "(allow {operation} ({filter} {}))\n",
        seatbelt_quoted_path(path)?
    ));
    Ok(())
}

#[cfg(target_os = "macos")]
fn seatbelt_quoted_path(path: &Path) -> Result<String> {
    let value = path.to_str().context("sandbox path is not valid UTF-8")?;
    if value
        .chars()
        .any(|character| character == '\"' || character as u32 == 92 || character.is_control())
    {
        anyhow::bail!("sandbox path contains an unsupported character");
    }
    Ok(format!("{value:?}"))
}

fn read_capped(mut reader: impl Read, limit: usize) -> (Vec<u8>, bool) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return (buffer, false),
            Ok(read) => {
                if buffer.len() + read > limit {
                    let remaining = limit.saturating_sub(buffer.len());
                    buffer.extend_from_slice(&chunk[..remaining]);
                    return (buffer, true);
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            Err(_) => return (buffer, false),
        }
    }
}

fn read_optional_report(path: &Path) -> Result<(Option<Vec<u8>>, bool)> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((None, false)),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "scanner report is not a regular file"
    );
    if metadata.len() > DEFAULT_MAX_OUTPUT as u64 {
        return Ok((None, true));
    }
    let (bytes, truncated) = read_capped(File::open(path)?, DEFAULT_MAX_OUTPUT);
    Ok((Some(bytes), truncated))
}

fn hash_file(file: &mut File) -> Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let bytes = file.read(&mut buffer)?;
        if bytes == 0 {
            break;
        }
        hasher.update(&buffer[..bytes]);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(hex::encode(hasher.finalize()))
}

fn incomplete_report(source: &str, input_sha256: Option<String>, reason: &str) -> EngineReport {
    EngineReport {
        source: source.to_string(),
        version: None,
        rule_bundle_sha256: None,
        database_sha256: None,
        coverage: if input_sha256.is_some() {
            Coverage::Partial
        } else {
            Coverage::Unknown
        },
        input_sha256,
        expected_inputs: 1,
        processed_inputs: 0,
        findings: Vec::new(),
        reason: Some(reason.to_string()),
    }
}

fn safe_code(value: &str) -> String {
    let mut code: String = value
        .bytes()
        .take(128)
        .map(|byte| {
            if byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte) {
                byte as char
            } else if byte.is_ascii_uppercase() {
                byte.to_ascii_lowercase() as char
            } else {
                '_'
            }
        })
        .collect();
    if code.is_empty() {
        code.push_str("unknown");
    }
    code
}

fn report_error_reason(report: &serde_json::Value) -> Option<&'static str> {
    match report.get("errors") {
        None => None,
        Some(serde_json::Value::Object(errors)) if errors.is_empty() => None,
        Some(serde_json::Value::Object(_)) => Some("scanner_reported_errors"),
        Some(_) => Some("invalid_report"),
    }
}

type ParsedReport = (Decimal, Vec<String>, Option<String>, Option<&'static str>);

fn parse_report(report: &serde_json::Value, format: ReportFormat) -> Result<ParsedReport> {
    let error_reason = report_error_reason(report);
    let (score, rules, severity) = match format {
        ReportFormat::GuardDog => {
            let score_text = report
                .get("risk_score")
                .and_then(|risk| risk.get("score"))
                .and_then(serde_json::Value::as_number)
                .context("guarddog report is missing risk_score.score")?
                .to_string();
            let score = Decimal::from_str_exact(&score_text)
                .or_else(|_| Decimal::from_scientific(&score_text))
                .context("guarddog risk score is not an exact decimal")?;
            if !(Decimal::ZERO..=Decimal::TEN).contains(&score) {
                anyhow::bail!("guarddog score is outside range");
            }
            let results = report
                .get("results")
                .and_then(serde_json::Value::as_object)
                .context("guarddog report is missing results")?;
            let mut rules: Vec<String> = results
                .iter()
                .filter(|(_, hits)| hits.as_array().is_some_and(|hits| !hits.is_empty()))
                .map(|(rule, _)| rule.clone())
                .collect();
            rules.sort();
            let severity = report
                .get("risk_score")
                .and_then(|risk| risk.get("label"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            (score, rules, severity)
        }
        ReportFormat::Normalized => {
            let score_text = report
                .get("score")
                .and_then(serde_json::Value::as_number)
                .context("scanner report is missing a numeric score")?
                .to_string();
            let score = Decimal::from_str_exact(&score_text)
                .or_else(|_| Decimal::from_scientific(&score_text))
                .context("scanner score is not an exact decimal")?;
            if score < Decimal::ZERO {
                anyhow::bail!("scanner score is below zero");
            }
            let rules = match report.get("rules") {
                None => Vec::new(),
                Some(serde_json::Value::Array(rules)) => rules
                    .iter()
                    .map(|rule| {
                        rule.as_str()
                            .map(str::to_string)
                            .context("scanner rule is not a string")
                    })
                    .collect::<Result<Vec<_>>>()?,
                Some(_) => anyhow::bail!("scanner rules are malformed"),
            };
            let severity = report
                .get("severity")
                .map(|severity| {
                    severity
                        .as_str()
                        .map(str::to_string)
                        .context("scanner severity is malformed")
                })
                .transpose()?;
            (score.min(Decimal::TEN), rules, severity)
        }
    };
    Ok((score, rules, severity, error_reason))
}

fn report_findings(
    source: &str,
    archive: &Path,
    rules: Vec<String>,
    score: Decimal,
    severity: Option<&str>,
) -> Result<(Vec<EngineFinding>, bool)> {
    if score.is_zero() {
        return Ok((Vec::new(), false));
    }
    let mut rules = rules;
    if rules.is_empty() {
        rules.push("external-risk".to_string());
    }
    let truncated = rules.len() > MAX_ENGINE_FINDINGS;
    let member = archive
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "archive".to_string());
    let severity = severity.map(safe_code);
    let findings = rules
        .into_iter()
        .take(MAX_ENGINE_FINDINGS)
        .enumerate()
        .map(|(index, raw_rule)| {
            let rule = safe_code(&raw_rule);
            let fingerprint = format!("{index}:{rule}");
            Ok(EngineFinding {
                id: engine_finding_id(source, &rule, &member, &fingerprint)?,
                rule,
                summary: "external scanner reported a finding".to_string(),
                location: None,
                native_severity: severity.clone(),
                policy_score: Some(score),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((findings, truncated))
}

impl ContentScanner for CommandScanner {
    fn scan_archive(
        &self,
        ecosystem: &Ecosystem,
        archive: &mut File,
        archive_path: &Path,
        _name: &str,
        _version: &PackageVersionId,
    ) -> Result<EngineReport> {
        let input_sha256 = match hash_file(archive) {
            Ok(digest) => digest,
            Err(_) => {
                let report = incomplete_report(&self.source, None, "input_unavailable");
                report.validate()?;
                return Ok(report);
            }
        };
        if !scanner_memory_limit_supported() {
            let report = incomplete_report(
                &self.source,
                Some(input_sha256),
                "scanner_memory_limit_unavailable",
            );
            report.validate()?;
            return Ok(report);
        }

        let stdout = match self.run(ecosystem, archive, archive_path) {
            Ok(stdout) => stdout,
            Err(_) => {
                let report =
                    incomplete_report(&self.source, Some(input_sha256), "scanner_execution_failed");
                report.validate()?;
                return Ok(report);
            }
        };
        let report = match serde_json::from_str::<serde_json::Value>(stdout.trim()) {
            Ok(report) => report,
            Err(_) => {
                let report = incomplete_report(&self.source, Some(input_sha256), "invalid_report");
                report.validate()?;
                return Ok(report);
            }
        };
        let (score, rules, severity, error_reason) = match parse_report(&report, self.format) {
            Ok(result) => result,
            Err(_) => {
                let report = incomplete_report(&self.source, Some(input_sha256), "invalid_report");
                report.validate()?;
                return Ok(report);
            }
        };
        let (findings, findings_truncated) = report_findings(
            &self.source,
            archive_path,
            rules,
            score,
            severity.as_deref(),
        )?;
        let reason = error_reason
            .or_else(|| findings_truncated.then_some("finding_limit"))
            .or(match &self.revision {
                EngineRevision::Unknown => Some("engine_revision_unavailable"),
                EngineRevision::Unverified => Some("engine_revision_unverified"),
                EngineRevision::Attested { .. } => None,
            });
        let (version, rule_bundle_sha256) = match &self.revision {
            EngineRevision::Attested {
                version,
                rule_bundle_sha256,
            } => (Some(version.clone()), Some(rule_bundle_sha256.clone())),
            _ => (None, None),
        };
        let engine_report = EngineReport {
            source: self.source.clone(),
            version,
            rule_bundle_sha256,
            database_sha256: None,
            input_sha256: Some(input_sha256),
            expected_inputs: 1,
            processed_inputs: 1,
            coverage: if reason.is_none() {
                Coverage::Complete
            } else {
                Coverage::Partial
            },
            findings,
            reason: reason.map(str::to_string),
        };
        engine_report.validate()?;
        Ok(engine_report)
    }
}

fn ecosystem_label(ecosystem: &Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPi => "pypi",
        Ecosystem::NuGet => "nuget",
        _ => "unknown",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn privileged_effective_uid_is_rejected() {
        assert!(ensure_unprivileged(0).is_err());
        assert!(ensure_unprivileged(1).is_ok());
    }

    /// Writes a shell body file. The file is handed to `sh` by the stable
    /// dispatcher below and is never executed directly, so a fresh write can
    /// never race `execve` into ETXTBSY on parallel Linux test threads.
    fn script(body: &str) -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("case.sh");
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "{body}").unwrap();
        file.sync_all().unwrap();
        (directory, path)
    }

    /// Writes an executable script that is never rewritten, so execing it cannot
    /// race `execve` into ETXTBSY on parallel Linux test threads. A child process
    /// writes it, so no sibling thread can inherit the write descriptor. It lives
    /// beside the test binary because the Linux sandbox binds scratch over /tmp.
    fn stable_script(body: &str) -> PathBuf {
        let exe = std::env::current_exe().unwrap();
        let directory = tempfile::tempdir_in(exe.parent().unwrap()).unwrap();
        let path = directory.path().join("stable.sh");
        let mut child = Command::new("/bin/sh")
            .args(["-c", "cat > \"$0\" && chmod 755 \"$0\""])
            .arg(&path)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(body.as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success());
        std::mem::forget(directory);
        path
    }

    /// One executable script per test binary that runs the body file passed as
    /// the second argument.
    fn dispatcher() -> PathBuf {
        static DISPATCHER: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        DISPATCHER
            .get_or_init(|| {
                stable_script("#!/bin/sh\nif [ \"$2\" = scan ]; then if [ \"$3\" = /scan/archive ]; then exec /bin/sh /dev/stdin; fi; exec /bin/sh \"$3\"; fi\nexec /bin/sh \"$2\"\n")
            })
            .clone()
    }

    /// Stands in for the sandbox runner: executes the scanner argv after `--`.
    #[cfg(target_os = "linux")]
    fn passthrough_runner() -> PathBuf {
        static RUNNER: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        RUNNER
            .get_or_init(|| {
                stable_script(
                    "#!/bin/sh\nwhile [ \"$1\" != \"--\" ]; do shift; done\nshift\nexec \"$@\"\n",
                )
            })
            .clone()
    }

    fn version() -> PackageVersionId {
        PackageVersionId::parse(&Ecosystem::Npm, "1.2.3").unwrap()
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn ossgadget_sandbox_scans_local_directory_without_network() {
        let root = tempfile::tempdir().unwrap();
        let install = root.path().join("install");
        let package = root.path().join("package");
        let scratch = root.path().join("scratch");
        std::fs::create_dir_all(&install).unwrap();
        std::fs::create_dir_all(&package).unwrap();
        std::fs::create_dir_all(&scratch).unwrap();
        let scanner = install.join("ossgadget");
        std::fs::write(&scanner, b"scanner").unwrap();
        let sarif = scratch.join("scan.sarif");
        let coverage = scratch.join("coverage.json");
        let command = ossgadget_sandbox_command(
            Path::new("/usr/bin/sandbox-exec"),
            &scanner,
            &install,
            &package,
            &scratch,
            &sarif,
            &coverage,
        )
        .unwrap();
        let args = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args.contains(&"detect-backdoor".to_string()));
        assert!(args.windows(2).any(|pair| pair == ["--format", "sarifv2"]));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["--output-file", sarif.to_str().unwrap()]));
        assert!(args.contains(&package.to_string_lossy().into_owned()));
        assert!(args.contains(&"--single-threaded".to_string()));
        #[cfg(target_os = "macos")]
        assert_eq!(
            command
                .get_envs()
                .find(|(key, _)| *key == std::ffi::OsStr::new(OSSGADGET_COVERAGE_ENV))
                .and_then(|(_, value)| value),
            Some(coverage.as_os_str())
        );
        #[cfg(target_os = "linux")]
        assert!(args.windows(3).any(|triple| triple
            == [
                "--setenv",
                OSSGADGET_COVERAGE_ENV,
                coverage.to_str().unwrap()
            ]));
        #[cfg(target_os = "macos")]
        assert!(args
            .iter()
            .any(|argument| argument.contains("(deny network*)")));
        #[cfg(target_os = "macos")]
        {
            let package_read_rule = format!(
                "(allow file-read* (subpath {:?}))",
                package.to_str().unwrap()
            );
            assert!(args
                .iter()
                .any(|argument| argument.contains(&package_read_rule)));
        }
        #[cfg(target_os = "linux")]
        assert!(args
            .windows(3)
            .any(|triple| triple == ["--ro-bind", package.to_str().unwrap(), "/scan/package"]));
        #[cfg(target_os = "linux")]
        assert!(args.contains(&"--unshare-all".to_string()));
    }

    fn scan_path(scanner: &CommandScanner, path: &Path, name: &str) -> EngineReport {
        let mut archive = File::open(path).unwrap();
        scanner
            .scan_archive(&Ecosystem::Npm, &mut archive, path, name, &version())
            .unwrap()
    }

    #[test]
    fn parses_real_guarddog_report() {
        let payload: serde_json::Value = serde_json::from_str(GUARDDOG_EVIL).unwrap();
        let finding = finding_from_guarddog(&payload, &Ecosystem::Npm, "evil", &version())
            .unwrap()
            .unwrap();
        assert_eq!(finding.score, Some(Decimal::from(8)));
        assert!(finding
            .rules
            .contains(&"capability-network-download".to_string()));
        assert!(finding
            .rules
            .contains(&"threat-network-exfiltration".to_string()));
        assert!(finding.summary.contains("high_risk"), "{}", finding.summary);
        assert!(
            finding.summary.contains("exfiltration"),
            "{}",
            finding.summary
        );
        assert_eq!(finding.source, "guarddog");
    }

    #[test]
    fn guarddog_clean_report_is_not_a_finding() {
        let payload: serde_json::Value = serde_json::from_str(GUARDDOG_CLEAN).unwrap();
        assert!(
            finding_from_guarddog(&payload, &Ecosystem::Npm, "lib", &version())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn guarddog_scores_keep_fractional_precision() {
        for (score, expected) in [(0.4, "0.4"), (7.5, "7.5")] {
            let payload = serde_json::json!({
                "risk_score": {"score": score, "label": "risk"},
                "results": {"rule": [{"message": "finding"}]},
                "errors": {}
            });
            let finding = finding_from_guarddog(&payload, &Ecosystem::Npm, "lib", &version())
                .unwrap()
                .unwrap();
            assert_eq!(finding.score.unwrap().to_string(), expected);
        }
    }

    #[test]
    fn guarddog_malformed_errors_field_fails_closed() {
        let array_errors: serde_json::Value =
            serde_json::from_str(r#"{"risk_score": {"score": 0.0}, "errors": ["boom"]}"#).unwrap();
        assert!(finding_from_guarddog(&array_errors, &Ecosystem::Npm, "odd", &version()).is_err());
        let string_errors: serde_json::Value =
            serde_json::from_str(r#"{"risk_score": {"score": 0.0}, "errors": "scan failed"}"#)
                .unwrap();
        assert!(finding_from_guarddog(&string_errors, &Ecosystem::Npm, "odd", &version()).is_err());
    }

    #[test]
    fn guarddog_errors_fail_closed() {
        let payload: serde_json::Value =
            serde_json::from_str(r#"{"risk_score": {"score": 3.0}, "errors": {"a": "boom"}}"#)
                .unwrap();
        assert!(finding_from_guarddog(&payload, &Ecosystem::Npm, "odd", &version()).is_err());
    }

    #[test]
    fn guarddog_missing_score_is_an_error() {
        let payload: serde_json::Value = serde_json::from_str(r#"{"results": {}}"#).unwrap();
        assert!(finding_from_guarddog(&payload, &Ecosystem::Npm, "odd", &version()).is_err());
    }

    #[test]
    fn guarddog_rejects_scores_outside_range() {
        for score in [-0.1, 10.1] {
            let payload = serde_json::json!({
                "risk_score": {"score": score, "label": "risk"},
                "results": {"rule": [{"message": "finding"}]},
                "errors": {}
            });
            assert!(
                finding_from_guarddog(&payload, &Ecosystem::Npm, "lib", &version()).is_err(),
                "accepted out-of-range score {score}"
            );
        }
    }

    #[test]
    fn guarddog_arguments_include_scan_and_json_output() {
        let args = scanner_args(
            ReportFormat::GuardDog,
            &Ecosystem::Npm,
            Path::new("/tmp/evil.tgz"),
        );
        assert_eq!(
            args,
            vec!["npm", "scan", "/tmp/evil.tgz", "--output-format", "json"]
        );
        let args = scanner_args(
            ReportFormat::Normalized,
            &Ecosystem::PyPi,
            Path::new("/tmp/x.tgz"),
        );
        assert_eq!(args, vec!["pypi", "/tmp/x.tgz"]);
    }

    #[test]
    fn scanner_adapter_parses_ossgadget_sarif_locations_and_diagnostics() {
        let sarif = parse_ossgadget_sarif(
            r#"{
              "version": "2.1.0",
              "runs": [{
                "tool": {"driver": {"name": "oss-detect-backdoor", "rules": [{"id": "Backdoor.Exec"}]}},
                "results": [{
                  "ruleId": "Backdoor.Exec",
                  "message": {"text": "private source excerpt"},
                  "locations": [{
                    "physicalLocation": {
                      "address": {"fullyQualifiedName": "lib/install.js"},
                      "region": {"startLine": 4, "startColumn": 7, "endLine": 4, "endColumn": 20}
                    }
                  }]
                }],
                "invocations": [{
                  "executionSuccessful": false,
                  "toolExecutionNotifications": [{"message": {"text": "private diagnostic"}}]
                }]
              }]
            }"#,
        )
        .unwrap();

        assert_eq!(sarif.findings.len(), 1);
        assert_eq!(sarif.findings[0].rule_id, "Backdoor.Exec");
        let location = sarif.findings[0].location.as_ref().unwrap();
        assert_eq!(location.path.as_deref(), Some("lib/install.js"));
        assert!(sarif.rules.contains("Backdoor.Exec"));
        assert_eq!(sarif.diagnostics, 2);
    }

    #[test]
    fn scanner_adapter_requires_exact_ossgadget_path_coverage() {
        let expected =
            std::collections::BTreeSet::from(["a.js".to_string(), "lib/b.js".to_string()]);
        let complete: OssGadgetCoverage = serde_json::from_str(
            r#"{"version":1,"scanned_paths":["a.js","lib/b.js"],"skipped_paths":[],"diagnostics":[]}"#,
        )
        .unwrap();
        assert!(ossgadget_coverage_matches(&complete, &expected));

        let unaccounted: OssGadgetCoverage = serde_json::from_str(
            r#"{"version":1,"scanned_paths":["a.js"],"skipped_paths":[],"diagnostics":[]}"#,
        )
        .unwrap();
        assert!(!ossgadget_coverage_matches(&unaccounted, &expected));

        let skipped: OssGadgetCoverage = serde_json::from_str(
            r#"{"version":1,"scanned_paths":["a.js"],"skipped_paths":[{"path":"lib/b.js","reason":"analysis_error"}],"diagnostics":["analysis_error"]}"#,
        )
        .unwrap();
        assert!(!ossgadget_coverage_matches(&skipped, &expected));
    }

    #[test]
    fn scanner_adapter_keeps_ossgadget_findings_when_coverage_fails() {
        let expected = std::collections::BTreeSet::from(["lib/install.js".to_string()]);
        let sarif = parse_ossgadget_sarif(
            r#"{
              "version":"2.1.0",
              "runs":[{
                "tool":{"driver":{"rules":[{"id":"Backdoor.Exec"}]}},
                "results":[{
                  "ruleId":"Backdoor.Exec",
                  "message":{"text":"private match text"},
                  "locations":[{"physicalLocation":{"address":{"fullyQualifiedName":"lib/install.js"},"region":{"startLine":2}}}]
                }],
                "invocations":[{"toolExecutionNotifications":[{"message":{"text":"private diagnostic"}}]}]
              }]
            }"#,
        )
        .unwrap();
        let coverage: OssGadgetCoverage = serde_json::from_str(
            r#"{"version":1,"scanned_paths":["lib/install.js"],"skipped_paths":[],"diagnostics":["analysis_error"]}"#,
        )
        .unwrap();

        let report = ossgadget_engine_report(
            OssGadgetReportContext {
                input_sha256: &"a".repeat(64),
                rule_bundle_sha256: &"b".repeat(64),
                bundle_rules: &std::collections::BTreeSet::new(),
                package_root: Path::new("/tmp/package"),
                guest_root: Path::new("/tmp/package"),
                expected_paths: &expected,
                inventory_complete: true,
                execution_succeeded: false,
                output_complete: true,
            },
            Some(sarif),
            Some(coverage),
        )
        .unwrap();

        assert_eq!(report.coverage, Coverage::Partial);
        assert_eq!(report.reason.as_deref(), Some("scanner_execution_failed"));
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].policy_score, Some(Decimal::from(4)));
        assert!(report.findings[0].location.is_none());
        assert!(!report.findings[0].summary.contains("private"));
        report.validate().unwrap();
    }

    #[test]
    fn scanner_adapter_accepts_real_ossgadget_rule_references_from_attested_bundle() {
        let expected = std::collections::BTreeSet::from(["README.md".to_string()]);
        let real_shape = r#"{
          "version":"2.1.0",
          "runs":[{
            "tool":{"driver":{"name":"ossgadget","version":"0.2.0"}},
            "results":[{
              "rule":{"id":"BD000610"},
              "message":{"text":"private match text"},
              "locations":[{"physicalLocation":{"address":{"relativeAddress":-1,"fullyQualifiedName":"scan/package/README.md"},"region":{"startLine":217,"startColumn":33}}}]
            }]
          }]
        }"#;
        let coverage = || -> OssGadgetCoverage {
            serde_json::from_str(
                r#"{"version":1,"scanned_paths":["README.md"],"skipped_paths":[],"diagnostics":[]}"#,
            )
            .unwrap()
        };
        let report_with = |bundle_rules: &std::collections::BTreeSet<String>| {
            ossgadget_engine_report(
                OssGadgetReportContext {
                    input_sha256: &"a".repeat(64),
                    rule_bundle_sha256: &"b".repeat(64),
                    bundle_rules,
                    package_root: Path::new("/work/package"),
                    guest_root: Path::new("/scan/package"),
                    expected_paths: &expected,
                    inventory_complete: true,
                    execution_succeeded: true,
                    output_complete: true,
                },
                Some(parse_ossgadget_sarif(real_shape).unwrap()),
                Some(coverage()),
            )
            .unwrap()
        };

        let attested = report_with(&std::collections::BTreeSet::from(["BD000610".to_string()]));
        assert_eq!(attested.coverage, Coverage::Complete);
        assert_eq!(attested.reason, None);
        assert_eq!(attested.findings.len(), 1);
        assert_eq!(attested.findings[0].rule, "bd000610");
        attested.validate().unwrap();

        let unknown_rule = report_with(&std::collections::BTreeSet::from(["BD000200".to_string()]));
        assert_eq!(unknown_rule.coverage, Coverage::Partial);
        assert_eq!(unknown_rule.reason.as_deref(), Some("missing_rules"));
    }

    fn ossgadget_report_for(
        files: &[String],
        occurrences: impl Iterator<Item = (String, u32)>,
    ) -> EngineReport {
        let expected = files
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let results = occurrences
            .map(|(file, line)| {
                serde_json::json!({
                    "rule": {"id": "BD000610"},
                    "message": {"text": "match"},
                    "locations": [{"physicalLocation": {
                        "address": {"relativeAddress": -1, "fullyQualifiedName": format!("scan/package/{file}")},
                        "region": {"startLine": line, "startColumn": 1}
                    }}]
                })
            })
            .collect::<Vec<_>>();
        let sarif = serde_json::json!({"version": "2.1.0", "runs": [{"results": results}]});
        let coverage = serde_json::json!({
            "version": 1, "scanned_paths": files, "skipped_paths": [], "diagnostics": []
        });
        ossgadget_engine_report(
            OssGadgetReportContext {
                input_sha256: &"a".repeat(64),
                rule_bundle_sha256: &"b".repeat(64),
                bundle_rules: &std::collections::BTreeSet::from(["BD000610".to_string()]),
                package_root: Path::new("/work/package"),
                guest_root: Path::new("/scan/package"),
                expected_paths: &expected,
                inventory_complete: true,
                execution_succeeded: true,
                output_complete: true,
            },
            Some(parse_ossgadget_sarif(&sarif.to_string()).unwrap()),
            Some(serde_json::from_value(coverage).unwrap()),
        )
        .unwrap()
    }

    #[test]
    fn ossgadget_repeated_rule_matches_in_one_file_are_one_finding() {
        let files = vec!["dist/bundle.js".to_string(), "README.md".to_string()];
        let occurrences = (1..=300)
            .map(|line| ("dist/bundle.js".to_string(), line))
            .chain([("README.md".to_string(), 7)]);
        let report = ossgadget_report_for(&files, occurrences);
        assert_eq!(report.coverage, Coverage::Complete);
        assert_eq!(report.reason, None);
        assert_eq!(report.findings.len(), 2);
        report.validate().unwrap();
    }

    #[test]
    fn ossgadget_distinct_rule_file_pairs_over_limit_stay_partial() {
        let files = (0..=MAX_ENGINE_FINDINGS)
            .map(|index| format!("lib/f{index}.js"))
            .collect::<Vec<_>>();
        let occurrences = files.clone().into_iter().map(|file| (file, 1));
        let report = ossgadget_report_for(&files, occurrences);
        assert_eq!(report.coverage, Coverage::Partial);
        assert_eq!(report.reason.as_deref(), Some("finding_limit"));
        assert_eq!(report.findings.len(), MAX_ENGINE_FINDINGS);
    }

    #[test]
    fn ossgadget_matches_inside_a_nested_archive_belong_to_that_member() {
        let files = vec!["dist/all.zip".to_string()];
        let inside = [
            ("dist/all.zip/a.js".to_string(), 1),
            ("dist/all.zip/b.js".to_string(), 1),
        ];
        let report = ossgadget_report_for(&files, inside.into_iter());
        assert_eq!(report.coverage, Coverage::Complete);
        assert_eq!(report.reason, None);
        assert_eq!(report.findings.len(), 2);

        let lookalike = [("dist/all.zipx/a.js".to_string(), 1)];
        let report = ossgadget_report_for(&files, lookalike.into_iter());
        assert_eq!(report.reason.as_deref(), Some("input_coverage_mismatch"));
    }

    #[test]
    fn scanner_adapter_accepts_empty_sarif_rules_after_verified_scan() {
        let expected = std::collections::BTreeSet::from(["lib/safe.js".to_string()]);
        let sarif = parse_ossgadget_sarif(
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"rules":[]}},"results":[]}]}"#,
        )
        .unwrap();
        let coverage: OssGadgetCoverage = serde_json::from_str(
            r#"{"version":1,"scanned_paths":["lib/safe.js"],"skipped_paths":[],"diagnostics":[]}"#,
        )
        .unwrap();

        let report = ossgadget_engine_report(
            OssGadgetReportContext {
                input_sha256: &"a".repeat(64),
                rule_bundle_sha256: &"b".repeat(64),
                bundle_rules: &std::collections::BTreeSet::new(),
                package_root: Path::new("/tmp/package"),
                guest_root: Path::new("/tmp/package"),
                expected_paths: &expected,
                inventory_complete: true,
                execution_succeeded: true,
                output_complete: true,
            },
            Some(sarif),
            Some(coverage),
        )
        .unwrap();

        assert_eq!(report.coverage, Coverage::Complete);
        assert_eq!(report.reason, None);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn scanner_adapter_marks_incomplete_archive_inventory_partial() {
        let expected = std::collections::BTreeSet::from(["lib/safe.js".to_string()]);
        let sarif = parse_ossgadget_sarif(
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"rules":[]}},"results":[]}]}"#,
        )
        .unwrap();
        let coverage: OssGadgetCoverage = serde_json::from_str(
            r#"{"version":1,"scanned_paths":["lib/safe.js"],"skipped_paths":[],"diagnostics":[]}"#,
        )
        .unwrap();

        let report = ossgadget_engine_report(
            OssGadgetReportContext {
                input_sha256: &"a".repeat(64),
                rule_bundle_sha256: &"b".repeat(64),
                bundle_rules: &std::collections::BTreeSet::new(),
                package_root: Path::new("/tmp/package"),
                guest_root: Path::new("/tmp/package"),
                expected_paths: &expected,
                inventory_complete: false,
                execution_succeeded: true,
                output_complete: true,
            },
            Some(sarif),
            Some(coverage),
        )
        .unwrap();

        assert_eq!(report.coverage, Coverage::Partial);
        assert_eq!(report.reason.as_deref(), Some("input_inventory_incomplete"));
    }

    #[test]
    fn ossgadget_manifest_binds_binary_and_rule_bytes() {
        let root = tempfile::tempdir().unwrap();
        let binary = root.path().join("ossgadget");
        let rules = root.path().join("Resources/BackdoorRules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(&binary, b"pinned binary").unwrap();
        std::fs::write(rules.join("rule.json"), b"{\"id\":\"rule\"}").unwrap();
        let mut manifest = OssGadgetInstallManifest {
            format_version: 1,
            upstream_commit: "4063457b40211c25b41d56465d41783f2d42c5c1".to_string(),
            binary_sha256: sha256_path(&binary).unwrap(),
            rule_bundle_sha256: sha256_directory(&rules).unwrap(),
        };

        assert!(verify_ossgadget_installation(&binary, &rules, &manifest).is_ok());
        std::fs::write(rules.join("rule.json"), b"{\"id\":\"changed\"}").unwrap();
        assert!(verify_ossgadget_installation(&binary, &rules, &manifest).is_err());
        manifest.upstream_commit = "unpinned".to_string();
        assert!(verify_ossgadget_installation(&binary, &rules, &manifest).is_err());
    }
    const GUARDDOG_EVIL: &str = r#"{
      "package": "/tmp/evil.tgz",
      "results": {
        "capability-network-download": [{"location": "package/beacon.js:1", "match": "https.get(", "message": "Detects downloading files from network"}],
        "capability-process-hooks": [{"location": "package/package.json:1", "match": "postinstall", "message": "has_npm_hook rule matched"}],
        "threat-network-exfil-messenger": [{"location": "package/beacon.js:1", "match": "discord.com/api/webhooks/1/", "message": "Detects hardcoded messaging platform tokens/webhooks used for data exfiltration"}],
        "threat-network-exfiltration": [{"location": "package/beacon.js:1", "match": "discord.com/api/webhooks", "message": "Detects URLs to suspicious domains often used for exfiltration or C2"}],
        "threat-process-hooks": [{"location": "package/package.json:1", "match": "postinstall", "message": "hook threat"}]
      },
      "risk_score": {"score": 8.0, "label": "high_risk", "findings_count": 6, "score_breakdown": {}},
      "risks": [{"name": "risk.network.outbound", "severity": "high"}],
      "issues": 7,
      "errors": {}
    }"#;

    const GUARDDOG_CLEAN: &str = r#"{
      "package": "/tmp/benign.tgz",
      "results": {"capability-network-download": {}, "threat-network-exfiltration": {}},
      "risk_score": {"score": 0.0, "label": "no_risks_detected", "findings_count": 0, "score_breakdown": {}},
      "risks": [],
      "issues": 0,
      "errors": {}
    }"#;

    #[test]
    fn parses_normalized_report_into_engine_findings() {
        let payload = serde_json::json!({
            "score": 9,
            "rules": ["install-script-network"],
            "summary": "postinstall beacon"
        });
        let (score, rules, severity, reason) =
            parse_report(&payload, ReportFormat::Normalized).unwrap();
        let (findings, truncated) = report_findings(
            "guarddog",
            Path::new("evil.tgz"),
            rules,
            score,
            severity.as_deref(),
        )
        .unwrap();

        assert_eq!(reason, None);
        assert!(!truncated);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].policy_score, Some(Decimal::from(9)));
        assert_eq!(findings[0].rule, "install-script-network");
        assert_eq!(findings[0].summary, "external scanner reported a finding");
        assert!(findings[0].location.is_none());
    }

    #[test]
    fn score_above_ten_is_clamped() {
        let payload = serde_json::json!({"score": 42, "rules": ["x"]});
        let (score, _, _, _) = parse_report(&payload, ReportFormat::Normalized).unwrap();
        assert_eq!(score, Decimal::TEN);
    }

    fn guarddog_install(root: &Path) -> PathBuf {
        let site = root.join("venv/lib/python3.11/site-packages");
        std::fs::create_dir_all(root.join("venv/bin")).unwrap();
        std::fs::create_dir_all(site.join("guarddog/analyzer")).unwrap();
        std::fs::create_dir_all(site.join("guarddog-3.2.0.dist-info")).unwrap();
        std::fs::write(root.join("venv/bin/guarddog"), "#!/bin/sh\n").unwrap();
        std::fs::write(site.join("guarddog/analyzer.py"), "rules = 1\n").unwrap();
        std::fs::write(site.join("guarddog/analyzer/rule.yml"), "id: x\n").unwrap();
        std::fs::write(
            site.join("guarddog-3.2.0.dist-info/METADATA"),
            "Name: guarddog\nVersion: 3.2.0\n",
        )
        .unwrap();
        let status = Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/scripts/write-guarddog-manifest.py"
            ))
            .arg("--install-root")
            .arg(root)
            .status()
            .unwrap();
        assert!(status.success());
        root.join("supply-guarddog-manifest.json")
    }

    #[test]
    fn guarddog_manifest_written_by_installer_attests_revision_until_tampered() {
        let directory = tempfile::tempdir().unwrap();
        let manifest = guarddog_install(directory.path());
        let executable = directory.path().join("venv/bin/guarddog");
        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();

        let attested = CommandScanner::guarddog(&executable).with_guarddog_manifest(&manifest);
        assert_eq!(
            attested.revision,
            EngineRevision::Attested {
                version: "3.2.0".to_string(),
                rule_bundle_sha256: written["package_sha256"].as_str().unwrap().to_string(),
            }
        );

        std::fs::write(
            directory
                .path()
                .join("venv/lib/python3.11/site-packages/guarddog/analyzer/rule.yml"),
            "id: tampered\n",
        )
        .unwrap();
        let tampered = CommandScanner::guarddog(&executable).with_guarddog_manifest(&manifest);
        assert_eq!(tampered.revision, EngineRevision::Unverified);
    }

    #[test]
    fn guarddog_manifest_rejects_escaping_package_dir_and_foreign_executable() {
        let directory = tempfile::tempdir().unwrap();
        let manifest = guarddog_install(directory.path());
        let executable = directory.path().join("venv/bin/guarddog");
        let mut written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();

        let other = directory.path().join("other");
        std::fs::write(&other, "#!/bin/sh\necho other\n").unwrap();
        let foreign = CommandScanner::guarddog(&other).with_guarddog_manifest(&manifest);
        assert_eq!(foreign.revision, EngineRevision::Unverified);

        written["package_dir"] = serde_json::json!("../venv/lib/python3.11/site-packages/guarddog");
        std::fs::write(&manifest, serde_json::to_vec(&written).unwrap()).unwrap();
        let escaping = CommandScanner::guarddog(&executable).with_guarddog_manifest(&manifest);
        assert_eq!(escaping.revision, EngineRevision::Unverified);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn guarddog_report_is_complete_only_with_attested_revision() {
        let (_directory, path) = script(
            r#"cat <<'EOF'
{"results": {"capability-network-download": {}}, "risk_score": {"score": 0.0, "label": "no_risks_detected"}, "errors": {}}
EOF"#,
        );
        let mut scanner = CommandScanner::guarddog(dispatcher());
        scanner.revision = EngineRevision::Attested {
            version: "3.2.0".to_string(),
            rule_bundle_sha256: "a".repeat(64),
        };
        let attested = scan_path(&scanner, &path, "clean");
        assert_eq!(attested.coverage, Coverage::Complete);
        assert_eq!(attested.reason, None);
        assert_eq!(attested.version.as_deref(), Some("3.2.0"));
        assert_eq!(attested.rule_bundle_sha256, Some("a".repeat(64)));
        attested.validate().unwrap();

        scanner.revision = EngineRevision::Unverified;
        let unverified = scan_path(&scanner, &path, "clean");
        assert_eq!(unverified.coverage, Coverage::Partial);
        assert_eq!(
            unverified.reason.as_deref(),
            Some("engine_revision_unverified")
        );
        assert_eq!(unverified.version, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn invalid_json_report_is_partial() {
        let (_directory, path) = script("echo not-json");
        let scanner = CommandScanner::new(dispatcher(), "guarddog");
        let report = scan_path(&scanner, &path, "odd");
        assert_eq!(report.coverage, Coverage::Partial);
        assert_eq!(report.reason.as_deref(), Some("invalid_report"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn clean_command_reports_no_findings_without_attesting_engine_revision() {
        let (_directory, path) = script(
            r#"cat <<'EOF'
{"score": 0, "rules": [], "summary": ""}
EOF"#,
        );
        let scanner = CommandScanner::new(dispatcher(), "guarddog");
        let report = scan_path(&scanner, &path, "clean");

        assert_eq!(report.coverage, Coverage::Partial);
        assert_eq!(
            report.reason.as_deref(),
            Some("engine_revision_unavailable")
        );
        assert!(report.findings.is_empty());
        assert!(report.input_sha256.is_some());
        report.validate().unwrap();
    }

    #[test]
    fn guarddog_report_retains_findings_with_errors_without_raw_evidence() {
        let payload: serde_json::Value = serde_json::from_str(
            r#"{
                "results": {
                    "threat-network-exfiltration": [{
                        "location": "/private/work/package/beacon.js:3",
                        "message": "token=secret-value"
                    }]
                },
                "risk_score": {"score": 8.0, "label": "high_risk"},
                "errors": {"other.js": "parse failed"}
            }"#,
        )
        .unwrap();
        let (score, rules, severity, reason) =
            parse_report(&payload, ReportFormat::GuardDog).unwrap();
        let (findings, truncated) = report_findings(
            "guarddog",
            Path::new("/private/work/package/archive.tgz"),
            rules,
            score,
            severity.as_deref(),
        )
        .unwrap();
        let serialized = serde_json::to_string(&findings).unwrap();

        assert_eq!(reason, Some("scanner_reported_errors"));
        assert!(!truncated);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].policy_score, Some(Decimal::from(8)));
        assert!(findings[0].location.is_none());
        assert_eq!(findings[0].summary, "external scanner reported a finding");
        assert!(!serialized.contains("/private/work"));
        assert!(!serialized.contains("secret-value"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_zero_exit_returns_incomplete_coverage() {
        let (_directory, path) = script("echo boom >&2; exit 3");
        let scanner = CommandScanner::new(dispatcher(), "guarddog");
        let report = scan_path(&scanner, &path, "odd");
        let serialized = serde_json::to_string(&report).unwrap();
        assert_eq!(report.coverage, Coverage::Partial);
        assert_eq!(report.reason.as_deref(), Some("scanner_execution_failed"));
        assert!(!serialized.contains("boom"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn drain_honours_a_single_grace_window() {
        // stdout closes at ~1.5s; stderr is held until ~3.2s. One 2s grace
        // window computed up front must time out the stderr wait; a fresh
        // per-stream window (ending ~3.5s) would incorrectly succeed. The wide
        // margins keep the test stable when the exit is noticed late on a
        // loaded host.
        let (_directory, path) = script(
            "(sleep 1.5; echo '{\"score\":0,\"rules\":[],\"summary\":\"\"}') 2>/dev/null & (sleep 3.2; echo x 1>&2) 1>/dev/null & exit 0",
        );
        let scanner = CommandScanner::guarddog(dispatcher())
            .with_limits(std::time::Duration::from_secs(30), 1024 * 1024);
        let mut archive = File::open(&path).unwrap();
        let error = scanner
            .run_with_runner(&Ecosystem::Npm, &mut archive, &path, &passthrough_runner())
            .unwrap_err()
            .to_string();
        assert!(error.contains("timed out"), "{error}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn background_pipe_holder_cannot_hang_the_scan() {
        let (_directory, path) = script("sleep 300 & exit 0");
        let scanner = CommandScanner::guarddog(dispatcher())
            .with_limits(std::time::Duration::from_secs(30), 1024 * 1024);
        let mut archive = File::open(&path).unwrap();
        let started = std::time::Instant::now();
        let error = scanner
            .run_with_runner(&Ecosystem::Npm, &mut archive, &path, &passthrough_runner())
            .unwrap_err()
            .to_string();
        assert!(error.contains("timed out"), "{error}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "drain blocked for {:?}",
            started.elapsed()
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn timeout_returns_incomplete_coverage() {
        let (_directory, path) = script("sleep 5");
        let scanner = CommandScanner::new(dispatcher(), "guarddog")
            .with_limits(std::time::Duration::from_millis(250), 1024 * 1024);
        let report = scan_path(&scanner, &path, "odd");
        assert_eq!(report.coverage, Coverage::Partial);
        assert_eq!(report.reason.as_deref(), Some("scanner_execution_failed"));
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn scanner_cannot_read_host_home_files() {
        if sandbox_runner().is_err() {
            return;
        }
        let home = PathBuf::from(std::env::var_os("HOME").unwrap());
        let secret_directory = tempfile::tempdir_in(home).unwrap();
        let secret = secret_directory.path().join("scanner-secret");
        std::fs::write(&secret, "host secret").unwrap();
        let body = format!(
            r#"if [ -r '{}' ]; then printf '%s\n' '{{"score":9,"rules":["host-readable"],"summary":"bad"}}'; else printf '%s\n' '{{"score":0,"rules":[],"summary":""}}'; fi"#,
            secret.display()
        );
        let (_directory, archive) = script(&body);
        let scanner = CommandScanner::new(dispatcher(), "guarddog");
        let report = scan_path(&scanner, &archive, "private");

        assert_eq!(
            report.reason.as_deref(),
            Some("engine_revision_unavailable")
        );
        assert!(report.findings.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn external_scanner_receives_address_space_limit() {
        let (_archive_directory, archive) = script("ulimit -v");
        let scanner = CommandScanner::guarddog(dispatcher());
        let mut archive_file = File::open(&archive).unwrap();
        let output = scanner
            .run_with_runner(
                &Ecosystem::Npm,
                &mut archive_file,
                &archive,
                &passthrough_runner(),
            )
            .unwrap();

        assert_eq!(output.trim(), "2097152");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn guarddog_can_copy_an_archive_larger_than_its_output_limit() {
        let (_archive_directory, archive) = script(
            "f=/tmp/supply-core-fsize-$$; /usr/bin/head -c 9000000 /dev/zero > \"$f\" && echo copied; /usr/bin/rm -f \"$f\"",
        );
        let scanner = CommandScanner::guarddog(dispatcher());
        let mut archive_file = File::open(&archive).unwrap();
        let output = scanner
            .run_with_runner(
                &Ecosystem::Npm,
                &mut archive_file,
                &archive,
                &passthrough_runner(),
            )
            .unwrap();

        assert_eq!(output.trim(), "copied");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unsupported_memory_limit_reports_incomplete_coverage() {
        let (_directory, archive) =
            script(r#"printf '%s\n' '{"score":0,"rules":[],"summary":""}'"#);
        let scanner = CommandScanner::new(dispatcher(), "guarddog");
        let report = scan_path(&scanner, &archive, "clean");

        assert_eq!(report.coverage, Coverage::Partial);
        assert_eq!(
            report.reason.as_deref(),
            Some("scanner_memory_limit_unavailable")
        );
        assert_eq!(report.input_sha256.as_deref().map(str::len), Some(64));
    }

    #[test]
    fn missing_sandbox_runner_never_launches_scanner() {
        let marker_directory = tempfile::tempdir().unwrap();
        let marker = marker_directory.path().join("scanner-launched");
        let body = format!("touch '{}'; echo unused", marker.display());
        let (_directory, archive) = script(&body);
        let missing_runner = marker_directory.path().join("missing-sandbox-runner");
        let scanner = CommandScanner::new(dispatcher(), "guarddog");

        let mut archive_file = File::open(&archive).unwrap();
        assert!(scanner
            .run_with_runner(
                &Ecosystem::Npm,
                &mut archive_file,
                &archive,
                &missing_runner
            )
            .is_err());
        assert!(!marker.exists());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn command_scanner_uses_open_descriptor_after_archive_path_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let archive_path = directory.path().join("archive.tgz");
        let replacement = directory.path().join("replacement.tgz");
        std::fs::write(&archive_path, b"echo pinned\n").unwrap();
        let mut archive = File::open(&archive_path).unwrap();
        std::fs::write(&replacement, b"echo replaced\n").unwrap();
        std::fs::remove_file(&archive_path).unwrap();
        std::fs::rename(&replacement, &archive_path).unwrap();

        let scanner = CommandScanner::guarddog(dispatcher());
        let output = scanner
            .run_with_runner(
                &Ecosystem::Npm,
                &mut archive,
                &archive_path,
                &passthrough_runner(),
            )
            .unwrap();

        assert_eq!(output.trim(), "pinned");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn oversized_output_returns_incomplete_coverage() {
        let (_directory, path) = script("head -c 4096 /dev/zero | tr '\\0' 'a'");
        let scanner = CommandScanner::new(dispatcher(), "guarddog")
            .with_limits(std::time::Duration::from_secs(10), 1024);
        let report = scan_path(&scanner, &path, "odd");
        assert_eq!(report.coverage, Coverage::Partial);
        assert_eq!(report.reason.as_deref(), Some("scanner_execution_failed"));
    }
    #[test]
    fn sandbox_mounts_reject_writable_scratch_aliases() {
        let directory = tempfile::tempdir().unwrap();
        let scratch = directory.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        let scratch_file = scratch.join("output");
        std::fs::write(&scratch_file, b"output").unwrap();
        let linked_input = directory.path().join("input");
        std::fs::hard_link(&scratch_file, &linked_input).unwrap();

        assert!(canonical_sandbox_mounts(
            &[SandboxMount {
                host_path: linked_input,
                sandbox_path: PathBuf::from("/scan/input"),
            }],
            &scratch,
        )
        .is_err());
        assert!(canonical_sandbox_mounts(
            &[SandboxMount {
                host_path: scratch_file,
                sandbox_path: PathBuf::from("/scan/input"),
            }],
            &scratch,
        )
        .is_err());

        let alias = directory.path().join("scratch-alias");
        std::os::unix::fs::symlink(&scratch, &alias).unwrap();
        assert!(canonical_sandbox_mounts(
            &[SandboxMount {
                host_path: alias,
                sandbox_path: PathBuf::from("/scan/input"),
            }],
            &scratch,
        )
        .is_err());
    }

    #[test]
    fn sandbox_mounts_reject_nested_symlink_aliases() {
        let directory = tempfile::tempdir().unwrap();
        let scratch = directory.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        let scratch_file = scratch.join("output");
        std::fs::write(&scratch_file, b"output").unwrap();
        let mount_root = directory.path().join("rules");
        std::fs::create_dir(&mount_root).unwrap();
        std::os::unix::fs::symlink(&scratch_file, mount_root.join("alias")).unwrap();

        assert!(canonical_sandbox_mounts(
            &[SandboxMount {
                host_path: mount_root,
                sandbox_path: PathBuf::from("/scan/rules"),
            }],
            &scratch,
        )
        .is_err());
    }

    #[test]
    fn sandbox_mounts_allow_nonoverlapping_siblings() {
        let directory = tempfile::tempdir().unwrap();
        let scratch = directory.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        let input = directory.path().join("input");
        std::fs::write(&input, b"immutable input").unwrap();

        let mounts = canonical_sandbox_mounts(
            &[SandboxMount {
                host_path: input.clone(),
                sandbox_path: PathBuf::from("/scan/input"),
            }],
            &scratch,
        )
        .unwrap();

        assert_eq!(mounts[0].host_path, std::fs::canonicalize(input).unwrap());
    }
}
