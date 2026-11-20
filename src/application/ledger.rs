use crate::adapters::storage::ledger::{
    LedgerOutboxItem, LedgerOutboxJob, LedgerStore, LocalLedgerHead,
};
use crate::domain::{
    Decision, DecisionStatus, Ecosystem, PackageVersion, PackageVersionId, Policy, Severity,
    Verdict,
};
use anyhow::{bail, ensure, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Mutex;

pub const LEDGER_PENDING: &str = "ledger_pending";
pub const LEDGER_EVENT_SCHEMA: &str = "supply-ledger.event.v1";

const REGISTERED_SOURCES: &[&str] = &[
    "cli",
    "evaluator",
    "guarddog",
    "historical-import",
    "npm",
    "nuget",
    "operator",
    "osv",
    "pypi",
    "policy-engine",
    "static-heuristics",
    "supply-core",
    "worker",
];
const REGISTERED_SCANNER_SOURCES: &[&str] = &[
    "box-js",
    "capa",
    "cosign",
    "dynamic",
    "external-scan",
    "fickling",
    "guarddog",
    "image-archive",
    "jsimplifier",
    "mcp-safeguard",
    "model-structure",
    "modelscan",
    "ossgadget",
    "static-heuristics",
    "trivy",
    "yarahunter",
];

const REGISTERED_METADATA_SCHEMAS: &[&str] = &[
    "npm.packument.v1",
    "nuget.registration.v1",
    "pypi.project.v1",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerEventKind {
    Discovered,
    ScanCompleted,
    ScanFailed,
    AdvisoryChanged,
    VerdictChanged,
    Withdrawn,
    Correction,
    HistoricalObservation,
    SourceHealth,
    EvaluationObserved,
    RequestedUnknown,
    JobFenced,
    PolicyChanged,
    RuleApproved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerSourceKind {
    Registry,
    Advisory,
    Scanner,
    Operator,
    Historical,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    Complete,
    Partial,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineFinding {
    pub id: String,
    pub rule: String,
    pub summary: String,
    pub location: Option<String>,
    pub native_severity: Option<String>,
    pub policy_score: Option<rust_decimal::Decimal>,
}

/// Maximum findings one engine report may retain. Large-but-clean packages
/// legitimately emit hundreds of deduplicated matches (zod emits ~277 from
/// OSSGadget); reports above the cap are marked partial with reason
/// `finding_limit`, so the bound must stay above real-world volume while
/// still capping memory and payload size.
pub const MAX_ENGINE_FINDINGS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineReport {
    pub source: String,
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_bundle_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_sha256: Option<String>,
    pub input_sha256: Option<String>,
    pub expected_inputs: u64,
    pub processed_inputs: u64,
    pub coverage: Coverage,
    pub findings: Vec<EngineFinding>,
    pub reason: Option<String>,
}

impl EngineReport {
    pub fn validate(&self) -> Result<()> {
        validate_scanner_source(&self.source)?;
        if let Some(version) = self.version.as_deref() {
            validate_text(version, "engine version", 128)?;
        }
        if let Some(digest) = self.input_sha256.as_deref() {
            validate_sha256(digest, "engine input sha256")?;
        }
        if let Some(digest) = self.rule_bundle_sha256.as_deref() {
            validate_sha256(digest, "engine rule bundle sha256")?;
        }
        if let Some(digest) = self.database_sha256.as_deref() {
            validate_sha256(digest, "engine database sha256")?;
        }
        ensure!(
            self.expected_inputs <= 10_000 && self.processed_inputs <= self.expected_inputs,
            "engine input counts exceed limits"
        );
        match self.coverage {
            Coverage::Complete => ensure!(
                self.version.is_some()
                    && self.rule_bundle_sha256.is_some()
                    && self.input_sha256.is_some()
                    && self.expected_inputs == self.processed_inputs
                    && self.reason.is_none(),
                "complete engine report must bind inputs and engine revisions"
            ),
            Coverage::Partial | Coverage::Unknown => {
                ensure!(
                    self.reason.is_some(),
                    "incomplete engine report requires a reason"
                );
            }
        }
        if let Some(reason) = self.reason.as_deref() {
            validate_code(reason, "engine report reason")?;
        }
        ensure!(
            self.findings.len() <= MAX_ENGINE_FINDINGS,
            "too many engine findings"
        );
        for (index, finding) in self.findings.iter().enumerate() {
            validate_sha256(&finding.id, "engine finding ID")?;
            validate_code(&finding.rule, "engine finding rule")?;
            validate_text(&finding.summary, "engine finding summary", 512)?;
            ensure!(
                !finding.summary.contains('/')
                    && !finding.summary.contains('\\')
                    && !finding.summary.contains("://"),
                "engine finding summary must be path-free"
            );
            if let Some(location) = finding.location.as_deref() {
                validate_text(location, "engine finding location", 512)?;
                ensure!(
                    !location.starts_with('/')
                        && !location.contains('\\')
                        && !location.split('/').any(|part| part == ".."),
                    "engine finding location must be relative"
                );
            }
            if let Some(severity) = finding.native_severity.as_deref() {
                validate_native_severity(severity)?;
            }
            if let Some(score) = finding.policy_score {
                ensure!(
                    (rust_decimal::Decimal::ZERO..=rust_decimal::Decimal::TEN).contains(&score),
                    "policy score must be between 0 and 10"
                );
            }
            ensure!(
                !self.findings[..index]
                    .iter()
                    .any(|previous| previous.id == finding.id),
                "duplicate engine finding ID"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanDecision {
    Pass,
    Review,
    Block,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReport {
    pub artifact_sha256: Option<String>,
    pub policy_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_policy_revision_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_key_sha256: Option<String>,
    pub coverage: Coverage,
    pub decision: ScanDecision,
    pub engines: Vec<EngineReport>,
    pub reason: Option<String>,
}

impl ArtifactReport {
    pub fn validate(&self) -> Result<()> {
        if let Some(digest) = self.artifact_sha256.as_deref() {
            validate_sha256(digest, "artifact sha256")?;
        }
        if let Some(digest) = self.policy_sha256.as_deref() {
            validate_sha256(digest, "policy sha256")?;
        }
        if let Some(digest) = self.engine_policy_revision_sha256.as_deref() {
            validate_sha256(digest, "engine policy revision sha256")?;
        }
        if let Some(cache_key) = self.cache_key_sha256.as_deref() {
            let (Some(artifact), Some(policy), Some(revision)) = (
                self.artifact_sha256.as_deref(),
                self.policy_sha256.as_deref(),
                self.engine_policy_revision_sha256.as_deref(),
            ) else {
                bail!("scan cache key requires artifact, policy, and engine revisions");
            };
            ensure!(
                cache_key == scan_cache_key_sha256(artifact, policy, revision)?,
                "scan cache key does not match report inputs"
            );
        }
        ensure!(self.engines.len() <= 32, "too many engine reports");
        for (index, engine) in self.engines.iter().enumerate() {
            engine.validate()?;
            ensure!(
                !self.engines[..index]
                    .iter()
                    .any(|previous| previous.source == engine.source),
                "duplicate engine report source"
            );
        }
        if let Some(reason) = self.reason.as_deref() {
            validate_code(reason, "artifact report reason")?;
        }
        let all_complete = !self.engines.is_empty()
            && self
                .engines
                .iter()
                .all(|engine| engine.coverage == Coverage::Complete);
        if self.coverage == Coverage::Complete {
            ensure!(
                self.artifact_sha256.is_some()
                    && self.policy_sha256.is_some()
                    && self.reason.is_none()
                    && all_complete,
                "complete artifact report requires bound complete engines"
            );
        } else {
            ensure!(
                self.reason.is_some(),
                "incomplete artifact report requires a reason"
            );
        }
        let findings = self
            .engines
            .iter()
            .any(|engine| !engine.findings.is_empty());
        match self.decision {
            ScanDecision::Pass => ensure!(
                self.coverage == Coverage::Complete,
                "pass decision requires complete coverage"
            ),
            ScanDecision::Review => ensure!(
                self.coverage == Coverage::Complete && findings,
                "review decision requires complete findings"
            ),
            ScanDecision::Block => ensure!(findings, "block decision requires a finding"),
            ScanDecision::Incomplete => ensure!(
                self.coverage != Coverage::Complete,
                "incomplete decision requires incomplete coverage"
            ),
        }
        Ok(())
    }
}

pub fn engine_finding_id(
    engine: &str,
    rule: &str,
    member_identity: &str,
    location_or_content_fingerprint: &str,
) -> Result<String> {
    validate_scanner_source(engine)?;
    validate_code(rule, "engine finding rule")?;
    validate_text(member_identity, "finding member identity", 1024)?;
    validate_text(
        location_or_content_fingerprint,
        "finding location fingerprint",
        1024,
    )?;
    let mut hasher = Sha256::new();
    for value in [
        engine,
        rule,
        member_identity,
        location_or_content_fingerprint,
    ] {
        let length = u64::try_from(value.len())?;
        hasher.update(length.to_be_bytes());
        hasher.update(value.as_bytes());
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn engine_policy_revision_sha256(
    required_sources: &[&str],
    reports: &[EngineReport],
) -> Result<String> {
    ensure!(
        required_sources.len() <= 32,
        "required engine source count exceeds limit"
    );
    ensure!(reports.len() <= 32, "too many engine reports");

    let mut required: Vec<String> = required_sources
        .iter()
        .map(|source| (*source).to_string())
        .collect();
    required.sort_unstable();
    ensure!(
        !required.windows(2).any(|pair| pair[0] == pair[1]),
        "duplicate required engine source"
    );
    for source in &required {
        validate_scanner_source(source)?;
    }

    let mut sources = required.iter().cloned().collect::<BTreeSet<_>>();
    let mut reported = BTreeSet::new();
    for report in reports {
        report.validate()?;
        ensure!(
            reported.insert(report.source.as_str()),
            "duplicate engine report source"
        );
        sources.insert(report.source.clone());
    }

    #[derive(Serialize)]
    struct EngineRevision {
        source: String,
        version: Option<String>,
        rule_bundle_sha256: Option<String>,
        database_sha256: Option<String>,
    }

    #[derive(Serialize)]
    struct ScanRevision {
        required_sources: Vec<String>,
        engines: Vec<EngineRevision>,
    }

    let engines = sources
        .into_iter()
        .map(|source| {
            let report = reports.iter().find(|report| report.source == source);
            EngineRevision {
                source,
                version: report.and_then(|report| report.version.clone()),
                rule_bundle_sha256: report.and_then(|report| report.rule_bundle_sha256.clone()),
                database_sha256: report.and_then(|report| report.database_sha256.clone()),
            }
        })
        .collect();
    let bytes = serde_json_canonicalizer::to_vec(&ScanRevision {
        required_sources: required,
        engines,
    })?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn scan_cache_key_sha256(
    artifact_sha256: &str,
    policy_sha256: &str,
    engine_policy_revision_sha256: &str,
) -> Result<String> {
    validate_sha256(artifact_sha256, "scan cache artifact sha256")?;
    validate_sha256(policy_sha256, "scan cache policy sha256")?;
    validate_sha256(
        engine_policy_revision_sha256,
        "scan cache engine policy revision sha256",
    )?;

    #[derive(Serialize)]
    struct ScanCacheKey<'a> {
        artifact_sha256: &'a str,
        policy_sha256: &'a str,
        engine_policy_revision_sha256: &'a str,
    }

    let bytes = serde_json_canonicalizer::to_vec(&ScanCacheKey {
        artifact_sha256,
        policy_sha256,
        engine_policy_revision_sha256,
    })?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceHealthStatus {
    Healthy,
    Degraded,
    Unavailable,
    Stale,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerIdentity {
    pub observation_id: Option<String>,
    pub stage: Option<String>,
    pub ecosystem: Option<Ecosystem>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub artifact_identity: Option<String>,
    pub generation: Option<String>,
    pub engine_policy_revision: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEvent {
    pub schema: String,
    pub event_id: String,
    pub kind: LedgerEventKind,
    pub recorded_at: Option<DateTime<Utc>>,
    pub observed_at: Option<DateTime<Utc>>,
    pub source: String,
    pub body: LedgerEventBody,
}
#[derive(Debug)]
pub struct LedgerRecordingError;

impl std::fmt::Display for LedgerRecordingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ledger observation recording failed")
    }
}

impl std::error::Error for LedgerRecordingError {}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerStatus {
    Pending,
}

#[derive(Clone)]
pub struct LedgerRecorder {
    store: std::sync::Arc<Mutex<LedgerStore>>,
}

impl LedgerRecorder {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self::new(LedgerStore::open(path)?))
    }

    pub fn open_in_memory() -> Result<Self> {
        Ok(Self::new(LedgerStore::open_in_memory()?))
    }

    pub fn new(store: LedgerStore) -> Self {
        Self {
            store: std::sync::Arc::new(Mutex::new(store)),
        }
    }

    pub fn record_observation(
        &self,
        event: &LedgerEvent,
        payload: serde_json::Value,
    ) -> Result<LedgerStatus> {
        let job = LedgerOutboxJob {
            job_key: format!("evaluate:{}", event.event_id),
            payload,
        };
        self.store
            .lock()
            .map_err(|_| anyhow::anyhow!("ledger recorder lock poisoned"))?
            .append_and_enqueue(event, &job)?;
        Ok(LedgerStatus::Pending)
    }

    pub fn record_evaluation(
        &self,
        version: &PackageVersion,
        policy: &Policy,
        decision: &Decision,
        observed_at: DateTime<Utc>,
    ) -> Result<LedgerStatus> {
        let policy_sha256 = hex::encode(Sha256::digest(serde_json_canonicalizer::to_vec(policy)?));
        let engine_sha256 = hex::encode(Sha256::digest(b"supply-core-evaluator-v1"));
        let version_text = version.version.to_string();
        let identity = LedgerIdentity {
            observation_id: Some(next_observation_id()),
            ecosystem: Some(version.package.ecosystem.clone()),
            name: Some(version.package.name.clone()),
            version: Some(version_text.clone()),
            engine_policy_revision: Some(policy_sha256.clone()),
            ..LedgerIdentity::default()
        };
        let event = LedgerEvent::new(
            "evaluator",
            identity,
            Some(observed_at),
            LedgerEventDetails::EvaluationObserved(EvaluationObservedBody {
                observed_verdict: Some(match &decision.status {
                    DecisionStatus::Allow => Verdict::Pending,
                    DecisionStatus::Warn => Verdict::Review,
                    DecisionStatus::Block => Verdict::Blocked,
                    DecisionStatus::Quarantine | DecisionStatus::Fallback => Verdict::Held,
                }),
                policy_sha256,
                engine_sha256,
                artifact_generation: None,
                advisory_revision: None,
            }),
        )?;
        self.record_observation(
            &event,
            serde_json::json!({
                "operation": "evaluate_version",
                "scope": "complete",
                "ecosystem": ecosystem_name(&version.package.ecosystem),
                "name": version.package.name,
                "version": version_text,
                "observation_id": event.body.identity.observation_id,
            }),
        )
    }
    pub fn record_discovered(
        &self,
        artifact: &crate::domain::FrozenArtifact,
        observed_at: DateTime<Utc>,
    ) -> Result<LedgerStatus> {
        let ecosystem = &artifact.package.ecosystem;
        let version_text = artifact.version.to_string();
        let observation_id = next_observation_id();
        let event = LedgerEvent::new(
            ecosystem_name(ecosystem),
            LedgerIdentity {
                observation_id: Some(observation_id.clone()),
                ecosystem: Some(ecosystem.clone()),
                name: Some(artifact.package.name.clone()),
                version: Some(version_text.clone()),
                artifact_identity: Some(artifact.sha256.clone()),
                ..LedgerIdentity::default()
            },
            Some(observed_at),
            LedgerEventDetails::Discovered(DiscoveredBody {
                evidence: PackageEvidence {
                    artifact_sha256: Some(artifact.sha256.clone()),
                    upstream_integrity: artifact.integrity.clone(),
                    coverage: Some(Coverage::Complete),
                    source_kind: Some(LedgerSourceKind::Registry),
                    ..PackageEvidence::default()
                },
            }),
        )?;
        self.record_observation(
            &event,
            serde_json::json!({
                "operation": "evaluate_version",
                "scope": "complete",
                "ecosystem": ecosystem_name(ecosystem),
                "name": artifact.package.name,
                "version": version_text,
                "observation_id": observation_id,
            }),
        )
    }
    pub fn pending_jobs(&self, limit: usize) -> Result<Vec<LedgerOutboxItem>> {
        self.store
            .lock()
            .map_err(|_| anyhow::anyhow!("ledger recorder lock poisoned"))?
            .pending_jobs(limit)
    }
    pub fn verify_integrity(&self) -> Result<LocalLedgerHead> {
        self.store
            .lock()
            .map_err(|_| anyhow::anyhow!("ledger recorder lock poisoned"))?
            .verify_integrity()
    }

    pub fn events_from(&self, from: u64, limit: usize) -> Result<Vec<LedgerEvent>> {
        self.store
            .lock()
            .map_err(|_| anyhow::anyhow!("ledger recorder lock poisoned"))?
            .events_from(from, limit)
    }
    pub fn record_rule_approval(
        &self,
        artifact_sha256: &str,
        finding_id: &str,
        policy_sha256: &str,
        expires_at: DateTime<Utc>,
        reason: &str,
    ) -> Result<u64> {
        ensure!(
            expires_at > Utc::now(),
            "rule approval expiry must be in the future"
        );
        let event = LedgerEvent::new(
            "operator",
            LedgerIdentity {
                observation_id: Some(next_observation_id()),
                engine_policy_revision: Some(policy_sha256.to_string()),
                ..LedgerIdentity::default()
            },
            Some(Utc::now()),
            LedgerEventDetails::RuleApproved(RuleApprovedBody {
                artifact_sha256: artifact_sha256.to_string(),
                finding_id: finding_id.to_string(),
                policy_sha256: policy_sha256.to_string(),
                expires_at,
                reason: reason.to_string(),
            }),
        )?;
        self.store
            .lock()
            .map_err(|_| anyhow::anyhow!("ledger recorder lock poisoned"))?
            .append(&event)
    }

    pub fn active_rule_approvals(
        &self,
        artifact_sha256: &str,
        policy_sha256: &str,
        now: DateTime<Utc>,
    ) -> Result<BTreeSet<String>> {
        self.store
            .lock()
            .map_err(|_| anyhow::anyhow!("ledger recorder lock poisoned"))?
            .active_rule_approvals(artifact_sha256, policy_sha256, now)
    }
}

pub fn verify_ledger_integrity(path: impl AsRef<Path>) -> Result<LocalLedgerHead> {
    LedgerStore::open_read_only(path)?.verify_integrity()
}

pub(crate) fn next_observation_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!(
        "local-{}-{}-{}",
        Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

fn ecosystem_name(ecosystem: &Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPi => "pypi",
        Ecosystem::NuGet => "nuget",
        Ecosystem::DockerImage => "docker",
        Ecosystem::GitHubActions => "github-actions",
        Ecosystem::AzurePipelines => "azure-pipelines",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEventBody {
    pub identity: LedgerIdentity,
    pub details: LedgerEventDetails,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum LedgerEventDetails {
    Discovered(DiscoveredBody),
    ScanCompleted(ScanCompletedBody),
    ScanFailed(ScanFailedBody),
    AdvisoryChanged(AdvisoryChangedBody),
    VerdictChanged(VerdictChangedBody),
    Withdrawn(WithdrawnBody),
    Correction(CorrectionBody),
    HistoricalObservation(HistoricalObservationBody),
    SourceHealth(SourceHealthBody),
    EvaluationObserved(EvaluationObservedBody),
    RequestedUnknown(RequestedUnknownBody),
    JobFenced(JobFencedBody),
    PolicyChanged(PolicyChangedBody),
    RuleApproved(RuleApprovedBody),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageEvidence {
    pub artifact_filename: Option<String>,
    pub artifact_sha256: Option<String>,
    pub upstream_integrity: Option<String>,
    pub coverage: Option<Coverage>,
    pub score: Option<String>,
    #[serde(default)]
    pub findings: Vec<LedgerFinding>,
    #[serde(default)]
    pub scanner_findings: Vec<ScannerFinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub engine_reports: Vec<EngineReport>,
    pub verdict: Option<Verdict>,
    pub source_kind: Option<LedgerSourceKind>,
    pub source_digest: Option<String>,
    pub metadata: Option<RegistryMetadata>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScannerFinding {
    pub source: String,
    pub rules: Vec<String>,
    pub summary: String,
    pub score: Option<String>,
    pub scan_incomplete: bool,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerFinding {
    pub source: String,
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub severity: Severity,
    pub score: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryMetadata {
    pub schema: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveredBody {
    pub evidence: PackageEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanCompletedBody {
    pub evidence: PackageEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanFailedBody {
    pub evidence: PackageEvidence,
    pub failure_code: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryChangedBody {
    pub evidence: PackageEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictChangedBody {
    pub previous: Option<Verdict>,
    pub current: Verdict,
    pub policy_sha256: String,
    pub engine_sha256: String,
    pub artifact_generation: String,
    pub advisory_revision: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithdrawnBody {
    pub source_kind: LedgerSourceKind,
    pub reason_code: String,
    pub source_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrectionBody {
    pub supersedes_event_id: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalObservationBody {
    pub source_file_sha256: String,
    pub record_position: String,
    pub original_recorded_at: Option<DateTime<Utc>>,
    pub source_kind: LedgerSourceKind,
    pub record_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceHealthBody {
    pub status: SourceHealthStatus,
    pub cursor: Option<String>,
    pub generation: Option<String>,
    pub last_successful_poll: Option<DateTime<Utc>>,
    pub failure_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationObservedBody {
    pub observed_verdict: Option<Verdict>,
    pub policy_sha256: String,
    pub engine_sha256: String,
    pub artifact_generation: Option<String>,
    pub advisory_revision: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedUnknownBody {
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobFencedBody {
    pub job_key: String,
    pub lease_token: String,
    pub lease_expires_at: DateTime<Utc>,
    pub artifact_generation: String,
    pub advisory_revision: String,
    pub policy_sha256: String,
    pub engine_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyChangedBody {
    pub previous_policy_sha256: Option<String>,
    pub policy_sha256: String,
    pub engine_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleApprovedBody {
    pub artifact_sha256: String,
    pub finding_id: String,
    pub policy_sha256: String,
    pub expires_at: DateTime<Utc>,
    pub reason: String,
}

impl LedgerEventDetails {
    pub fn kind(&self) -> LedgerEventKind {
        match self {
            Self::Discovered(_) => LedgerEventKind::Discovered,
            Self::ScanCompleted(_) => LedgerEventKind::ScanCompleted,
            Self::ScanFailed(_) => LedgerEventKind::ScanFailed,
            Self::AdvisoryChanged(_) => LedgerEventKind::AdvisoryChanged,
            Self::VerdictChanged(_) => LedgerEventKind::VerdictChanged,
            Self::Withdrawn(_) => LedgerEventKind::Withdrawn,
            Self::Correction(_) => LedgerEventKind::Correction,
            Self::HistoricalObservation(_) => LedgerEventKind::HistoricalObservation,
            Self::SourceHealth(_) => LedgerEventKind::SourceHealth,
            Self::EvaluationObserved(_) => LedgerEventKind::EvaluationObserved,
            Self::RequestedUnknown(_) => LedgerEventKind::RequestedUnknown,
            Self::JobFenced(_) => LedgerEventKind::JobFenced,
            Self::PolicyChanged(_) => LedgerEventKind::PolicyChanged,
            Self::RuleApproved(_) => LedgerEventKind::RuleApproved,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEventWireBytes(Vec<u8>);

impl LedgerEventWireBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SemanticLedgerEventBytes(Vec<u8>);

impl SemanticLedgerEventBytes {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by the planned public ledger API")
)]
#[derive(Debug, Serialize)]
pub(crate) struct PublicLedgerProjection<'a> {
    schema: &'a str,
    kind: LedgerEventKind,
    observed_at: Option<&'a DateTime<Utc>>,
    source: &'a str,
    ecosystem: &'a Ecosystem,
    name: &'a str,
    version: &'a str,
    coverage: Option<Coverage>,
    findings: PublicFindings<'a>,
    withdrawn: bool,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by the planned public ledger API")
)]
#[derive(Debug)]
struct PublicFindings<'a>(&'a [LedgerFinding]);

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by the planned public ledger API")
)]
#[derive(Serialize)]
struct PublicFinding<'a> {
    id: &'a str,
    aliases: &'a [String],
    severity: &'a Severity,
}

impl Serialize for PublicFindings<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;

        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for finding in self.0 {
            sequence.serialize_element(&PublicFinding {
                id: &finding.id,
                aliases: finding.aliases.as_slice(),
                severity: &finding.severity,
            })?;
        }
        sequence.end()
    }
}

impl PublicLedgerProjection<'_> {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "consumed by the planned public ledger API")
    )]
    pub(crate) fn to_jcs(&self) -> Result<Vec<u8>> {
        Ok(serde_json_canonicalizer::to_vec(self)?)
    }
}

impl LedgerEvent {
    pub fn new(
        source: impl Into<String>,
        identity: LedgerIdentity,
        observed_at: Option<DateTime<Utc>>,
        details: LedgerEventDetails,
    ) -> Result<Self> {
        let source = source.into();
        let kind = details.kind();
        let event_id = derive_event_id(&kind, &source, &identity)?;
        let event = Self {
            schema: LEDGER_EVENT_SCHEMA.to_string(),
            event_id,
            kind,
            recorded_at: None,
            observed_at,
            source,
            body: LedgerEventBody { identity, details },
        };
        event.validate()?;
        Ok(event)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == LEDGER_EVENT_SCHEMA,
            "unsupported ledger event schema"
        );
        ensure!(
            self.kind == self.body.details.kind(),
            "ledger event kind does not match body"
        );
        validate_source(&self.source)?;
        validate_identity(&self.body.identity)?;
        validate_details(&self.body.identity, &self.body.details)?;
        ensure!(
            self.event_id == derive_event_id(&self.kind, &self.source, &self.body.identity)?,
            "ledger event ID does not match canonical identity"
        );
        Ok(())
    }

    pub fn validate_committed(&self) -> Result<()> {
        self.validate()?;
        ensure!(
            self.recorded_at.is_some(),
            "committed ledger events require recorded_at"
        );
        Ok(())
    }

    pub fn canonical_wire_bytes(&self) -> Result<LedgerEventWireBytes> {
        self.validate()?;
        Ok(LedgerEventWireBytes(serde_json_canonicalizer::to_vec(
            self,
        )?))
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "consumed by the planned public ledger API")
    )]
    pub(crate) fn public_projection(&self) -> Result<PublicLedgerProjection<'_>> {
        self.validate_committed()?;
        let public_provenance_matches = match (&self.body.details, self.source.as_str()) {
            (LedgerEventDetails::Discovered(body), "npm" | "nuget" | "pypi") => {
                body.evidence.source_kind == Some(LedgerSourceKind::Registry)
            }
            (LedgerEventDetails::AdvisoryChanged(body), "osv") => {
                body.evidence.source_kind == Some(LedgerSourceKind::Advisory)
            }
            (LedgerEventDetails::Withdrawn(body), "npm" | "nuget" | "pypi") => {
                body.source_kind == LedgerSourceKind::Registry
            }
            (LedgerEventDetails::Withdrawn(body), "osv") => {
                body.source_kind == LedgerSourceKind::Advisory
            }
            _ => false,
        };
        ensure!(
            public_provenance_matches,
            "event lacks public-feed provenance"
        );

        let identity = &self.body.identity;
        require_package(identity)?;
        let ecosystem = identity
            .ecosystem
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("public projection requires package ecosystem"))?;
        let name = identity
            .name
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("public projection requires package name"))?;
        let version = identity
            .version
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("public projection requires package version"))?;
        let (coverage, findings, withdrawn) = match &self.body.details {
            LedgerEventDetails::Discovered(body) => (body.evidence.coverage, &[][..], false),
            LedgerEventDetails::AdvisoryChanged(body) => (
                body.evidence.coverage,
                body.evidence.findings.as_slice(),
                false,
            ),
            LedgerEventDetails::Withdrawn(_) => (None, &[][..], true),
            _ => bail!("event is not eligible for public projection"),
        };
        Ok(PublicLedgerProjection {
            schema: &self.schema,
            kind: self.kind,
            observed_at: self.observed_at.as_ref(),
            source: &self.source,
            ecosystem,
            name,
            version,
            coverage,
            findings: PublicFindings(findings),
            withdrawn,
        })
    }

    pub(crate) fn semantic_payload(&self) -> Result<SemanticLedgerEventBytes> {
        self.validate()?;
        #[derive(Serialize)]
        struct SemanticEvent<'a> {
            schema: &'a str,
            kind: &'a LedgerEventKind,
            observed_at: Option<&'a DateTime<Utc>>,
            source: &'a str,
            body: &'a LedgerEventBody,
        }
        Ok(SemanticLedgerEventBytes(serde_json_canonicalizer::to_vec(
            &SemanticEvent {
                schema: &self.schema,
                kind: &self.kind,
                observed_at: self.observed_at.as_ref(),
                source: &self.source,
                body: &self.body,
            },
        )?))
    }

    pub(crate) fn sequenced_at(&self, recorded_at: DateTime<Utc>) -> Result<Self> {
        let mut event = self.clone();
        event.recorded_at = Some(recorded_at);
        event.validate_committed()?;
        Ok(event)
    }
}
pub fn derive_event_id(
    kind: &LedgerEventKind,
    source: &str,
    identity: &LedgerIdentity,
) -> Result<String> {
    #[derive(Serialize)]
    struct EventIdInput<'a> {
        kind: &'a LedgerEventKind,
        source: &'a str,
        observation_id: Option<&'a str>,
        stage: Option<&'a str>,
        ecosystem: Option<&'a Ecosystem>,
        name: Option<&'a str>,
        version: Option<&'a str>,
        artifact_identity: Option<&'a str>,
        generation: Option<&'a str>,
        engine_policy_revision: Option<&'a str>,
    }

    let bytes = serde_json_canonicalizer::to_vec(&EventIdInput {
        kind,
        source,
        observation_id: identity.observation_id.as_deref(),
        stage: identity.stage.as_deref(),
        ecosystem: identity.ecosystem.as_ref(),
        name: identity.name.as_deref(),
        version: identity.version.as_deref(),
        artifact_identity: identity.artifact_identity.as_deref(),
        generation: identity.generation.as_deref(),
        engine_policy_revision: identity.engine_policy_revision.as_deref(),
    })?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn validate_source(source: &str) -> Result<()> {
    ensure!(
        REGISTERED_SOURCES.contains(&source),
        "unregistered ledger source: {source}"
    );
    Ok(())
}
fn validate_scanner_source(source: &str) -> Result<()> {
    ensure!(
        REGISTERED_SCANNER_SOURCES.contains(&source),
        "unregistered scanner finding source: {source}"
    );
    Ok(())
}

fn validate_identity(identity: &LedgerIdentity) -> Result<()> {
    for (value, field, limit) in [
        (identity.observation_id.as_deref(), "observation_id", 512),
        (identity.stage.as_deref(), "stage", 128),
        (identity.name.as_deref(), "name", 512),
        (identity.version.as_deref(), "version", 256),
        (
            identity.artifact_identity.as_deref(),
            "artifact_identity",
            2048,
        ),
        (identity.generation.as_deref(), "generation", 64),
        (
            identity.engine_policy_revision.as_deref(),
            "engine_policy_revision",
            64,
        ),
    ] {
        if let Some(value) = value {
            validate_text(value, field, limit)?;
        }
    }

    let package_fields = [
        identity.ecosystem.is_some(),
        identity.name.is_some(),
        identity.version.is_some(),
    ];
    ensure!(
        package_fields.iter().all(|present| *present)
            || package_fields.iter().all(|present| !*present),
        "package identity requires ecosystem, name, and version together"
    );
    if let (Some(ecosystem), Some(name), Some(version)) = (
        identity.ecosystem.as_ref(),
        identity.name.as_deref(),
        identity.version.as_deref(),
    ) {
        validate_package_name(ecosystem, name)?;
        let parsed = PackageVersionId::parse(ecosystem, version)?;
        ensure!(
            parsed.canonical() == version,
            "package version is not canonical"
        );
    }

    if let Some(observation_id) = identity.observation_id.as_deref() {
        ensure!(
            !observation_id.contains('/') && !observation_id.contains('\\'),
            "observation ID must not contain a path"
        );
    }
    if let Some(stage) = identity.stage.as_deref() {
        ensure!(
            !stage.contains('/') && !stage.contains('\\'),
            "stage must not contain a path"
        );
    }

    if let Some(artifact_identity) = identity.artifact_identity.as_deref() {
        ensure!(
            !artifact_identity.starts_with('/')
                && !artifact_identity.starts_with('\\')
                && !artifact_identity.starts_with("file:")
                && !artifact_identity
                    .as_bytes()
                    .get(1)
                    .is_some_and(|byte| *byte == b':'),
            "artifact identity must not contain a local path"
        );
        if artifact_identity.contains("://") {
            let url = reqwest::Url::parse(artifact_identity)?;
            ensure!(url.scheme() == "https", "artifact URLs must use HTTPS");
            ensure!(
                url.username().is_empty() && url.password().is_none(),
                "artifact URLs must not contain userinfo"
            );
        } else {
            ensure!(
                !artifact_identity.contains('/') && !artifact_identity.contains('\\'),
                "artifact filename must not contain a path"
            );
        }
    }

    if let Some(generation) = identity.generation.as_deref() {
        ensure!(
            generation.bytes().all(|byte| byte.is_ascii_digit())
                && (generation == "0" || !generation.starts_with('0')),
            "generation must be a canonical non-negative integer string"
        );
    }
    if let Some(revision) = identity.engine_policy_revision.as_deref() {
        validate_sha256(revision, "engine_policy_revision")?;
    }
    Ok(())
}

fn validate_package_name(ecosystem: &Ecosystem, name: &str) -> Result<()> {
    validate_text(name, "package name", 214)?;
    let valid = match ecosystem {
        Ecosystem::Npm => {
            let valid_segment = |segment: &str| {
                !segment.is_empty()
                    && !segment.starts_with('.')
                    && !segment.starts_with('_')
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
                    })
            };
            if let Some(scoped) = name.strip_prefix('@') {
                scoped.split_once('/').is_some_and(|(scope, package)| {
                    valid_segment(scope) && valid_segment(package) && !package.contains('/')
                })
            } else {
                valid_segment(name) && !name.contains('/')
            }
        }
        Ecosystem::PyPi => {
            name == crate::adapters::pypi::normalize_package_name(name)
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        }
        Ecosystem::NuGet => {
            name == name.to_ascii_lowercase()
                && name.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-_".contains(&byte)
                })
        }
        _ => false,
    };
    ensure!(valid, "package name is not canonical for its ecosystem");
    Ok(())
}

fn validate_details(identity: &LedgerIdentity, details: &LedgerEventDetails) -> Result<()> {
    ensure!(
        identity.observation_id.is_some(),
        "ledger events require an observation ID"
    );
    match details {
        LedgerEventDetails::Discovered(body) => {
            require_package(identity)?;
            validate_evidence(&body.evidence)?;
            ensure!(
                body.evidence.source_kind == Some(LedgerSourceKind::Registry),
                "discovery events require registry provenance"
            );
        }
        LedgerEventDetails::ScanCompleted(body) => {
            require_package(identity)?;
            validate_evidence(&body.evidence)?;
            ensure!(
                body.evidence.coverage.is_some(),
                "completed scans require coverage"
            );
            ensure!(
                identity.generation.is_some() && identity.engine_policy_revision.is_some(),
                "completed scans require artifact generation and engine policy revision"
            );
        }
        LedgerEventDetails::ScanFailed(body) => {
            require_package(identity)?;
            validate_evidence(&body.evidence)?;
            ensure!(
                body.evidence.coverage.is_some(),
                "failed scans require coverage"
            );
            ensure!(
                identity.generation.is_some() && identity.engine_policy_revision.is_some(),
                "failed scans require artifact generation and engine policy revision"
            );
            validate_code(&body.failure_code, "failure_code")?;
        }
        LedgerEventDetails::AdvisoryChanged(body) => {
            require_package(identity)?;
            validate_evidence(&body.evidence)?;
            ensure!(
                body.evidence.source_kind == Some(LedgerSourceKind::Advisory)
                    && body.evidence.source_digest.is_some(),
                "advisory changes require advisory provenance and source digest"
            );
        }
        LedgerEventDetails::VerdictChanged(body) => {
            require_package(identity)?;
            validate_sha256(&body.policy_sha256, "policy_sha256")?;
            validate_sha256(&body.engine_sha256, "engine_sha256")?;
            validate_decimal_string(&body.artifact_generation, "artifact_generation", 64)?;
            validate_text(&body.advisory_revision, "advisory_revision", 256)?;
            ensure!(
                identity.generation.as_deref() == Some(body.artifact_generation.as_str())
                    && identity.engine_policy_revision.as_deref()
                        == Some(body.policy_sha256.as_str()),
                "verdict changes must bind current generations and policy revision"
            );
            validate_code(&body.reason_code, "reason_code")?;
        }
        LedgerEventDetails::Withdrawn(body) => {
            require_package(identity)?;
            validate_code(&body.reason_code, "reason_code")?;
            if let Some(digest) = body.source_digest.as_deref() {
                validate_sha256(digest, "source_digest")?;
            }
        }
        LedgerEventDetails::Correction(body) => {
            validate_sha256(&body.supersedes_event_id, "supersedes_event_id")?;
            validate_code(&body.reason_code, "reason_code")?;
        }
        LedgerEventDetails::HistoricalObservation(body) => {
            validate_sha256(&body.source_file_sha256, "source_file_sha256")?;
            validate_decimal_string(&body.record_position, "record_position", 20)?;
            if let Some(digest) = body.record_sha256.as_deref() {
                validate_sha256(digest, "record_sha256")?;
            }
            let expected = format!("{}:{}", body.source_file_sha256, body.record_position);
            ensure!(
                identity.observation_id.as_deref() == Some(expected.as_str()),
                "historical observation ID must bind file digest and record position"
            );
        }
        LedgerEventDetails::SourceHealth(body) => {
            if let Some(cursor) = body.cursor.as_deref() {
                validate_text(cursor, "cursor", 2048)?;
            }
            if let Some(generation) = body.generation.as_deref() {
                validate_decimal_string(generation, "generation", 64)?;
            }
            if let Some(code) = body.failure_code.as_deref() {
                validate_code(code, "failure_code")?;
            }
        }
        LedgerEventDetails::EvaluationObserved(body) => {
            require_package(identity)?;
            validate_sha256(&body.policy_sha256, "policy_sha256")?;
            validate_sha256(&body.engine_sha256, "engine_sha256")?;
            if let Some(generation) = body.artifact_generation.as_deref() {
                validate_decimal_string(generation, "artifact_generation", 64)?;
                ensure!(
                    identity.generation.as_deref() == Some(generation),
                    "evaluation must bind its artifact generation"
                );
            }
            if let Some(revision) = body.advisory_revision.as_deref() {
                validate_text(revision, "advisory_revision", 256)?;
            }
            ensure!(
                identity.engine_policy_revision.as_deref() == Some(body.policy_sha256.as_str()),
                "evaluation must bind its policy revision"
            );
        }
        LedgerEventDetails::RequestedUnknown(body) => {
            require_package(identity)?;
            validate_code(&body.reason_code, "reason_code")?;
        }
        LedgerEventDetails::JobFenced(body) => {
            require_package(identity)?;
            validate_text(&body.job_key, "job_key", 512)?;
            validate_text(&body.lease_token, "lease_token", 256)?;
            validate_decimal_string(&body.artifact_generation, "artifact_generation", 64)?;
            validate_text(&body.advisory_revision, "advisory_revision", 256)?;
            validate_sha256(&body.policy_sha256, "policy_sha256")?;
            validate_sha256(&body.engine_sha256, "engine_sha256")?;
            ensure!(
                identity.generation.as_deref() == Some(body.artifact_generation.as_str())
                    && identity.engine_policy_revision.as_deref()
                        == Some(body.policy_sha256.as_str()),
                "job fence must bind current generations and policy revision"
            );
        }
        LedgerEventDetails::PolicyChanged(body) => {
            if let Some(digest) = body.previous_policy_sha256.as_deref() {
                validate_sha256(digest, "previous_policy_sha256")?;
            }
            validate_sha256(&body.policy_sha256, "policy_sha256")?;
            validate_sha256(&body.engine_sha256, "engine_sha256")?;
            ensure!(
                identity.engine_policy_revision.as_deref() == Some(body.policy_sha256.as_str()),
                "policy change must bind its new policy revision"
            );
        }
        LedgerEventDetails::RuleApproved(body) => {
            validate_sha256(&body.artifact_sha256, "artifact_sha256")?;
            validate_sha256(&body.finding_id, "finding_id")?;
            validate_sha256(&body.policy_sha256, "policy_sha256")?;
            validate_text(&body.reason, "approval reason", 512)?;
            ensure!(
                identity.engine_policy_revision.as_deref() == Some(body.policy_sha256.as_str()),
                "rule approval must bind its engine policy revision"
            );
        }
    }
    Ok(())
}

fn validate_evidence(evidence: &PackageEvidence) -> Result<()> {
    if let Some(filename) = evidence.artifact_filename.as_deref() {
        validate_text(filename, "artifact_filename", 255)?;
        ensure!(
            filename != "."
                && filename != ".."
                && !filename.contains('/')
                && !filename.contains('\\'),
            "artifact filename must be a basename"
        );
    }
    if let Some(digest) = evidence.artifact_sha256.as_deref() {
        validate_sha256(digest, "artifact_sha256")?;
    }
    if let Some(integrity) = evidence.upstream_integrity.as_deref() {
        validate_text(integrity, "upstream_integrity", 2048)?;
    }
    if let Some(score) = evidence.score.as_deref() {
        validate_decimal_string(score, "score", 128)?;
    }
    if evidence.findings.len() > 256 {
        bail!("too many ledger findings");
    }
    for finding in &evidence.findings {
        validate_source(&finding.source)?;
        validate_text(&finding.id, "finding ID", 256)?;
        ensure!(finding.aliases.len() <= 128, "too many finding aliases");
        for alias in &finding.aliases {
            validate_text(alias, "finding alias", 256)?;
        }
        if let Some(score) = finding.score.as_deref() {
            validate_decimal_string(score, "finding score", 128)?;
        }
    }
    if evidence.scanner_findings.len() > 256 {
        bail!("too many scanner findings");
    }
    for finding in &evidence.scanner_findings {
        validate_scanner_source(&finding.source)?;
        if finding.rules.len() > 128 {
            bail!("too many scanner finding rules");
        }
        for rule in &finding.rules {
            validate_text(rule, "scanner finding rule", 256)?;
        }
        validate_text(&finding.summary, "scanner finding summary", 4096)?;
        if let Some(score) = finding.score.as_deref() {
            validate_decimal_string(score, "scanner finding score", 128)?;
        }
    }
    if evidence.engine_reports.len() > 32 {
        bail!("too many engine reports");
    }
    for report in &evidence.engine_reports {
        report.validate()?;
        ensure!(
            report
                .findings
                .iter()
                .all(|finding| finding.location.is_none()),
            "ledger engine findings cannot include local locations"
        );
    }
    if let Some(digest) = evidence.source_digest.as_deref() {
        validate_sha256(digest, "source_digest")?;
    }
    if let Some(metadata) = evidence.metadata.as_ref() {
        validate_text(&metadata.schema, "metadata schema", 64)?;
        ensure!(
            REGISTERED_METADATA_SCHEMAS.contains(&metadata.schema.as_str()),
            "unsupported registry metadata schema"
        );
        validate_sha256(&metadata.sha256, "metadata sha256")?;
    }
    Ok(())
}

fn require_package(identity: &LedgerIdentity) -> Result<()> {
    ensure!(
        identity.ecosystem.is_some() && identity.name.is_some() && identity.version.is_some(),
        "event requires canonical package identity"
    );
    Ok(())
}

fn validate_code(value: &str, field: &str) -> Result<()> {
    validate_text(value, field, 128)?;
    ensure!(
        value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        }),
        "{field} must be a lowercase code"
    );
    Ok(())
}

fn validate_native_severity(value: &str) -> Result<()> {
    validate_text(value, "native severity", 128)?;
    ensure!(
        value
            .bytes()
            .all(|byte| { byte.is_ascii_alphanumeric() || b"._-".contains(&byte) }),
        "native severity must be a code"
    );
    Ok(())
}

fn validate_decimal_string(value: &str, field: &str, limit: usize) -> Result<()> {
    validate_text(value, field, limit)?;
    ensure!(
        value.parse::<rust_decimal::Decimal>().is_ok(),
        "{field} must be a decimal string"
    );
    Ok(())
}

fn validate_sha256(value: &str, field: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{field} must be a lowercase SHA-256 hex digest"
    );
    Ok(())
}

fn validate_text(value: &str, field: &str, limit: usize) -> Result<()> {
    ensure!(!value.is_empty(), "{field} must not be empty");
    ensure!(value.len() <= limit, "{field} exceeds size limit");
    ensure!(
        !value.chars().any(char::is_control),
        "{field} must not contain control characters"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    fn discovered(mut identity: LedgerIdentity) -> Result<LedgerEvent> {
        if identity.observation_id.is_none() {
            identity.observation_id = Some("test-observation".to_string());
        }
        LedgerEvent::new(
            "npm",
            identity,
            None,
            LedgerEventDetails::Discovered(DiscoveredBody {
                evidence: PackageEvidence {
                    source_kind: Some(LedgerSourceKind::Registry),
                    ..PackageEvidence::default()
                },
            }),
        )
    }
    #[test]
    fn scanner_evidence_rejects_unregistered_sources() {
        let evidence = PackageEvidence {
            scanner_findings: vec![ScannerFinding {
                source: "attacker-controlled".to_string(),
                rules: vec![],
                summary: "unexpected scanner source".to_string(),
                score: None,
                scan_incomplete: false,
                detected_at: Utc::now(),
            }],
            ..PackageEvidence::default()
        };

        assert!(validate_evidence(&evidence).is_err());
    }
    #[test]
    fn coverage_engine_evidence_rejects_local_locations() -> Result<()> {
        let report = EngineReport {
            source: "guarddog".to_string(),
            version: Some("3.2.0".to_string()),
            rule_bundle_sha256: Some("b".repeat(64)),
            database_sha256: None,
            input_sha256: Some("a".repeat(64)),
            expected_inputs: 1,
            processed_inputs: 1,
            coverage: Coverage::Complete,
            findings: vec![EngineFinding {
                id: engine_finding_id("guarddog", "rule", "package/file.js", "line:1")?,
                rule: "rule".to_string(),
                summary: "suspicious content".to_string(),
                location: Some("package/file.js".to_string()),
                native_severity: None,
                policy_score: None,
            }],
            reason: None,
        };
        let evidence = PackageEvidence {
            engine_reports: vec![report],
            ..PackageEvidence::default()
        };

        assert!(validate_evidence(&evidence).is_err());
        Ok(())
    }

    #[test]
    fn complete_engine_report_requires_version() {
        let report = EngineReport {
            source: "guarddog".to_string(),
            version: None,
            rule_bundle_sha256: Some("b".repeat(64)),
            database_sha256: None,
            input_sha256: Some("a".repeat(64)),
            expected_inputs: 1,
            processed_inputs: 1,
            coverage: Coverage::Complete,
            findings: Vec::new(),
            reason: None,
        };

        assert!(report.validate().is_err());
    }

    #[test]
    fn complete_engine_report_requires_rule_bundle_digest() {
        let report = EngineReport {
            source: "guarddog".to_string(),
            version: Some("3.2.0".to_string()),
            rule_bundle_sha256: None,
            database_sha256: None,
            input_sha256: Some("a".repeat(64)),
            expected_inputs: 1,
            processed_inputs: 1,
            coverage: Coverage::Complete,
            findings: Vec::new(),
            reason: None,
        };

        assert!(report.validate().is_err());
    }

    #[test]
    fn engine_policy_revision_and_cache_key_bind_all_inputs() -> Result<()> {
        let artifact_sha256 = "a".repeat(64);
        let policy_sha256 = "b".repeat(64);
        let report = EngineReport {
            source: "guarddog".to_string(),
            version: Some("3.2.0".to_string()),
            rule_bundle_sha256: Some("c".repeat(64)),
            database_sha256: Some("d".repeat(64)),
            input_sha256: Some(artifact_sha256.clone()),
            expected_inputs: 1,
            processed_inputs: 1,
            coverage: Coverage::Complete,
            findings: Vec::new(),
            reason: None,
        };
        let reports = vec![report.clone()];
        let revision = engine_policy_revision_sha256(&["guarddog"], &reports)?;
        let cache_key = scan_cache_key_sha256(&artifact_sha256, &policy_sha256, &revision)?;

        let mut changed = reports.clone();
        changed[0].version = Some("3.2.1".to_string());
        assert_ne!(
            revision,
            engine_policy_revision_sha256(&["guarddog"], &changed)?
        );
        changed[0] = report.clone();
        changed[0].rule_bundle_sha256 = Some("e".repeat(64));
        assert_ne!(
            revision,
            engine_policy_revision_sha256(&["guarddog"], &changed)?
        );
        changed[0] = report.clone();
        changed[0].database_sha256 = Some("f".repeat(64));
        assert_ne!(
            revision,
            engine_policy_revision_sha256(&["guarddog"], &changed)?
        );
        assert_ne!(
            revision,
            engine_policy_revision_sha256(&["guarddog", "ossgadget"], &reports)?
        );
        assert_ne!(
            cache_key,
            scan_cache_key_sha256(&"e".repeat(64), &policy_sha256, &revision)?
        );
        assert_ne!(
            cache_key,
            scan_cache_key_sha256(&artifact_sha256, &"f".repeat(64), &revision)?
        );
        assert_ne!(
            cache_key,
            scan_cache_key_sha256(
                &artifact_sha256,
                &policy_sha256,
                &engine_policy_revision_sha256(&["guarddog"], &changed)?
            )?
        );
        Ok(())
    }
    #[test]
    fn coverage_engine_report_validates_inventory_and_keeps_findings() -> Result<()> {
        let finding = EngineFinding {
            id: engine_finding_id("guarddog", "script-rule", "package/a.js", "loc:1")?,
            rule: "script-rule".to_string(),
            summary: "suspicious script pattern".to_string(),
            location: None,
            native_severity: Some("medium".to_string()),
            policy_score: Some(rust_decimal::Decimal::new(75, 1)),
        };
        let report = EngineReport {
            source: "guarddog".to_string(),
            version: Some("3.2.0".to_string()),
            rule_bundle_sha256: Some("b".repeat(64)),
            database_sha256: None,
            input_sha256: Some("a".repeat(64)),
            expected_inputs: 2,
            processed_inputs: 2,
            coverage: Coverage::Complete,
            findings: vec![finding.clone()],
            reason: None,
        };

        report.validate()?;
        let incomplete = EngineReport {
            processed_inputs: 1,
            coverage: Coverage::Partial,
            reason: Some("input_skipped".to_string()),
            ..report.clone()
        };
        incomplete.validate()?;
        assert_eq!(incomplete.findings, vec![finding]);
        assert!(EngineReport {
            processed_inputs: 1,
            ..report.clone()
        }
        .validate()
        .is_err());
        let artifact_sha256 = "b".repeat(64);
        let policy_sha256 = "c".repeat(64);
        let engine_revision =
            engine_policy_revision_sha256(&["guarddog"], std::slice::from_ref(&report))?;
        let cache_key = scan_cache_key_sha256(&artifact_sha256, &policy_sha256, &engine_revision)?;
        let review = ArtifactReport {
            artifact_sha256: Some(artifact_sha256),
            policy_sha256: Some(policy_sha256),
            engine_policy_revision_sha256: Some(engine_revision),
            cache_key_sha256: Some(cache_key),
            coverage: Coverage::Complete,
            decision: ScanDecision::Review,
            engines: vec![report.clone()],
            reason: None,
        };
        review.validate()?;
        let mut tampered = review.clone();
        tampered.cache_key_sha256 = Some("e".repeat(64));
        assert!(tampered.validate().is_err());
        assert_eq!(serde_json::to_value(ScanDecision::Review)?, json!("review"));

        let blocked = ArtifactReport {
            coverage: Coverage::Partial,
            decision: ScanDecision::Block,
            engines: vec![incomplete.clone()],
            reason: Some("engine_failed".to_string()),
            ..review
        };
        blocked.validate()?;
        Ok(())
    }

    #[test]
    fn pass_decision_allows_findings_below_review_policy_threshold() -> Result<()> {
        let report = ArtifactReport {
            artifact_sha256: Some("a".repeat(64)),
            policy_sha256: Some("b".repeat(64)),
            engine_policy_revision_sha256: None,
            cache_key_sha256: None,
            coverage: Coverage::Complete,
            decision: ScanDecision::Pass,
            engines: vec![EngineReport {
                source: "guarddog".to_string(),
                version: Some("3.2.0".to_string()),
                rule_bundle_sha256: Some("c".repeat(64)),
                database_sha256: None,
                input_sha256: Some("a".repeat(64)),
                expected_inputs: 1,
                processed_inputs: 1,
                coverage: Coverage::Complete,
                findings: vec![EngineFinding {
                    id: engine_finding_id("guarddog", "low-rule", "package", "content")?,
                    rule: "low-rule".to_string(),
                    summary: "low-level observation".to_string(),
                    location: None,
                    native_severity: None,
                    policy_score: Some(rust_decimal::Decimal::new(4, 1)),
                }],
                reason: None,
            }],
            reason: None,
        };

        report.validate()
    }

    #[test]
    fn engine_finding_id_binds_occurrence_location() -> Result<()> {
        let first = engine_finding_id("guarddog", "rule", "package/a.js", "loc:1")?;
        assert_eq!(
            first,
            engine_finding_id("guarddog", "rule", "package/a.js", "loc:1")?
        );
        assert_ne!(
            first,
            engine_finding_id("guarddog", "rule", "package/a.js", "loc:2")?
        );
        assert_ne!(
            first,
            engine_finding_id("guarddog", "rule", "package/b.js", "loc:1")?
        );
        Ok(())
    }

    #[test]
    fn event_id_hashes_jcs_identity_with_explicit_nulls() -> Result<()> {
        let identity = LedgerIdentity {
            ecosystem: Some(Ecosystem::Npm),
            name: Some("lodash".to_string()),
            version: Some("4.17.21".to_string()),
            ..LedgerIdentity::default()
        };
        let identity_json = serde_json::to_value(&identity)?;
        assert_eq!(identity_json["observation_id"], serde_json::Value::Null);
        assert_eq!(identity_json["stage"], serde_json::Value::Null);
        assert_eq!(identity_json["artifact_identity"], serde_json::Value::Null);
        assert_eq!(identity_json["generation"], serde_json::Value::Null);
        assert_eq!(
            identity_json["engine_policy_revision"],
            serde_json::Value::Null
        );

        let fields = json!({
            "kind": "discovered",
            "source": "npm",
            "observation_id": null,
            "stage": null,
            "ecosystem": "Npm",
            "name": "lodash",
            "version": "4.17.21",
            "artifact_identity": null,
            "generation": null,
            "engine_policy_revision": null
        });
        let expected = hex::encode(Sha256::digest(serde_json_canonicalizer::to_vec(&fields)?));
        assert_eq!(
            derive_event_id(&LedgerEventKind::Discovered, "npm", &identity)?,
            expected
        );
        Ok(())
    }
    #[test]
    fn event_id_changes_when_any_identity_component_changes() -> Result<()> {
        let identity = LedgerIdentity {
            observation_id: Some("revision-1".to_string()),
            stage: Some("discovery".to_string()),
            ecosystem: Some(Ecosystem::Npm),
            name: Some("lodash".to_string()),
            version: Some("4.17.21".to_string()),
            artifact_identity: Some("lodash-4.17.21.tgz".to_string()),
            generation: Some("1".to_string()),
            engine_policy_revision: Some("a".repeat(64)),
        };
        let original = derive_event_id(&LedgerEventKind::Discovered, "npm", &identity)?;

        let mut changed = identity.clone();
        changed.observation_id = Some("revision-2".to_string());
        assert_ne!(
            original,
            derive_event_id(&LedgerEventKind::Discovered, "npm", &changed)?
        );
        let mut changed = identity.clone();
        changed.stage = Some("scan".to_string());
        assert_ne!(
            original,
            derive_event_id(&LedgerEventKind::Discovered, "npm", &changed)?
        );
        let mut changed = identity.clone();
        changed.ecosystem = Some(Ecosystem::PyPi);
        assert_ne!(
            original,
            derive_event_id(&LedgerEventKind::Discovered, "npm", &changed)?
        );
        let mut changed = identity.clone();
        changed.name = Some("express".to_string());
        assert_ne!(
            original,
            derive_event_id(&LedgerEventKind::Discovered, "npm", &changed)?
        );
        let mut changed = identity.clone();
        changed.version = Some("4.17.20".to_string());
        assert_ne!(
            original,
            derive_event_id(&LedgerEventKind::Discovered, "npm", &changed)?
        );
        let mut changed = identity.clone();
        changed.artifact_identity = Some("lodash-4.17.21-copy.tgz".to_string());
        assert_ne!(
            original,
            derive_event_id(&LedgerEventKind::Discovered, "npm", &changed)?
        );
        let mut changed = identity.clone();
        changed.generation = Some("2".to_string());
        assert_ne!(
            original,
            derive_event_id(&LedgerEventKind::Discovered, "npm", &changed)?
        );
        let mut changed = identity;
        changed.engine_policy_revision = Some("b".repeat(64));
        assert_ne!(
            original,
            derive_event_id(&LedgerEventKind::Discovered, "npm", &changed)?
        );
        Ok(())
    }

    #[test]
    fn public_projection_excludes_event_id_and_private_sources() -> Result<()> {
        let mut event = discovered(LedgerIdentity {
            ecosystem: Some(Ecosystem::Npm),
            name: Some("lodash".to_string()),
            version: Some("4.17.21".to_string()),
            ..LedgerIdentity::default()
        })?;
        event.recorded_at =
            Some(DateTime::parse_from_rfc3339("2026-11-14T12:00:00Z")?.with_timezone(&Utc));
        let public = event.public_projection()?.to_jcs()?;
        let public: serde_json::Value = serde_json::from_slice(&public)?;
        assert!(public.get("event_id").is_none());
        assert!(public.get("privacy_nonce").is_none());

        event.source = "worker".to_string();
        event.event_id = derive_event_id(&event.kind, &event.source, &event.body.identity)?;
        assert!(event.public_projection().is_err());
        Ok(())
    }
    #[test]
    fn public_projection_exposes_only_allowlisted_package_fields() -> Result<()> {
        let mut event = LedgerEvent::new(
            "npm",
            LedgerIdentity {
                observation_id: Some("local-evaluation-12".to_string()),
                stage: Some("local-cli".to_string()),
                ecosystem: Some(Ecosystem::Npm),
                name: Some("lodash".to_string()),
                version: Some("4.17.21".to_string()),
                artifact_identity: Some("lodash-4.17.21.tgz".to_string()),
                generation: Some("12".to_string()),
                engine_policy_revision: Some("a".repeat(64)),
            },
            Some(DateTime::parse_from_rfc3339("2026-11-14T12:00:00Z")?.with_timezone(&Utc)),
            LedgerEventDetails::Discovered(DiscoveredBody {
                evidence: PackageEvidence {
                    source_kind: Some(LedgerSourceKind::Registry),
                    ..PackageEvidence::default()
                },
            }),
        )?;
        event.recorded_at =
            Some(DateTime::parse_from_rfc3339("2026-11-14T12:01:00Z")?.with_timezone(&Utc));

        let public: serde_json::Value =
            serde_json::from_slice(&event.public_projection()?.to_jcs()?)?;

        assert_eq!(public["name"], "lodash");
        assert_eq!(public["version"], "4.17.21");
        assert!(public.get("body").is_none());
        assert!(public.get("observation_id").is_none());
        assert!(public.get("event_id").is_none());
        assert!(!public.to_string().contains("local-evaluation-12"));
        Ok(())
    }

    #[test]
    fn public_projection_rejects_historical_provenance_with_public_source_label() -> Result<()> {
        let source_file_sha256 = "b".repeat(64);
        let mut event = LedgerEvent::new(
            "npm",
            LedgerIdentity {
                observation_id: Some(format!("{source_file_sha256}:1")),
                ..LedgerIdentity::default()
            },
            None,
            LedgerEventDetails::HistoricalObservation(HistoricalObservationBody {
                source_file_sha256,
                record_position: "1".to_string(),
                original_recorded_at: None,
                source_kind: LedgerSourceKind::Historical,
                record_sha256: None,
            }),
        )?;
        event.recorded_at =
            Some(DateTime::parse_from_rfc3339("2026-11-14T12:01:00Z")?.with_timezone(&Utc));

        assert!(event.public_projection().is_err());
        Ok(())
    }

    #[test]
    fn source_health_requires_an_observation_id() {
        let event = LedgerEvent::new(
            "npm",
            LedgerIdentity::default(),
            None,
            LedgerEventDetails::SourceHealth(SourceHealthBody {
                status: SourceHealthStatus::Healthy,
                cursor: None,
                generation: None,
                last_successful_poll: None,
                failure_code: None,
            }),
        );

        assert!(event.is_err());
    }

    #[test]
    fn scan_completion_requires_a_run_id() {
        let event = LedgerEvent::new(
            "static-heuristics",
            LedgerIdentity {
                ecosystem: Some(Ecosystem::Npm),
                name: Some("lodash".to_string()),
                version: Some("4.17.21".to_string()),
                generation: Some("1".to_string()),
                engine_policy_revision: Some("a".repeat(64)),
                ..LedgerIdentity::default()
            },
            None,
            LedgerEventDetails::ScanCompleted(ScanCompletedBody {
                evidence: PackageEvidence {
                    coverage: Some(Coverage::Partial),
                    source_kind: Some(LedgerSourceKind::Scanner),
                    ..PackageEvidence::default()
                },
            }),
        );

        assert!(event.is_err());
    }

    #[test]
    fn artifact_identity_rejects_https_userinfo() {
        let event = LedgerEvent::new(
            "npm",
            LedgerIdentity {
                observation_id: Some("release-1".to_string()),
                ecosystem: Some(Ecosystem::Npm),
                name: Some("lodash".to_string()),
                version: Some("4.17.21".to_string()),
                artifact_identity: Some(
                    "https://user:secret@registry.example.test/lodash.tgz".to_string(),
                ),
                ..LedgerIdentity::default()
            },
            None,
            LedgerEventDetails::Discovered(DiscoveredBody {
                evidence: PackageEvidence {
                    source_kind: Some(LedgerSourceKind::Registry),
                    ..PackageEvidence::default()
                },
            }),
        );

        assert!(event.is_err());
    }

    #[test]
    fn observation_id_rejects_repository_paths() {
        let event = LedgerEvent::new(
            "npm",
            LedgerIdentity {
                observation_id: Some("/Users/private/repository/run-1".to_string()),
                ecosystem: Some(Ecosystem::Npm),
                name: Some("lodash".to_string()),
                version: Some("4.17.21".to_string()),
                ..LedgerIdentity::default()
            },
            None,
            LedgerEventDetails::Discovered(DiscoveredBody {
                evidence: PackageEvidence {
                    source_kind: Some(LedgerSourceKind::Registry),
                    ..PackageEvidence::default()
                },
            }),
        );

        assert!(event.is_err());
    }

    #[test]
    fn deserialization_rejects_duplicate_wire_keys() -> Result<()> {
        let event = discovered(LedgerIdentity {
            ecosystem: Some(Ecosystem::Npm),
            name: Some("lodash".to_string()),
            version: Some("4.17.21".to_string()),
            ..LedgerIdentity::default()
        })?;
        let wire = serde_json::to_string(&event)?;
        let duplicate = wire.replacen(
            "\"schema\":\"supply-ledger.event.v1\"",
            "\"schema\":\"supply-ledger.event.v1\",\"schema\":\"supply-ledger.event.v1\"",
            1,
        );
        assert!(serde_json::from_str::<LedgerEvent>(&duplicate).is_err());
        Ok(())
    }
    #[test]
    fn rule_approval_event_kind_deserializes() {
        let event = serde_json::from_value::<LedgerEvent>(json!({
            "schema": LEDGER_EVENT_SCHEMA,
            "event_id": "a".repeat(64),
            "kind": "rule_approved",
            "recorded_at": null,
            "observed_at": null,
            "source": "operator",
            "body": {
                "identity": {
                    "observation_id": "approval-event-1",
                    "stage": "rule_approval",
                    "ecosystem": null,
                    "name": null,
                    "version": null,
                    "artifact_identity": "b".repeat(64),
                    "generation": null,
                    "engine_policy_revision": null
                },
                "details": {
                    "type": "rule_approved",
                    "data": {
                        "artifact_sha256": "b".repeat(64),
                        "finding_id": "c".repeat(64),
                        "policy_sha256": "d".repeat(64),
                        "expires_at": "2030-01-01T00:00:00Z",
                        "reason": "reviewed"
                    }
                }
            }
        }));
        assert!(event.is_ok(), "{event:?}");
    }
}
