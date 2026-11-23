use anyhow::{ensure, Result};
use regex::Regex;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::HashMap, fmt, str::FromStr};

pub const REDACTION_POLICY_VERSION: u32 = 1;
pub const MAX_FIELD_BYTES: usize = 8 * 1024;
pub const MAX_STDOUT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_STDERR_BYTES: usize = 1536 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RunId(pub [u8; 16]);

impl RunId {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl FromStr for RunId {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        ensure!(
            value.len() == 32,
            "run ID must contain exactly 32 hex digits"
        );
        ensure!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "run ID must use lowercase hexadecimal"
        );
        let bytes = hex::decode(value)?;
        let bytes: [u8; 16] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("run ID has an invalid length"))?;
        Ok(Self(bytes))
    }
}

impl Serialize for RunId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for RunId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Running,
    Complete,
    Incomplete,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ProcessExec,
    ProcessExit,
    FileOpen,
    FileWrite,
    FileDelete,
    NetworkConnect,
    NetworkSend,
    DnsQuery,
    Stdout,
    Stderr,
    OtherObserved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Succeeded,
    Failed,
    Denied,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Install,
    Import,
    Execute,
    Build,
}

impl Phase {
    pub const ALL: [Self; 4] = [Self::Install, Self::Import, Self::Execute, Self::Build];
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensor {
    SyscallTrace,
    ProcessOutput,
    GuestMonitor,
}

impl Sensor {
    pub const ALL: [Self; 3] = [Self::SyscallTrace, Self::ProcessOutput, Self::GuestMonitor];
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    Observed,
    Inferred,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    PermissionDenied,
    NetworkUnreachable,
    NotFound,
    Other,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    Complete,
    Partial,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageReason {
    KnownEventLoss,
    UnknownEventLoss,
    SourceLoss,
    UnsupportedEvent,
    EventLimit,
    JournalLimit,
    OutputTruncated,
    ProjectionTruncated,
    MissingPhase,
    MissingSensor,
    Recovery,
    StorageFailure,
    RedactionWithheld,
    ExplicitIncomplete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub state: CoverageState,
    pub reasons: Vec<CoverageReason>,
    pub event_loss_count: Option<u64>,
    pub source_loss_count: Option<u64>,
}

impl Coverage {
    pub fn unknown() -> Self {
        Self {
            state: CoverageState::Unknown,
            reasons: vec![CoverageReason::UnknownEventLoss],
            event_loss_count: None,
            source_loss_count: None,
        }
    }

    pub fn complete() -> Self {
        Self {
            state: CoverageState::Complete,
            reasons: Vec::new(),
            event_loss_count: Some(0),
            source_loss_count: Some(0),
        }
    }

    pub fn mark_partial(&mut self, reason: CoverageReason) {
        if self.state != CoverageState::Unknown {
            self.state = CoverageState::Partial;
        }
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }

    pub fn record_event_loss(&mut self, count: u64) {
        self.mark_partial(CoverageReason::KnownEventLoss);
        self.event_loss_count = Some(self.event_loss_count.unwrap_or(0).saturating_add(count));
    }

    pub fn record_unknown_event_loss(&mut self) {
        self.mark_partial(CoverageReason::UnknownEventLoss);
        self.event_loss_count = None;
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_generation: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentVariable {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrivateFields {
    ProcessExec {
        process: ProcessIdentity,
        executable: String,
        arguments: Vec<String>,
        cwd: Option<String>,
        environment: Vec<EnvironmentVariable>,
    },
    ProcessExit {
        process: ProcessIdentity,
        exit_code: Option<i32>,
    },
    FileOpen {
        process: Option<ProcessIdentity>,
        path: String,
        flags: Option<String>,
    },
    FileWrite {
        process: Option<ProcessIdentity>,
        path: String,
        bytes: u64,
    },
    FileDelete {
        process: Option<ProcessIdentity>,
        path: String,
    },
    NetworkConnect {
        process: Option<ProcessIdentity>,
        host: String,
        port: u16,
    },
    NetworkSend {
        process: Option<ProcessIdentity>,
        host: String,
        port: u16,
        bytes: u64,
    },
    DnsQuery {
        process: Option<ProcessIdentity>,
        query: String,
    },
    Stdout {
        bytes: Vec<u8>,
    },
    Stderr {
        bytes: Vec<u8>,
    },
    OtherObserved {
        payload: serde_json::Value,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedEvent {
    pub run_id: RunId,
    pub seq: u64,
    pub offset_ns: Option<u64>,
    pub source_seq: Option<u64>,
    pub phase: Phase,
    pub sensor: Sensor,
    pub observation: ObservationKind,
    pub kind: EventKind,
    pub outcome: Outcome,
    pub failure: Option<FailureKind>,
    pub private_fields: PrivateFields,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunProvenance {
    pub artifact_sha256: [u8; 32],
    pub static_scan_event_id: Option<String>,
    pub public_bundle_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WithheldReason {
    BinaryContent,
    InvalidUtf8,
    Overlong,
    UnsupportedEvent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicRun {
    pub run_id: RunId,
    pub state: RunState,
    pub coverage: Coverage,
    pub phases: Vec<Phase>,
    pub event_count: u64,
    pub public_bundle_sha256: String,
    pub redaction_policy_version: u32,
    pub automatic_redaction_limitation: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicEvent {
    pub run_id: RunId,
    pub seq: u64,
    pub offset_ms: Option<u64>,
    pub phase: Phase,
    pub sensor: Sensor,
    pub observation: ObservationKind,
    pub kind: EventKind,
    pub outcome: Outcome,
    pub failure: Option<FailureKind>,
    pub actor: Option<String>,
    pub target: Option<String>,
    pub details: Vec<String>,
    pub text: Option<String>,
    pub redacted_fields: Vec<String>,
    pub withheld_reason: Option<WithheldReason>,
    pub coverage: CoverageState,
    pub automatic_redaction_limitation: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ProcessKey {
    pid: u32,
    start_generation: u64,
}

#[derive(Clone, Debug)]
pub struct RunLabels {
    run_id: RunId,
    processes: HashMap<ProcessKey, String>,
    files: HashMap<String, String>,
    next_process: u64,
    next_file: u64,
}

impl RunLabels {
    pub fn new(run_id: RunId) -> Self {
        Self {
            run_id,
            processes: HashMap::new(),
            files: HashMap::new(),
            next_process: 1,
            next_file: 1,
        }
    }

    pub fn process_label(&mut self, process: &ProcessIdentity) -> String {
        let key = ProcessKey {
            pid: process.pid,
            start_generation: process.start_generation,
        };
        if let Some(label) = self.processes.get(&key) {
            return label.clone();
        }
        let label = format!("P{}", self.next_process);
        self.next_process = self.next_process.saturating_add(1);
        self.processes.insert(key, label.clone());
        label
    }

    pub fn file_label(&mut self, path: &str) -> String {
        if let Some(label) = self.files.get(path) {
            return label.clone();
        }
        let label = format!("F{}", self.next_file);
        self.next_file = self.next_file.saturating_add(1);
        self.files.insert(path.to_string(), label.clone());
        label
    }

    pub fn run_id(&self) -> RunId {
        self.run_id
    }
}

#[derive(Clone)]
struct RedactionRule {
    regex: Regex,
    replacement: &'static str,
    marker: &'static str,
}

#[derive(Clone)]
pub struct Redactor {
    rules: Vec<RedactionRule>,
    terminal_escape: Regex,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactionResult {
    pub text: Option<String>,
    pub redacted_fields: Vec<String>,
    pub withheld_reason: Option<WithheldReason>,
    pub truncated: bool,
}

pub struct RedactionStream {
    redactor: Redactor,
    field: String,
    limit: usize,
    bytes: Vec<u8>,
    truncated: bool,
}

impl Redactor {
    pub fn new() -> Result<Self> {
        let definitions = [
            (
                r"(?i)[A-Za-z][A-Za-z0-9+.-]*://(?P<secret>[^/\s?#@]+@)",
                "",
                "url_userinfo",
            ),
            (
                r"(?i)\bauthorization\s*:\s*(?:bearer|basic)\s+(?P<secret>[A-Za-z0-9._~+/=-]+)",
                "[REDACTED]",
                "authorization_token",
            ),
            (
                r"(?i)\bauthorization\s*=\s*(?:bearer\s+|basic\s+)?(?P<secret>[^,\s;]+)",
                "[REDACTED]",
                "authorization_token",
            ),
            (
                concat!(
                    r"(?i)(?:\b|_)(?:api[_-]?(?:key|token)|access[_-]?(?:token|key)|",
                    r"refresh[_-]?token|auth[_-]?token|token|secret[_-]?key|secret|",
                    r"password|passwd|credential|client[_-]?secret|private[_-]?key|",
                    r"aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key)\b",
                    r#"\s*[:=]\s*["']?(?P<secret>[^"'\s,;]+)"#
                ),
                "[REDACTED]",
                "credential_value",
            ),
            (
                r"\b(?P<secret>AKIA[0-9A-Z]{16})\b",
                "[REDACTED]",
                "aws_access_key",
            ),
            (
                r"\b(?P<secret>gh[pousr]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{12,})\b",
                "[REDACTED]",
                "github_token",
            ),
            (
                r"\b(?P<secret>eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b",
                "[REDACTED]",
                "jwt",
            ),
            (
                r"(?s)(?P<secret>-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)",
                "[REDACTED]",
                "private_key",
            ),
            (
                r"(?:/Users/|/home/)(?P<secret>[^/\s]+)",
                "[REDACTED]",
                "home_directory",
            ),
        ];
        let rules = definitions
            .into_iter()
            .map(|(pattern, replacement, marker)| {
                Ok(RedactionRule {
                    regex: Regex::new(pattern)?,
                    replacement,
                    marker,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            rules,
            terminal_escape: Regex::new(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")?,
        })
    }

    pub fn version(&self) -> u32 {
        REDACTION_POLICY_VERSION
    }

    pub fn redact_text(&self, text: &str, field: &str) -> RedactionResult {
        if text.len() > MAX_FIELD_BYTES {
            return withheld(field, WithheldReason::Overlong);
        }
        if text.contains('\0') {
            return withheld(field, WithheldReason::BinaryContent);
        }
        self.redact_valid_text(text, field, MAX_FIELD_BYTES, false)
    }

    pub fn redact_bytes(&self, bytes: &[u8], field: &str, max_bytes: usize) -> RedactionResult {
        let truncated = bytes.len() > max_bytes;
        let bounded = &bytes[..bytes.len().min(max_bytes)];
        if bounded.contains(&0) {
            return withheld_with_truncation(field, WithheldReason::BinaryContent, truncated);
        }
        let Ok(text) = std::str::from_utf8(bounded) else {
            return withheld_with_truncation(field, WithheldReason::InvalidUtf8, truncated);
        };
        self.redact_valid_text(text, field, max_bytes, truncated)
    }

    pub fn stream(&self, field: impl Into<String>, max_bytes: usize) -> RedactionStream {
        RedactionStream {
            redactor: self.clone(),
            field: field.into(),
            limit: max_bytes,
            bytes: Vec::new(),
            truncated: false,
        }
    }

    fn redact_valid_text(
        &self,
        text: &str,
        field: &str,
        max_bytes: usize,
        truncated: bool,
    ) -> RedactionResult {
        redact_valid_text_mapped(self, text, field, max_bytes, truncated, Vec::new()).0
    }

    pub fn redact_chunks(
        &self,
        chunks: &[&[u8]],
        field: &str,
        max_bytes: usize,
    ) -> Vec<RedactionResult> {
        if chunks.is_empty() {
            return Vec::new();
        }
        let size_hint = chunks
            .iter()
            .fold(0usize, |total, chunk| total.saturating_add(chunk.len()));
        let mut input = Vec::with_capacity(max_bytes.min(size_hint));
        let mut boundaries = Vec::with_capacity(chunks.len() + 1);
        let mut truncated = false;
        boundaries.push(0);
        for chunk in chunks {
            let remaining = max_bytes.saturating_sub(input.len());
            let count = remaining.min(chunk.len());
            input.extend_from_slice(&chunk[..count]);
            truncated |= count < chunk.len();
            boundaries.push(input.len());
        }
        if input.contains(&0) {
            return withheld_chunks(
                chunks.len(),
                field,
                WithheldReason::BinaryContent,
                truncated,
            );
        }
        let Ok(text) = std::str::from_utf8(&input) else {
            return withheld_chunks(chunks.len(), field, WithheldReason::InvalidUtf8, truncated);
        };
        let (result, offsets) =
            redact_valid_text_mapped(self, text, field, max_bytes, truncated, boundaries);
        let Some(redacted) = result.text.as_deref() else {
            return withheld_chunks(
                chunks.len(),
                field,
                result
                    .withheld_reason
                    .unwrap_or(WithheldReason::InvalidUtf8),
                result.truncated,
            );
        };
        let mut results = Vec::with_capacity(chunks.len());
        let mut previous = 0;
        for index in 0..chunks.len() {
            let start = char_boundary_up(redacted, offsets[index].min(redacted.len()));
            let end = char_boundary_up(redacted, offsets[index + 1].min(redacted.len()));
            let start = start.max(previous).min(redacted.len());
            let end = end.max(start).min(redacted.len());
            let mut chunk_result = RedactionResult {
                text: Some(redacted[start..end].to_string()),
                redacted_fields: if index == 0 {
                    result.redacted_fields.clone()
                } else {
                    Vec::new()
                },
                withheld_reason: None,
                truncated: false,
            };
            if index + 1 == chunks.len() && result.truncated {
                chunk_result.truncated = true;
                chunk_result
                    .redacted_fields
                    .push(format!("{field}:truncated"));
            }
            previous = end;
            results.push(chunk_result);
        }
        results
    }
}
fn redact_valid_text_mapped(
    redactor: &Redactor,
    text: &str,
    field: &str,
    max_bytes: usize,
    mut truncated: bool,
    mut offsets: Vec<usize>,
) -> (RedactionResult, Vec<usize>) {
    let mut current = text.to_string();
    let mut markers = Vec::new();
    for rule in &redactor.rules {
        let ranges = rule
            .regex
            .captures_iter(&current)
            .filter_map(|captures| captures.name("secret"))
            .map(|secret| (secret.start(), secret.end()))
            .collect::<Vec<_>>();
        if !ranges.is_empty() {
            current = replace_ranges(&current, &ranges, rule.replacement, &mut offsets);
            markers.push(format!("{field}:{}", rule.marker));
        }
    }
    let terminal_ranges = redactor
        .terminal_escape
        .find_iter(&current)
        .map(|matched| (matched.start(), matched.end()))
        .collect::<Vec<_>>();
    if !terminal_ranges.is_empty() {
        current = replace_ranges(&current, &terminal_ranges, "", &mut offsets);
        markers.push(format!("{field}:terminal_control"));
    }
    let control_ranges = current
        .char_indices()
        .filter_map(|(start, character)| {
            (is_bidi_format(character)
                || (character.is_control() && !matches!(character, '\n' | '\r' | '\t')))
            .then_some((start, start + character.len_utf8()))
        })
        .collect::<Vec<_>>();
    if !control_ranges.is_empty() {
        current = replace_ranges(&current, &control_ranges, "", &mut offsets);
        markers.push(format!("{field}:terminal_control"));
    }
    let mut max_bytes = max_bytes.min(current.len());
    while !current.is_char_boundary(max_bytes) {
        max_bytes -= 1;
    }
    if max_bytes < current.len() {
        current.truncate(max_bytes);
        truncated = true;
    }
    for offset in &mut offsets {
        *offset = char_boundary_up(&current, (*offset).min(current.len()));
    }
    if truncated {
        markers.push(format!("{field}:truncated"));
    }
    (
        RedactionResult {
            text: Some(current),
            redacted_fields: markers,
            withheld_reason: None,
            truncated,
        },
        offsets,
    )
}

fn replace_ranges(
    input: &str,
    ranges: &[(usize, usize)],
    replacement: &str,
    offsets: &mut [usize],
) -> String {
    for offset in offsets.iter_mut() {
        *offset = map_range_position(*offset, ranges, replacement.len());
    }
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    for &(start, end) in ranges {
        if start < cursor || end < start || end > input.len() {
            continue;
        }
        output.push_str(&input[cursor..start]);
        output.push_str(replacement);
        cursor = end;
    }
    output.push_str(&input[cursor..]);
    output
}

fn map_range_position(position: usize, ranges: &[(usize, usize)], replacement_len: usize) -> usize {
    let mut output_position = 0;
    let mut cursor = 0;
    for &(start, end) in ranges {
        if start < cursor || end < start {
            continue;
        }
        if position <= start {
            return output_position + position.saturating_sub(cursor);
        }
        output_position += start - cursor;
        let replacement_start = output_position;
        output_position += replacement_len;
        if position < end {
            return replacement_start;
        }
        if position == end {
            return output_position;
        }
        cursor = end;
    }
    output_position + position.saturating_sub(cursor)
}

fn char_boundary_up(text: &str, position: usize) -> usize {
    let mut boundary = position.min(text.len());
    while !text.is_char_boundary(boundary) {
        boundary += 1;
    }
    boundary
}

impl RedactionStream {
    pub fn push(&mut self, chunk: &[u8]) {
        let remaining = self.limit.saturating_sub(self.bytes.len());
        let count = remaining.min(chunk.len());
        self.bytes.extend_from_slice(&chunk[..count]);
        self.truncated |= count < chunk.len();
    }

    pub fn finish(self) -> RedactionResult {
        let mut result = self
            .redactor
            .redact_bytes(&self.bytes, &self.field, self.limit);
        if self.truncated && !result.truncated {
            result.truncated = true;
            result
                .redacted_fields
                .push(format!("{}:truncated", self.field));
        }
        result
    }
}

fn withheld_chunks(
    count: usize,
    field: &str,
    reason: WithheldReason,
    truncated: bool,
) -> Vec<RedactionResult> {
    (0..count)
        .map(|index| {
            let mut result =
                withheld_with_truncation(field, reason, truncated && index + 1 == count);
            if index > 0 {
                result
                    .redacted_fields
                    .retain(|marker| marker == &format!("{field}:truncated"));
            }
            result
        })
        .collect()
}

fn withheld(field: &str, reason: WithheldReason) -> RedactionResult {
    withheld_with_truncation(field, reason, false)
}

fn withheld_with_truncation(
    field: &str,
    reason: WithheldReason,
    truncated: bool,
) -> RedactionResult {
    let mut redacted_fields = vec![format!("{field}:withheld")];
    if truncated {
        redacted_fields.push(format!("{field}:truncated"));
    }
    RedactionResult {
        text: None,
        redacted_fields,
        withheld_reason: Some(reason),
        truncated,
    }
}

fn is_bidi_format(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
    )
}

pub fn project_event(
    event: &ObservedEvent,
    labels: &mut RunLabels,
    redactor: &Redactor,
) -> Result<PublicEvent> {
    project_event_internal(event, labels, redactor, true)
}

pub fn project_event_without_output(
    event: &ObservedEvent,
    labels: &mut RunLabels,
    redactor: &Redactor,
) -> Result<PublicEvent> {
    project_event_internal(event, labels, redactor, false)
}

fn project_event_internal(
    event: &ObservedEvent,
    labels: &mut RunLabels,
    redactor: &Redactor,
    include_output: bool,
) -> Result<PublicEvent> {
    ensure!(
        event.run_id == labels.run_id(),
        "event run ID does not match labels"
    );
    ensure!(event.seq > 0, "event sequence must start at 1");
    ensure!(
        kind_matches(event.kind, &event.private_fields),
        "event kind does not match private fields"
    );

    let mut projected = PublicEvent {
        run_id: event.run_id,
        seq: event.seq,
        offset_ms: event.offset_ns.map(|offset| offset / 1_000_000),
        phase: event.phase,
        sensor: event.sensor,
        observation: event.observation,
        kind: event.kind,
        outcome: event.outcome,
        failure: event.failure,
        actor: None,
        target: None,
        details: Vec::new(),
        text: None,
        redacted_fields: Vec::new(),
        withheld_reason: None,
        coverage: CoverageState::Complete,
        automatic_redaction_limitation: true,
    };

    match &event.private_fields {
        PrivateFields::ProcessExec {
            process,
            executable,
            arguments,
            cwd,
            environment,
        } => {
            projected.actor = Some(labels.process_label(process));
            projected.target = Some(labels.file_label(executable));
            append_detail(&mut projected, redactor, "executable", executable);
            for (index, argument) in arguments.iter().enumerate() {
                append_detail(
                    &mut projected,
                    redactor,
                    &format!("arguments[{index}]"),
                    argument,
                );
            }
            if let Some(cwd) = cwd {
                append_detail(&mut projected, redactor, "cwd", cwd);
            }
            for variable in environment {
                let combined = format!("{}={}", variable.name, variable.value);
                append_detail(
                    &mut projected,
                    redactor,
                    &format!("environment[{}]", variable.name),
                    &combined,
                );
            }
        }
        PrivateFields::ProcessExit { process, exit_code } => {
            projected.actor = Some(labels.process_label(process));
            if let Some(code) = exit_code {
                projected.details.push(format!("exit_code={code}"));
            }
        }
        PrivateFields::FileOpen {
            process,
            path,
            flags,
        } => {
            set_file_event(&mut projected, labels, redactor, process.as_ref(), path);
            if let Some(flags) = flags {
                append_detail(&mut projected, redactor, "flags", flags);
            }
        }
        PrivateFields::FileWrite {
            process,
            path,
            bytes,
        } => {
            set_file_event(&mut projected, labels, redactor, process.as_ref(), path);
            projected.details.push(format!("bytes={bytes}"));
        }
        PrivateFields::FileDelete { process, path } => {
            set_file_event(&mut projected, labels, redactor, process.as_ref(), path);
        }
        PrivateFields::NetworkConnect {
            process,
            host,
            port,
        } => {
            set_process_actor(&mut projected, labels, process.as_ref());
            let target = format!("{host}:{port}");
            projected.target =
                append_redacted_detail(&mut projected, redactor, "network.target", &target);
        }
        PrivateFields::NetworkSend {
            process,
            host,
            port,
            bytes,
        } => {
            set_process_actor(&mut projected, labels, process.as_ref());
            let target = format!("{host}:{port}");
            projected.target =
                append_redacted_detail(&mut projected, redactor, "network.target", &target);
            projected.details.push(format!("bytes={bytes}"));
        }
        PrivateFields::DnsQuery { process, query } => {
            set_process_actor(&mut projected, labels, process.as_ref());
            projected.target = append_redacted_detail(&mut projected, redactor, "dns.query", query);
        }
        PrivateFields::Stdout { bytes } if include_output => {
            apply_stream_result(
                &mut projected,
                redactor.redact_bytes(bytes, "stdout", MAX_STDOUT_BYTES),
            );
        }
        PrivateFields::Stdout { .. } => {}
        PrivateFields::Stderr { bytes } if include_output => {
            apply_stream_result(
                &mut projected,
                redactor.redact_bytes(bytes, "stderr", MAX_STDERR_BYTES),
            );
        }
        PrivateFields::Stderr { .. } => {}
        PrivateFields::OtherObserved { .. } => {
            projected.coverage = CoverageState::Partial;
            projected.withheld_reason = Some(WithheldReason::UnsupportedEvent);
            projected
                .redacted_fields
                .push("private_fields:unsupported".to_string());
        }
    }
    Ok(projected)
}

fn set_file_event(
    projected: &mut PublicEvent,
    labels: &mut RunLabels,
    redactor: &Redactor,
    process: Option<&ProcessIdentity>,
    path: &str,
) {
    set_process_actor(projected, labels, process);
    projected.target = Some(labels.file_label(path));
    append_detail(projected, redactor, "file.path", path);
}

fn set_process_actor(
    projected: &mut PublicEvent,
    labels: &mut RunLabels,
    process: Option<&ProcessIdentity>,
) {
    projected.actor = process.map(|identity| labels.process_label(identity));
}

fn append_detail(projected: &mut PublicEvent, redactor: &Redactor, field: &str, value: &str) {
    if let Some(text) = append_redacted_detail(projected, redactor, field, value) {
        projected.details.push(text);
    }
}

fn append_redacted_detail(
    projected: &mut PublicEvent,
    redactor: &Redactor,
    field: &str,
    value: &str,
) -> Option<String> {
    let result = redactor.redact_text(value, field);
    projected.redacted_fields.extend(result.redacted_fields);
    if projected.withheld_reason.is_none() {
        projected.withheld_reason = result.withheld_reason;
    }
    if result.truncated {
        projected.coverage = CoverageState::Partial;
    }
    result.text
}

fn apply_stream_result(projected: &mut PublicEvent, result: RedactionResult) {
    projected.redacted_fields.extend(result.redacted_fields);
    projected.text = result.text;
    projected.withheld_reason = result.withheld_reason;
    if projected.withheld_reason.is_some() || result.truncated {
        projected.coverage = CoverageState::Partial;
    }
}

fn kind_matches(kind: EventKind, fields: &PrivateFields) -> bool {
    matches!(
        (kind, fields),
        (EventKind::ProcessExec, PrivateFields::ProcessExec { .. })
            | (EventKind::ProcessExit, PrivateFields::ProcessExit { .. })
            | (EventKind::FileOpen, PrivateFields::FileOpen { .. })
            | (EventKind::FileWrite, PrivateFields::FileWrite { .. })
            | (EventKind::FileDelete, PrivateFields::FileDelete { .. })
            | (
                EventKind::NetworkConnect,
                PrivateFields::NetworkConnect { .. }
            )
            | (EventKind::NetworkSend, PrivateFields::NetworkSend { .. })
            | (EventKind::DnsQuery, PrivateFields::DnsQuery { .. })
            | (EventKind::Stdout, PrivateFields::Stdout { .. })
            | (EventKind::Stderr, PrivateFields::Stderr { .. })
            | (
                EventKind::OtherObserved,
                PrivateFields::OtherObserved { .. }
            )
    )
}
