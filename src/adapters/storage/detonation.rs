use crate::application::detonation::{
    project_event, project_event_without_output, Coverage, CoverageReason, CoverageState,
    EventKind, ObservedEvent, Phase, PrivateFields, PublicEvent, PublicRun, Redactor, RunId,
    RunLabels, RunProvenance, RunState, Sensor, WithheldReason, REDACTION_POLICY_VERSION,
};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::unix::{
    fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    io::AsRawFd,
};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

const MIB: u64 = 1024 * 1024;
const RAW_RESERVATION_BYTES: u64 = 8 * MIB;
const PROJECTION_RESERVATION_BYTES: u64 = 8 * MIB;
const SCRATCH_RESERVATION_BYTES: u64 = 8 * MIB;
const CONTROL_RESERVATION_BYTES: u64 = MIB;
const RUN_RESERVATION_BYTES: u64 = 25 * MIB;
const JOURNAL_LIMIT_BYTES: u64 = 4 * MIB;
const JOURNAL_FRAME_LIMIT: usize = 4096;
const FRAME_LIMIT_BYTES: usize = 1024;
const FRAME_HEADER_BYTES: usize = 4;
const FRAME_DIGEST_BYTES: usize = 32;
const STDOUT_OFFSET: u64 = 4 * MIB;
const STDOUT_LIMIT_BYTES: u64 = 2 * MIB;
const STDERR_OFFSET: u64 = 6 * MIB;
const STDERR_LIMIT_BYTES: u64 = 1536 * 1024;
const CONTROL_SLOT_BYTES: u64 = 4096;
const MANIFEST_RECORD_OFFSET: u64 = 2 * CONTROL_SLOT_BYTES;
const CONTROL_RECORD_LIMIT: usize = 3500;
const MANIFEST_RECORD_LIMIT: usize = (CONTROL_RESERVATION_BYTES - MANIFEST_RECORD_OFFSET) as usize;
const DEFAULT_STORE_LIMIT_BYTES: u64 = 256 * MIB;
const IO_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct StoreConfig {
    pub max_store_bytes: u64,
    pub artifacts_dir: Option<PathBuf>,
    pub web_root: Option<PathBuf>,
    pub public_store: Option<PathBuf>,
    pub download_root: Option<PathBuf>,
    pub ledger_path: Option<PathBuf>,
    pub max_events: u64,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            max_store_bytes: DEFAULT_STORE_LIMIT_BYTES,
            artifacts_dir: None,
            web_root: None,
            public_store: None,
            download_root: None,
            ledger_path: None,
            max_events: JOURNAL_FRAME_LIMIT as u64,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunMetadata {
    pub ecosystem: Option<String>,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub vm_image_sha256: Option<[u8; 32]>,
    pub runner_version: Option<String>,
    pub monitor_version: Option<String>,
    pub policy_revision: Option<String>,
    pub started_at_unix_ms: u64,
    pub expected_phases: Vec<Phase>,
    pub required_sensors: Vec<Sensor>,
}

impl Default for RunMetadata {
    fn default() -> Self {
        Self {
            ecosystem: None,
            package_name: None,
            package_version: None,
            vm_image_sha256: None,
            runner_version: None,
            monitor_version: None,
            policy_revision: None,
            started_at_unix_ms: now_unix_ms(),
            expected_phases: Phase::ALL.to_vec(),
            required_sensors: Sensor::ALL.to_vec(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRef {
    pub name: String,
    pub sha256: String,
    pub byte_count: u64,
    pub source: String,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControlRecord {
    run_id: RunId,
    generation: u64,
    provenance: RunProvenance,
    metadata: RunMetadata,
    acknowledged_seq: u64,
    journal_bytes: u64,
    frame_count: u64,
    stdout_bytes: u64,
    stderr_bytes: u64,
    event_loss_count: Option<u64>,
    source_loss_count: Option<u64>,
    source_seq_by_sensor: [Option<u64>; 3],
    phase_mask: u8,
    sensor_mask: u8,
    partial: bool,
    unknown_loss: bool,
    stdout_truncated: bool,
    stderr_truncated: bool,
    event_limit: bool,
    journal_limit: bool,
    failed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunManifest {
    run_id: RunId,
    state: RunState,
    metadata: RunMetadata,
    provenance: RunProvenance,
    actual_phases: Vec<Phase>,
    acknowledged_sensors: Vec<Sensor>,
    event_count: u64,
    durable_seq: u64,
    journal_bytes: u64,
    stdout_bytes: u64,
    stderr_bytes: u64,
    public_bundle_bytes: u64,
    coverage: Coverage,
    objects: Vec<ObjectRef>,
    public_event_count: u64,
    redaction_policy_version: u32,
    ended_at_unix_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredFrame {
    event: ObservedEvent,
    output: Option<OutputReference>,
}
#[derive(Serialize)]
struct StoredFrameRef<'a> {
    event: StoredEventRef<'a>,
    output: Option<&'a OutputReference>,
}

#[derive(Serialize)]
struct StoredEventRef<'a> {
    run_id: RunId,
    seq: u64,
    offset_ns: Option<u64>,
    source_seq: Option<u64>,
    phase: Phase,
    sensor: Sensor,
    observation: crate::application::detonation::ObservationKind,
    kind: EventKind,
    outcome: crate::application::detonation::Outcome,
    failure: Option<crate::application::detonation::FailureKind>,
    private_fields: StoredPrivateFieldsRef<'a>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum StoredPrivateFieldsRef<'a> {
    ProcessExec {
        process: &'a crate::application::detonation::ProcessIdentity,
        executable: &'a str,
        arguments: &'a [String],
        cwd: Option<&'a str>,
        environment: &'a [crate::application::detonation::EnvironmentVariable],
    },
    ProcessExit {
        process: &'a crate::application::detonation::ProcessIdentity,
        exit_code: Option<i32>,
    },
    FileOpen {
        process: Option<&'a crate::application::detonation::ProcessIdentity>,
        path: &'a str,
        flags: Option<&'a str>,
    },
    FileWrite {
        process: Option<&'a crate::application::detonation::ProcessIdentity>,
        path: &'a str,
        bytes: u64,
    },
    FileDelete {
        process: Option<&'a crate::application::detonation::ProcessIdentity>,
        path: &'a str,
    },
    NetworkConnect {
        process: Option<&'a crate::application::detonation::ProcessIdentity>,
        host: &'a str,
        port: u16,
    },
    NetworkSend {
        process: Option<&'a crate::application::detonation::ProcessIdentity>,
        host: &'a str,
        port: u16,
        bytes: u64,
    },
    DnsQuery {
        process: Option<&'a crate::application::detonation::ProcessIdentity>,
        query: &'a str,
    },
    Stdout {
        bytes: &'a [u8],
    },
    Stderr {
        bytes: &'a [u8],
    },
    OtherObserved {
        payload: &'a serde_json::Value,
    },
}

impl<'a> StoredEventRef<'a> {
    fn new(event: &'a ObservedEvent) -> Self {
        Self {
            run_id: event.run_id,
            seq: event.seq,
            offset_ns: event.offset_ns,
            source_seq: event.source_seq,
            phase: event.phase,
            sensor: event.sensor,
            observation: event.observation,
            kind: event.kind,
            outcome: event.outcome,
            failure: event.failure,
            private_fields: StoredPrivateFieldsRef::new(&event.private_fields),
        }
    }
}

impl<'a> StoredPrivateFieldsRef<'a> {
    fn new(fields: &'a PrivateFields) -> Self {
        match fields {
            PrivateFields::ProcessExec {
                process,
                executable,
                arguments,
                cwd,
                environment,
            } => Self::ProcessExec {
                process,
                executable,
                arguments,
                cwd: cwd.as_deref(),
                environment,
            },
            PrivateFields::ProcessExit { process, exit_code } => Self::ProcessExit {
                process,
                exit_code: *exit_code,
            },
            PrivateFields::FileOpen {
                process,
                path,
                flags,
            } => Self::FileOpen {
                process: process.as_ref(),
                path,
                flags: flags.as_deref(),
            },
            PrivateFields::FileWrite {
                process,
                path,
                bytes,
            } => Self::FileWrite {
                process: process.as_ref(),
                path,
                bytes: *bytes,
            },
            PrivateFields::FileDelete { process, path } => Self::FileDelete {
                process: process.as_ref(),
                path,
            },
            PrivateFields::NetworkConnect {
                process,
                host,
                port,
            } => Self::NetworkConnect {
                process: process.as_ref(),
                host,
                port: *port,
            },
            PrivateFields::NetworkSend {
                process,
                host,
                port,
                bytes,
            } => Self::NetworkSend {
                process: process.as_ref(),
                host,
                port: *port,
                bytes: *bytes,
            },
            PrivateFields::DnsQuery { process, query } => Self::DnsQuery {
                process: process.as_ref(),
                query,
            },
            PrivateFields::Stdout { .. } => Self::Stdout { bytes: &[] },
            PrivateFields::Stderr { .. } => Self::Stderr { bytes: &[] },
            PrivateFields::OtherObserved { payload } => Self::OtherObserved { payload },
        }
    }
}

struct CappedFrameWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl std::io::Write for CappedFrameWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "journal frame limit exceeded",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode_frame(
    event: &ObservedEvent,
    output: Option<&OutputReference>,
) -> Result<Option<Vec<u8>>> {
    let frame = StoredFrameRef {
        event: StoredEventRef::new(event),
        output,
    };
    let limit = FRAME_LIMIT_BYTES - FRAME_HEADER_BYTES - FRAME_DIGEST_BYTES;
    let mut writer = CappedFrameWriter {
        bytes: Vec::with_capacity(limit),
        limit,
        exceeded: false,
    };
    if let Err(error) = serde_json::to_writer(&mut writer, &frame) {
        if writer.exceeded {
            return Ok(None);
        }
        return Err(error.into());
    }
    Ok(Some(writer.bytes))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OutputReference {
    stream: OutputStream,
    offset: u64,
    len: u64,
    truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedRun {
    pub run: PublicRun,
    pub events: Vec<PublicEvent>,
    pub provenance: RunProvenance,
    pub objects: Vec<ObjectRef>,
}

pub struct EvidenceStore {
    runs: PathBuf,
    lock_path: PathBuf,
    max_store_bytes: u64,
    ledger_path: Option<PathBuf>,
    max_events: u64,
}

pub struct RunWriter {
    run_dir: PathBuf,
    raw: File,
    projection: File,
    _scratch: File,
    control: File,
    record: ControlRecord,
    max_events: u64,
    failed: bool,
}

struct StoreLock(File);

impl EvidenceStore {
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        Self::with_config(root, StoreConfig::default())
    }

    pub fn with_config(root: impl AsRef<Path>, config: StoreConfig) -> Result<Self> {
        ensure!(
            config.max_events > 0 && config.max_events <= JOURNAL_FRAME_LIMIT as u64,
            "configured event cap must be between 1 and 4096"
        );
        let intended_root = canonicalize_allow_missing(root.as_ref())?;
        check_private_root(&intended_root, &config)?;
        create_directory_tree(root.as_ref())?;
        let root = root.as_ref().canonicalize()?;
        check_private_root(&root, &config)?;
        set_directory_mode(&root)?;
        let runs = root.join("runs");
        ensure_private_directory(&runs)?;
        let lock_path = root.join(".detonation-store.lock");
        open_or_create_lock(&lock_path)?;
        let ledger_path = config
            .ledger_path
            .map(|path| path.canonicalize())
            .transpose()?;
        Ok(Self {
            runs,
            lock_path,
            max_store_bytes: config.max_store_bytes,
            ledger_path,
            max_events: config.max_events,
        })
    }

    pub fn begin_run(&self, provenance: RunProvenance) -> Result<RunWriter> {
        self.begin_run_with_metadata(provenance, RunMetadata::default())
    }

    pub fn begin_run_with_metadata(
        &self,
        provenance: RunProvenance,
        mut metadata: RunMetadata,
    ) -> Result<RunWriter> {
        if metadata.started_at_unix_ms == 0 {
            metadata.started_at_unix_ms = now_unix_ms();
        }
        validate_run_inputs(&metadata, &provenance)?;
        if let Some(event_id) = provenance.static_scan_event_id.as_deref() {
            let ledger_path = self
                .ledger_path
                .as_deref()
                .context("a static scan reference requires a configured ledger path")?;
            verify_static_scan_reference(ledger_path, event_id, provenance.artifact_sha256)?;
        }
        let _lock = lock_store(&self.lock_path)?;
        let used = used_bytes(&self.runs)?;
        ensure!(
            used.checked_add(RUN_RESERVATION_BYTES)
                .is_some_and(|total| total <= self.max_store_bytes),
            "detonation evidence store quota exhausted"
        );

        let mut created = None;
        for _ in 0..16 {
            let run_id = RunId::generate()?;
            let run_dir = self.runs.join(run_id.to_string());
            match fs::create_dir(&run_dir) {
                Ok(()) => {
                    set_directory_mode(&run_dir)?;
                    created = Some((run_id, run_dir));
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        let (run_id, run_dir) = created
            .ok_or_else(|| anyhow::anyhow!("could not allocate a unique detonation run ID"))?;
        let raw = create_reserved_file(&run_dir.join("raw.reserve"), RAW_RESERVATION_BYTES)?;
        let projection = create_reserved_file(
            &run_dir.join("projection.reserve"),
            PROJECTION_RESERVATION_BYTES,
        )?;
        let scratch =
            create_reserved_file(&run_dir.join("scratch.reserve"), SCRATCH_RESERVATION_BYTES)?;
        let control =
            create_reserved_file(&run_dir.join("control.reserve"), CONTROL_RESERVATION_BYTES)?;
        sync_directory(&run_dir)?;
        sync_directory(&self.runs)?;
        let record = ControlRecord {
            run_id,
            generation: 0,
            provenance,
            metadata,
            acknowledged_seq: 0,
            journal_bytes: 0,
            frame_count: 0,
            stdout_bytes: 0,
            stderr_bytes: 0,
            event_loss_count: Some(0),
            source_loss_count: Some(0),
            source_seq_by_sensor: [None, None, None],
            phase_mask: 0,
            sensor_mask: 0,
            partial: false,
            unknown_loss: false,
            stdout_truncated: false,
            stderr_truncated: false,
            event_limit: false,
            journal_limit: false,
            failed: false,
        };
        let mut writer = RunWriter {
            run_dir,
            raw,
            projection,
            _scratch: scratch,
            control,
            record,
            max_events: self.max_events,
            failed: false,
        };
        writer.persist_control()?;
        Ok(writer)
    }

    pub fn used_bytes(&self) -> Result<u64> {
        used_bytes(&self.runs)
    }

    pub fn recover(root: &Path) -> Result<Vec<SealedRun>> {
        let canonical = root
            .canonicalize()
            .with_context(|| format!("evidence root does not exist: {}", root.display()))?;
        ensure!(
            fs::symlink_metadata(&canonical)?.mode() & 0o777 == 0o700,
            "evidence root must have mode 0700"
        );
        let runs = canonical.join("runs");
        ensure_plain_directory(&runs)?;
        ensure!(
            fs::symlink_metadata(&runs)?.mode() & 0o777 == 0o700,
            "evidence runs directory must have mode 0700"
        );
        let mut entries = fs::read_dir(&runs)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        let mut recovered = Vec::with_capacity(entries.len());
        for entry in entries {
            let metadata = fs::symlink_metadata(entry.path())?;
            ensure!(
                metadata.file_type().is_dir(),
                "run entry is not a plain directory"
            );
            ensure!(
                metadata.mode() & 0o777 == 0o700,
                "run directory must have mode 0700"
            );
            let run_id = RunId::from_str(
                entry
                    .file_name()
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("run directory name is not UTF-8"))?,
            )?;
            let run_dir = entry.path().canonicalize()?;
            ensure!(
                run_dir.starts_with(&runs),
                "run directory escapes evidence root"
            );
            let manifest_path = run_dir.join("manifest.json");
            if path_is_file(&manifest_path)? {
                recovered.push(read_sealed_run(run_id, &run_dir)?);
            } else {
                recovered.push(recover_incomplete(run_id, run_dir)?);
            }
        }
        Ok(recovered)
    }
}

impl RunWriter {
    pub fn run_id(&self) -> RunId {
        self.record.run_id
    }

    pub fn append(&mut self, event: &ObservedEvent) -> Result<()> {
        if self.failed {
            bail!("detonation run writer is failed");
        }
        if event.run_id != self.record.run_id
            || event.seq == 0
            || event.seq <= self.record.acknowledged_seq
        {
            self.fail_closed()?;
            bail!("event run ID or sequence conflicts with the active run");
        }
        if let Err(error) = validate_event(event) {
            self.fail_closed()?;
            return Err(error);
        }

        let mut next = self.record.clone();
        let expected_seq = next.acknowledged_seq.saturating_add(1);
        if event.seq > expected_seq {
            next.record_event_loss(event.seq - expected_seq);
        }
        if let Some(source_seq) = event.source_seq {
            let index = sensor_index(event.sensor);
            let previous = next.source_seq_by_sensor[index].unwrap_or(0);
            if source_seq <= previous {
                self.fail_closed()?;
                bail!("source sequence is not strictly increasing");
            }
            if source_seq > previous.saturating_add(1) {
                next.source_loss_count = Some(
                    next.source_loss_count
                        .unwrap_or(0)
                        .saturating_add(source_seq - previous - 1),
                );
                next.partial = true;
            }
            next.source_seq_by_sensor[index] = Some(source_seq);
        }
        next.acknowledged_seq = event.seq;

        let output = output_reference(event, &next)?;
        if next.frame_count >= self.max_events {
            next.record_event_loss(1);
            next.partial = true;
            next.event_limit = true;
            self.record = next;
            if let Err(error) = self.persist_control() {
                self.fail_closed()?;
                return Err(error);
            }
            bail!("event limit reached; event was dropped");
        }
        let Some(frame) = encode_frame(event, output.as_ref())? else {
            next.record_event_loss(1);
            next.partial = true;
            next.journal_limit = true;
            self.record = next;
            if let Err(error) = self.persist_control() {
                self.fail_closed()?;
                return Err(error);
            }
            bail!("event frame exceeded its byte limit and was dropped");
        };
        let framed_len = frame
            .len()
            .checked_add(FRAME_HEADER_BYTES + FRAME_DIGEST_BYTES)
            .ok_or_else(|| anyhow::anyhow!("journal frame size overflow"))?;
        if next
            .journal_bytes
            .checked_add(framed_len as u64)
            .is_none_or(|total| total > JOURNAL_LIMIT_BYTES)
        {
            next.record_event_loss(1);
            next.partial = true;
            next.journal_limit = true;
            self.record = next;
            if let Err(error) = self.persist_control() {
                self.fail_closed()?;
                return Err(error);
            }
            bail!("journal limit reached; event was dropped");
        }

        if let Some(output) = output.as_ref() {
            let input = output_bytes(event)?;
            let region_offset = match output.stream {
                OutputStream::Stdout => STDOUT_OFFSET + output.offset,
                OutputStream::Stderr => STDERR_OFFSET + output.offset,
            };
            if let Err(error) = write_all_at(
                &self.raw,
                &input[..usize::try_from(output.len)?],
                region_offset,
            ) {
                self.fail_closed()?;
                return Err(error);
            }
        }
        let checksum = Sha256::digest(&frame);
        let mut encoded = Vec::with_capacity(frame.len() + FRAME_HEADER_BYTES + FRAME_DIGEST_BYTES);
        encoded.extend_from_slice(&u32::try_from(frame.len())?.to_be_bytes());
        encoded.extend_from_slice(&frame);
        encoded.extend_from_slice(&checksum);
        let journal_offset = next.journal_bytes;
        if let Err(error) = write_all_at(&self.raw, &encoded, journal_offset) {
            self.fail_closed()?;
            return Err(error);
        }
        if let Err(error) = self.raw.sync_data() {
            self.fail_closed()?;
            return Err(error.into());
        }
        next.journal_bytes = next
            .journal_bytes
            .checked_add(u64::try_from(encoded.len())?)
            .ok_or_else(|| anyhow::anyhow!("journal size overflow"))?;
        next.frame_count += 1;
        next.phase_mask |= phase_bit(event.phase);
        next.sensor_mask |= sensor_bit(event.sensor);
        if event.kind == EventKind::OtherObserved {
            next.partial = true;
        }
        if let Some(output) = output {
            match output.stream {
                OutputStream::Stdout => {
                    next.stdout_bytes += output.len;
                    next.stdout_truncated |= output.truncated;
                }
                OutputStream::Stderr => {
                    next.stderr_bytes += output.len;
                    next.stderr_truncated |= output.truncated;
                }
            }
            if output.truncated {
                next.partial = true;
            }
        }
        self.record = next;
        if let Err(error) = self.persist_control() {
            self.fail_closed()?;
            return Err(error);
        }
        Ok(())
    }

    pub fn seal(mut self, state: RunState) -> Result<SealedRun> {
        ensure!(
            state != RunState::Running,
            "cannot seal a running detonation run"
        );
        ensure!(!self.failed, "cannot seal a failed detonation run");
        if state == RunState::Complete {
            ensure!(
                self.record.event_loss_count == Some(0)
                    && self.record.source_loss_count == Some(0)
                    && !self.record.partial
                    && !self.record.unknown_loss
                    && includes_all_phases(self.record.phase_mask, &self.record.metadata.expected_phases)
                    && includes_all_sensors(self.record.sensor_mask, &self.record.metadata.required_sensors),
                "complete run lacks required phases, sensor acknowledgements, or loss-free coverage"
            );
        }
        if state == RunState::Incomplete && !self.record.unknown_loss {
            self.record.partial = true;
        }
        self.persist_control()?;
        seal_writer(self, state)
    }

    fn persist_control(&mut self) -> Result<()> {
        write_control(&self.control, &mut self.record)
    }

    fn fail_closed(&mut self) -> Result<()> {
        self.failed = true;
        self.record.failed = true;
        self.record.partial = true;
        self.record.unknown_loss = true;
        self.record.event_loss_count = None;
        let _ = self.raw.sync_data();
        self.persist_control()
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl ControlRecord {
    fn record_event_loss(&mut self, count: u64) {
        self.event_loss_count = Some(self.event_loss_count.unwrap_or(0).saturating_add(count));
        self.partial = true;
    }
}

fn create_directory_tree(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => ensure!(
            metadata.file_type().is_dir(),
            "evidence root is not a plain directory"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir_all(path)?,
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn check_private_root(root: &Path, config: &StoreConfig) -> Result<()> {
    for forbidden in [
        config.artifacts_dir.as_deref(),
        config.web_root.as_deref(),
        config.public_store.as_deref(),
        config.download_root.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let resolved = canonicalize_allow_missing(forbidden)?;
        ensure!(
            !root.starts_with(&resolved),
            "evidence root is inside a public or artifact directory"
        );
    }
    Ok(())
}

fn canonicalize_allow_missing(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    match absolute.canonicalize() {
        Ok(path) => return Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut existing = absolute.as_path();
    let mut suffix = Vec::new();
    loop {
        if fs::symlink_metadata(existing).is_ok() {
            break;
        }
        let component = existing
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("protected path has no existing ancestor"))?;
        suffix.push(component.to_os_string());
        existing = existing
            .parent()
            .ok_or_else(|| anyhow::anyhow!("protected path has no existing ancestor"))?;
    }
    let mut resolved = existing.canonicalize()?;
    for component in suffix.into_iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => set_directory_mode(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure_plain_directory(path)?;
            set_directory_mode(path)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn ensure_plain_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_dir(),
        "path is not a plain directory: {}",
        path.display()
    );
    Ok(())
}

fn set_directory_mode(path: &Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn open_or_create_lock(path: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path)?;
    ensure!(
        file.metadata()?.file_type().is_file(),
        "store lock is not a regular file"
    );
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn lock_store(path: &Path) -> Result<StoreLock> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path)?;
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    ensure!(result == 0, "could not lock detonation store quota");
    Ok(StoreLock(file))
}

#[cfg(not(target_os = "macos"))]
extern "C" {
    fn posix_fallocate(fd: libc::c_int, offset: libc::off_t, len: libc::off_t) -> libc::c_int;
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct FileStore {
    flags: u32,
    position_mode: i32,
    offset: libc::off_t,
    length: libc::off_t,
    _allocated_bytes: libc::off_t,
}

#[cfg(target_os = "macos")]
fn allocate_file(file: &File, size: u64) -> Result<()> {
    const F_PREALLOCATE: libc::c_int = 42;
    const F_ALLOCATECONTIG: u32 = 0x0000_0002;
    const F_ALLOCATEALL: u32 = 0x0000_0004;
    const F_PEOFPOSMODE: i32 = 3;
    let length = libc::off_t::try_from(size)?;
    let mut allocation = FileStore {
        flags: F_ALLOCATECONTIG,
        position_mode: F_PEOFPOSMODE,
        offset: 0,
        length,
        _allocated_bytes: 0,
    };
    let mut result = unsafe { libc::fcntl(file.as_raw_fd(), F_PREALLOCATE, &mut allocation) };
    if result != 0 || allocation._allocated_bytes < length {
        allocation.flags = F_ALLOCATEALL;
        result = unsafe { libc::fcntl(file.as_raw_fd(), F_PREALLOCATE, &mut allocation) };
    }
    ensure!(
        result == 0 && allocation._allocated_bytes >= length,
        "filesystem could not allocate reserved evidence space"
    );
    file.set_len(size)?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn allocate_file(file: &File, size: u64) -> Result<()> {
    let allocation = unsafe { posix_fallocate(file.as_raw_fd(), 0, libc::off_t::try_from(size)?) };
    ensure!(
        allocation == 0,
        "filesystem could not allocate reserved evidence space"
    );
    Ok(())
}

fn create_reserved_file(path: &Path, size: u64) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path)?;
    allocate_file(&file, size)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.len() == size,
        "reserved evidence file has an incorrect length"
    );
    #[cfg(not(target_os = "macos"))]
    ensure!(
        metadata.blocks().saturating_mul(512) >= size,
        "filesystem did not physically allocate reserved evidence space"
    );
    Ok(file)
}

fn used_bytes(runs: &Path) -> Result<u64> {
    ensure_plain_directory(runs)?;
    let mut inodes = HashSet::new();
    let mut total = 0u64;
    for entry in fs::read_dir(runs)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        ensure!(
            metadata.file_type().is_dir(),
            "run entry is not a plain directory"
        );
        RunId::from_str(
            entry
                .file_name()
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("run directory name is not UTF-8"))?,
        )?;
        for file_entry in fs::read_dir(entry.path())? {
            let file_entry = file_entry?;
            let file_metadata = fs::symlink_metadata(file_entry.path())?;
            ensure!(
                file_metadata.file_type().is_file(),
                "run object is not a regular file"
            );
            let key = (file_metadata.dev(), file_metadata.ino());
            if inodes.insert(key) {
                total = total
                    .checked_add(file_metadata.len())
                    .ok_or_else(|| anyhow::anyhow!("store usage overflow"))?;
            }
        }
    }
    Ok(total)
}

fn output_reference(
    event: &ObservedEvent,
    record: &ControlRecord,
) -> Result<Option<OutputReference>> {
    let output = match &event.private_fields {
        PrivateFields::Stdout { bytes } => {
            let len = u64::try_from(bytes.len().min(usize::try_from(
                STDOUT_LIMIT_BYTES.saturating_sub(record.stdout_bytes),
            )?))?;
            Some(OutputReference {
                stream: OutputStream::Stdout,
                offset: record.stdout_bytes,
                len,
                truncated: len < u64::try_from(bytes.len())?,
            })
        }
        PrivateFields::Stderr { bytes } => {
            let len = u64::try_from(bytes.len().min(usize::try_from(
                STDERR_LIMIT_BYTES.saturating_sub(record.stderr_bytes),
            )?))?;
            Some(OutputReference {
                stream: OutputStream::Stderr,
                offset: record.stderr_bytes,
                len,
                truncated: len < u64::try_from(bytes.len())?,
            })
        }
        _ => None,
    };
    Ok(output)
}

fn output_bytes(event: &ObservedEvent) -> Result<&[u8]> {
    match &event.private_fields {
        PrivateFields::Stdout { bytes } | PrivateFields::Stderr { bytes } => Ok(bytes),
        _ => bail!("output reference does not belong to an output event"),
    }
}

fn validate_run_inputs(metadata: &RunMetadata, provenance: &RunProvenance) -> Result<()> {
    ensure!(
        metadata.started_at_unix_ms > 0,
        "run start time must be set"
    );
    let phases = metadata
        .expected_phases
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    ensure!(
        phases.len() == metadata.expected_phases.len(),
        "expected phases contain duplicates"
    );
    let sensors = metadata
        .required_sensors
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    ensure!(
        sensors.len() == metadata.required_sensors.len(),
        "required sensors contain duplicates"
    );
    if let Some(event_id) = provenance.static_scan_event_id.as_deref() {
        ensure!(
            event_id.len() == 64
                && event_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "static scan event ID must use lowercase SHA-256 hex"
        );
    }
    let mut writer = CappedFrameWriter {
        bytes: Vec::with_capacity(CONTROL_RECORD_LIMIT - 512),
        limit: CONTROL_RECORD_LIMIT - 512,
        exceeded: false,
    };
    if let Err(error) = serde_json::to_writer(&mut writer, &(metadata, provenance)) {
        if writer.exceeded {
            bail!("run metadata exceeds the reserved control-record budget");
        }
        return Err(error.into());
    }
    Ok(())
}

fn verify_static_scan_reference(
    path: &Path,
    event_id: &str,
    artifact_sha256: [u8; 32],
) -> Result<()> {
    let ledger = crate::adapters::storage::ledger::LedgerStore::open_read_only(path)?;
    let head = ledger.verify_integrity()?;
    let artifact_digest = hex::encode(artifact_sha256);
    let mut from = 0;
    while from < head.tree_size {
        let events = ledger.events_from(from, 1000)?;
        ensure!(!events.is_empty(), "ledger ended before its verified head");
        from = from
            .checked_add(u64::try_from(events.len())?)
            .ok_or_else(|| anyhow::anyhow!("ledger position overflow"))?;
        for event in events {
            if event.event_id != event_id {
                continue;
            }
            event.validate_committed()?;
            ensure!(
                event.kind == crate::application::ledger::LedgerEventKind::ScanCompleted,
                "static scan reference is not a completed scan"
            );
            let evidence = match &event.body.details {
                crate::application::ledger::LedgerEventDetails::ScanCompleted(body) => {
                    &body.evidence
                }
                _ => bail!("static scan event kind conflicts with its details"),
            };
            ensure!(
                evidence.artifact_sha256.as_deref() == Some(artifact_digest.as_str()),
                "static scan artifact digest does not match the run"
            );
            return Ok(());
        }
    }
    bail!("static scan event does not exist in the verified ledger")
}

fn validate_event(event: &ObservedEvent) -> Result<()> {
    ensure!(event.seq > 0, "event sequence must start at 1");
    let valid = matches!(
        (event.kind, &event.private_fields),
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
    );
    ensure!(valid, "event kind does not match private fields");
    Ok(())
}

fn write_control(file: &File, record: &mut ControlRecord) -> Result<()> {
    record.generation = record.generation.saturating_add(1);
    let payload = serde_json::to_vec(record)?;
    ensure!(
        payload.len() + FRAME_HEADER_BYTES + FRAME_DIGEST_BYTES <= CONTROL_RECORD_LIMIT,
        "control record exceeds its reserved slot"
    );
    let offset = (record.generation % 2) * CONTROL_SLOT_BYTES;
    let mut framed = Vec::with_capacity(payload.len() + FRAME_HEADER_BYTES + FRAME_DIGEST_BYTES);
    framed.extend_from_slice(&u32::try_from(payload.len())?.to_be_bytes());
    framed.extend_from_slice(&payload);
    framed.extend_from_slice(&Sha256::digest(&payload));
    write_all_at(file, &framed, offset)?;
    file.sync_data()?;
    Ok(())
}

fn read_control(file: &File, run_id: RunId) -> Result<ControlRecord> {
    let mut selected: Option<ControlRecord> = None;
    for offset in [0, CONTROL_SLOT_BYTES] {
        let mut len_bytes = [0; FRAME_HEADER_BYTES];
        if read_exact_at(file, &mut len_bytes, offset).is_err() {
            continue;
        }
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len == 0 || len + FRAME_HEADER_BYTES + FRAME_DIGEST_BYTES > CONTROL_RECORD_LIMIT {
            continue;
        }
        let mut payload = vec![0; len];
        let mut digest = [0; FRAME_DIGEST_BYTES];
        if read_exact_at(file, &mut payload, offset + FRAME_HEADER_BYTES as u64).is_err()
            || read_exact_at(
                file,
                &mut digest,
                offset + FRAME_HEADER_BYTES as u64 + len as u64,
            )
            .is_err()
        {
            continue;
        }
        if Sha256::digest(&payload).as_slice() != digest {
            continue;
        }
        let Ok(record) = serde_json::from_slice::<ControlRecord>(&payload) else {
            continue;
        };
        if record.run_id != run_id {
            continue;
        }
        if selected
            .as_ref()
            .is_none_or(|current| record.generation > current.generation)
        {
            selected = Some(record);
        }
    }
    selected.ok_or_else(|| anyhow::anyhow!("no valid detonation control record"))
}

fn load_frames(raw: &File, record: &ControlRecord) -> Result<Vec<StoredFrame>> {
    ensure!(
        record.frame_count <= JOURNAL_FRAME_LIMIT as u64
            && record.journal_bytes <= JOURNAL_LIMIT_BYTES
            && record.stdout_bytes <= STDOUT_LIMIT_BYTES
            && record.stderr_bytes <= STDERR_LIMIT_BYTES,
        "control record exceeds detonation run limits"
    );
    let mut frames = Vec::with_capacity(usize::try_from(record.frame_count)?);
    let mut previous_seq = 0;
    let mut offset = 0u64;
    while offset < record.journal_bytes {
        let mut len_bytes = [0; FRAME_HEADER_BYTES];
        read_exact_at(raw, &mut len_bytes, offset)
            .context("truncated acknowledged journal header")?;
        let payload_len = u32::from_be_bytes(len_bytes) as usize;
        let frame_len = payload_len
            .checked_add(FRAME_HEADER_BYTES + FRAME_DIGEST_BYTES)
            .ok_or_else(|| anyhow::anyhow!("journal frame size overflow"))?;
        ensure!(
            frame_len <= FRAME_LIMIT_BYTES,
            "journal frame exceeds configured limit"
        );
        ensure!(
            offset + frame_len as u64 <= record.journal_bytes,
            "acknowledged journal frame is torn"
        );
        let mut payload = vec![0; payload_len];
        let mut digest = [0; FRAME_DIGEST_BYTES];
        read_exact_at(raw, &mut payload, offset + FRAME_HEADER_BYTES as u64)?;
        read_exact_at(
            raw,
            &mut digest,
            offset + FRAME_HEADER_BYTES as u64 + payload_len as u64,
        )?;
        ensure!(
            Sha256::digest(&payload).as_slice() == digest,
            "journal frame digest mismatch"
        );
        let frame: StoredFrame = serde_json::from_slice(&payload)?;
        ensure!(
            frame.event.run_id == record.run_id,
            "journal frame run ID conflicts with manifest"
        );
        ensure!(
            frame.event.seq > previous_seq,
            "journal event sequences are not strictly increasing"
        );
        previous_seq = frame.event.seq;
        if let Some(output) = &frame.output {
            let (max, recorded) = match output.stream {
                OutputStream::Stdout => (STDOUT_LIMIT_BYTES, record.stdout_bytes),
                OutputStream::Stderr => (STDERR_LIMIT_BYTES, record.stderr_bytes),
            };
            ensure!(
                output
                    .offset
                    .checked_add(output.len)
                    .is_some_and(|end| end <= max && end <= recorded),
                "output reference escapes its reserved stream"
            );
        }
        frames.push(frame);
        offset += frame_len as u64;
    }
    ensure!(
        offset == record.journal_bytes,
        "journal length is inconsistent"
    );
    ensure!(
        frames.len() as u64 == record.frame_count,
        "journal frame count is inconsistent"
    );
    Ok(frames)
}

fn hydrate_frames(raw: &File, frames: &[StoredFrame]) -> Result<Vec<ObservedEvent>> {
    frames
        .iter()
        .map(|frame| {
            let mut event = frame.event.clone();
            if let Some(output) = &frame.output {
                let (base, variant) = match output.stream {
                    OutputStream::Stdout => (STDOUT_OFFSET + output.offset, EventKind::Stdout),
                    OutputStream::Stderr => (STDERR_OFFSET + output.offset, EventKind::Stderr),
                };
                ensure!(
                    event.kind == variant,
                    "output reference conflicts with event kind"
                );
                let mut bytes = vec![0; usize::try_from(output.len)?];
                read_exact_at(raw, &mut bytes, base)?;
                event.private_fields = match output.stream {
                    OutputStream::Stdout => PrivateFields::Stdout { bytes },
                    OutputStream::Stderr => PrivateFields::Stderr { bytes },
                };
            }
            Ok(event)
        })
        .collect()
}

fn recover_incomplete(run_id: RunId, run_dir: PathBuf) -> Result<SealedRun> {
    let raw = open_regular(&run_dir.join("raw.reserve"))?;
    let projection = open_regular(&run_dir.join("projection.reserve"))?;
    let scratch = open_regular(&run_dir.join("scratch.reserve"))?;
    let control = open_regular(&run_dir.join("control.reserve"))?;
    let mut record = read_control(&control, run_id)?;
    ensure!(
        record.run_id == run_id,
        "control record run ID conflicts with directory"
    );
    load_frames(&raw, &record)?;
    let unknown_tail = has_nonzero_bytes(
        &raw,
        record.journal_bytes,
        JOURNAL_LIMIT_BYTES - record.journal_bytes,
    )? || has_nonzero_bytes(
        &raw,
        STDOUT_OFFSET + record.stdout_bytes,
        STDOUT_LIMIT_BYTES.saturating_sub(record.stdout_bytes),
    )? || has_nonzero_bytes(
        &raw,
        STDERR_OFFSET + record.stderr_bytes,
        STDERR_LIMIT_BYTES.saturating_sub(record.stderr_bytes),
    )?;
    record.unknown_loss = true;
    record.event_loss_count = None;
    record.partial = true;
    record.failed |= unknown_tail;
    write_control(&control, &mut record)?;
    let writer = RunWriter {
        run_dir,
        raw,
        projection,
        _scratch: scratch,
        control,
        record,
        max_events: JOURNAL_FRAME_LIMIT as u64,
        failed: false,
    };
    seal_writer(writer, RunState::Incomplete)
}

fn seal_writer(mut writer: RunWriter, state: RunState) -> Result<SealedRun> {
    let record = writer.record.clone();
    writer.raw.sync_all()?;
    let stored = load_frames(&writer.raw, &record)?;
    let private_events = hydrate_frames(&writer.raw, &stored)?;
    let redactor = Redactor::new()?;
    let mut labels = RunLabels::new(record.run_id);
    let mut coverage = coverage_from_record(&record);
    let mut public_events = Vec::with_capacity(private_events.len());
    for event in &private_events {
        let projected = if matches!(event.kind, EventKind::Stdout | EventKind::Stderr) {
            project_event_without_output(event, &mut labels, &redactor)?
        } else {
            project_event(event, &mut labels, &redactor)?
        };
        if event.kind == EventKind::OtherObserved {
            coverage.mark_partial(CoverageReason::UnsupportedEvent);
        }
        if projected.withheld_reason.is_some()
            && !matches!(
                event.kind,
                EventKind::OtherObserved | EventKind::Stdout | EventKind::Stderr
            )
        {
            coverage.mark_partial(CoverageReason::RedactionWithheld);
        }
        if projected.coverage == CoverageState::Partial
            && !matches!(
                event.kind,
                EventKind::OtherObserved | EventKind::Stdout | EventKind::Stderr
            )
        {
            coverage.mark_partial(CoverageReason::OutputTruncated);
        }
        public_events.push(projected);
    }
    redact_output_stream(
        OutputStream::Stdout,
        &stored,
        &private_events,
        &mut public_events,
        &redactor,
        &mut coverage,
    )?;
    redact_output_stream(
        OutputStream::Stderr,
        &stored,
        &private_events,
        &mut public_events,
        &redactor,
        &mut coverage,
    )?;
    if state == RunState::Incomplete && coverage.state != CoverageState::Unknown {
        coverage.mark_partial(CoverageReason::ExplicitIncomplete);
    }
    if record.stdout_truncated || record.stderr_truncated {
        coverage.mark_partial(CoverageReason::OutputTruncated);
    }
    let (bundle, public_events) = bounded_bundle(public_events, &mut coverage)?;
    ensure!(
        bundle.len() as u64 <= PROJECTION_RESERVATION_BYTES,
        "public projection exceeds reserved space"
    );
    write_all_at(&writer.projection, &bundle, 0)?;
    writer.projection.sync_data()?;
    let public_path = writer.run_dir.join("public.bundle");
    match fs::symlink_metadata(&public_path) {
        Ok(metadata) => {
            let source = writer.projection.metadata()?;
            ensure!(
                metadata.file_type().is_file()
                    && metadata.dev() == source.dev()
                    && metadata.ino() == source.ino(),
                "public bundle path conflicts with its reserved projection"
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::hard_link(writer.run_dir.join("projection.reserve"), &public_path)?;
        }
        Err(error) => return Err(error.into()),
    }
    sync_directory(&writer.run_dir)?;

    let public_digest: [u8; 32] = Sha256::digest(&bundle).into();
    let mut provenance = record.provenance.clone();
    provenance.public_bundle_sha256 = public_digest;
    let actual_phases = phases_from_mask(record.phase_mask);
    let acknowledged_sensors = sensors_from_mask(record.sensor_mask);
    let objects = vec![
        ObjectRef {
            name: "journal".to_string(),
            sha256: hex::encode(hash_region(&writer.raw, 0, record.journal_bytes)?),
            byte_count: record.journal_bytes,
            source: "raw.reserve".to_string(),
            truncated: record.event_loss_count.is_some_and(|count| count > 0),
        },
        ObjectRef {
            name: "stdout".to_string(),
            sha256: hex::encode(hash_region(
                &writer.raw,
                STDOUT_OFFSET,
                record.stdout_bytes,
            )?),
            byte_count: record.stdout_bytes,
            source: "raw.reserve".to_string(),
            truncated: record.stdout_truncated,
        },
        ObjectRef {
            name: "stderr".to_string(),
            sha256: hex::encode(hash_region(
                &writer.raw,
                STDERR_OFFSET,
                record.stderr_bytes,
            )?),
            byte_count: record.stderr_bytes,
            source: "raw.reserve".to_string(),
            truncated: record.stderr_truncated,
        },
    ];
    let manifest = RunManifest {
        run_id: record.run_id,
        state,
        metadata: record.metadata.clone(),
        provenance: provenance.clone(),
        actual_phases: actual_phases.clone(),
        acknowledged_sensors: acknowledged_sensors.clone(),
        event_count: record.frame_count,
        durable_seq: record.acknowledged_seq,
        journal_bytes: record.journal_bytes,
        stdout_bytes: record.stdout_bytes,
        stderr_bytes: record.stderr_bytes,
        public_bundle_bytes: bundle.len() as u64,
        coverage: coverage.clone(),
        objects: objects.clone(),
        public_event_count: public_events.len() as u64,
        redaction_policy_version: REDACTION_POLICY_VERSION,
        ended_at_unix_ms: now_unix_ms(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    write_record_at(&writer.control, MANIFEST_RECORD_OFFSET, &manifest_bytes)?;
    writer.control.sync_data()?;
    ensure!(
        !path_is_file(&writer.run_dir.join("manifest.json"))?,
        "manifest already exists without a committed recovery"
    );
    fs::hard_link(
        writer.run_dir.join("control.reserve"),
        writer.run_dir.join("manifest.json"),
    )?;
    sync_directory(&writer.run_dir)?;

    let public_run = PublicRun {
        run_id: record.run_id,
        state,
        coverage,
        phases: actual_phases,
        event_count: public_events.len() as u64,
        public_bundle_sha256: hex::encode(public_digest),
        redaction_policy_version: REDACTION_POLICY_VERSION,
        automatic_redaction_limitation: true,
    };
    let sealed = SealedRun {
        run: public_run,
        events: public_events,
        provenance,
        objects,
    };
    let _ = &mut writer;
    Ok(sealed)
}

fn redact_output_stream(
    stream: OutputStream,
    frames: &[StoredFrame],
    private_events: &[ObservedEvent],
    public_events: &mut [PublicEvent],
    redactor: &Redactor,
    coverage: &mut Coverage,
) -> Result<()> {
    ensure!(
        frames.len() == private_events.len() && frames.len() == public_events.len(),
        "event projections do not align with journal frames"
    );
    let (field, max_bytes) = match stream {
        OutputStream::Stdout => ("stdout", STDOUT_LIMIT_BYTES as usize),
        OutputStream::Stderr => ("stderr", STDERR_LIMIT_BYTES as usize),
    };
    let mut indexes = Vec::new();
    let mut chunks = Vec::new();
    let mut truncated = Vec::new();
    for (index, frame) in frames.iter().enumerate() {
        let Some(output) = frame
            .output
            .as_ref()
            .filter(|output| output.stream == stream)
        else {
            continue;
        };
        let bytes = match (&private_events[index].private_fields, stream) {
            (PrivateFields::Stdout { bytes }, OutputStream::Stdout)
            | (PrivateFields::Stderr { bytes }, OutputStream::Stderr) => bytes.as_slice(),
            _ => bail!("output frame does not match its event"),
        };
        indexes.push(index);
        chunks.push(bytes);
        truncated.push(output.truncated);
    }
    if chunks.is_empty() {
        return Ok(());
    }
    let results = redactor.redact_chunks(&chunks, field, max_bytes);
    ensure!(
        results.len() == indexes.len(),
        "redactor changed output chunk count"
    );
    for ((index, result), stream_truncated) in indexes.into_iter().zip(results).zip(truncated) {
        let event = &mut public_events[index];
        event.text = result.text;
        event.redacted_fields = result.redacted_fields;
        event.withheld_reason = result.withheld_reason;
        let withheld = event.withheld_reason.is_some();
        let partial = withheld || result.truncated || stream_truncated;
        if withheld {
            coverage.mark_partial(CoverageReason::RedactionWithheld);
        }
        if result.truncated || stream_truncated {
            coverage.mark_partial(CoverageReason::OutputTruncated);
            if !event
                .redacted_fields
                .iter()
                .any(|marker| marker == &format!("{field}:truncated"))
            {
                event.redacted_fields.push(format!("{field}:truncated"));
            }
        }
        if partial {
            event.coverage = CoverageState::Partial;
        }
    }
    Ok(())
}

fn read_sealed_run(run_id: RunId, run_dir: &Path) -> Result<SealedRun> {
    let raw = open_regular(&run_dir.join("raw.reserve"))?;
    let projection = open_regular(&run_dir.join("public.bundle"))?;
    let manifest_file = open_regular(&run_dir.join("manifest.json"))?;
    let manifest_bytes = read_record_at(&manifest_file, MANIFEST_RECORD_OFFSET)?;
    let manifest: RunManifest = serde_json::from_slice(&manifest_bytes)?;
    ensure!(
        manifest.run_id == run_id,
        "manifest run ID conflicts with directory"
    );
    ensure!(
        manifest.redaction_policy_version == REDACTION_POLICY_VERSION,
        "redaction policy version mismatch"
    );
    ensure!(
        manifest.public_bundle_bytes <= PROJECTION_RESERVATION_BYTES,
        "public bundle length exceeds its reservation"
    );
    ensure!(
        manifest.provenance.public_bundle_sha256
            == hash_region(&projection, 0, manifest.public_bundle_bytes)?,
        "public bundle digest mismatch"
    );
    let bundle = read_region(&projection, 0, manifest.public_bundle_bytes)?;
    let events = bundle
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(serde_json::from_slice::<PublicEvent>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        events.len() as u64 == manifest.public_event_count,
        "public event count mismatch"
    );
    let record = ControlRecord {
        run_id,
        generation: 0,
        provenance: manifest.provenance.clone(),
        metadata: manifest.metadata.clone(),
        acknowledged_seq: manifest.durable_seq,
        journal_bytes: manifest.journal_bytes,
        frame_count: manifest.event_count,
        stdout_bytes: manifest.stdout_bytes,
        stderr_bytes: manifest.stderr_bytes,
        event_loss_count: manifest.coverage.event_loss_count,
        source_loss_count: manifest.coverage.source_loss_count,
        source_seq_by_sensor: [None, None, None],
        phase_mask: phase_mask(&manifest.actual_phases),
        sensor_mask: sensor_mask(&manifest.acknowledged_sensors),
        partial: manifest.coverage.state != CoverageState::Complete,
        unknown_loss: manifest.coverage.state == CoverageState::Unknown,
        stdout_truncated: manifest
            .objects
            .iter()
            .any(|object| object.name == "stdout" && object.truncated),
        stderr_truncated: manifest
            .objects
            .iter()
            .any(|object| object.name == "stderr" && object.truncated),
        event_limit: false,
        journal_limit: false,
        failed: false,
    };
    let frames = load_frames(&raw, &record)?;
    ensure!(
        frames.len() as u64 == manifest.event_count,
        "journal event count mismatch"
    );
    let journal_digest = hash_region(&raw, 0, manifest.journal_bytes)?;
    ensure!(
        manifest
            .objects
            .iter()
            .any(|object| object.name == "journal" && object.sha256 == hex::encode(journal_digest)),
        "journal digest mismatch"
    );
    for object in &manifest.objects {
        let (offset, length) = match object.name.as_str() {
            "stdout" => (STDOUT_OFFSET, manifest.stdout_bytes),
            "stderr" => (STDERR_OFFSET, manifest.stderr_bytes),
            "journal" => (0, manifest.journal_bytes),
            _ => bail!("manifest contains an unknown private object"),
        };
        ensure!(
            object.byte_count == length,
            "private object length mismatch"
        );
        ensure!(
            object.sha256 == hex::encode(hash_region(&raw, offset, length)?),
            "private object digest mismatch"
        );
    }
    Ok(SealedRun {
        run: PublicRun {
            run_id,
            state: manifest.state,
            coverage: manifest.coverage,
            phases: manifest.actual_phases,
            event_count: manifest.public_event_count,
            public_bundle_sha256: hex::encode(manifest.provenance.public_bundle_sha256),
            redaction_policy_version: manifest.redaction_policy_version,
            automatic_redaction_limitation: true,
        },
        events,
        provenance: manifest.provenance,
        objects: manifest.objects,
    })
}

fn coverage_from_record(record: &ControlRecord) -> Coverage {
    let mut coverage = Coverage {
        state: CoverageState::Complete,
        reasons: Vec::new(),
        event_loss_count: record.event_loss_count,
        source_loss_count: record.source_loss_count,
    };
    if record.event_loss_count.is_some_and(|count| count > 0) {
        coverage.mark_partial(CoverageReason::KnownEventLoss);
    }
    if record.event_loss_count.is_none() || record.unknown_loss {
        coverage.state = CoverageState::Unknown;
        if !coverage.reasons.contains(&CoverageReason::UnknownEventLoss) {
            coverage.reasons.push(CoverageReason::UnknownEventLoss);
        }
    }
    if record.source_loss_count.is_some_and(|count| count > 0) {
        coverage.mark_partial(CoverageReason::SourceLoss);
    }
    if record.source_loss_count.is_none() {
        coverage.mark_partial(CoverageReason::SourceLoss);
    }
    if record.stdout_truncated || record.stderr_truncated {
        coverage.mark_partial(CoverageReason::OutputTruncated);
    }
    if !includes_all_phases(record.phase_mask, &record.metadata.expected_phases) {
        coverage.mark_partial(CoverageReason::MissingPhase);
    }
    if !includes_all_sensors(record.sensor_mask, &record.metadata.required_sensors) {
        coverage.mark_partial(CoverageReason::MissingSensor);
    }
    if record.event_limit {
        coverage.mark_partial(CoverageReason::EventLimit);
    }
    if record.journal_limit {
        coverage.mark_partial(CoverageReason::JournalLimit);
    }
    if record.failed {
        coverage.mark_partial(CoverageReason::StorageFailure);
    }
    if record.partial && coverage.state == CoverageState::Complete {
        coverage.mark_partial(CoverageReason::KnownEventLoss);
    }
    coverage
}

fn bounded_bundle(
    mut events: Vec<PublicEvent>,
    coverage: &mut Coverage,
) -> Result<(Vec<u8>, Vec<PublicEvent>)> {
    const MIN_EVENT_BYTES: usize = 512;
    let count = events.len();
    let mut bundle = Vec::new();
    let mut retained = Vec::with_capacity(count);
    for (index, mut event) in events.drain(..).enumerate() {
        let remaining =
            usize::try_from(PROJECTION_RESERVATION_BYTES.saturating_sub(bundle.len() as u64))?;
        let future = count.saturating_sub(index + 1);
        let reserved = future.saturating_mul(MIN_EVENT_BYTES);
        let event_budget = remaining.saturating_sub(reserved);
        ensure!(
            event_budget >= MIN_EVENT_BYTES,
            "public projection cannot preserve remaining event positions"
        );
        let mut encoded = serde_json::to_vec(&event)?;
        if encoded.len() >= event_budget {
            let original = event.text.take();
            if let Some(original) = original {
                let mut low = 0usize;
                let mut high = original.len();
                while low < high {
                    let middle = low + (high - low).div_ceil(2);
                    let mut candidate = original.clone();
                    truncate_utf8(&mut candidate, middle);
                    event.text = Some(candidate);
                    if serde_json::to_vec(&event)?.len() < event_budget {
                        low = middle;
                    } else {
                        high = middle - 1;
                    }
                }
                let mut shortened = original;
                truncate_utf8(&mut shortened, low);
                event.text = Some(shortened);
            }
            while serde_json::to_vec(&event)?.len() >= event_budget && !event.details.is_empty() {
                event.details.pop();
            }
            if serde_json::to_vec(&event)?.len() >= event_budget {
                event.actor = None;
                event.target = None;
                event.details.clear();
                event.text = None;
                event.redacted_fields.clear();
                event
                    .redacted_fields
                    .push("projection:withheld".to_string());
                event.withheld_reason = Some(WithheldReason::Overlong);
            } else if !event
                .redacted_fields
                .iter()
                .any(|field| field == "projection:truncated")
            {
                event
                    .redacted_fields
                    .push("projection:truncated".to_string());
            }
            event.coverage = CoverageState::Partial;
            coverage.mark_partial(CoverageReason::ProjectionTruncated);
            encoded = serde_json::to_vec(&event)?;
        }
        ensure!(
            encoded.len() < event_budget,
            "public event exceeds its reserved projection space"
        );
        bundle.extend_from_slice(&encoded);
        bundle.push(b'\n');
        retained.push(event);
    }
    Ok((bundle, retained))
}

fn write_record_at(file: &File, offset: u64, payload: &[u8]) -> Result<()> {
    ensure!(
        payload.len() + FRAME_HEADER_BYTES + FRAME_DIGEST_BYTES <= MANIFEST_RECORD_LIMIT,
        "manifest exceeds control reservation"
    );
    let mut framed = Vec::with_capacity(payload.len() + FRAME_HEADER_BYTES + FRAME_DIGEST_BYTES);
    framed.extend_from_slice(&u32::try_from(payload.len())?.to_be_bytes());
    framed.extend_from_slice(payload);
    framed.extend_from_slice(&Sha256::digest(payload));
    write_all_at(file, &framed, offset)?;
    Ok(())
}

fn read_record_at(file: &File, offset: u64) -> Result<Vec<u8>> {
    let mut len_bytes = [0; FRAME_HEADER_BYTES];
    read_exact_at(file, &mut len_bytes, offset)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    ensure!(
        len > 0 && len + FRAME_HEADER_BYTES + FRAME_DIGEST_BYTES <= MANIFEST_RECORD_LIMIT,
        "manifest record length is invalid"
    );
    let mut payload = vec![0; len];
    let mut digest = [0; FRAME_DIGEST_BYTES];
    read_exact_at(file, &mut payload, offset + FRAME_HEADER_BYTES as u64)?;
    read_exact_at(
        file,
        &mut digest,
        offset + FRAME_HEADER_BYTES as u64 + len as u64,
    )?;
    ensure!(
        Sha256::digest(&payload).as_slice() == digest,
        "manifest record digest mismatch"
    );
    Ok(payload)
}

fn open_regular(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.file_type().is_file(),
        "evidence object is not a regular file"
    );
    ensure!(
        metadata.mode() & 0o777 == 0o600,
        "evidence object must have mode 0600"
    );
    Ok(file)
}

fn path_is_file(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_file(),
                "evidence object is not a regular file"
            );
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn has_nonzero_bytes(file: &File, offset: u64, length: u64) -> Result<bool> {
    let mut buffer = [0; IO_BUFFER_BYTES];
    let mut current = offset;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| anyhow::anyhow!("evidence range overflow"))?;
    while current < end {
        let count = usize::try_from((end - current).min(buffer.len() as u64))?;
        read_exact_at(file, &mut buffer[..count], current)?;
        if buffer[..count].iter().any(|byte| *byte != 0) {
            return Ok(true);
        }
        current += count as u64;
    }
    Ok(false)
}

fn hash_region(file: &File, offset: u64, length: u64) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = [0; IO_BUFFER_BYTES];
    let mut current = offset;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| anyhow::anyhow!("evidence range overflow"))?;
    while current < end {
        let count = usize::try_from((end - current).min(buffer.len() as u64))?;
        read_exact_at(file, &mut buffer[..count], current)?;
        hasher.update(&buffer[..count]);
        current += count as u64;
    }
    Ok(hasher.finalize().into())
}

fn read_region(file: &File, offset: u64, length: u64) -> Result<Vec<u8>> {
    let mut bytes = vec![0; usize::try_from(length)?];
    read_exact_at(file, &mut bytes, offset)?;
    Ok(bytes)
}

fn read_exact_at(file: &File, buffer: &mut [u8], mut offset: u64) -> Result<()> {
    let mut remaining = buffer;
    while !remaining.is_empty() {
        let count = file.read_at(remaining, offset)?;
        ensure!(count != 0, "unexpected end of evidence object");
        offset = offset
            .checked_add(count as u64)
            .ok_or_else(|| anyhow::anyhow!("evidence offset overflow"))?;
        remaining = &mut remaining[count..];
    }
    Ok(())
}

fn write_all_at(file: &File, mut buffer: &[u8], mut offset: u64) -> Result<()> {
    while !buffer.is_empty() {
        let count = file.write_at(buffer, offset)?;
        ensure!(count != 0, "short write to evidence reservation");
        offset = offset
            .checked_add(count as u64)
            .ok_or_else(|| anyhow::anyhow!("evidence offset overflow"))?;
        buffer = &buffer[count..];
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn phase_bit(phase: Phase) -> u8 {
    match phase {
        Phase::Install => 1,
        Phase::Import => 2,
        Phase::Execute => 4,
        Phase::Build => 8,
    }
}

fn sensor_bit(sensor: Sensor) -> u8 {
    match sensor {
        Sensor::SyscallTrace => 1,
        Sensor::ProcessOutput => 2,
        Sensor::GuestMonitor => 4,
    }
}

fn sensor_index(sensor: Sensor) -> usize {
    match sensor {
        Sensor::SyscallTrace => 0,
        Sensor::ProcessOutput => 1,
        Sensor::GuestMonitor => 2,
    }
}

fn phase_mask(phases: &[Phase]) -> u8 {
    phases
        .iter()
        .fold(0, |mask, phase| mask | phase_bit(*phase))
}

fn sensor_mask(sensors: &[Sensor]) -> u8 {
    sensors
        .iter()
        .fold(0, |mask, sensor| mask | sensor_bit(*sensor))
}

fn phases_from_mask(mask: u8) -> Vec<Phase> {
    Phase::ALL
        .into_iter()
        .filter(|phase| mask & phase_bit(*phase) != 0)
        .collect()
}

fn sensors_from_mask(mask: u8) -> Vec<Sensor> {
    Sensor::ALL
        .into_iter()
        .filter(|sensor| mask & sensor_bit(*sensor) != 0)
        .collect()
}

fn includes_all_phases(mask: u8, expected: &[Phase]) -> bool {
    expected.iter().all(|phase| mask & phase_bit(*phase) != 0)
}

fn includes_all_sensors(mask: u8, required: &[Sensor]) -> bool {
    required
        .iter()
        .all(|sensor| mask & sensor_bit(*sensor) != 0)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn truncate_utf8(text: &mut String, max_bytes: usize) {
    let mut end = max_bytes.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
}
