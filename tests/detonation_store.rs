use anyhow::{ensure, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{symlink, FileExt, MetadataExt, PermissionsExt},
    path::Path,
    str::FromStr,
};
use supply_core::{
    adapters::storage::detonation::{EvidenceStore, RunMetadata, SealedRun, StoreConfig},
    application::detonation::{
        project_event, CoverageReason, CoverageState, EventKind, FailureKind, ObservationKind,
        ObservedEvent, Outcome, Phase, PrivateFields, ProcessIdentity, PublicEvent, Redactor,
        RunId, RunLabels, RunProvenance, RunState, Sensor, WithheldReason, MAX_FIELD_BYTES,
        MAX_STDOUT_BYTES,
    },
};

const RESERVATION_BYTES: u64 = 25 * 1024 * 1024;

fn provenance() -> RunProvenance {
    RunProvenance {
        artifact_sha256: [0x11; 32],
        static_scan_event_id: None,
        public_bundle_sha256: [0; 32],
    }
}

fn metadata(phases: Vec<Phase>, sensors: Vec<Sensor>) -> RunMetadata {
    RunMetadata {
        ecosystem: Some("npm".to_string()),
        package_name: Some("detonation-fixture".to_string()),
        package_version: Some("1.2.3".to_string()),
        vm_image_sha256: Some([0x22; 32]),
        runner_version: Some("fixture-runner".to_string()),
        monitor_version: Some("fixture-monitor".to_string()),
        policy_revision: Some("fixture-policy".to_string()),
        started_at_unix_ms: 1,
        expected_phases: phases,
        required_sensors: sensors,
    }
}

fn event(run_id: RunId, seq: u64, private_fields: PrivateFields) -> ObservedEvent {
    let kind = match &private_fields {
        PrivateFields::ProcessExec { .. } => EventKind::ProcessExec,
        PrivateFields::ProcessExit { .. } => EventKind::ProcessExit,
        PrivateFields::FileOpen { .. } => EventKind::FileOpen,
        PrivateFields::FileWrite { .. } => EventKind::FileWrite,
        PrivateFields::FileDelete { .. } => EventKind::FileDelete,
        PrivateFields::NetworkConnect { .. } => EventKind::NetworkConnect,
        PrivateFields::NetworkSend { .. } => EventKind::NetworkSend,
        PrivateFields::DnsQuery { .. } => EventKind::DnsQuery,
        PrivateFields::Stdout { .. } => EventKind::Stdout,
        PrivateFields::Stderr { .. } => EventKind::Stderr,
        PrivateFields::OtherObserved { .. } => EventKind::OtherObserved,
    };
    ObservedEvent {
        run_id,
        seq,
        offset_ns: Some(seq * 1_000_000),
        source_seq: None,
        phase: Phase::Install,
        sensor: if matches!(kind, EventKind::Stdout | EventKind::Stderr) {
            Sensor::ProcessOutput
        } else {
            Sensor::SyscallTrace
        },
        observation: ObservationKind::Observed,
        kind,
        outcome: Outcome::Succeeded,
        failure: None,
        private_fields,
    }
}

fn process_exec(
    run_id: RunId,
    seq: u64,
    process: ProcessIdentity,
    executable: &str,
    arguments: Vec<String>,
) -> ObservedEvent {
    event(
        run_id,
        seq,
        PrivateFields::ProcessExec {
            process,
            executable: executable.to_string(),
            arguments,
            cwd: None,
            environment: Vec::new(),
        },
    )
}

fn process_exit(run_id: RunId, seq: u64, process: ProcessIdentity) -> ObservedEvent {
    event(
        run_id,
        seq,
        PrivateFields::ProcessExit {
            process,
            exit_code: Some(0),
        },
    )
}

fn complete_metadata() -> RunMetadata {
    metadata(vec![Phase::Install], vec![Sensor::SyscallTrace])
}

fn read_exact_at(file: &File, mut buffer: &mut [u8], mut offset: u64) -> Result<()> {
    while !buffer.is_empty() {
        let count = file.read_at(buffer, offset)?;
        ensure!(count > 0, "unexpected EOF in test control record");
        offset += count as u64;
        buffer = &mut buffer[count..];
    }
    Ok(())
}

fn write_all_at(file: &File, mut bytes: &[u8], mut offset: u64) -> Result<()> {
    while !bytes.is_empty() {
        let count = file.write_at(bytes, offset)?;
        ensure!(count > 0, "test file write made no progress");
        offset += count as u64;
        bytes = &bytes[count..];
    }
    Ok(())
}

fn acknowledged_journal_bytes(run_dir: &Path) -> Result<u64> {
    let control = File::open(run_dir.join("control.reserve"))?;
    let mut selected: Option<(u64, u64)> = None;
    for offset in [0, 4096] {
        let mut length = [0; 4];
        read_exact_at(&control, &mut length, offset)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length + 36 > 3500 {
            continue;
        }
        let mut payload = vec![0; length];
        let mut digest = [0; 32];
        read_exact_at(&control, &mut payload, offset + 4)?;
        read_exact_at(&control, &mut digest, offset + 4 + length as u64)?;
        let actual: [u8; 32] = Sha256::digest(&payload).into();
        if actual != digest {
            continue;
        }
        let record: Value = serde_json::from_slice(&payload)?;
        let generation = record["generation"].as_u64().unwrap_or(0);
        let journal_bytes = record["journal_bytes"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("control record has no journal length"))?;
        if selected.is_none_or(|(current, _)| generation > current) {
            selected = Some((generation, journal_bytes));
        }
    }
    selected
        .map(|(_, journal_bytes)| journal_bytes)
        .ok_or_else(|| anyhow::anyhow!("no valid control record"))
}

fn one_run(runs: &[SealedRun], id: RunId) -> Result<&SealedRun> {
    runs.iter()
        .find(|run| run.run.run_id == id)
        .ok_or_else(|| anyhow::anyhow!("expected run ID in recovered store"))
}

#[test]
fn run_ids_are_lowercase_hex_and_parse_without_aliases() -> Result<()> {
    let id = RunId([0xab; 16]);
    assert_eq!(id.to_string(), "abababababababababababababababab");
    assert_eq!(RunId::from_str(&id.to_string())?, id);
    assert!(RunId::from_str("ABABABABABABABABABABABABABABABAB").is_err());
    assert!(RunId::from_str("abab").is_err());
    Ok(())
}

#[test]
fn two_runs_keep_events_and_ordinal_labels_independent() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let store = EvidenceStore::new(directory.path())?;
    let process = ProcessIdentity {
        pid: 41,
        start_generation: 1,
    };
    let mut first = store.begin_run_with_metadata(provenance(), complete_metadata())?;
    let first_id = first.run_id();
    first.append(&process_exec(
        first_id,
        1,
        process.clone(),
        "/tmp/alpha-tool",
        vec!["alpha-only".to_string()],
    ))?;
    first.append(&event(
        first_id,
        2,
        PrivateFields::FileOpen {
            process: Some(process.clone()),
            path: "/tmp/alpha-tool".to_string(),
            flags: Some("read".to_string()),
        },
    ))?;
    let mut second = store.begin_run_with_metadata(provenance(), complete_metadata())?;
    let second_id = second.run_id();
    second.append(&process_exec(
        second_id,
        1,
        process.clone(),
        "/tmp/beta-tool",
        vec!["beta-only".to_string()],
    ))?;
    first.seal(RunState::Complete)?;
    second.seal(RunState::Complete)?;

    let runs = EvidenceStore::recover(directory.path())?;
    assert_eq!(runs.len(), 2);
    let first_run = one_run(&runs, first_id)?;
    let second_run = one_run(&runs, second_id)?;
    assert!(first_run.events.iter().all(|item| item.run_id == first_id));
    assert!(second_run
        .events
        .iter()
        .all(|item| item.run_id == second_id));
    assert!(first_run.events[0].details.join(" ").contains("alpha-only"));
    assert!(!first_run.events[0].details.join(" ").contains("beta-only"));
    assert!(second_run.events[0].details.join(" ").contains("beta-only"));
    assert_eq!(first_run.events[0].actor.as_deref(), Some("P1"));
    assert_eq!(first_run.events[1].actor.as_deref(), Some("P1"));
    assert_eq!(first_run.events[0].target.as_deref(), Some("F1"));
    assert_eq!(first_run.events[1].target.as_deref(), Some("F1"));
    assert_eq!(second_run.events[0].actor.as_deref(), Some("P1"));
    assert_eq!(second_run.events[0].target.as_deref(), Some("F1"));

    let mut left = RunLabels::new(first_id);
    let mut right = RunLabels::new(second_id);
    assert_eq!(left.process_label(&process), "P1");
    assert_eq!(
        left.process_label(&ProcessIdentity {
            pid: 42,
            start_generation: 1
        }),
        "P2"
    );
    assert_eq!(right.process_label(&process), "P1");
    assert_eq!(left.process_label(&process), "P1");
    assert_eq!(left.file_label("/tmp/a"), "F1");
    assert_eq!(left.file_label("/tmp/b"), "F2");
    assert_eq!(right.file_label("/tmp/a"), "F1");
    assert_eq!(right.file_label("/tmp/b"), "F2");
    Ok(())
}

#[test]
fn torn_unacknowledged_frame_recovers_as_incomplete_with_unknown_loss() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let store = EvidenceStore::new(directory.path())?;
    let mut writer = store.begin_run_with_metadata(provenance(), complete_metadata())?;
    let run_id = writer.run_id();
    writer.append(&process_exec(
        run_id,
        1,
        ProcessIdentity {
            pid: 7,
            start_generation: 1,
        },
        "/tmp/tool",
        Vec::new(),
    ))?;
    drop(writer);

    let run_dir = directory.path().join("runs").join(run_id.to_string());
    let offset = acknowledged_journal_bytes(&run_dir)?;
    let raw = OpenOptions::new()
        .write(true)
        .open(run_dir.join("raw.reserve"))?;
    write_all_at(&raw, &[0, 0, 0, 80, b'{', b'"', b'e', b'v'], offset)?;
    raw.sync_all()?;

    let recovered = EvidenceStore::recover(directory.path())?;
    let run = one_run(&recovered, run_id)?;
    assert_eq!(run.run.state, RunState::Incomplete);
    assert_eq!(run.run.coverage.state, CoverageState::Unknown);
    assert_eq!(run.run.coverage.event_loss_count, None);
    assert_eq!(run.events.len(), 1);
    assert_eq!(run.events[0].seq, 1);
    Ok(())
}

#[test]
fn output_and_event_caps_preserve_earlier_observations() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let store = EvidenceStore::with_config(
        directory.path(),
        StoreConfig {
            max_events: 2,
            ..StoreConfig::default()
        },
    )?;
    let mut writer =
        store.begin_run_with_metadata(provenance(), metadata(Vec::new(), Vec::new()))?;
    let run_id = writer.run_id();
    writer.append(&event(
        run_id,
        1,
        PrivateFields::Stdout {
            bytes: vec![b'x'; MAX_STDOUT_BYTES + 64],
        },
    ))?;
    writer.append(&process_exit(
        run_id,
        2,
        ProcessIdentity {
            pid: 1,
            start_generation: 1,
        },
    ))?;
    assert!(writer
        .append(&process_exit(
            run_id,
            3,
            ProcessIdentity {
                pid: 1,
                start_generation: 1
            },
        ))
        .is_err());
    writer.seal(RunState::Incomplete)?;

    let recovered = EvidenceStore::recover(directory.path())?;
    let run = one_run(&recovered, run_id)?;
    assert_eq!(run.events.len(), 2);
    assert_eq!(run.events[0].seq, 1);
    assert_eq!(run.events[1].seq, 2);
    assert_eq!(
        run.events[0].text.as_deref().map(str::len),
        Some(MAX_STDOUT_BYTES)
    );
    assert!(run.events[0]
        .redacted_fields
        .iter()
        .any(|field| field == "stdout:truncated"));
    assert_eq!(run.run.coverage.state, CoverageState::Partial);
    assert!(run
        .run
        .coverage
        .reasons
        .contains(&CoverageReason::OutputTruncated));
    assert!(run
        .run
        .coverage
        .reasons
        .contains(&CoverageReason::EventLimit));
    assert_eq!(run.run.coverage.event_loss_count, Some(1));
    Ok(())
}

#[test]
fn redactor_sanitizes_nested_fields_and_preserves_benign_route_text() -> Result<()> {
    let redactor = Redactor::new()?;
    let run_id = RunId([1; 16]);
    let process = ProcessIdentity {
        pid: 5,
        start_generation: 3,
    };
    let observed = event(
        run_id,
        1,
        PrivateFields::ProcessExec {
            process: process.clone(),
            executable: "/tmp/tool".to_string(),
            arguments: vec![
                "Authorization: Bearer example-secret".to_string(),
                "https://alice:password@example.invalid/path".to_string(),
                "https://host.invalid/?token=url-canary".to_string(),
                "import benign.module".to_string(),
                "fetch(\"https://example.invalid/package\")".to_string(),
            ],
            cwd: Some("/Users/alice/work".to_string()),
            environment: vec![supply_core::application::detonation::EnvironmentVariable {
                name: "API_TOKEN".to_string(),
                value: "nested-canary".to_string(),
            }],
        },
    );
    let mut labels = RunLabels::new(run_id);
    let public = project_event(&observed, &mut labels, &redactor)?;
    let rendered = public.details.join("\n");
    assert!(rendered.contains("Authorization: Bearer [REDACTED]"));
    assert!(rendered.contains("https://example.invalid/path"));
    assert!(rendered.contains("https://host.invalid/?token=[REDACTED]"));
    assert!(rendered.contains("import benign.module"));
    assert!(rendered.contains("fetch(\"https://example.invalid/package\")"));
    assert!(!rendered.contains("example-secret"));
    assert!(!rendered.contains("alice:password"));
    assert!(!rendered.contains("url-canary"));
    assert!(!rendered.contains("nested-canary"));
    assert!(!rendered.contains("/Users/alice"));
    assert!(!public.redacted_fields.is_empty());

    let file_event = event(
        run_id,
        2,
        PrivateFields::FileOpen {
            process: Some(process),
            path: "/home/fixture/private-path".to_string(),
            flags: None,
        },
    );
    let file_public = project_event(&file_event, &mut labels, &redactor)?;
    assert!(!file_public.details.join(" ").contains("/home/fixture"));
    assert_eq!(file_public.target.as_deref(), Some("F2"));
    Ok(())
}

#[test]
fn redactor_catches_credentials_in_prefixed_environment_names() -> Result<()> {
    let redactor = Redactor::new()?;
    let run_id = RunId([2; 16]);
    let observed = event(
        run_id,
        1,
        PrivateFields::ProcessExec {
            process: ProcessIdentity {
                pid: 6,
                start_generation: 1,
            },
            executable: "/tmp/tool".to_string(),
            arguments: Vec::new(),
            cwd: None,
            environment: vec![
                supply_core::application::detonation::EnvironmentVariable {
                    name: "DB_PASSWORD".to_string(),
                    value: "database-canary".to_string(),
                },
                supply_core::application::detonation::EnvironmentVariable {
                    name: "STRIPE_SECRET_KEY".to_string(),
                    value: "stripe-canary".to_string(),
                },
            ],
        },
    );
    let public = project_event(&observed, &mut RunLabels::new(run_id), &redactor)?;
    let rendered = public.details.join("\n");
    assert!(rendered.contains("DB_PASSWORD=[REDACTED]"));
    assert!(rendered.contains("STRIPE_SECRET_KEY=[REDACTED]"));
    assert!(!rendered.contains("database-canary"));
    assert!(!rendered.contains("stripe-canary"));
    Ok(())
}

#[test]
fn redactor_strips_userinfo_from_non_http_urls() -> Result<()> {
    let redactor = Redactor::new()?;
    for (input, expected) in [
        (
            "ftp://alice:password@example.invalid/path",
            "ftp://example.invalid/path",
        ),
        (
            "prefixftp://alice:password@example.invalid/path",
            "prefixftp://example.invalid/path",
        ),
    ] {
        let result = redactor.redact_text(input, "argument");
        assert_eq!(result.text.as_deref(), Some(expected));
        assert!(!result.redacted_fields.is_empty());
    }
    Ok(())
}

#[test]
fn large_valid_metadata_seals_and_recovers() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let store = EvidenceStore::new(directory.path())?;
    let mut run_metadata = metadata(Phase::ALL.to_vec(), Sensor::ALL.to_vec());
    run_metadata.package_name = Some("p".repeat(1800));
    let mut writer = store.begin_run_with_metadata(provenance(), run_metadata)?;
    let run_id = writer.run_id();
    let process = ProcessIdentity {
        pid: 7,
        start_generation: 1,
    };
    let mut seq = 0;
    for phase in Phase::ALL {
        for sensor in Sensor::ALL {
            seq += 1;
            let mut observed = process_exec(run_id, seq, process.clone(), "/tmp/tool", Vec::new());
            observed.phase = phase;
            observed.sensor = sensor;
            writer.append(&observed)?;
        }
    }
    writer.seal(RunState::Complete)?;
    let recovered = EvidenceStore::recover(directory.path())?;
    assert_eq!(one_run(&recovered, run_id)?.run.state, RunState::Complete);
    Ok(())
}

#[test]
fn admitted_metadata_can_always_be_recovered() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let store = EvidenceStore::new(directory.path())?;
    let mut run_metadata = metadata(Phase::ALL.to_vec(), Sensor::ALL.to_vec());
    run_metadata.package_name = Some("p".repeat(2600));
    let mut writer = match store.begin_run_with_metadata(provenance(), run_metadata) {
        Ok(writer) => writer,
        Err(_) => return Ok(()),
    };
    let run_id = writer.run_id();
    let process = ProcessIdentity {
        pid: 7,
        start_generation: 1,
    };
    let mut seq = 0;
    for phase in Phase::ALL {
        for sensor in Sensor::ALL {
            seq += 1;
            let mut observed = process_exec(run_id, seq, process.clone(), "/tmp/tool", Vec::new());
            observed.phase = phase;
            observed.sensor = sensor;
            writer.append(&observed)?;
        }
    }
    writer.seal(RunState::Complete)?;
    let recovered = EvidenceStore::recover(directory.path())?;
    assert_eq!(one_run(&recovered, run_id)?.run.state, RunState::Complete);
    Ok(())
}

#[test]
fn redactor_handles_split_streams_controls_invalid_bytes_and_idempotence() -> Result<()> {
    let redactor = Redactor::new()?;
    let stdout = redactor.redact_chunks(
        &[
            b"request started Authorization: Bearer example-",
            b"secret then done",
        ],
        "stdout",
        MAX_STDOUT_BYTES,
    );
    let stdout_text = stdout
        .iter()
        .map(|chunk| chunk.text.as_deref().unwrap_or_default())
        .collect::<String>();
    assert_eq!(
        stdout_text,
        "request started Authorization: Bearer [REDACTED] then done"
    );
    assert!(!stdout_text.contains("example-secret"));
    assert!(stdout.iter().any(|chunk| !chunk.redacted_fields.is_empty()));
    let idempotent = redactor.redact_text(&stdout_text, "stdout");
    assert_eq!(idempotent.text.as_deref(), Some(stdout_text.as_str()));

    let stderr = redactor.redact_chunks(
        &[
            b"before https://host.invalid/?token=stderr-",
            b"canary after",
        ],
        "stderr",
        MAX_STDOUT_BYTES,
    );
    let stderr_text = stderr
        .iter()
        .map(|chunk| chunk.text.as_deref().unwrap_or_default())
        .collect::<String>();
    assert_eq!(
        stderr_text,
        "before https://host.invalid/?token=[REDACTED] after"
    );

    let controls = redactor.redact_text("safe\u{202e}text\u{1b}[31mred\u{1b}[0m", "argument");
    assert_eq!(controls.text.as_deref(), Some("safetextred"));
    assert!(!controls.redacted_fields.is_empty());
    assert_eq!(
        redactor
            .redact_bytes(&[0xff], "stdout", 100)
            .withheld_reason,
        Some(WithheldReason::InvalidUtf8)
    );
    assert_eq!(
        redactor
            .redact_bytes(b"a\0b", "stderr", 100)
            .withheld_reason,
        Some(WithheldReason::BinaryContent)
    );
    assert_eq!(
        redactor
            .redact_text(&"x".repeat(MAX_FIELD_BYTES + 1), "argument")
            .withheld_reason,
        Some(WithheldReason::Overlong)
    );

    let unsupported = event(
        RunId([2; 16]),
        1,
        PrivateFields::OtherObserved {
            payload: serde_json::json!({"nested": {"token": "never-public"}}),
        },
    );
    let mut labels = RunLabels::new(unsupported.run_id);
    let projected = project_event(&unsupported, &mut labels, &redactor)?;
    assert_eq!(
        projected.withheld_reason,
        Some(WithheldReason::UnsupportedEvent)
    );
    assert!(!serde_json::to_string(&projected)?.contains("never-public"));
    Ok(())
}

#[test]
fn repeated_sequence_and_conflicting_run_id_fail_closed() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let store = EvidenceStore::new(directory.path())?;
    let process = ProcessIdentity {
        pid: 8,
        start_generation: 1,
    };

    let mut repeated = store.begin_run_with_metadata(provenance(), complete_metadata())?;
    let repeated_id = repeated.run_id();
    repeated.append(&process_exec(
        repeated_id,
        1,
        process.clone(),
        "/tmp/tool",
        Vec::new(),
    ))?;
    assert!(repeated
        .append(&process_exit(repeated_id, 1, process.clone()))
        .is_err());
    drop(repeated);

    let mut conflicting = store.begin_run_with_metadata(provenance(), complete_metadata())?;
    let conflicting_id = conflicting.run_id();
    conflicting.append(&process_exec(
        conflicting_id,
        1,
        process.clone(),
        "/tmp/tool",
        Vec::new(),
    ))?;
    assert!(conflicting
        .append(&process_exit(RunId([0x55; 16]), 2, process))
        .is_err());
    drop(conflicting);

    let recovered = EvidenceStore::recover(directory.path())?;
    for id in [repeated_id, conflicting_id] {
        let run = one_run(&recovered, id)?;
        assert_eq!(run.run.state, RunState::Incomplete);
        assert_eq!(run.run.coverage.state, CoverageState::Unknown);
        assert_eq!(run.events.len(), 1);
        assert_eq!(run.events[0].seq, 1);
    }
    Ok(())
}

#[test]
fn quota_exhaustion_keeps_acknowledged_evidence_and_control_state() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let store = EvidenceStore::with_config(
        directory.path(),
        StoreConfig {
            max_store_bytes: RESERVATION_BYTES,
            ..StoreConfig::default()
        },
    )?;
    let mut writer = store.begin_run_with_metadata(provenance(), complete_metadata())?;
    let run_id = writer.run_id();
    writer.append(&process_exec(
        run_id,
        1,
        ProcessIdentity {
            pid: 9,
            start_generation: 1,
        },
        "/tmp/tool",
        Vec::new(),
    ))?;
    assert_eq!(store.used_bytes()?, RESERVATION_BYTES);
    assert!(store.begin_run(provenance()).is_err());
    drop(writer);

    let recovered = EvidenceStore::recover(directory.path())?;
    let run = one_run(&recovered, run_id)?;
    assert_eq!(run.run.state, RunState::Incomplete);
    assert_eq!(run.run.coverage.event_loss_count, None);
    assert_eq!(run.events.len(), 1);
    Ok(())
}

#[test]
fn missing_and_symlink_paths_fail_without_removing_existing_files() -> Result<()> {
    let parent = tempfile::tempdir()?;
    let missing = parent.path().join("missing-evidence");
    assert!(EvidenceStore::recover(&missing).is_err());
    assert!(!missing.exists());

    let root = parent.path().join("store");
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let lock_path = root.join(".detonation-store.lock");
    fs::write(&lock_path, b"preserve existing bytes")?;
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))?;
    let store = EvidenceStore::new(&root)?;
    assert_eq!(fs::read(&lock_path)?, b"preserve existing bytes");
    drop(store);

    let outside = tempfile::tempdir()?;
    let run_id = RunId([0x44; 16]);
    symlink(outside.path(), root.join("runs").join(run_id.to_string()))?;
    assert!(EvidenceStore::recover(&root).is_err());
    assert!(outside.path().exists());
    Ok(())
}

#[test]
fn protected_roots_are_resolved_before_creation() -> Result<()> {
    let parent = tempfile::tempdir()?;
    let public = parent.path().join("public");
    let alias = parent.path().join("public-alias");
    fs::create_dir(&public)?;
    symlink(&public, &alias)?;
    let root = alias.join("private-evidence");
    let config = StoreConfig {
        artifacts_dir: Some(public.clone()),
        ..StoreConfig::default()
    };
    assert!(EvidenceStore::with_config(&root, config).is_err());
    assert!(!public.join("private-evidence").exists());
    Ok(())
}

#[test]
fn sealed_digest_mismatch_is_rejected() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let store = EvidenceStore::new(directory.path())?;
    let mut writer = store.begin_run_with_metadata(provenance(), complete_metadata())?;
    let run_id = writer.run_id();
    writer.append(&process_exec(
        run_id,
        1,
        ProcessIdentity {
            pid: 10,
            start_generation: 1,
        },
        "/tmp/tool",
        Vec::new(),
    ))?;
    writer.seal(RunState::Complete)?;

    let public = directory
        .path()
        .join("runs")
        .join(run_id.to_string())
        .join("public.bundle");
    let file = OpenOptions::new().write(true).open(public)?;
    write_all_at(&file, b"!", 0)?;
    file.sync_all()?;
    assert!(EvidenceStore::recover(directory.path()).is_err());
    Ok(())
}

#[test]
fn directories_and_reserved_objects_keep_private_modes() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let store = EvidenceStore::new(directory.path())?;
    let writer = store.begin_run_with_metadata(provenance(), complete_metadata())?;
    let run_dir = directory
        .path()
        .join("runs")
        .join(writer.run_id().to_string());
    assert_eq!(fs::symlink_metadata(&run_dir)?.mode() & 0o777, 0o700);
    assert_eq!(
        fs::symlink_metadata(run_dir.join("raw.reserve"))?.mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::symlink_metadata(run_dir.join("control.reserve"))?.mode() & 0o777,
        0o600
    );
    drop(writer);
    Ok(())
}

#[test]
fn public_event_wire_types_reject_unknown_fields() -> Result<()> {
    let public = PublicEvent {
        run_id: RunId([3; 16]),
        seq: 1,
        offset_ms: None,
        phase: Phase::Install,
        sensor: Sensor::SyscallTrace,
        observation: ObservationKind::Observed,
        kind: EventKind::ProcessExit,
        outcome: Outcome::Failed,
        failure: Some(FailureKind::NotFound),
        actor: None,
        target: None,
        details: Vec::new(),
        text: None,
        redacted_fields: Vec::new(),
        withheld_reason: None,
        coverage: CoverageState::Complete,
        automatic_redaction_limitation: true,
    };
    let mut json = serde_json::to_value(public)?;
    json["unexpected"] = Value::Bool(true);
    assert!(serde_json::from_value::<PublicEvent>(json).is_err());
    Ok(())
}
