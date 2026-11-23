use crate::application::detonation::{
    Coverage, EventKind, Phase, PublicEvent, RunId, RunState, Sensor, REDACTION_POLICY_VERSION,
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod publisher;

pub const PROJECTION_VERSION: u32 = 1;
pub const MAX_BUNDLE_BYTES: usize = 25 * 1024 * 1024 + 64 * 1024;
pub const MAX_EVENT_RECORD_BYTES: usize = 16 * 1024;
pub const MAX_EVENT_COUNT: usize = 4096;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub schema_version: u32,
    pub projection_version: u32,
    pub redaction_policy_version: u32,
    pub redactor_build_sha256: String,
    pub run_id: RunId,
    pub state: RunState,
    pub ecosystem: Option<String>,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub event_count: u64,
    pub redaction_count: u64,
    pub event_loss_count: Option<u64>,
    pub source_loss_count: Option<u64>,
    pub started_at_unix_ms: u64,
    pub ended_at_unix_ms: u64,
    pub artifact_sha256: String,
    pub static_scan_event_id: Option<String>,
    pub bundle_sha256: String,
    pub durable_seq: u64,
    pub phases: Vec<Phase>,
    pub sensors: Vec<Sensor>,
    pub coverage: Coverage,
    pub automatic_redaction_limitation: bool,
    pub key_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "record", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum BundleLine {
    Manifest { manifest: Box<BundleManifest> },
    Event { event: PublicEvent },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerKeyFile {
    pub keys: Vec<PublisherKey>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublisherKey {
    pub key_id: String,
    pub key_hex: String,
}

pub(crate) struct ParsedBundle {
    pub manifest: BundleManifest,
    pub events: Vec<PublicEvent>,
    pub event_bytes: Vec<u8>,
}

pub fn redactor_build_sha256() -> String {
    hex::encode(Sha256::digest(include_bytes!(
        "../../application/detonation.rs"
    )))
}

pub fn encode_public_bundle(
    mut manifest: BundleManifest,
    events: &[PublicEvent],
    key_id: &str,
    key: &[u8],
) -> Result<Vec<u8>> {
    ensure!(!key.is_empty(), "publisher HMAC key is empty");
    ensure!(events.len() <= MAX_EVENT_COUNT, "event count exceeds limit");
    ensure!(manifest.run_id.to_string().len() == 32, "run ID is invalid");
    let mut event_bytes = Vec::new();
    let mut previous_seq = 0;
    for event in events {
        ensure!(event.run_id == manifest.run_id, "event run ID mismatch");
        ensure!(event.seq > previous_seq, "event sequence is not increasing");
        previous_seq = event.seq;
        let line = serde_json::to_vec(&BundleLine::Event {
            event: event.clone(),
        })?;
        ensure!(
            line.len() <= MAX_EVENT_RECORD_BYTES,
            "event record exceeds limit"
        );
        event_bytes.extend_from_slice(&line);
        event_bytes.push(b'\n');
    }
    manifest.event_count = events.len() as u64;
    manifest.durable_seq = manifest.durable_seq.max(previous_seq);
    manifest.redaction_count = events
        .iter()
        .map(|event| event.redacted_fields.len() as u64)
        .sum();
    manifest.bundle_sha256 = hex::encode(Sha256::digest(&event_bytes));
    manifest.key_id = key_id.to_string();
    manifest.signature.clear();
    let signing_bytes = signing_bytes(&manifest, &event_bytes)?;
    manifest.signature = hex::encode(hmac_sha256(key, &signing_bytes));
    let mut bundle = serde_json::to_vec(&BundleLine::Manifest {
        manifest: Box::new(manifest),
    })?;
    bundle.push(b'\n');
    bundle.extend_from_slice(&event_bytes);
    ensure!(bundle.len() <= MAX_BUNDLE_BYTES, "bundle exceeds limit");
    Ok(bundle)
}

pub(crate) fn parse_public_bundle(bytes: &[u8]) -> Result<ParsedBundle> {
    ensure!(!bytes.is_empty(), "bundle is empty");
    ensure!(bytes.len() <= MAX_BUNDLE_BYTES, "bundle exceeds limit");
    ensure!(bytes.last() == Some(&b'\n'), "bundle lacks final newline");
    let mut lines = bytes.split(|byte| *byte == b'\n');
    let manifest_line = lines.next().context("bundle manifest is missing")?;
    ensure!(
        !manifest_line.is_empty() && manifest_line.len() <= MAX_EVENT_RECORD_BYTES,
        "manifest record exceeds limit"
    );
    let manifest_record: BundleLine = serde_json::from_slice(manifest_line)?;
    let BundleLine::Manifest { manifest } = manifest_record else {
        anyhow::bail!("bundle manifest must be first");
    };
    ensure!(
        serde_json::to_vec(&BundleLine::Manifest {
            manifest: manifest.clone(),
        })? == manifest_line,
        "manifest record is not canonical"
    );
    let mut events = Vec::new();
    let mut event_bytes = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        ensure!(
            line.len() <= MAX_EVENT_RECORD_BYTES,
            "event record exceeds limit"
        );
        let record: BundleLine = serde_json::from_slice(line)?;
        let BundleLine::Event { event } = record else {
            anyhow::bail!("manifest is repeated");
        };
        ensure!(
            serde_json::to_vec(&BundleLine::Event {
                event: event.clone(),
            })? == line,
            "event record is not canonical"
        );
        event_bytes.extend_from_slice(line);
        event_bytes.push(b'\n');
        events.push(event);
        ensure!(events.len() <= MAX_EVENT_COUNT, "event count exceeds limit");
    }
    ensure!(
        manifest.event_count == events.len() as u64,
        "event count mismatch"
    );
    ensure!(
        manifest.bundle_sha256 == hex::encode(Sha256::digest(&event_bytes)),
        "bundle digest mismatch"
    );
    Ok(ParsedBundle {
        manifest: *manifest,
        events,
        event_bytes,
    })
}

pub(crate) fn signing_bytes(manifest: &BundleManifest, event_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut unsigned = manifest.clone();
    unsigned.signature.clear();
    let mut bytes = serde_json::to_vec(&BundleLine::Manifest {
        manifest: Box::new(unsigned),
    })?;
    bytes.push(b'\n');
    bytes.extend_from_slice(event_bytes);
    Ok(bytes)
}

pub(crate) fn hmac_sha256(key: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut key_block = [0_u8; 64];
    if key.len() > key_block.len() {
        key_block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for (index, byte) in key_block.iter().copied().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(bytes);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

pub(crate) fn redaction_count(events: &[PublicEvent]) -> u64 {
    events
        .iter()
        .map(|event| event.redacted_fields.len() as u64)
        .sum()
}

pub(crate) fn event_loss_is_consistent(manifest: &BundleManifest, events: &[PublicEvent]) -> bool {
    let mut missing = 0_u64;
    let mut previous = 0_u64;
    for event in events {
        if event.seq == 0 || event.seq <= previous || event.run_id != manifest.run_id {
            return false;
        }
        missing = missing.saturating_add(event.seq.saturating_sub(previous.saturating_add(1)));
        previous = event.seq;
    }
    missing = missing.saturating_add(manifest.durable_seq.saturating_sub(previous));
    match manifest.event_loss_count {
        Some(count) => count == missing,
        None => true,
    }
}

pub(crate) fn kind_matches_text(event: &PublicEvent) -> bool {
    match event.kind {
        EventKind::Stdout | EventKind::Stderr => true,
        _ => event.text.is_none(),
    }
}

pub(crate) fn redaction_policy_matches(version: u32) -> bool {
    version == REDACTION_POLICY_VERSION
}
