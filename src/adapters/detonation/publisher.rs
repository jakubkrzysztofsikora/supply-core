use super::{
    encode_public_bundle, redactor_build_sha256, BundleManifest, PublisherKey, PROJECTION_VERSION,
};
use crate::{
    adapters::storage::detonation::{EvidenceStore, RunMetadata, SealedRun},
    application::detonation::{RunId, RunState, REDACTION_POLICY_VERSION},
};
use anyhow::{bail, ensure, Context, Result};
use reqwest::{redirect::Policy, Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::IpAddr,
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

const PENDING_DIR: &str = ".detonation-pending";
const PUBLISHER_KEY_FILE: &str = "publisher-hmac-key.json";
const CONTROL_RECORD_OFFSET: u64 = 8192;
const CONTROL_RECORD_LIMIT: usize = 3500;
const MAX_SECRET_FILE_BYTES: u64 = 64 * 1024;
const MAX_RECEIPT_BYTES: u64 = 4096;
const MAX_ACK_BYTES: usize = 4096;

#[derive(Deserialize)]
struct EvidenceManifest {
    run_id: RunId,
    state: RunState,
    metadata: RunMetadata,
    actual_phases: Vec<crate::application::detonation::Phase>,
    acknowledged_sensors: Vec<crate::application::detonation::Sensor>,
    durable_seq: u64,
    ended_at_unix_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublisherKeyFile {
    key_id: String,
    key_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishAcknowledgement {
    state: String,
    run_id: RunId,
    bundle_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SealedReceipt {
    endpoint: String,
    run_id: String,
    bundle_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConflictMarker {
    endpoint: String,
    run_id: String,
    bundle_sha256: String,
}

enum UploadOutcome {
    Pending,
    Sealed(String),
    Conflict(String),
}

pub async fn publish_pending(
    public_url: &str,
    ingest_token_file: &Path,
    evidence_dir: &Path,
    pending: bool,
) -> Result<usize> {
    ensure!(pending, "--pending is required for durable publication");
    let signing_key = read_publisher_key(&evidence_dir.join(PUBLISHER_KEY_FILE))?;
    let pending_dir = evidence_dir.join(PENDING_DIR);
    ensure_private_directory(&pending_dir)?;
    let runs = EvidenceStore::recover(evidence_dir).context("recover sealed detonation runs")?;
    for run in runs {
        let id = run.run.run_id;
        let path = pending_path(&pending_dir, id);
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let bytes = create_bundle(evidence_dir, &run, &signing_key)?;
                persist_pending(&pending_dir, id, &bytes)?;
            }
            Err(error) => return Err(error).context("inspect detonation pending bundle"),
        }
    }

    let endpoint = publish_endpoint(public_url)?;
    let endpoint_identity = endpoint.as_str();
    let token = read_secret(ingest_token_file, 8192)?;
    ensure!(!token.is_empty(), "ingestion token file is empty");
    let client = Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(60))
        .build()
        .context("create detonation publisher client")?;
    let mut published = 0;
    for entry in fs::read_dir(&pending_dir).context("read pending detonation bundles")? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(id_text) = name.strip_suffix(".bundle") else {
            continue;
        };
        let Ok(id) = RunId::from_str(id_text) else {
            continue;
        };
        let bytes = read_regular_file(&path, super::MAX_BUNDLE_BYTES as u64)?;
        let bundle_sha256 = {
            let bundle =
                super::parse_public_bundle(&bytes).context("validate pending public bundle")?;
            ensure!(
                bundle.manifest.run_id == id,
                "pending bundle run ID mismatch"
            );
            bundle.manifest.bundle_sha256
        };
        if let Some(receipt) = read_receipt(&pending_dir, endpoint_identity, id)? {
            ensure!(
                receipt.bundle_sha256 == bundle_sha256,
                "pending bundle conflicts with sealed detonation receipt"
            );
            if read_conflict_marker(&pending_dir, endpoint_identity, id)?.is_some() {
                fs::remove_file(conflict_marker_path(&pending_dir, endpoint_identity, id))
                    .context("clear superseded detonation conflict marker")?;
                sync_directory(&pending_dir)?;
            }
            fs::remove_file(&path).context("clear sealed detonation pending bundle")?;
            sync_directory(&pending_dir)?;
            continue;
        }
        if let Some(marker) = read_conflict_marker(&pending_dir, endpoint_identity, id)? {
            ensure!(
                marker.bundle_sha256 != bundle_sha256,
                "pending bundle conflicts with durable server conflict marker"
            );
            fs::remove_file(conflict_marker_path(&pending_dir, endpoint_identity, id))
                .context("clear stale detonation conflict marker")?;
            sync_directory(&pending_dir)?;
        }
        match upload(&client, &endpoint, &token, id, bytes, bundle_sha256).await? {
            UploadOutcome::Pending => {}
            UploadOutcome::Sealed(bundle_sha256) => {
                persist_receipt(&pending_dir, endpoint_identity, id, &bundle_sha256)?;
                fs::remove_file(&path).context("clear accepted detonation pending bundle")?;
                sync_directory(&pending_dir)?;
                published += 1;
            }
            UploadOutcome::Conflict(bundle_sha256) => {
                persist_conflict_marker(&pending_dir, endpoint_identity, id, &bundle_sha256)?;
                bail!("detonation run {id} conflicts with existing server content");
            }
        }
    }
    Ok(published)
}

fn create_bundle(evidence_dir: &Path, run: &SealedRun, key: &PublisherKey) -> Result<Vec<u8>> {
    let private = read_private_manifest(evidence_dir, run.run.run_id)?;
    ensure!(
        private.run_id == run.run.run_id,
        "private run manifest ID mismatch"
    );
    ensure!(private.state == run.run.state, "private run state mismatch");
    let manifest = BundleManifest {
        schema_version: 1,
        projection_version: PROJECTION_VERSION,
        redaction_policy_version: REDACTION_POLICY_VERSION,
        redactor_build_sha256: redactor_build_sha256(),
        run_id: run.run.run_id,
        state: run.run.state,
        ecosystem: private.metadata.ecosystem,
        package_name: private.metadata.package_name,
        package_version: private.metadata.package_version,
        event_count: 0,
        redaction_count: 0,
        event_loss_count: run.run.coverage.event_loss_count,
        source_loss_count: run.run.coverage.source_loss_count,
        started_at_unix_ms: private.metadata.started_at_unix_ms,
        ended_at_unix_ms: private.ended_at_unix_ms,
        artifact_sha256: hex::encode(run.provenance.artifact_sha256),
        static_scan_event_id: run.provenance.static_scan_event_id.clone(),
        bundle_sha256: String::new(),
        durable_seq: private.durable_seq,
        phases: private.actual_phases,
        sensors: private.acknowledged_sensors,
        coverage: run.run.coverage.clone(),
        automatic_redaction_limitation: run.run.automatic_redaction_limitation,
        key_id: key.key_id.clone(),
        signature: String::new(),
    };
    let key_bytes = hex::decode(&key.key_hex).context("decode publisher HMAC key")?;
    ensure!(
        (32..=64).contains(&key_bytes.len()),
        "publisher HMAC key length is invalid"
    );
    encode_public_bundle(manifest, &run.events, &key.key_id, &key_bytes)
}

async fn upload(
    client: &Client,
    endpoint: &Url,
    token: &str,
    id: RunId,
    bytes: Vec<u8>,
    expected_digest: String,
) -> Result<UploadOutcome> {
    let mut run_endpoint = endpoint.clone();
    run_endpoint.set_path(&format!("{}/{id}", endpoint.path().trim_end_matches('/')));
    let mut response = client
        .put(run_endpoint)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
        .body(bytes)
        .send()
        .await
        .context("send detonation bundle")?;
    let status = response.status();
    if status == StatusCode::CONFLICT {
        return Ok(UploadOutcome::Conflict(expected_digest));
    }
    if !matches!(
        status,
        StatusCode::OK | StatusCode::CREATED | StatusCode::ACCEPTED
    ) {
        bail!("detonation server rejected bundle with HTTP {status}");
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ACK_BYTES as u64)
    {
        bail!("detonation acknowledgement exceeds limit");
    }
    let mut body = Vec::with_capacity(MAX_ACK_BYTES);
    while let Some(chunk) = response
        .chunk()
        .await
        .context("read detonation acknowledgement")?
    {
        ensure!(
            chunk.len() <= MAX_ACK_BYTES - body.len(),
            "detonation acknowledgement exceeds limit"
        );
        body.extend_from_slice(&chunk);
    }
    let acknowledgement: PublishAcknowledgement =
        serde_json::from_slice(&body).context("parse detonation acknowledgement")?;
    ensure!(
        acknowledgement.run_id == id,
        "detonation acknowledgement run ID mismatch"
    );
    let expected_state = if status == StatusCode::ACCEPTED {
        "pending"
    } else {
        "sealed"
    };
    ensure!(
        acknowledgement.state == expected_state,
        "detonation acknowledgement state mismatch"
    );
    ensure!(
        acknowledgement.bundle_sha256.len() == 64
            && hex::decode(&acknowledgement.bundle_sha256).is_ok(),
        "detonation acknowledgement digest is invalid"
    );
    if status == StatusCode::ACCEPTED {
        ensure!(
            acknowledgement.bundle_sha256 == expected_digest,
            "detonation acknowledgement digest mismatch"
        );
        return Ok(UploadOutcome::Pending);
    }
    if acknowledgement.bundle_sha256 != expected_digest {
        return Ok(UploadOutcome::Conflict(expected_digest));
    }
    Ok(UploadOutcome::Sealed(expected_digest))
}

fn publish_endpoint(public_url: &str) -> Result<Url> {
    let mut url = Url::parse(public_url).context("parse public URL")?;
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "public URL cannot contain credentials"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "public URL cannot contain query or fragment"
    );
    if url.scheme() != "https" {
        let host = url.host_str().context("public URL has no host")?;
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback());
        ensure!(loopback, "HTTPS is required outside loopback");
        ensure!(url.scheme() == "http", "public URL scheme is unsupported");
    }
    let base_path = url.path().trim_end_matches('/');
    url.set_path(&format!("{base_path}/api/v1/detonations"));
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn read_publisher_key(path: &Path) -> Result<PublisherKey> {
    let bytes = read_secret(path, MAX_SECRET_FILE_BYTES)?;
    let key: PublisherKeyFile =
        serde_json::from_str(&bytes).context("parse publisher HMAC key file")?;
    ensure!(
        !key.key_id.is_empty() && key.key_id.len() <= 128,
        "publisher key ID is invalid"
    );
    let key_bytes = hex::decode(&key.key_hex).context("decode publisher key")?;
    ensure!(
        (32..=64).contains(&key_bytes.len()),
        "publisher HMAC key length is invalid"
    );
    Ok(PublisherKey {
        key_id: key.key_id,
        key_hex: hex::encode(key_bytes),
    })
}

fn read_private_manifest(evidence_dir: &Path, id: RunId) -> Result<EvidenceManifest> {
    let path = evidence_dir
        .join("runs")
        .join(id.to_string())
        .join("manifest.json");
    let metadata = fs::symlink_metadata(&path).context("inspect private run manifest")?;
    ensure!(
        metadata.file_type().is_file(),
        "private run manifest is not regular"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .context("open private run manifest")?;
    let length_bytes = read_exact_at(&file, CONTROL_RECORD_OFFSET, 4)?;
    let length = u32::from_be_bytes(
        length_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("manifest length is invalid"))?,
    ) as usize;
    ensure!(
        length > 0 && length + 36 <= CONTROL_RECORD_LIMIT,
        "private run manifest exceeds limit"
    );
    let payload = read_exact_at(&file, CONTROL_RECORD_OFFSET + 4, length)?;
    let digest = read_exact_at(&file, CONTROL_RECORD_OFFSET + 4 + length as u64, 32)?;
    ensure!(
        Sha256::digest(&payload).as_slice() == digest,
        "private run manifest digest mismatch"
    );
    serde_json::from_slice(&payload).context("parse private run manifest")
}

fn read_exact_at(file: &File, mut offset: u64, length: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0; length];
    let mut remaining = bytes.as_mut_slice();
    while !remaining.is_empty() {
        let count = file.read_at(remaining, offset)?;
        ensure!(count > 0, "private manifest is truncated");
        offset = offset.saturating_add(count as u64);
        remaining = &mut remaining[count..];
    }
    Ok(bytes)
}

fn read_secret(path: &Path, max_bytes: u64) -> Result<String> {
    let metadata = fs::symlink_metadata(path).context("inspect secret file")?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() > 0 && metadata.len() <= max_bytes,
        "secret file is invalid"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .context("open secret file")?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == metadata.len() && bytes.len() as u64 <= max_bytes,
        "secret file changed while reading"
    );
    Ok(std::str::from_utf8(&bytes)?.trim().to_string())
}

fn read_regular_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).context("inspect pending file")?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() <= max_bytes,
        "pending bundle is invalid"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .context("open pending bundle")?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == metadata.len() && bytes.len() as u64 <= max_bytes,
        "pending bundle changed while reading"
    );
    Ok(bytes)
}

fn persist_pending(directory: &Path, id: RunId, bytes: &[u8]) -> Result<()> {
    let temp = directory.join(format!(".{}.{}.tmp", id, random_id()?));
    let final_path = pending_path(directory, id);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)
        .context("create pending bundle")?;
    file.write_all(bytes).context("write pending bundle")?;
    file.sync_all().context("sync pending bundle")?;
    fs::hard_link(&temp, &final_path).context("commit pending bundle")?;
    sync_directory(directory)?;
    fs::remove_file(temp).context("remove pending staging file")?;
    sync_directory(directory)?;
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => ensure!(
            metadata.file_type().is_dir() && metadata.mode() & 0o077 == 0,
            "pending directory is not private"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).context("create pending directory")?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .context("protect pending directory")?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .context("sync publication directory")
}

fn endpoint_record_path(directory: &Path, endpoint: &str, id: RunId, suffix: &str) -> PathBuf {
    let mut digest = Sha256::new();
    digest.update(endpoint.as_bytes());
    digest.update([0]);
    digest.update(id.to_string().as_bytes());
    directory.join(format!("{id}.{}.{suffix}", hex::encode(digest.finalize())))
}

fn receipt_path(directory: &Path, endpoint: &str, id: RunId) -> PathBuf {
    endpoint_record_path(directory, endpoint, id, "sealed")
}

fn conflict_marker_path(directory: &Path, endpoint: &str, id: RunId) -> PathBuf {
    endpoint_record_path(directory, endpoint, id, "conflict")
}

fn read_receipt(directory: &Path, endpoint: &str, id: RunId) -> Result<Option<SealedReceipt>> {
    let path = receipt_path(directory, endpoint, id);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect sealed detonation receipt"),
    };
    ensure!(
        metadata.file_type().is_file() && metadata.mode() & 0o077 == 0,
        "sealed detonation receipt is not private"
    );
    let bytes = read_regular_file(&path, MAX_RECEIPT_BYTES)?;
    let receipt: SealedReceipt =
        serde_json::from_slice(&bytes).context("parse sealed detonation receipt")?;
    ensure!(
        receipt.endpoint == endpoint && receipt.run_id == id.to_string(),
        "sealed detonation receipt identity mismatch"
    );
    ensure!(
        receipt.bundle_sha256.len() == 64 && hex::decode(&receipt.bundle_sha256).is_ok(),
        "sealed detonation receipt digest is invalid"
    );
    Ok(Some(receipt))
}

fn read_conflict_marker(
    directory: &Path,
    endpoint: &str,
    id: RunId,
) -> Result<Option<ConflictMarker>> {
    let path = conflict_marker_path(directory, endpoint, id);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect detonation conflict marker"),
    };
    ensure!(
        metadata.file_type().is_file() && metadata.mode() & 0o077 == 0,
        "detonation conflict marker is not private"
    );
    let bytes = read_regular_file(&path, MAX_RECEIPT_BYTES)?;
    let marker: ConflictMarker =
        serde_json::from_slice(&bytes).context("parse detonation conflict marker")?;
    ensure!(
        marker.endpoint == endpoint && marker.run_id == id.to_string(),
        "detonation conflict marker identity mismatch"
    );
    ensure!(
        marker.bundle_sha256.len() == 64 && hex::decode(&marker.bundle_sha256).is_ok(),
        "detonation conflict marker digest is invalid"
    );
    Ok(Some(marker))
}

fn persist_conflict_marker(
    directory: &Path,
    endpoint: &str,
    id: RunId,
    bundle_sha256: &str,
) -> Result<()> {
    let marker = ConflictMarker {
        endpoint: endpoint.to_string(),
        run_id: id.to_string(),
        bundle_sha256: bundle_sha256.to_string(),
    };
    let bytes = serde_json::to_vec(&marker).context("serialize detonation conflict marker")?;
    ensure!(
        bytes.len() as u64 <= MAX_RECEIPT_BYTES,
        "detonation conflict marker exceeds limit"
    );
    let temp = directory.join(format!(".{}.{}.tmp", id, random_id()?));
    let final_path = conflict_marker_path(directory, endpoint, id);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)
        .context("create detonation conflict marker")?;
    file.write_all(&bytes)
        .context("write detonation conflict marker")?;
    file.sync_all().context("sync detonation conflict marker")?;
    fs::hard_link(&temp, &final_path).context("commit detonation conflict marker")?;
    sync_directory(directory)?;
    fs::remove_file(temp).context("remove detonation conflict staging file")?;
    sync_directory(directory)?;
    Ok(())
}

fn persist_receipt(directory: &Path, endpoint: &str, id: RunId, bundle_sha256: &str) -> Result<()> {
    let receipt = SealedReceipt {
        endpoint: endpoint.to_string(),
        run_id: id.to_string(),
        bundle_sha256: bundle_sha256.to_string(),
    };
    let bytes = serde_json::to_vec(&receipt).context("serialize sealed detonation receipt")?;
    ensure!(
        bytes.len() as u64 <= MAX_RECEIPT_BYTES,
        "sealed detonation receipt exceeds limit"
    );
    let temp = directory.join(format!(".{}.{}.tmp", id, random_id()?));
    let final_path = receipt_path(directory, endpoint, id);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)
        .context("create sealed detonation receipt")?;
    file.write_all(&bytes)
        .context("write sealed detonation receipt")?;
    file.sync_all().context("sync sealed detonation receipt")?;
    fs::hard_link(&temp, &final_path).context("commit sealed detonation receipt")?;
    sync_directory(directory)?;
    fs::remove_file(temp).context("remove sealed receipt staging file")?;
    sync_directory(directory)?;
    Ok(())
}

fn pending_path(directory: &Path, id: RunId) -> PathBuf {
    directory.join(format!("{id}.bundle"))
}

fn random_id() -> Result<String> {
    let mut bytes = [0; 8];
    getrandom::fill(&mut bytes)?;
    Ok(hex::encode(bytes))
}
