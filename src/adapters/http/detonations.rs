use crate::{
    adapters::{
        detonation::{
            constant_time_eq, event_loss_is_consistent, hmac_sha256, parse_public_bundle,
            redaction_count, redaction_policy_matches, redactor_build_sha256, signing_bytes,
            BundleLine, BundleManifest, ParsedBundle, ServerKeyFile, MAX_BUNDLE_BYTES,
            MAX_EVENT_COUNT, PROJECTION_VERSION,
        },
        http::ServerConfig,
    },
    application::detonation::{
        EventKind, PublicEvent, Redactor, RunId, RunState, MAX_FIELD_BYTES, MAX_STDERR_BYTES,
        MAX_STDOUT_BYTES,
    },
};
use axum::{
    body::Body,
    extract::{Path as AxumPath, RawQuery, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
    routing::get,
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_util::StreamExt;
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, LazyLock, Mutex, OnceLock},
    time::{Duration, SystemTime},
};
use tokio::{io::AsyncWriteExt, sync::Semaphore};
use tower_http::cors::{Any, CorsLayer};

const PUBLIC_STORE_LIMIT_BYTES: u64 = 256 * 1024 * 1024;
const KEY_FILE_LIMIT_BYTES: u64 = 64 * 1024;
const TOKEN_FILE_LIMIT_BYTES: u64 = 8 * 1024;
const INGEST_TIMEOUT: Duration = Duration::from_secs(60);
const STALE_STAGE_AGE: Duration = Duration::from_secs(60 * 60);
static INGEST_SLOTS: Semaphore = Semaphore::const_new(4);
static PUBLIC_READ_SLOTS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(8)));
static PUBLISH_LOCK: Mutex<()> = Mutex::new(());
static STALE_CLEANUP_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub fn routes() -> Router<std::sync::Arc<ServerConfig>> {
    Router::new()
        .route("/api/v1/detonations", get(list_runs))
        .route("/api/v1/detonations/:run_id", get(get_run).put(publish_run))
        .route("/api/v1/detonations/:run_id/events", get(list_events))
        .route("/api/v1/detonations/:run_id/logs", get(read_logs))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([axum::http::Method::GET]),
        )
}

pub(crate) async fn route_gate(request: Request, next: Next) -> Response {
    if (request.uri().path() == "/api/v1/detonations"
        || request.uri().path().starts_with("/api/v1/detonations/"))
        && !routes_enabled()
    {
        disabled_response()
    } else {
        next.run(request).await
    }
}

#[allow(clippy::result_large_err)]
async fn read_blocking<T, F>(operation: F) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, Response> + Send + 'static,
{
    let unavailable = || {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "detonation store unavailable",
        )
    };
    let permit = PUBLIC_READ_SLOTS
        .clone()
        .try_acquire_owned()
        .map_err(|_| unavailable())?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation()
    })
    .await
    .map_err(|_| unavailable())?
}

#[derive(Serialize)]
struct RunSummary {
    run_id: RunId,
    ecosystem: Option<String>,
    package_name: Option<String>,
    package_version: Option<String>,
    state: &'static str,
    ended_at_unix_ms: u64,
    event_count: u64,
    redaction_count: u64,
}

#[derive(Serialize)]
struct LossDescriptor {
    after_seq: u64,
    before_seq: Option<u64>,
    count: Option<u64>,
}

#[derive(Serialize)]
struct PublicDetail<'a> {
    run_id: RunId,
    ecosystem: &'a Option<String>,
    package_name: &'a Option<String>,
    package_version: &'a Option<String>,
    state: &'static str,
    counts: Value,
    timestamps: Value,
    provenance: Value,
    schema_versions: Value,
    phases: &'a [crate::application::detonation::Phase],
    sensors: &'a [crate::application::detonation::Sensor],
    coverage: &'a crate::application::detonation::Coverage,
    automatic_redaction_limitation: bool,
}

#[derive(Serialize)]
struct LogSlice {
    offset: u64,
    text: String,
}

#[derive(Serialize)]
struct RedactionMarker {
    seq: u64,
    offset: u64,
    length: u64,
    fields: Vec<String>,
    withheld: Option<crate::application::detonation::WithheldReason>,
}

#[allow(clippy::result_large_err)]
async fn list_runs(
    State(state): State<std::sync::Arc<ServerConfig>>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let query = match parse_query(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return response,
    };
    let limit = match page_limit(query.get("limit")) {
        Ok(limit) => limit,
        Err(response) => return response,
    };
    let cursor = match query.get("cursor") {
        Some(value) => match decode_cursor(value) {
            Some(cursor) => Some(cursor),
            None => return api_error(StatusCode::BAD_REQUEST, "invalid cursor"),
        },
        None => None,
    };
    let runs = match read_blocking(move || {
        let root = configured_store(&state, false)?;
        read_all_manifests(&root).map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "detonation store unavailable",
            )
        })
    })
    .await
    {
        Ok(runs) => runs,
        Err(response) => return response,
    };
    let mut summaries = runs
        .iter()
        .map(|manifest| RunSummary {
            run_id: manifest.run_id,
            ecosystem: manifest.ecosystem.clone(),
            package_name: manifest.package_name.clone(),
            package_version: manifest.package_version.clone(),
            state: state_name(manifest.state),
            ended_at_unix_ms: manifest.ended_at_unix_ms,
            event_count: manifest.event_count,
            redaction_count: manifest.redaction_count,
        })
        .collect::<Vec<_>>();
    summaries.sort_by(|left, right| {
        right
            .ended_at_unix_ms
            .cmp(&left.ended_at_unix_ms)
            .then_with(|| right.run_id.to_string().cmp(&left.run_id.to_string()))
    });
    if let Some((timestamp, run_id)) = cursor {
        summaries.retain(|summary| {
            summary.ended_at_unix_ms < timestamp
                || (summary.ended_at_unix_ms == timestamp && summary.run_id.to_string() < run_id)
        });
    }
    let has_more = summaries.len() > limit;
    summaries.truncate(limit);
    let next_cursor = if has_more {
        summaries
            .last()
            .map(|summary| encode_cursor(summary.ended_at_unix_ms, &summary.run_id.to_string()))
    } else {
        None
    };
    json_response(
        StatusCode::OK,
        json!({ "runs": summaries, "next_cursor": next_cursor }),
    )
}

#[allow(clippy::result_large_err)]
async fn get_run(
    AxumPath(run_id): AxumPath<String>,
    State(state): State<std::sync::Arc<ServerConfig>>,
) -> Response {
    let id = match parse_run_id(&run_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let bundle = match read_blocking(move || {
        let root = configured_store(&state, false)?;
        read_public_bundle(&root, id)
    })
    .await
    {
        Ok(Some(bundle)) => bundle,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "not found"),
        Err(response) => return response,
    };
    let manifest = &bundle.manifest;
    let detail = PublicDetail {
        run_id: manifest.run_id,
        ecosystem: &manifest.ecosystem,
        package_name: &manifest.package_name,
        package_version: &manifest.package_version,
        state: state_name(manifest.state),
        counts: json!({
            "events": manifest.event_count,
            "redactions": manifest.redaction_count,
            "event_loss": manifest.event_loss_count,
            "source_loss": manifest.source_loss_count
        }),
        timestamps: json!({
            "started_at_unix_ms": manifest.started_at_unix_ms,
            "ended_at_unix_ms": manifest.ended_at_unix_ms
        }),
        provenance: json!({
            "artifact_sha256": manifest.artifact_sha256,
            "static_scan_event_id": manifest.static_scan_event_id,
            "bundle_sha256": manifest.bundle_sha256
        }),
        schema_versions: json!({
            "bundle": manifest.schema_version,
            "projection": manifest.projection_version,
            "redaction_policy": manifest.redaction_policy_version
        }),
        phases: &manifest.phases,
        sensors: &manifest.sensors,
        coverage: &manifest.coverage,
        automatic_redaction_limitation: manifest.automatic_redaction_limitation,
    };
    json_response(StatusCode::OK, json!({ "run": detail }))
}

#[allow(clippy::result_large_err)]
async fn list_events(
    AxumPath(run_id): AxumPath<String>,
    State(state): State<std::sync::Arc<ServerConfig>>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let id = match parse_run_id(&run_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let query = match parse_query(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return response,
    };
    let after = match parse_offset(query.get("after_seq"), "after_seq") {
        Ok(value) => value.unwrap_or(0),
        Err(response) => return response,
    };
    let limit = match page_limit(query.get("limit")) {
        Ok(limit) => limit,
        Err(response) => return response,
    };
    let bundle = match read_blocking(move || {
        let root = configured_store(&state, false)?;
        read_public_bundle(&root, id)
    })
    .await
    {
        Ok(Some(bundle)) => bundle,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "not found"),
        Err(response) => return response,
    };
    let start = bundle.events.partition_point(|event| event.seq <= after);
    let end = start.saturating_add(limit).min(bundle.events.len());
    let events = &bundle.events[start..end];
    let next_after_seq = events.last().map(|event| event.seq).unwrap_or(after);
    let losses = loss_descriptors(&bundle.manifest, &bundle.events);
    json_response(
        StatusCode::OK,
        json!({
            "run_id": id,
            "events": events,
            "losses": losses,
            "next_after_seq": next_after_seq
        }),
    )
}

#[allow(clippy::result_large_err)]
async fn read_logs(
    AxumPath(run_id): AxumPath<String>,
    State(state): State<std::sync::Arc<ServerConfig>>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let id = match parse_run_id(&run_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let query = match parse_query(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return response,
    };
    let Some(stream) = query.get("stream").cloned() else {
        return api_error(StatusCode::BAD_REQUEST, "invalid stream");
    };
    let event_kind = match stream.as_str() {
        "stdout" => EventKind::Stdout,
        "stderr" => EventKind::Stderr,
        _ => return api_error(StatusCode::BAD_REQUEST, "invalid stream"),
    };
    let after = match parse_offset(query.get("after"), "after") {
        Ok(value) => value.unwrap_or(0),
        Err(response) => return response,
    };
    let limit = match log_byte_limit(query.get("limit")) {
        Ok(limit) => limit,
        Err(response) => return response,
    };
    let (bundle, text, markers, available, withheld) = match read_blocking(move || {
        let root = configured_store(&state, false)?;
        let bundle = read_public_bundle(&root, id)?
            .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "not found"))?;
        let (bytes, markers, available, withheld) = stream_bytes(&bundle.events, event_kind);
        let text =
            String::from_utf8(bytes).map_err(|_| api_error(StatusCode::NOT_FOUND, "not found"))?;
        Ok((bundle, text, markers, available, withheld))
    })
    .await
    {
        Ok(result) => result,
        Err(response) => return response,
    };
    if after > text.len() as u64 || !text.is_char_boundary(after as usize) {
        return api_error(StatusCode::BAD_REQUEST, "invalid offset");
    }
    let begin = after as usize;
    let mut end = begin.saturating_add(limit).min(text.len());
    while end > begin && !text.is_char_boundary(end) {
        end -= 1;
    }
    if end == begin && begin < text.len() {
        end = text[begin..]
            .char_indices()
            .nth(1)
            .map(|(index, _)| begin + index)
            .unwrap_or(text.len());
    }
    let slice = text[begin..end].to_string();
    let next_offset = end as u64;
    let selected_markers = markers
        .into_iter()
        .filter(|marker| {
            if marker.length == 0 {
                (marker.offset >= after && marker.offset < next_offset)
                    || (begin == end && marker.offset == after)
            } else {
                marker.offset < next_offset && marker.offset.saturating_add(marker.length) > after
            }
        })
        .collect::<Vec<_>>();
    json_response(
        StatusCode::OK,
        json!({
            "run_id": id,
            "stream": stream,
            "available": available,
            "offset": after,
            "next_offset": next_offset,
            "total_bytes": text.len(),
            "slices": [LogSlice { offset: after, text: slice }],
            "redactions": selected_markers,
            "losses": loss_descriptors(&bundle.manifest, &bundle.events),
            "withheld_reason": withheld
        }),
    )
}

async fn publish_run(
    AxumPath(run_id): AxumPath<String>,
    State(state): State<std::sync::Arc<ServerConfig>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(token_path) = state.detonation_ingest_token_file.as_deref() else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "detonation ingestion unavailable",
        );
    };
    let expected_token = match read_secret_file(token_path, TOKEN_FILE_LIMIT_BYTES) {
        Ok(token) => match std::str::from_utf8(&token) {
            Ok(token) => token.trim().as_bytes().to_vec(),
            Err(_) => {
                return api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "detonation ingestion unavailable",
                )
            }
        },
        Err(()) => {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "detonation ingestion unavailable",
            )
        }
    };
    if expected_token.is_empty() {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "detonation ingestion unavailable",
        );
    }
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::as_bytes)
        .unwrap_or_default();
    if !constant_time_eq(supplied, &expected_token) {
        return api_error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let id = match parse_run_id(&run_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let root = match configured_store(&state, true) {
        Ok(root) => root,
        Err(response) => return response,
    };
    let permit = match INGEST_SLOTS.try_acquire() {
        Ok(permit) => permit,
        Err(_) => return api_error(StatusCode::SERVICE_UNAVAILABLE, "detonation ingestion busy"),
    };
    let result = tokio::time::timeout(INGEST_TIMEOUT, receive_bundle(body, &root, id)).await;
    drop(permit);
    match result {
        Err(_) => api_error(
            StatusCode::REQUEST_TIMEOUT,
            "detonation ingestion timed out",
        ),
        Ok(Err(status)) => api_error(status, ingest_error(status)),
        Ok(Ok((staged, bundle_bytes))) => {
            let keys = match read_server_keys() {
                Ok(keys) => keys,
                Err(()) => {
                    return api_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "detonation ingestion unavailable",
                    )
                }
            };
            let parsed = match validate_bundle(&bundle_bytes, id, &keys) {
                Ok(parsed) => parsed,
                Err(status) => return api_error(status, ingest_error(status)),
            };
            let versions_match = parsed.manifest.schema_version == 1
                && parsed.manifest.projection_version == PROJECTION_VERSION
                && redaction_policy_matches(parsed.manifest.redaction_policy_version)
                && parsed.manifest.redactor_build_sha256 == redactor_build_sha256();
            let _publish_guard = PUBLISH_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let destination_dir = if versions_match {
                &root
            } else {
                &root.join("pending")
            };
            if ensure_private_directory(destination_dir).is_err() {
                return api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "detonation ingestion unavailable",
                );
            }
            let destination = destination_dir.join(format!("{id}.bundle"));
            let existing = match read_existing(&destination) {
                Ok(existing) => existing,
                Err(_) => {
                    return api_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "detonation ingestion unavailable",
                    )
                }
            };
            if let Some(existing) = existing {
                if existing == bundle_bytes {
                    let status = if versions_match {
                        StatusCode::OK
                    } else {
                        StatusCode::ACCEPTED
                    };
                    return json_response(
                        status,
                        json!({ "state": if versions_match { "sealed" } else { "pending" }, "run_id": id, "bundle_sha256": parsed.manifest.bundle_sha256 }),
                    );
                }
                return api_error(StatusCode::CONFLICT, "run ID conflict");
            }
            let size = match store_size(&root) {
                Ok(size) => size,
                Err(_) => {
                    return api_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "detonation ingestion unavailable",
                    )
                }
            };
            if size > PUBLIC_STORE_LIMIT_BYTES {
                return api_error(StatusCode::INSUFFICIENT_STORAGE, "detonation store full");
            }
            match publish_staged(&staged.path, destination_dir, &destination) {
                Ok(()) => json_response(
                    if versions_match {
                        StatusCode::CREATED
                    } else {
                        StatusCode::ACCEPTED
                    },
                    json!({
                        "state": if versions_match { "sealed" } else { "pending" },
                        "run_id": id,
                        "bundle_sha256": parsed.manifest.bundle_sha256
                    }),
                ),
                Err(error) if error.raw_os_error() == Some(libc::ENOSPC) => {
                    api_error(StatusCode::INSUFFICIENT_STORAGE, "detonation store full")
                }
                Err(_) => api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "detonation ingestion unavailable",
                ),
            }
        }
    }
}

struct StagedFile {
    path: PathBuf,
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

async fn receive_bundle(
    body: Body,
    root: &Path,
    id: RunId,
) -> Result<(StagedFile, Vec<u8>), StatusCode> {
    ensure_private_directory(root).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let staging = root.join("staging");
    ensure_private_directory(&staging).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    cleanup_staging(&staging);
    let path = staging.join(format!(
        "{}.tmp",
        random_name().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    ));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let staged = StagedFile { path };
    let mut file = tokio::fs::File::from_std(file);
    let mut total = 0usize;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
        total = total
            .checked_add(chunk.len())
            .ok_or(StatusCode::PAYLOAD_TOO_LARGE)?;
        if total > MAX_BUNDLE_BYTES {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        file.write_all(&chunk)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    }
    file.sync_all()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    drop(file);
    let bytes = fs::read(&staged.path).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if bytes.len() != total || bytes.len() > MAX_BUNDLE_BYTES {
        return Err(StatusCode::BAD_REQUEST);
    }
    let parsed = parse_public_bundle(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    if parsed.manifest.run_id != id {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok((staged, bytes))
}

fn verify_bundle(
    bytes: &[u8],
    id: RunId,
    keys: &HashMap<String, Vec<u8>>,
) -> Result<ParsedBundle, StatusCode> {
    let parsed = parse_public_bundle(bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let Some(key) = keys.get(&parsed.manifest.key_id) else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let signing = signing_bytes(&parsed.manifest, &parsed.event_bytes)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let expected_signature = hmac_sha256(key, &signing);
    let supplied_signature =
        hex::decode(&parsed.manifest.signature).map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !constant_time_eq(&expected_signature, &supplied_signature) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    validate_manifest(&parsed.manifest, &parsed.events, id).map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(parsed)
}

/// Ingest-side check: re-runs the redactor over the submitted content. The
/// read path deliberately skips this (content is HMAC-covered and redaction
/// was enforced here at publish time); re-running it per anonymous read is a
/// CPU-amplification DoS.
fn validate_bundle(
    bytes: &[u8],
    id: RunId,
    keys: &HashMap<String, Vec<u8>>,
) -> Result<ParsedBundle, StatusCode> {
    let parsed = verify_bundle(bytes, id, keys)?;
    validate_redaction(&parsed.events).map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(parsed)
}

fn validate_manifest(
    manifest: &BundleManifest,
    events: &[PublicEvent],
    id: RunId,
) -> anyhow::Result<()> {
    anyhow::ensure!(manifest.schema_version == 1, "unsupported schema version");
    anyhow::ensure!(manifest.run_id == id, "manifest run ID mismatch");
    anyhow::ensure!(manifest.state != RunState::Running, "run is not sealed");
    anyhow::ensure!(
        manifest.automatic_redaction_limitation,
        "redaction limitation is missing"
    );
    anyhow::ensure!(
        manifest.event_count == events.len() as u64,
        "event count mismatch"
    );
    anyhow::ensure!(
        manifest.redaction_count == redaction_count(events),
        "redaction count mismatch"
    );
    anyhow::ensure!(
        manifest.durable_seq >= events.last().map(|event| event.seq).unwrap_or(0),
        "durable sequence is invalid"
    );
    anyhow::ensure!(
        event_loss_is_consistent(manifest, events),
        "event loss count is inconsistent"
    );
    anyhow::ensure!(
        manifest.ended_at_unix_ms >= manifest.started_at_unix_ms,
        "run timestamps are invalid"
    );
    anyhow::ensure!(
        is_sha256(&manifest.artifact_sha256),
        "artifact digest is invalid"
    );
    anyhow::ensure!(
        is_sha256(&manifest.bundle_sha256),
        "bundle digest is invalid"
    );
    anyhow::ensure!(
        is_sha256(&manifest.redactor_build_sha256),
        "redactor digest is invalid"
    );
    anyhow::ensure!(valid_key_id(&manifest.key_id), "key ID is invalid");
    anyhow::ensure!(
        manifest.signature.len() == 64
            && manifest
                .signature
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "signature is invalid"
    );
    for value in [
        &manifest.ecosystem,
        &manifest.package_name,
        &manifest.package_version,
    ]
    .into_iter()
    .flatten()
    {
        anyhow::ensure!(
            value.len() <= MAX_FIELD_BYTES && !value.contains('\0'),
            "package field exceeds limit"
        );
    }
    if let Some(event_id) = &manifest.static_scan_event_id {
        anyhow::ensure!(
            event_id.len() <= 256
                && !event_id.contains('\0')
                && !event_id.contains('/')
                && !event_id.contains('\\'),
            "static event reference is invalid"
        );
    }
    anyhow::ensure!(events.len() <= MAX_EVENT_COUNT, "event count exceeds limit");
    for event in events {
        anyhow::ensure!(
            event.run_id == id && event.seq > 0,
            "event identity is invalid"
        );
        anyhow::ensure!(
            event.seq <= manifest.durable_seq,
            "event exceeds durable sequence"
        );
        anyhow::ensure!(
            event.details.len() <= 64 && event.redacted_fields.len() <= 64,
            "event list exceeds limit"
        );
        anyhow::ensure!(
            crate::adapters::detonation::kind_matches_text(event),
            "event text kind is invalid"
        );
        for value in event
            .actor
            .iter()
            .chain(event.target.iter())
            .chain(event.details.iter())
            .chain(event.redacted_fields.iter())
            .chain(event.text.iter())
        {
            anyhow::ensure!(
                value.len() <= MAX_FIELD_BYTES && !value.contains('\0'),
                "event text exceeds limit"
            );
        }
        anyhow::ensure!(
            event.automatic_redaction_limitation,
            "event redaction limitation is missing"
        );
    }
    Ok(())
}

fn validate_redaction(events: &[PublicEvent]) -> anyhow::Result<()> {
    let redactor = Redactor::new()?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    for event in events {
        for (field, value) in event
            .actor
            .iter()
            .map(|value| ("actor", value))
            .chain(event.target.iter().map(|value| ("target", value)))
            .chain(event.details.iter().map(|value| ("detail", value)))
            .chain(event.text.iter().map(|value| ("text", value)))
        {
            let result = redactor.redact_text(value, field);
            anyhow::ensure!(
                result.redacted_fields.is_empty()
                    && result.text.as_deref() == Some(value.as_str())
                    && result.withheld_reason.is_none(),
                "public text needs redaction"
            );
        }
        let record = serde_json::to_vec(&BundleLine::Event {
            event: event.clone(),
        })?;
        let record_text = std::str::from_utf8(&record)?;
        let result = redactor.redact_text(record_text, "record");
        anyhow::ensure!(
            result.redacted_fields.is_empty()
                && result.text.as_deref() == Some(record_text)
                && result.withheld_reason.is_none(),
            "public event needs redaction"
        );
        match event.kind {
            EventKind::Stdout => {
                if let Some(text) = &event.text {
                    stdout.extend_from_slice(text.as_bytes());
                }
            }
            EventKind::Stderr => {
                if let Some(text) = &event.text {
                    stderr.extend_from_slice(text.as_bytes());
                }
            }
            _ => {}
        }
    }
    for (stream, field, limit) in [
        (stdout.as_slice(), "stdout", MAX_STDOUT_BYTES),
        (stderr.as_slice(), "stderr", MAX_STDERR_BYTES),
    ] {
        anyhow::ensure!(stream.len() <= limit, "output stream exceeds limit");
        let result = redactor.redact_bytes(stream, field, limit);
        let expected = std::str::from_utf8(stream).ok();
        anyhow::ensure!(
            result.redacted_fields.is_empty()
                && result.text.as_deref() == expected
                && result.withheld_reason.is_none(),
            "reassembled output needs redaction"
        );
    }
    Ok(())
}

fn read_all_manifests(root: &Path) -> Result<Vec<BundleManifest>, ()> {
    // Manifests only: verified bundles' events are dropped here so a listing
    // never materializes the whole store in memory (the store cap is 256 MiB).
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(()),
    };
    let mut keys = None;
    let mut output = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| ())?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(id_text) = name.strip_suffix(".bundle") else {
            continue;
        };
        let Ok(id) = RunId::from_str(id_text) else {
            continue;
        };
        if keys.is_none() {
            keys = Some(read_server_keys()?);
        }
        let current_keys = keys.as_ref().ok_or(())?;
        if let Some(bundle) = read_bundle(root, id, current_keys)? {
            output.push(bundle.manifest);
        }
    }
    Ok(output)
}

fn read_bundle(
    root: &Path,
    id: RunId,
    keys: &HashMap<String, Vec<u8>>,
) -> Result<Option<ParsedBundle>, ()> {
    let path = root.join(format!("{id}.bundle"));
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) => return Err(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    if metadata.len() > MAX_BUNDLE_BYTES as u64 {
        return Err(());
    }
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    if file
        .take(MAX_BUNDLE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 != metadata.len()
    {
        return Err(());
    }
    match verify_bundle(&bytes, id, keys) {
        Ok(bundle)
            if bundle.manifest.projection_version == PROJECTION_VERSION
                && redaction_policy_matches(bundle.manifest.redaction_policy_version)
                && bundle.manifest.redactor_build_sha256 == redactor_build_sha256() =>
        {
            Ok(Some(bundle))
        }
        _ => Ok(None),
    }
}

#[allow(clippy::result_large_err)]
fn read_public_bundle(root: &Path, id: RunId) -> Result<Option<ParsedBundle>, Response> {
    let path = root.join(format!("{id}.bundle"));
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => {}
        Ok(_) => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "detonation store unavailable",
            ))
        }
    }
    let keys = read_server_keys().map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "detonation store unavailable",
        )
    })?;
    match read_bundle(root, id, &keys) {
        Ok(bundle) => Ok(bundle),
        Err(()) => Ok(None),
    }
}

fn read_server_keys() -> Result<HashMap<String, Vec<u8>>, ()> {
    let path = std::env::var_os("SUPPLY_DETONATION_INGEST_KEYS_FILE")
        .map(PathBuf::from)
        .ok_or(())?;
    let bytes = read_secret_file(&path, KEY_FILE_LIMIT_BYTES).map_err(|_| ())?;
    let parsed: ServerKeyFile = serde_json::from_slice(&bytes).map_err(|_| ())?;
    if parsed.keys.is_empty() || parsed.keys.len() > 32 {
        return Err(());
    }
    let mut keys = HashMap::new();
    for key in parsed.keys {
        if !valid_key_id(&key.key_id) || keys.contains_key(&key.key_id) {
            return Err(());
        }
        let bytes = hex::decode(&key.key_hex).map_err(|_| ())?;
        if !(32..=64).contains(&bytes.len())
            || key.key_hex.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err(());
        }
        keys.insert(key.key_id, bytes);
    }
    Ok(keys)
}

fn read_secret_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ())?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > max_bytes {
        return Err(());
    }
    Ok(bytes)
}

#[allow(clippy::result_large_err)]
fn configured_store(state: &ServerConfig, create: bool) -> Result<PathBuf, Response> {
    let Some(root) = state.detonation_public_store.as_deref() else {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "detonation store unavailable",
        ));
    };
    if create {
        match fs::symlink_metadata(root) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(root)
                    .and_then(|()| fs::set_permissions(root, fs::Permissions::from_mode(0o700)))
                    .map_err(|_| {
                        api_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "detonation store unavailable",
                        )
                    })?;
            }
            Err(_) => {
                return Err(api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "detonation store unavailable",
                ))
            }
        }
    }
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(root.to_path_buf())
        }
        Err(_) => {
            return Err(api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "detonation store unavailable",
            ))
        }
    };
    if !metadata.file_type().is_dir() || metadata.mode() & 0o777 != 0o700 {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "detonation store unavailable",
        ));
    }
    root.canonicalize().map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "detonation store unavailable",
        )
    })
}

fn ensure_private_directory(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && metadata.mode() & 0o777 == 0o700 => Ok(()),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "directory is not private",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        }
        Err(error) => Err(error),
    }
}

fn cleanup_staging(staging: &Path) {
    let lock = STALE_CLEANUP_LOCK.get_or_init(|| std::sync::Mutex::new(()));
    let Ok(_guard) = lock.lock() else { return };
    let Ok(entries) = fs::read_dir(staging) else {
        return;
    };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let Ok(metadata) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if !metadata.file_type().is_file() {
            continue;
        }
        if metadata
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age > STALE_STAGE_AGE)
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn random_name() -> std::io::Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(std::io::Error::other)?;
    Ok(hex::encode(bytes))
}

fn publish_staged(staged: &Path, directory: &Path, destination: &Path) -> std::io::Result<()> {
    fs::hard_link(staged, destination)?;
    File::open(directory)?.sync_all()
}

fn read_existing(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "existing bundle is not a regular file",
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if metadata.len() > MAX_BUNDLE_BYTES as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "existing bundle exceeds size limit",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_BUNDLE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "existing bundle changed while reading",
        ));
    }
    Ok(Some(bytes))
}

fn add_file_sizes(directory: &Path, total: &mut u64) -> std::io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_file() {
            *total = total.checked_add(metadata.len()).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "store size overflow")
            })?;
        }
    }
    Ok(())
}

fn store_size(root: &Path) -> std::io::Result<u64> {
    let mut total = 0_u64;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_file() {
            total = total.checked_add(metadata.len()).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "store size overflow")
            })?;
        } else if metadata.file_type().is_dir()
            && matches!(name.to_str(), Some("pending" | "staging"))
        {
            add_file_sizes(&path, &mut total)?;
        }
    }
    Ok(total)
}

fn stream_bytes(
    events: &[PublicEvent],
    kind: EventKind,
) -> (
    Vec<u8>,
    Vec<RedactionMarker>,
    bool,
    Option<crate::application::detonation::WithheldReason>,
) {
    let mut bytes = Vec::new();
    let mut markers = Vec::new();
    let mut available = false;
    let mut withheld = None;
    for event in events.iter().filter(|event| event.kind == kind) {
        available = true;
        let offset = bytes.len() as u64;
        let length = event.text.as_ref().map_or(0, |text| text.len() as u64);
        if !event.redacted_fields.is_empty() || event.withheld_reason.is_some() {
            markers.push(RedactionMarker {
                seq: event.seq,
                offset,
                length,
                fields: event.redacted_fields.clone(),
                withheld: event.withheld_reason,
            });
        }
        if withheld.is_none() {
            withheld = event.withheld_reason;
        }
        if let Some(text) = &event.text {
            bytes.extend_from_slice(text.as_bytes());
        }
    }
    (bytes, markers, available, withheld)
}

fn loss_descriptors(manifest: &BundleManifest, events: &[PublicEvent]) -> Vec<LossDescriptor> {
    let mut losses = Vec::new();
    let mut previous = 0_u64;
    for event in events {
        if event.seq > previous.saturating_add(1) {
            let gap = event.seq - previous - 1;
            losses.push(LossDescriptor {
                after_seq: previous,
                before_seq: Some(event.seq),
                count: manifest.event_loss_count.map(|_| gap),
            });
        }
        previous = event.seq;
    }
    if manifest.durable_seq > previous {
        losses.push(LossDescriptor {
            after_seq: previous,
            before_seq: Some(manifest.durable_seq.saturating_add(1)),
            count: manifest
                .event_loss_count
                .map(|_| manifest.durable_seq - previous),
        });
    } else if manifest.event_loss_count.is_none() {
        losses.push(LossDescriptor {
            after_seq: previous,
            before_seq: None,
            count: None,
        });
    }
    losses
}

#[allow(clippy::result_large_err)]
fn parse_run_id(value: &str) -> Result<RunId, Response> {
    RunId::from_str(value).map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid run ID"))
}

fn routes_enabled() -> bool {
    std::env::var("SUPPLY_DETONATION_ROUTES_ENABLED").is_ok_and(|value| value == "1")
}

fn disabled_response() -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}

fn api_error(status: StatusCode, message: &str) -> Response {
    json_response(status, json!({ "error": message }))
}

fn json_response(status: StatusCode, value: Value) -> Response {
    response_with_headers(status, "application/json", Body::from(value.to_string()))
}

fn response_with_headers(status: StatusCode, content_type: &'static str, body: Body) -> Response {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn ingest_error(status: StatusCode) -> &'static str {
    match status {
        StatusCode::PAYLOAD_TOO_LARGE => "payload too large",
        StatusCode::UNAUTHORIZED => "unauthorized",
        StatusCode::REQUEST_TIMEOUT => "detonation ingestion timed out",
        StatusCode::SERVICE_UNAVAILABLE => "detonation ingestion unavailable",
        _ => "invalid detonation bundle",
    }
}

#[allow(clippy::result_large_err)]
fn parse_query(raw: Option<&str>) -> Result<HashMap<String, String>, Response> {
    let mut query = HashMap::new();
    if let Some(raw) = raw {
        for field in raw.split('&') {
            if field.is_empty() {
                continue;
            }
            let (key, value) = field.split_once('=').unwrap_or((field, ""));
            let key = urlencoding::decode(key)
                .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid query"))?
                .into_owned();
            let value = urlencoding::decode(value)
                .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid query"))?
                .into_owned();
            if !matches!(
                key.as_str(),
                "limit" | "cursor" | "after_seq" | "stream" | "after"
            ) || query.insert(key, value).is_some()
            {
                return Err(api_error(StatusCode::BAD_REQUEST, "invalid query"));
            }
        }
    }
    Ok(query)
}

#[allow(clippy::result_large_err)]
fn page_limit(raw: Option<&String>) -> Result<usize, Response> {
    let Some(raw) = raw else { return Ok(50) };
    let value = raw
        .parse::<usize>()
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid limit"))?;
    if value == 0 {
        return Err(api_error(StatusCode::BAD_REQUEST, "invalid limit"));
    }
    Ok(value.min(100))
}

#[allow(clippy::result_large_err)]
fn log_byte_limit(raw: Option<&String>) -> Result<usize, Response> {
    let Some(raw) = raw else {
        return Ok(64 * 1024);
    };
    let value = raw
        .parse::<usize>()
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid limit"))?;
    if value == 0 {
        return Err(api_error(StatusCode::BAD_REQUEST, "invalid limit"));
    }
    Ok(value.min(1024 * 1024))
}

#[allow(clippy::result_large_err)]
fn parse_offset(raw: Option<&String>, _name: &str) -> Result<Option<u64>, Response> {
    raw.map(|value| {
        value
            .parse::<u64>()
            .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid offset"))
    })
    .transpose()
}

fn encode_cursor(timestamp: u64, run_id: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{timestamp}:{run_id}"))
}

fn decode_cursor(value: &str) -> Option<(u64, String)> {
    let decoded = URL_SAFE_NO_PAD.decode(value).ok()?;
    let decoded = std::str::from_utf8(&decoded).ok()?;
    let (timestamp, run_id) = decoded.split_once(':')?;
    let timestamp = timestamp.parse().ok()?;
    RunId::from_str(run_id).ok()?;
    Some((timestamp, run_id.to_string()))
}

fn state_name(state: RunState) -> &'static str {
    match state {
        RunState::Complete => "complete",
        RunState::Incomplete => "incomplete",
        RunState::Running => "incomplete",
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_key_id(key_id: &str) -> bool {
    !key_id.is_empty()
        && key_id.len() <= 128
        && key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}
