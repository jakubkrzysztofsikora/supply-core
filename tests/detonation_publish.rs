use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{Request, StatusCode, Uri},
    middleware::{from_fn_with_state, Next},
    response::{Json, Response},
    routing::put,
    Router,
};
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
};
use supply_core::{
    adapters::{
        detonation::{encode_public_bundle, publisher::publish_pending, BundleManifest},
        http::{app_with_config, ServerConfig},
        storage::detonation::{EvidenceStore, RunMetadata},
    },
    application::detonation::{
        EventKind, ObservationKind, ObservedEvent, Outcome, Phase, PrivateFields, PublicEvent,
        RunProvenance, RunState, Sensor,
    },
};
use tower::ServiceExt;

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
const TEST_KEY: &[u8] = b"synthetic publisher hmac key for tests";
struct ContractFixture {
    status: StatusCode,
    requests: Mutex<Vec<String>>,
    bundles: Mutex<Vec<Vec<u8>>>,
    acknowledgement_digest: Option<String>,
}

async fn observed_upload(
    State(fixture): State<Arc<ContractFixture>>,
    uri: Uri,
    body: Bytes,
) -> (StatusCode, Json<Value>) {
    let manifest_line = body.split(|byte| *byte == b'\n').next().unwrap_or_default();
    let bundle: Value = serde_json::from_slice(manifest_line).unwrap_or_default();
    let manifest = bundle.get("manifest").cloned().unwrap_or(Value::Null);
    let run_id = manifest
        .get("run_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let digest = manifest
        .get("bundle_sha256")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let digest = fixture.acknowledgement_digest.clone().unwrap_or(digest);
    fixture
        .bundles
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(body.to_vec());
    fixture
        .requests
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(format!("{}:{run_id}", uri.path()));
    let state = if fixture.status == StatusCode::ACCEPTED {
        "pending"
    } else {
        "sealed"
    };
    (
        fixture.status,
        Json(json!({
            "state": state,
            "run_id": run_id,
            "bundle_sha256": digest,
        })),
    )
}

async fn start_contract_fixture(
    status: StatusCode,
) -> (
    SocketAddr,
    Arc<ContractFixture>,
    tokio::task::JoinHandle<()>,
) {
    start_contract_fixture_with_digest(status, None).await
}

async fn start_contract_fixture_with_digest(
    status: StatusCode,
    acknowledgement_digest: Option<String>,
) -> (
    SocketAddr,
    Arc<ContractFixture>,
    tokio::task::JoinHandle<()>,
) {
    let fixture = Arc::new(ContractFixture {
        status,
        requests: Mutex::new(Vec::new()),
        bundles: Mutex::new(Vec::new()),
        acknowledgement_digest,
    });
    let app = Router::new()
        .route("/api/v1/detonations/:run_id", put(observed_upload))
        .with_state(Arc::clone(&fixture));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| panic!("bind contract fixture"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|_| panic!("contract fixture address"));
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .unwrap_or_else(|_| panic!("contract fixture exits"));
    });
    (address, fixture, server)
}

async fn oversized_acknowledgement() -> Response<Body> {
    let body = futures_util::stream::once(async {
        Ok::<_, std::io::Error>(Bytes::from(vec![b'x'; 8192]))
    })
    .chain(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());
    let mut response = Response::new(Body::from_stream(body));
    *response.status_mut() = StatusCode::CREATED;
    response
}

async fn start_oversized_ack_fixture() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/api/v1/detonations/:run_id",
        put(oversized_acknowledgement),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| panic!("bind oversized acknowledgement fixture"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|_| panic!("oversized acknowledgement fixture address"));
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .unwrap_or_else(|_| panic!("oversized acknowledgement fixture exits"));
    });
    (address, server)
}

fn observed_requests(fixture: &ContractFixture) -> usize {
    fixture
        .requests
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .len()
}

fn observed_bundles(fixture: &ContractFixture) -> Vec<Vec<u8>> {
    fixture
        .bundles
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

struct EnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    old_routes: Option<std::ffi::OsString>,
    old_keys: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn enabled(keys_file: &Path) -> Self {
        let lock = ENV_LOCK.get_or_init(|| Mutex::new(()));
        let guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let old_routes = std::env::var_os("SUPPLY_DETONATION_ROUTES_ENABLED");
        let old_keys = std::env::var_os("SUPPLY_DETONATION_INGEST_KEYS_FILE");
        std::env::set_var("SUPPLY_DETONATION_ROUTES_ENABLED", "1");
        std::env::set_var("SUPPLY_DETONATION_INGEST_KEYS_FILE", keys_file);
        Self {
            _lock: guard,
            old_routes,
            old_keys,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        restore_env("SUPPLY_DETONATION_ROUTES_ENABLED", self.old_routes.take());
        restore_env("SUPPLY_DETONATION_INGEST_KEYS_FILE", self.old_keys.take());
    }
}

fn restore_env(name: &str, value: Option<std::ffi::OsString>) {
    match value {
        Some(value) => std::env::set_var(name, value),
        None => std::env::remove_var(name),
    }
}

fn write_key_files(directory: &Path) -> (PathBuf, PathBuf) {
    let keys = directory.join("server-keys.json");
    fs::write(
        &keys,
        format!(
            "{{\"keys\":[{{\"key_id\":\"test-key\",\"key_hex\":\"{}\"}}]}}",
            hex::encode(TEST_KEY)
        ),
    )
    .unwrap_or_else(|_| panic!("server key fixture"));
    let token = directory.join("token");
    fs::write(&token, "test-token\n").unwrap_or_else(|_| panic!("token fixture"));
    (keys, token)
}

fn evidence(directory: &Path) -> String {
    let root = directory.join("evidence");
    let store = EvidenceStore::new(&root).unwrap_or_else(|_| panic!("evidence store"));
    let metadata = RunMetadata {
        ecosystem: Some("npm".into()),
        package_name: Some("synthetic-package".into()),
        package_version: Some("1.2.3".into()),
        expected_phases: Vec::new(),
        required_sensors: Vec::new(),
        ..RunMetadata::default()
    };
    let mut writer = store
        .begin_run_with_metadata(
            RunProvenance {
                artifact_sha256: [0x11; 32],
                static_scan_event_id: None,
                public_bundle_sha256: [0; 32],
            },
            metadata,
        )
        .unwrap_or_else(|_| panic!("begin synthetic run"));
    let run_id = writer.run_id();
    writer
        .append(&ObservedEvent {
            run_id,
            seq: 1,
            offset_ns: Some(10_000_000),
            source_seq: Some(1),
            phase: Phase::Execute,
            sensor: Sensor::GuestMonitor,
            observation: ObservationKind::Observed,
            kind: EventKind::NetworkConnect,
            outcome: Outcome::Failed,
            failure: Some(supply_core::application::detonation::FailureKind::NetworkUnreachable),
            private_fields: PrivateFields::NetworkConnect {
                process: None,
                host: "example.invalid".into(),
                port: 443,
            },
        })
        .unwrap_or_else(|_| panic!("append synthetic event"));
    writer
        .seal(RunState::Incomplete)
        .unwrap_or_else(|_| panic!("seal synthetic run"));
    fs::write(
        root.join("publisher-hmac-key.json"),
        format!(
            "{{\"key_id\":\"test-key\",\"key_hex\":\"{}\"}}",
            hex::encode(TEST_KEY)
        ),
    )
    .unwrap_or_else(|_| panic!("publisher key fixture"));
    run_id.to_string()
}

fn changed_bundle(original: &[u8]) -> Vec<u8> {
    let mut lines = original.split(|byte| *byte == b'\n');
    let manifest_record: Value = serde_json::from_slice(lines.next().unwrap_or_default())
        .unwrap_or_else(|_| panic!("parse original manifest"));
    let event_record: Value = serde_json::from_slice(lines.next().unwrap_or_default())
        .unwrap_or_else(|_| panic!("parse original event"));
    let manifest: BundleManifest = serde_json::from_value(manifest_record["manifest"].clone())
        .unwrap_or_else(|_| panic!("decode original manifest"));
    let mut event: PublicEvent = serde_json::from_value(event_record["event"].clone())
        .unwrap_or_else(|_| panic!("decode original event"));
    event.target = Some("changed.invalid:443".into());
    encode_public_bundle(manifest, &[event], "test-key", TEST_KEY)
        .unwrap_or_else(|_| panic!("encode changed bundle"))
}

async fn start_server(directory: &Path) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let (_, token) = write_key_files(directory);
    let config = ServerConfig {
        detonation_public_store: Some(directory.join("public")),
        detonation_ingest_token_file: Some(token),
        ..ServerConfig::default()
    };
    let app = app_with_config(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| panic!("bind server"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|_| panic!("server address"));
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .unwrap_or_else(|_| panic!("server exits"));
    });
    (address, task)
}

async fn count_server_requests(
    State(request_count): State<Arc<AtomicUsize>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    request_count.fetch_add(1, Ordering::SeqCst);
    next.run(request).await
}

async fn start_counted_server(
    directory: &Path,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let (_, token) = write_key_files(directory);
    let config = ServerConfig {
        detonation_public_store: Some(directory.join("public")),
        detonation_ingest_token_file: Some(token),
        ..ServerConfig::default()
    };
    let request_count = Arc::new(AtomicUsize::new(0));
    let app = app_with_config(config).layer(from_fn_with_state(
        Arc::clone(&request_count),
        count_server_requests,
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| panic!("bind counted server"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|_| panic!("counted server address"));
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .unwrap_or_else(|_| panic!("counted server exits"));
    });
    (address, request_count, task)
}

#[tokio::test]
async fn failed_transfer_keeps_durable_public_bundle_then_retry_clears_marker() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let run_id = evidence(directory.path());
    let (keys, token) = write_key_files(directory.path());
    let _env = EnvGuard::enabled(&keys);
    let evidence_dir = directory.path().join("evidence");
    let unused = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| panic!("reserve local address"));
    let address = unused
        .local_addr()
        .unwrap_or_else(|_| panic!("unused address"));
    drop(unused);
    let public_url = format!("http://{address}");
    let failed = publish_pending(&public_url, &token, &evidence_dir, true).await;
    assert!(failed.is_err());
    let pending = evidence_dir
        .join(".detonation-pending")
        .join(format!("{run_id}.bundle"));
    assert!(pending.is_file());

    let (server_address, server) = start_server(directory.path()).await;
    let accepted = publish_pending(
        &format!("http://{server_address}"),
        &token,
        &evidence_dir,
        true,
    )
    .await;
    assert!(accepted.is_ok());
    assert!(!pending.exists());

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{server_address}/api/v1/detonations/{run_id}/events?after_seq=0&limit=10"
        ))
        .send()
        .await
        .unwrap_or_else(|_| panic!("read published events"));
    assert_eq!(response.status(), StatusCode::OK);
    let result: serde_json::Value = response
        .json()
        .await
        .unwrap_or_else(|_| panic!("published event JSON"));
    assert_eq!(result["events"][0]["failure"], "network_unreachable");
    assert_eq!(result["events"][0]["outcome"], "failed");
    assert_eq!(result["events"][0]["target"], "example.invalid:443");
    server.abort();
}
#[tokio::test]
async fn pending_acknowledgement_retains_durable_bundle() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let run_id = evidence(directory.path());
    let (keys, token) = write_key_files(directory.path());
    let _env = EnvGuard::enabled(&keys);
    let evidence_dir = directory.path().join("evidence");
    let pending = evidence_dir
        .join(".detonation-pending")
        .join(format!("{run_id}.bundle"));
    let (address, fixture, server) = start_contract_fixture(StatusCode::ACCEPTED).await;

    let published =
        publish_pending(&format!("http://{address}"), &token, &evidence_dir, true).await;

    assert_eq!(
        published.unwrap_or_else(|_| panic!("pending acknowledgement")),
        0
    );
    assert!(pending.is_file());
    assert_eq!(observed_requests(&fixture), 1);
    server.abort();
}

#[tokio::test]
async fn oversized_acknowledgement_is_rejected_before_response_finishes() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let run_id = evidence(directory.path());
    let (keys, token) = write_key_files(directory.path());
    let _env = EnvGuard::enabled(&keys);
    let evidence_dir = directory.path().join("evidence");
    let pending = evidence_dir
        .join(".detonation-pending")
        .join(format!("{run_id}.bundle"));
    let (address, server) = start_oversized_ack_fixture().await;

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        publish_pending(&format!("http://{address}"), &token, &evidence_dir, true),
    )
    .await;

    let Ok(Err(error)) = result else {
        panic!("publisher must reject oversized acknowledgement before stream ends");
    };
    assert!(format!("{error:#}").contains("acknowledgement exceeds limit"));
    assert!(pending.is_file());
    server.abort();
}

#[tokio::test]
async fn sealed_run_is_not_uploaded_again_to_same_target() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let _ = evidence(directory.path());
    let (keys, token) = write_key_files(directory.path());
    let _env = EnvGuard::enabled(&keys);
    let evidence_dir = directory.path().join("evidence");
    let (address, fixture, server) = start_contract_fixture(StatusCode::CREATED).await;
    let target = format!("http://{address}");

    assert_eq!(
        publish_pending(&target, &token, &evidence_dir, true)
            .await
            .unwrap_or_else(|_| panic!("first sealed publication")),
        1
    );
    assert_eq!(
        publish_pending(&target, &token, &evidence_dir, true)
            .await
            .unwrap_or_else(|_| panic!("repeat sealed publication")),
        0
    );
    assert_eq!(observed_requests(&fixture), 1);
    server.abort();
}

#[tokio::test]
async fn changed_bundle_conflicts_with_existing_sealed_receipt() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let run_id = evidence(directory.path());
    let (keys, token) = write_key_files(directory.path());
    let _env = EnvGuard::enabled(&keys);
    let evidence_dir = directory.path().join("evidence");
    let (address, fixture, server) = start_contract_fixture(StatusCode::CREATED).await;
    let target = format!("http://{address}");

    assert_eq!(
        publish_pending(&target, &token, &evidence_dir, true)
            .await
            .unwrap_or_else(|_| panic!("first sealed publication")),
        1
    );
    let original = observed_bundles(&fixture)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("captured public bundle"));
    let pending = evidence_dir
        .join(".detonation-pending")
        .join(format!("{run_id}.bundle"));
    fs::write(&pending, changed_bundle(&original))
        .unwrap_or_else(|_| panic!("write changed pending bundle"));

    let error = publish_pending(&target, &token, &evidence_dir, true)
        .await
        .err()
        .unwrap_or_else(|| panic!("changed bundle conflicts with sealed receipt"));

    assert!(
        format!("{error:#}").contains("sealed detonation receipt"),
        "{error:#}"
    );
    assert!(pending.is_file());
    assert_eq!(observed_requests(&fixture), 1);
    server.abort();
}

#[tokio::test]
async fn sealed_digest_conflict_is_not_reuploaded() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let run_id = evidence(directory.path());
    let (keys, token) = write_key_files(directory.path());
    let _env = EnvGuard::enabled(&keys);
    let evidence_dir = directory.path().join("evidence");
    let pending = evidence_dir
        .join(".detonation-pending")
        .join(format!("{run_id}.bundle"));
    let (address, fixture, server) =
        start_contract_fixture_with_digest(StatusCode::CREATED, Some("00".repeat(32))).await;
    let target = format!("http://{address}");

    assert!(publish_pending(&target, &token, &evidence_dir, true)
        .await
        .is_err());
    assert!(pending.is_file());
    assert!(publish_pending(&target, &token, &evidence_dir, true)
        .await
        .is_err());

    assert_eq!(observed_requests(&fixture), 1);
    assert!(pending.is_file());
    server.abort();
}

#[tokio::test]
async fn real_run_id_conflict_is_not_uploaded_again() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let run_id = evidence(directory.path());
    let (keys, token) = write_key_files(directory.path());
    let _env = EnvGuard::enabled(&keys);
    let evidence_dir = directory.path().join("evidence");
    let pending = evidence_dir
        .join(".detonation-pending")
        .join(format!("{run_id}.bundle"));
    let unused = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| panic!("reserve unused publisher port"));
    let unused_address = unused
        .local_addr()
        .unwrap_or_else(|_| panic!("unused publisher address"));
    drop(unused);

    assert!(publish_pending(
        &format!("http://{unused_address}"),
        &token,
        &evidence_dir,
        true,
    )
    .await
    .is_err());
    let original = fs::read(&pending).unwrap_or_else(|_| panic!("read durable pending bundle"));
    let (address, request_count, server) = start_counted_server(directory.path()).await;
    let seeded = reqwest::Client::new()
        .put(format!("http://{address}/api/v1/detonations/{run_id}"))
        .header(reqwest::header::AUTHORIZATION, "Bearer test-token")
        .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
        .body(changed_bundle(&original))
        .send()
        .await
        .unwrap_or_else(|_| panic!("seed real ingestion route"));
    assert!(matches!(
        seeded.status(),
        StatusCode::CREATED | StatusCode::ACCEPTED
    ));
    assert_eq!(request_count.load(Ordering::SeqCst), 1);

    let target = format!("http://{address}");
    assert!(publish_pending(&target, &token, &evidence_dir, true)
        .await
        .is_err());
    assert_eq!(request_count.load(Ordering::SeqCst), 2);
    assert!(pending.is_file());

    let error = publish_pending(&target, &token, &evidence_dir, true)
        .await
        .err()
        .unwrap_or_else(|| panic!("conflicted run remains terminal"));
    assert_eq!(request_count.load(Ordering::SeqCst), 2);
    assert!(format!("{error:#}").contains("conflict"));
    assert!(pending.is_file());
    server.abort();
}

#[tokio::test]
async fn sealed_run_can_be_published_to_different_target() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let _ = evidence(directory.path());
    let (keys, token) = write_key_files(directory.path());
    let _env = EnvGuard::enabled(&keys);
    let evidence_dir = directory.path().join("evidence");
    let (first_address, first_fixture, first_server) =
        start_contract_fixture(StatusCode::CREATED).await;
    let (second_address, second_fixture, second_server) =
        start_contract_fixture(StatusCode::CREATED).await;

    for address in [first_address, second_address] {
        assert_eq!(
            publish_pending(&format!("http://{address}"), &token, &evidence_dir, true,)
                .await
                .unwrap_or_else(|_| panic!("target-specific publication")),
            1
        );
    }
    assert_eq!(observed_requests(&first_fixture), 1);
    assert_eq!(observed_requests(&second_fixture), 1);
    first_server.abort();
    second_server.abort();
}

#[tokio::test]
async fn publisher_requires_tls_for_non_loopback_and_never_sends_private_evidence() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let run_id = evidence(directory.path());
    let (keys, token) = write_key_files(directory.path());
    let _env = EnvGuard::enabled(&keys);
    let evidence_dir = directory.path().join("evidence");
    let error = publish_pending("http://example.invalid", &token, &evidence_dir, true).await;
    assert!(error.is_err());
    assert!(evidence_dir
        .join(".detonation-pending")
        .join(format!("{run_id}.bundle"))
        .is_file());
}

#[tokio::test]
async fn publisher_rejects_non_pending_mode() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let _ = evidence(directory.path());
    let (keys, token) = write_key_files(directory.path());
    let _env = EnvGuard::enabled(&keys);
    let error = publish_pending(
        "http://127.0.0.1:1",
        &token,
        &directory.path().join("evidence"),
        false,
    )
    .await;
    assert!(error.is_err());
}

#[tokio::test]
async fn server_restart_preserves_published_history() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let run_id = evidence(directory.path());
    let (keys, token) = write_key_files(directory.path());
    let _env = EnvGuard::enabled(&keys);
    let evidence_dir = directory.path().join("evidence");
    let (address, server) = start_server(directory.path()).await;
    publish_pending(&format!("http://{address}"), &token, &evidence_dir, true)
        .await
        .unwrap_or_else(|error| panic!("publish synthetic run: {error:?}"));
    server.abort();

    let config = ServerConfig {
        detonation_public_store: Some(directory.path().join("public")),
        detonation_ingest_token_file: Some(token),
        ..ServerConfig::default()
    };
    let app = app_with_config(config);
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/detonations/{run_id}"))
                .body(Body::empty())
                .unwrap_or_else(|_| panic!("detail request")),
        )
        .await
        .unwrap_or_else(|_| panic!("detail response"));
    assert_eq!(response.status(), StatusCode::OK);
}
