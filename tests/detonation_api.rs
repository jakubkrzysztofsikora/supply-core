use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use std::{
    fs::{self, File},
    os::unix::fs::{symlink, FileExt, PermissionsExt},
    path::Path,
    sync::{Mutex, OnceLock},
    task::Poll,
};
use supply_core::{
    adapters::{
        detonation::{encode_public_bundle, BundleManifest},
        http::{app_with_config, ServerConfig},
    },
    application::detonation::{
        Coverage, CoverageState, EventKind, FailureKind, ObservationKind, Outcome, Phase,
        PublicEvent, RunId, RunState, Sensor, WithheldReason, REDACTION_POLICY_VERSION,
    },
};
use tower::ServiceExt;

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
const TEST_KEY: &[u8] = b"synthetic publisher hmac key for tests";

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

fn configure(directory: &Path) -> (ServerConfig, EnvGuard) {
    let keys = directory.join("keys.json");
    fs::write(
        &keys,
        format!(
            "{{\"keys\":[{{\"key_id\":\"test-key\",\"key_hex\":\"{}\"}}]}}",
            hex::encode(TEST_KEY)
        ),
    )
    .unwrap_or_else(|_| panic!("key fixture writes"));
    fs::write(directory.join("token"), "test-token\n")
        .unwrap_or_else(|_| panic!("token fixture writes"));
    let guard = EnvGuard::enabled(&keys);
    (
        ServerConfig {
            detonation_public_store: Some(directory.join("public")),
            detonation_ingest_token_file: Some(directory.join("token")),
            ..ServerConfig::default()
        },
        guard,
    )
}

fn event(run_id: RunId, seq: u64, kind: EventKind, text: Option<&str>) -> PublicEvent {
    PublicEvent {
        run_id,
        seq,
        offset_ms: Some(seq * 10),
        phase: Phase::Execute,
        sensor: Sensor::GuestMonitor,
        observation: ObservationKind::Observed,
        kind,
        outcome: if kind == EventKind::NetworkConnect {
            Outcome::Failed
        } else {
            Outcome::Succeeded
        },
        failure: (kind == EventKind::NetworkConnect).then_some(FailureKind::NetworkUnreachable),
        actor: Some("P1".into()),
        target: Some("example.invalid:443".into()),
        details: Vec::new(),
        text: text.map(str::to_owned),
        redacted_fields: Vec::new(),
        withheld_reason: None::<WithheldReason>,
        coverage: CoverageState::Complete,
        automatic_redaction_limitation: true,
    }
}

fn manifest(run_id: RunId, state: RunState, time: u64, event_loss: Option<u64>) -> BundleManifest {
    BundleManifest {
        schema_version: 1,
        projection_version: supply_core::adapters::detonation::PROJECTION_VERSION,
        redaction_policy_version: REDACTION_POLICY_VERSION,
        redactor_build_sha256: supply_core::adapters::detonation::redactor_build_sha256(),
        run_id,
        state,
        ecosystem: Some("npm".into()),
        package_name: Some("synthetic-package".into()),
        package_version: Some("1.2.3".into()),
        event_count: 0,
        redaction_count: 0,
        event_loss_count: event_loss,
        source_loss_count: Some(0),
        started_at_unix_ms: time,
        ended_at_unix_ms: time + 100,
        artifact_sha256: "11".repeat(32),
        static_scan_event_id: None,
        bundle_sha256: String::new(),
        durable_seq: 0,
        phases: vec![Phase::Execute],
        sensors: Vec::<Sensor>::new(),
        coverage: if state == RunState::Complete {
            Coverage::complete()
        } else {
            Coverage::unknown()
        },
        automatic_redaction_limitation: true,
        key_id: "test-key".into(),
        signature: String::new(),
    }
}

fn bundle(run_id: RunId, state: RunState, time: u64, events: &[PublicEvent]) -> Vec<u8> {
    encode_public_bundle(
        manifest(run_id, state, time, Some(0)),
        events,
        "test-key",
        TEST_KEY,
    )
    .unwrap_or_else(|_| panic!("synthetic bundle encodes"))
}

async fn send(app: &axum::Router, request: Request<Body>) -> axum::response::Response {
    app.clone()
        .oneshot(request)
        .await
        .unwrap_or_else(|_| panic!("request completes"))
}

fn put_request(run_id: &str, token: Option<&str>, bytes: Vec<u8>) -> Request<Body> {
    let mut request = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/detonations/{run_id}"));
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    request
        .body(Body::from(bytes))
        .unwrap_or_else(|_| panic!("valid PUT"))
}

#[tokio::test]
async fn ingestion_auth_runs_before_body_polling_and_missing_token_configuration_is_unavailable() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let (config, _env) = configure(directory.path());
    let app = app_with_config(config.clone());
    let polled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = polled.clone();
    let body = Body::from_stream(futures_util::stream::poll_fn(move |_| {
        observed.store(true, std::sync::atomic::Ordering::SeqCst);
        Poll::<Option<Result<axum::body::Bytes, std::io::Error>>>::Pending
    }));
    let request = Request::builder()
        .method("PUT")
        .uri("/api/v1/detonations/0123456789abcdef0123456789abcdef")
        .header(header::AUTHORIZATION, "Bearer wrong")
        .body(body)
        .unwrap_or_else(|_| panic!("valid request"));
    let response = send(&app, request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(!polled.load(std::sync::atomic::Ordering::SeqCst));

    let missing = app_with_config(ServerConfig {
        detonation_ingest_token_file: None,
        ..config
    });
    let response = send(
        &missing,
        put_request(
            "0123456789abcdef0123456789abcdef",
            Some("test-token"),
            Vec::new(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn uploads_are_idempotent_conflict_safe_and_visible_through_paginated_reads() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let (config, _env) = configure(directory.path());
    let app = app_with_config(config);
    let first_id = RunId([1; 16]);
    let second_id = RunId([2; 16]);
    let events = [
        event(first_id, 1, EventKind::ProcessExec, None),
        event(first_id, 2, EventKind::NetworkConnect, None),
    ];
    let first = bundle(first_id, RunState::Complete, 1000, &events);
    let response = send(
        &app,
        put_request(&first_id.to_string(), Some("test-token"), first.clone()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(response.headers()["cache-control"], "no-store");
    let retry = send(
        &app,
        put_request(&first_id.to_string(), Some("test-token"), first),
    )
    .await;
    assert_eq!(retry.status(), StatusCode::OK);
    let conflict = bundle(
        first_id,
        RunState::Complete,
        1000,
        &[event(first_id, 1, EventKind::ProcessExit, None)],
    );
    let response = send(
        &app,
        put_request(&first_id.to_string(), Some("test-token"), conflict),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let second = bundle(
        second_id,
        RunState::Incomplete,
        2000,
        &[event(
            second_id,
            1,
            EventKind::Stdout,
            Some("request started"),
        )],
    );
    let response = send(
        &app,
        put_request(&second_id.to_string(), Some("test-token"), second),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = send(
        &app,
        Request::builder()
            .uri("/api/v1/detonations?limit=1")
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("list request")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap_or_else(|_| panic!("list body"));
    let list: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or_else(|_| panic!("list JSON"));
    assert_eq!(list["runs"].as_array().map(Vec::len), Some(1));
    assert_eq!(list["runs"][0]["run_id"], second_id.to_string());
    assert!(list["next_cursor"].is_string());

    let response = send(
        &app,
        Request::builder()
            .uri(format!("/api/v1/detonations/{second_id}"))
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("detail request")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap_or_else(|_| panic!("detail body"));
    let detail: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or_else(|_| panic!("detail JSON"));
    assert_eq!(detail["run"]["state"], "incomplete");
    assert_eq!(detail["run"]["package_name"], "synthetic-package");

    let response = send(
        &app,
        Request::builder()
            .uri(format!(
                "/api/v1/detonations/{first_id}/events?after_seq=0&limit=1"
            ))
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("events request")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap_or_else(|_| panic!("events body"));
    let page: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or_else(|_| panic!("events JSON"));
    assert_eq!(page["events"][0]["seq"], 1);
    assert_eq!(page["next_after_seq"], 1);
    assert_eq!(page["events"][0]["automatic_redaction_limitation"], true);

    let response = send(
        &app,
        Request::builder()
            .uri(format!(
                "/api/v1/detonations/{first_id}/events?after_seq=1&limit=1"
            ))
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("next events request")),
    )
    .await;
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap_or_else(|_| panic!("next events body"));
    let page: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or_else(|_| panic!("next events JSON"));
    assert_eq!(page["events"][0]["failure"], "network_unreachable");
    assert_eq!(page["events"][0]["outcome"], "failed");
}

#[tokio::test]
async fn invalid_ids_parameters_cursors_and_disabled_routes_fail_closed() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let (config, _env) = configure(directory.path());
    let app = app_with_config(config);
    for uri in [
        "/api/v1/detonations?limit=0",
        "/api/v1/detonations?limit=not-a-number",
        "/api/v1/detonations?limit=50&cursor=not-a-cursor",
        "/api/v1/detonations/not-hex",
        "/api/v1/detonations/0123456789abcdef0123456789abcdef/events?after_seq=18446744073709551616",
        "/api/v1/detonations/0123456789abcdef0123456789abcdef/events?limit=-1",
        "/api/v1/detonations/0123456789abcdef0123456789abcdef/logs",
        "/api/v1/detonations/0123456789abcdef0123456789abcdef/logs?stream=private",
        "/api/v1/detonations/0123456789abcdef0123456789abcdef/logs?stream=stdout&after=-1",
    ] {
        let response = send(&app, Request::builder().uri(uri).body(Body::empty()).unwrap_or_else(|_| panic!("valid GET"))).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
    }
    let response = send(
        &app,
        Request::builder()
            .uri("/api/v1/detonations")
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("list request")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap_or_else(|_| panic!("empty list body"));
    let empty: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or_else(|_| panic!("empty list JSON"));
    assert_eq!(empty["runs"], serde_json::json!([]));

    std::env::set_var("SUPPLY_DETONATION_ROUTES_ENABLED", "0");
    let disabled = send(
        &app,
        Request::builder()
            .uri("/api/v1/detonations")
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("disabled request")),
    )
    .await;
    let unknown = send(
        &app,
        Request::builder()
            .uri("/no-such-route")
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("unknown request")),
    )
    .await;
    assert_eq!(disabled.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        disabled.headers().get(header::CONTENT_TYPE),
        unknown.headers().get(header::CONTENT_TYPE)
    );
    assert_eq!(
        axum::body::to_bytes(disabled.into_body(), 1024)
            .await
            .unwrap_or_else(|_| panic!("disabled body")),
        axum::body::to_bytes(unknown.into_body(), 1024)
            .await
            .unwrap_or_else(|_| panic!("unknown body"))
    );
}

#[tokio::test]
async fn corrupt_bundle_and_symlink_entries_look_absent_and_artifact_symlinks_are_not_served() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let (mut config, _env) = configure(directory.path());
    config.artifacts_dir = Some(directory.path().join("artifacts"));
    fs::create_dir_all(
        config
            .artifacts_dir
            .as_ref()
            .unwrap_or_else(|| panic!("artifact dir")),
    )
    .unwrap_or_else(|_| panic!("artifact directory"));
    let outside = directory.path().join("outside");
    fs::write(&outside, "private canary").unwrap_or_else(|_| panic!("outside file"));
    symlink(
        &outside,
        config
            .artifacts_dir
            .as_ref()
            .unwrap_or_else(|| panic!("artifact dir"))
            .join("link"),
    )
    .unwrap_or_else(|_| panic!("artifact symlink"));
    let app = app_with_config(config.clone());
    let response = send(
        &app,
        Request::builder()
            .uri("/api/v1/download/link")
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("download request")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let id = RunId([3; 16]);
    let bytes = bundle(
        id,
        RunState::Complete,
        10,
        &[event(id, 1, EventKind::ProcessExec, None)],
    );
    let response = send(
        &app,
        put_request(&id.to_string(), Some("test-token"), bytes),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let path = config
        .detonation_public_store
        .as_ref()
        .unwrap_or_else(|| panic!("public store"))
        .join(format!("{id}.bundle"));
    let file =
        OpenOptionsCompat::open_write(&path).unwrap_or_else(|_| panic!("open sealed bundle"));
    file.write_at(b"x", 0)
        .unwrap_or_else(|_| panic!("tamper bundle"));
    file.sync_all().unwrap_or_else(|_| panic!("sync tamper"));
    let response = send(
        &app,
        Request::builder()
            .uri(format!("/api/v1/detonations/{id}"))
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("detail request")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let other = RunId([4; 16]);
    symlink(
        &outside,
        config
            .detonation_public_store
            .as_ref()
            .unwrap_or_else(|| panic!("public store"))
            .join(format!("{other}.bundle")),
    )
    .unwrap_or_else(|_| panic!("bundle symlink"));
    let response = send(
        &app,
        Request::builder()
            .uri(format!("/api/v1/detonations/{other}"))
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("symlink detail request")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn oversized_or_unredacted_bundles_and_split_stream_secrets_are_rejected_without_echo() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let (config, _env) = configure(directory.path());
    let app = app_with_config(config);
    let id = RunId([5; 16]);
    let secret = "token=canary-should-never-leak";
    let malicious = bundle(
        id,
        RunState::Complete,
        100,
        &[event(id, 1, EventKind::ProcessExec, Some(secret))],
    );
    let response = send(
        &app,
        put_request(&id.to_string(), Some("test-token"), malicious),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap_or_else(|_| panic!("error body"));
    assert!(!String::from_utf8_lossy(&body).contains(secret));

    let split_id = RunId([6; 16]);
    let split = [
        event(split_id, 1, EventKind::Stdout, Some("token")),
        event(split_id, 2, EventKind::Stdout, Some("=split-canary")),
    ];
    let response = send(
        &app,
        put_request(
            &split_id.to_string(),
            Some("test-token"),
            bundle(split_id, RunState::Complete, 200, &split),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let oversized_id = RunId([7; 16]);
    let response = send(
        &app,
        put_request(
            &oversized_id.to_string(),
            Some("test-token"),
            vec![b'x'; 26 * 1024 * 1024],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn concurrent_same_id_puts_publish_once_and_policy_mismatch_is_pending() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let (config, _env) = configure(directory.path());
    let app = app_with_config(config);
    let id = RunId([8; 16]);
    let bytes = bundle(
        id,
        RunState::Incomplete,
        300,
        &[event(id, 1, EventKind::ProcessExit, None)],
    );
    let first = app.clone().oneshot(put_request(
        &id.to_string(),
        Some("test-token"),
        bytes.clone(),
    ));
    let second = app
        .clone()
        .oneshot(put_request(&id.to_string(), Some("test-token"), bytes));
    let (first, second) = tokio::join!(first, second);
    let statuses = [
        first.unwrap_or_else(|_| panic!("first request")).status(),
        second.unwrap_or_else(|_| panic!("second request")).status(),
    ];
    assert!(statuses.contains(&StatusCode::CREATED));
    assert!(statuses.contains(&StatusCode::OK));

    let mismatch_id = RunId([9; 16]);
    let mut mismatch = manifest(mismatch_id, RunState::Complete, 400, Some(0));
    mismatch.redaction_policy_version += 1;
    let bytes = encode_public_bundle(
        mismatch,
        &[event(mismatch_id, 1, EventKind::ProcessExec, None)],
        "test-key",
        TEST_KEY,
    )
    .unwrap_or_else(|_| panic!("mismatch bundle encodes"));
    let response = send(
        &app,
        put_request(&mismatch_id.to_string(), Some("test-token"), bytes),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap_or_else(|_| panic!("pending body"));
    let pending: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or_else(|_| panic!("pending JSON"));
    assert_eq!(pending["state"], "pending");
}

#[tokio::test]
async fn public_store_full_returns_507_and_empty_or_missing_run_behavior_is_stable() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let (config, _env) = configure(directory.path());
    let app = app_with_config(config.clone());
    let store = config
        .detonation_public_store
        .as_ref()
        .unwrap_or_else(|| panic!("public store"));
    fs::create_dir_all(store).unwrap_or_else(|_| panic!("public store directory"));
    fs::set_permissions(store, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|_| panic!("public store permissions"));
    File::create(store.join("fill"))
        .and_then(|file| file.set_len(256 * 1024 * 1024))
        .unwrap_or_else(|_| panic!("sparse quota fixture"));
    let id = RunId([10; 16]);
    let response = send(
        &app,
        put_request(
            &id.to_string(),
            Some("test-token"),
            bundle(id, RunState::Complete, 500, &[]),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::INSUFFICIENT_STORAGE);
    let response = send(
        &app,
        Request::builder()
            .uri("/api/v1/detonations/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("missing detail")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

async fn assert_responses_match(left: axum::response::Response, right: axum::response::Response) {
    assert_eq!(left.status(), right.status());
    assert_eq!(left.headers(), right.headers());
    let left = axum::body::to_bytes(left.into_body(), 1024)
        .await
        .unwrap_or_else(|_| panic!("left response body"));
    let right = axum::body::to_bytes(right.into_body(), 1024)
        .await
        .unwrap_or_else(|_| panic!("right response body"));
    assert_eq!(left, right);
}

#[tokio::test]
async fn disabled_routes_match_unknown_routes_and_preserve_enabled_cors() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let (config, _env) = configure(directory.path());
    let app = app_with_config(config);
    let enabled = send(
        &app,
        Request::builder()
            .uri("/api/v1/detonations")
            .header(header::ORIGIN, "https://client.invalid")
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("enabled GET")),
    )
    .await;
    assert_eq!(enabled.status(), StatusCode::OK);
    assert_eq!(enabled.headers()["access-control-allow-origin"], "*");
    let enabled_preflight = send(
        &app,
        Request::builder()
            .method("OPTIONS")
            .uri("/api/v1/detonations")
            .header(header::ORIGIN, "https://client.invalid")
            .header("access-control-request-method", "GET")
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("enabled preflight")),
    )
    .await;
    assert_eq!(enabled_preflight.status(), StatusCode::OK);
    assert_eq!(
        enabled_preflight.headers()["access-control-allow-origin"],
        "*"
    );

    std::env::set_var("SUPPLY_DETONATION_ROUTES_ENABLED", "0");
    let disabled_get = send(
        &app,
        Request::builder()
            .uri("/api/v1/detonations")
            .header(header::ORIGIN, "https://client.invalid")
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("disabled GET")),
    )
    .await;
    let unknown_get = send(
        &app,
        Request::builder()
            .uri("/no-such-route")
            .header(header::ORIGIN, "https://client.invalid")
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("unknown GET")),
    )
    .await;
    assert_responses_match(disabled_get, unknown_get).await;
    let disabled_post = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/api/v1/detonations")
            .header(header::ORIGIN, "https://client.invalid")
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("disabled POST")),
    )
    .await;
    let unknown_post = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/no-such-route")
            .header(header::ORIGIN, "https://client.invalid")
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("unknown POST")),
    )
    .await;
    assert_responses_match(disabled_post, unknown_post).await;

    let disabled_options = send(
        &app,
        Request::builder()
            .method("OPTIONS")
            .uri("/api/v1/detonations")
            .header(header::ORIGIN, "https://client.invalid")
            .header("access-control-request-method", "GET")
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("disabled preflight")),
    )
    .await;
    let unknown_options = send(
        &app,
        Request::builder()
            .method("OPTIONS")
            .uri("/no-such-route")
            .header(header::ORIGIN, "https://client.invalid")
            .header("access-control-request-method", "GET")
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("unknown preflight")),
    )
    .await;
    assert_responses_match(disabled_options, unknown_options).await;
}

#[tokio::test]
async fn log_limit_returns_multi_kibibyte_byte_slices() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let (config, _env) = configure(directory.path());
    let app = app_with_config(config);
    let id = RunId([11; 16]);
    let text = "x".repeat(6 * 1024);
    let events = (1..=200)
        .map(|seq| event(id, seq, EventKind::Stdout, Some(&text)))
        .collect::<Vec<_>>();
    let bytes = bundle(id, RunState::Complete, 600, &events);
    let uploaded = send(
        &app,
        put_request(&id.to_string(), Some("test-token"), bytes),
    )
    .await;
    assert_eq!(uploaded.status(), StatusCode::CREATED);

    let response = send(
        &app,
        Request::builder()
            .uri(format!(
                "/api/v1/detonations/{id}/logs?stream=stdout&limit=4096"
            ))
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("log request")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
        .await
        .unwrap_or_else(|_| panic!("log body"));
    let logs: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or_else(|_| panic!("log JSON"));
    assert_eq!(logs["slices"][0]["text"].as_str().map(str::len), Some(4096));
    assert_eq!(logs["next_offset"], 4096);
    let default_response = send(
        &app,
        Request::builder()
            .uri(format!("/api/v1/detonations/{id}/logs?stream=stdout"))
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("default log request")),
    )
    .await;
    assert_eq!(default_response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(default_response.into_body(), 128 * 1024)
        .await
        .unwrap_or_else(|_| panic!("default log body"));
    let logs: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or_else(|_| panic!("default log JSON"));
    assert_eq!(
        logs["slices"][0]["text"].as_str().map(str::len),
        Some(64 * 1024)
    );
    assert_eq!(logs["next_offset"], 64 * 1024);

    let capped_response = send(
        &app,
        Request::builder()
            .uri(format!(
                "/api/v1/detonations/{id}/logs?stream=stdout&limit=2097152"
            ))
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("capped log request")),
    )
    .await;
    assert_eq!(capped_response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(capped_response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap_or_else(|_| panic!("capped log body"));
    let logs: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or_else(|_| panic!("capped log JSON"));
    assert_eq!(
        logs["slices"][0]["text"].as_str().map(str::len),
        Some(1024 * 1024)
    );
    assert_eq!(logs["next_offset"], 1024 * 1024);
}

#[tokio::test]
async fn missing_public_store_reads_do_not_create_store_directory() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let (config, _env) = configure(directory.path());
    let store = config
        .detonation_public_store
        .as_ref()
        .unwrap_or_else(|| panic!("public store"))
        .clone();
    let app = app_with_config(config);
    let id = RunId([12; 16]);

    let response = send(
        &app,
        Request::builder()
            .uri("/api/v1/detonations")
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("list request")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap_or_else(|_| panic!("empty list body"));
    let list: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or_else(|_| panic!("empty list JSON"));
    assert_eq!(list["runs"], serde_json::json!([]));
    assert!(!store.exists());

    for uri in [
        format!("/api/v1/detonations/{id}"),
        format!("/api/v1/detonations/{id}/events"),
        format!("/api/v1/detonations/{id}/logs?stream=stdout"),
    ] {
        let response = send(
            &app,
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .unwrap_or_else(|_| panic!("run-scoped request")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(!store.exists());
    }
}

#[tokio::test]
async fn receive_failures_and_cancellation_remove_staging_files() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let (config, _env) = configure(directory.path());
    let store = config
        .detonation_public_store
        .as_ref()
        .unwrap_or_else(|| panic!("public store"))
        .clone();
    let app = app_with_config(config);
    let id = RunId([13; 16]);
    let failed_body = Body::from_stream(futures_util::stream::iter([Err::<
        axum::body::Bytes,
        std::io::Error,
    >(std::io::Error::other(
        "body failed",
    ))]));
    let response = send(
        &app,
        Request::builder()
            .method("PUT")
            .uri(format!("/api/v1/detonations/{id}"))
            .header(header::AUTHORIZATION, "Bearer test-token")
            .body(failed_body)
            .unwrap_or_else(|_| panic!("failed body request")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let staging = store.join("staging");
    let entries = fs::read_dir(&staging)
        .unwrap_or_else(|_| panic!("staging directory"))
        .count();
    assert_eq!(entries, 0);

    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let mut started_tx = Some(started_tx);
    let pending_body = Body::from_stream(futures_util::stream::poll_fn(move |_| {
        if let Some(started_tx) = started_tx.take() {
            let _ = started_tx.send(());
            Poll::Ready(Some(Ok::<_, std::io::Error>(
                axum::body::Bytes::from_static(b"partial"),
            )))
        } else {
            Poll::Pending
        }
    }));
    let request = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/detonations/{id}"))
        .header(header::AUTHORIZATION, "Bearer test-token")
        .body(pending_body)
        .unwrap_or_else(|_| panic!("pending body request"));
    let request_task = tokio::spawn(app.oneshot(request));
    tokio::time::timeout(std::time::Duration::from_secs(2), started_rx)
        .await
        .unwrap_or_else(|_| panic!("body stream starts"))
        .unwrap_or_else(|_| panic!("body stream signal"));
    request_task.abort();
    let _ = request_task.await;

    let entries = fs::read_dir(&staging)
        .unwrap_or_else(|_| panic!("staging directory after cancellation"))
        .count();
    assert_eq!(entries, 0);
}

#[tokio::test]
async fn staging_bytes_count_toward_public_store_quota() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let (config, _env) = configure(directory.path());
    let store = config
        .detonation_public_store
        .as_ref()
        .unwrap_or_else(|| panic!("public store"));
    let staging = store.join("staging");
    fs::create_dir_all(&staging).unwrap_or_else(|_| panic!("staging directory"));
    fs::set_permissions(store, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|_| panic!("public store permissions"));
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|_| panic!("staging permissions"));
    File::create(staging.join("existing.tmp"))
        .and_then(|file| file.set_len(256 * 1024 * 1024))
        .unwrap_or_else(|_| panic!("staging quota fixture"));
    let app = app_with_config(config);
    let id = RunId([14; 16]);
    let response = send(
        &app,
        put_request(
            &id.to_string(),
            Some("test-token"),
            bundle(id, RunState::Complete, 700, &[]),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::INSUFFICIENT_STORAGE);
}

#[tokio::test]
async fn unreadable_existing_bundle_returns_service_unavailable() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let (config, _env) = configure(directory.path());
    let store = config
        .detonation_public_store
        .as_ref()
        .unwrap_or_else(|| panic!("public store"));
    fs::create_dir(store).unwrap_or_else(|_| panic!("public store directory"));
    fs::set_permissions(store, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|_| panic!("public store permissions"));
    let id = RunId([15; 16]);
    fs::create_dir(store.join(format!("{id}.bundle")))
        .unwrap_or_else(|_| panic!("invalid existing bundle"));
    let app = app_with_config(config);
    let response = send(
        &app,
        put_request(
            &id.to_string(),
            Some("test-token"),
            bundle(id, RunState::Complete, 800, &[]),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

struct OpenOptionsCompat;
impl OpenOptionsCompat {
    fn open_write(path: &Path) -> std::io::Result<File> {
        std::fs::OpenOptions::new().write(true).open(path)
    }
}
