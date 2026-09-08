use crate::{
    adapters::{
        azure_devops::pipeline_annotations, config::parse_policy_str, github::workflow_annotations,
    },
    application::{AzurePipelinesScanner, GitHubActionsScanner},
    domain::{Decision, GitHubActionReference, PipelineReference, Policy},
    ports::WorkflowReader,
};
use anyhow::Result;
use axum::{
    extract::{Path as AxumPath, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

const PUBLIC_STATUS_PAGE: &str = include_str!("../../../web/index.html");

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub service_name: String,
    pub artifacts_dir: Option<PathBuf>,
    pub auth_token: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            service_name: std::env::var("SUPPLY_SERVICE_NAME")
                .unwrap_or_else(|_| "supply-core-official".to_string()),
            artifacts_dir: std::env::var("SUPPLY_ARTIFACTS_DIR")
                .ok()
                .map(PathBuf::from),
            auth_token: std::env::var("SUPPLY_AUTH_TOKEN").ok(),
        }
    }
}

pub struct MemoryWorkflowReader {
    pub files: Vec<(String, String)>,
}

impl WorkflowReader for MemoryWorkflowReader {
    fn read(&self, _root: &Path) -> Result<Vec<(String, String)>> {
        Ok(self.files.clone())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FileInput {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PipelineScanRequest {
    #[serde(default)]
    pub policy: Option<String>,
    pub files: Vec<FileInput>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PipelineScanResponse {
    pub blocking: bool,
    pub scanned_references_count: usize,
    pub findings: Vec<Decision>,
    pub references: Vec<PipelineReference>,
    pub annotations: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ActionScanRequest {
    #[serde(default)]
    pub policy: Option<String>,
    pub files: Vec<FileInput>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActionScanResponse {
    pub blocking: bool,
    pub scanned_references_count: usize,
    pub findings: Vec<Decision>,
    pub references: Vec<GitHubActionReference>,
    pub annotations: Vec<String>,
}

pub fn app() -> Router {
    app_with_config(ServerConfig::default())
}

pub fn app_with_config(config: ServerConfig) -> Router {
    let state = Arc::new(config);

    Router::new()
        .route("/health", get(health_check))
        .route("/", get(status_page))
        .route("/api/v1/health", get(detailed_health))
        .route("/api/v1/status", get(public_status))
        .route("/api/v1/version", get(version_info))
        .route("/api/v1/download/:artifact", get(download_artifact))
        .route("/api/v1/scan/pipelines", post(scan_azure_pipelines))
        .route("/api/v1/scan/azure-pipelines", post(scan_azure_pipelines))
        .route("/api/v1/scan/actions", post(scan_github_actions))
        .route("/api/v1/scan/github-actions", post(scan_github_actions))
        .with_state(state)
}

async fn status_page() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        PUBLIC_STATUS_PAGE,
    )
}

fn check_auth(state: &ServerConfig, headers: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
    let Some(expected_token) = &state.auth_token else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "scan authentication is not configured"})),
        ));
    };
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    let token_match = match auth_header {
        Some(val) if val.starts_with("Bearer ") => {
            let token = val.trim_start_matches("Bearer ").trim();
            token == expected_token
        }
        _ => false,
    };

    if !token_match {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized: valid Bearer token required"})),
        ));
    }
    Ok(())
}

async fn public_status(State(state): State<Arc<ServerConfig>>) -> Json<Value> {
    Json(json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "service": state.service_name,
        "version": env!("CARGO_PKG_VERSION"),
        "health": {"status": "ok"},
        "quarantine": {
            "enabled": true,
            "minimum_age_days": 7,
            "packages": []
        }
    }))
}

async fn health_check(State(state): State<Arc<ServerConfig>>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": state.service_name,
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn detailed_health(State(state): State<Arc<ServerConfig>>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": state.service_name,
        "version": env!("CARGO_PKG_VERSION"),
        "tailnet": "tail5d39b4.ts.net",
        "features": [
            "azure-pipelines-scan",
            "github-actions-scan",
            "artifact-distribution",
            "policy-validation"
        ],
        "artifacts_dir_configured": state.artifacts_dir.is_some(),
        "auth_configured": state.auth_token.is_some()
    }))
}

async fn version_info(State(state): State<Arc<ServerConfig>>) -> Json<Value> {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "service": state.service_name,
        "repository": "https://github.com/jakubkrzysztofsikora/supply-core",
        "download_base": "/api/v1/download",
        "artifacts": [
            "supply-core-linux-x86_64",
            "supply-core-macos-arm64",
            "supply-core-macos-x86_64"
        ]
    }))
}

async fn download_artifact(
    AxumPath(artifact): AxumPath<String>,
    State(state): State<Arc<ServerConfig>>,
) -> Response {
    if artifact.contains('/') || artifact.contains('\\') || artifact.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid artifact name"})),
        )
            .into_response();
    }

    if let Some(dir) = &state.artifacts_dir {
        let file_path = dir.join(&artifact);
        if file_path.is_file() {
            if let Ok(bytes) = std::fs::read(&file_path) {
                let headers = [
                    (header::CONTENT_TYPE, "application/octet-stream"),
                    (
                        header::CONTENT_DISPOSITION,
                        &format!("attachment; filename=\"{artifact}\""),
                    ),
                ];
                return (StatusCode::OK, headers, bytes).into_response();
            }
        }
    }

    let github_url = format!(
        "https://github.com/jakubkrzysztofsikora/supply-core/releases/latest/download/{artifact}"
    );
    Redirect::temporary(&github_url).into_response()
}

async fn scan_azure_pipelines(
    headers: HeaderMap,
    State(state): State<Arc<ServerConfig>>,
    Json(payload): Json<PipelineScanRequest>,
) -> Result<Json<PipelineScanResponse>, (StatusCode, Json<Value>)> {
    check_auth(&state, &headers)?;

    let policy = match payload.policy {
        Some(yaml_str) => parse_policy_str(&yaml_str).map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid policy YAML: {err}")})),
            )
        })?,
        None => Policy::default(),
    };

    let files: Vec<(String, String)> = payload
        .files
        .into_iter()
        .map(|f| (f.path, f.content))
        .collect();

    let reader = MemoryWorkflowReader { files };
    let scanner = AzurePipelinesScanner {
        policy: &policy,
        reader: &reader,
    };

    let report = scanner.scan(Path::new(".")).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("failed to scan pipelines: {err}")})),
        )
    })?;

    let annotations = pipeline_annotations(&report);

    Ok(Json(PipelineScanResponse {
        blocking: report.is_blocking(),
        scanned_references_count: report.references.len(),
        findings: report.findings,
        references: report.references,
        annotations,
    }))
}

async fn scan_github_actions(
    headers: HeaderMap,
    State(state): State<Arc<ServerConfig>>,
    Json(payload): Json<ActionScanRequest>,
) -> Result<Json<ActionScanResponse>, (StatusCode, Json<Value>)> {
    check_auth(&state, &headers)?;

    let policy = match payload.policy {
        Some(yaml_str) => parse_policy_str(&yaml_str).map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid policy YAML: {err}")})),
            )
        })?,
        None => Policy::default(),
    };

    let files: Vec<(String, String)> = payload
        .files
        .into_iter()
        .map(|f| (f.path, f.content))
        .collect();

    let reader = MemoryWorkflowReader { files };
    let scanner = GitHubActionsScanner {
        policy: &policy,
        reader: &reader,
    };

    let report = scanner.scan(Path::new(".")).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("failed to scan workflows: {err}")})),
        )
    })?;

    let annotations = workflow_annotations(&report);

    Ok(Json(ActionScanResponse {
        blocking: report.is_blocking(),
        scanned_references_count: report.references.len(),
        findings: report.findings,
        references: report.references,
        annotations,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_endpoints() {
        let app = app();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap_or_else(|_| panic!("valid request")),
            )
            .await
            .unwrap_or_else(|_| panic!("request succeeds"));

        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .body(axum::body::Body::empty())
                    .unwrap_or_else(|_| panic!("valid request")),
            )
            .await
            .unwrap_or_else(|_| panic!("request succeeds"));

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_public_status_page_and_diagnostics() {
        let app = app();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(axum::body::Body::empty())
                    .unwrap_or_else(|_| panic!("valid request")),
            )
            .await
            .unwrap_or_else(|_| panic!("request succeeds"));
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8")
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .body(axum::body::Body::empty())
                    .unwrap_or_else(|_| panic!("valid request")),
            )
            .await
            .unwrap_or_else(|_| panic!("request succeeds"));
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_remote_pipeline_scan_passes() {
        let app = app_with_config(ServerConfig {
            auth_token: Some("test-token".into()),
            ..ServerConfig::default()
        });

        let payload = json!({
            "files": [
                {
                    "path": "azure-pipelines.yml",
                    "content": "steps:\n- checkout: self\n- task: NodeTool@0\n"
                }
            ]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/scan/pipelines")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(axum::body::Body::from(payload.to_string()))
                    .unwrap_or_else(|_| panic!("valid request")),
            )
            .await
            .unwrap_or_else(|_| panic!("request succeeds"));

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_remote_pipeline_scan_blocks_unpinned() {
        let app = app_with_config(ServerConfig {
            auth_token: Some("test-token".into()),
            ..ServerConfig::default()
        });

        let payload = json!({
            "files": [
                {
                    "path": "azure-pipelines.yml",
                    "content": "steps:\n- checkout: git://Circit/unpinned-repo@main\n"
                }
            ]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/scan/pipelines")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(axum::body::Body::from(payload.to_string()))
                    .unwrap_or_else(|_| panic!("valid request")),
            )
            .await
            .unwrap_or_else(|_| panic!("request succeeds"));

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_remote_scan_requires_configured_authentication() {
        let app = app();
        let payload = json!({"files": []});
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/scan/pipelines")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(payload.to_string()))
                    .unwrap_or_else(|_| panic!("valid request")),
            )
            .await
            .unwrap_or_else(|_| panic!("request succeeds"));

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
