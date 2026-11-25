use crate::{
    adapters::{
        azure_devops::pipeline_annotations, config::parse_policy_str, docker_mirror,
        github::workflow_annotations,
    },
    application::{AzurePipelinesScanner, GitHubActionsScanner},
    domain::{Decision, GitHubActionReference, PipelineReference, Policy},
    ports::WorkflowReader,
};
use anyhow::Result;
use axum::{
    extract::{Path as AxumPath, State},
    http::{header, HeaderMap, Method, StatusCode},
    middleware,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tower_http::cors::{Any, CorsLayer};

mod detonations;

const PUBLIC_STATUS_PAGE: &str = include_str!("../../../web/index.html");

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub service_name: String,
    pub artifacts_dir: Option<PathBuf>,
    pub status_file: Option<PathBuf>,
    pub auth_token: Option<String>,
    pub tailnet_domain: Option<String>,
    pub detonation_public_store: Option<PathBuf>,
    pub detonation_ingest_token_file: Option<PathBuf>,
}

fn configured_token(raw: Option<String>) -> Option<String> {
    raw.map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
}

pub fn configured_domain() -> Option<String> {
    configured_token(std::env::var("SUPPLY_TAILNET_DOMAIN").ok())
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            service_name: std::env::var("SUPPLY_SERVICE_NAME")
                .unwrap_or_else(|_| "supply-core".to_string()),
            artifacts_dir: std::env::var("SUPPLY_ARTIFACTS_DIR")
                .ok()
                .map(PathBuf::from),
            status_file: std::env::var("SUPPLY_STATUS_FILE").ok().map(PathBuf::from),
            auth_token: configured_token(std::env::var("SUPPLY_AUTH_TOKEN").ok()),
            tailnet_domain: configured_domain(),
            detonation_public_store: std::env::var_os("SUPPLY_DETONATION_PUBLIC_STORE")
                .map(PathBuf::from),
            detonation_ingest_token_file: std::env::var_os("SUPPLY_DETONATION_INGEST_TOKEN_FILE")
                .map(PathBuf::from),
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

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
struct QuarantinedPackage {
    name: String,
    version: String,
    age_days: i64,
    status: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
struct ConfirmedFinding {
    name: String,
    version: String,
    #[serde(default)]
    advisory: String,
    #[serde(default)]
    severity: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
struct SuspectedFinding {
    name: String,
    version: String,
    #[serde(default)]
    score: u8,
    #[serde(default)]
    rules: Vec<String>,
}
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
struct IncompleteFinding {
    name: String,
    version: String,
    verdict: String,
}

const MAX_SCAN_ROWS: usize = 1_000;
const MAX_SCAN_CANDIDATES: usize = 100_000;
const MAX_SCAN_ERRORS: usize = 100_000;
const MAX_SCAN_FINDINGS: usize = 100_000;
const MAX_SCAN_IDENTIFIERS: usize = 16;
const MAX_SCAN_FIELD_BYTES: usize = 256;
const MAX_SCAN_IDENTIFIER_BYTES: usize = 120;
const MAX_SCAN_SCORE_BYTES: usize = 32;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
struct ScannedPackageSummary {
    name: String,
    version: String,
    decision: String,
    coverage: String,
    findings: usize,
    score: Option<String>,
    rules: Vec<String>,
    sources: Vec<String>,
    #[serde(default)]
    reasons: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
struct ScanSummary {
    captured_at: String,
    candidate_count: usize,
    scanned: Vec<ScannedPackageSummary>,
    error_count: usize,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
struct QuarantineSnapshot {
    captured_at: String,
    packages: Vec<QuarantinedPackage>,
    #[serde(default)]
    confirmed: Vec<ConfirmedFinding>,
    #[serde(default)]
    suspected: Vec<SuspectedFinding>,
    #[serde(default)]
    scan_incomplete: Vec<IncompleteFinding>,
    #[serde(default)]
    scan_incomplete_truncated: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scan: Option<ScanSummary>,
}

pub fn app() -> Router {
    app_with_config(ServerConfig::default())
}

pub fn app_with_config(config: ServerConfig) -> Router {
    match docker_mirror::Config::from_env(Policy::default())
        .map(docker_mirror::routes)
        .transpose()
    {
        Ok(mirror) => server_routes(config, mirror),
        Err(error) => {
            eprintln!("Docker mirror could not start: {error:#}");
            server_routes(config, None)
        }
    }
}

pub fn app_with_policy(config: ServerConfig, policy: Policy) -> Result<Router> {
    let mirror = docker_mirror::Config::from_env(policy)
        .map(docker_mirror::routes)
        .transpose()?;
    Ok(server_routes(config, mirror))
}

fn server_routes(config: ServerConfig, mirror: Option<Router>) -> Router {
    let state = Arc::new(config);
    let public_cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET]);

    let public = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/health", get(detailed_health))
        .route("/api/v1/status", get(public_status))
        .route("/api/v1/status/card.svg", get(status_card))
        .route("/api/v1/version", get(version_info))
        .layer(public_cors);

    let server = Router::new()
        .route("/", get(status_page))
        .route("/api/v1/status/quarantine", put(publish_quarantine_status))
        .route("/api/v1/download/:artifact", get(download_artifact))
        .route("/api/v1/scan/pipelines", post(scan_azure_pipelines))
        .route("/api/v1/scan/azure-pipelines", post(scan_azure_pipelines))
        .route("/api/v1/scan/actions", post(scan_github_actions))
        .route("/api/v1/scan/github-actions", post(scan_github_actions))
        .merge(public)
        .merge(detonations::routes())
        .with_state(state);
    Router::new()
        .fallback_service(server.merge(mirror.unwrap_or_default()))
        .layer(middleware::from_fn(detonations::route_gate))
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
            crate::adapters::detonation::constant_time_eq(
                token.as_bytes(),
                expected_token.as_bytes(),
            )
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
    let snapshot = read_quarantine_snapshot(state.status_file.as_deref())
        .ok()
        .flatten();
    let scan = snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.scan.as_ref())
        .map(|scan| {
            let blocked: Vec<_> = scan
                .scanned
                .iter()
                .filter(|row| row.decision == "block")
                .collect();
            json!({
                "captured_at": &scan.captured_at,
                "candidate_count": scan.candidate_count,
                "scanned_count": scan.scanned.len(),
                "blocked_count": blocked.len(),
                "error_count": scan.error_count,
                "scanned": &scan.scanned,
                "blocked": blocked
            })
        });
    Json(json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "service": state.service_name,
        "version": env!("CARGO_PKG_VERSION"),
        "health": {"status": "ok"},
        "quarantine": {
            "enabled": true,
            "minimum_age_days": 7,
            "captured_at": snapshot.as_ref().map(|snapshot| &snapshot.captured_at),
            "packages": snapshot.as_ref().map(|snapshot| snapshot.packages.clone()).unwrap_or_default(),
            "confirmed": snapshot.as_ref().map(|snapshot| snapshot.confirmed.clone()).unwrap_or_default(),
            "suspected": snapshot.as_ref().map(|snapshot| snapshot.suspected.clone()).unwrap_or_default(),
            "scan_incomplete": snapshot.as_ref().map(|snapshot| snapshot.scan_incomplete.clone()).unwrap_or_default(),
            "scan_incomplete_truncated": snapshot.as_ref().map(|snapshot| snapshot.scan_incomplete_truncated).unwrap_or_default()
        },
        "scan": scan
    }))
}

const CARD_FONT: &str = "ui-monospace,SFMono-Regular,Menlo,monospace";
const CARD_MAX_ROWS: usize = 8;
const MAX_INCOMPLETE_FINDINGS: usize = 1_000;

fn xml_escape(raw: &str) -> String {
    let mut escaped = String::with_capacity(raw.len());
    for character in raw.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            '\t'
            | '\n'
            | '\r'
            | '\u{20}'..='\u{d7ff}'
            | '\u{e000}'..='\u{fffd}'
            | '\u{10000}'..='\u{10ffff}' => escaped.push(character),
            _ => escaped.push('\u{fffd}'),
        }
    }
    escaped
}

fn card_section<T>(items: &[T], format_row: impl Fn(&T) -> String) -> (Vec<String>, usize) {
    let mut lines: Vec<String> = items.iter().take(CARD_MAX_ROWS).map(format_row).collect();
    let hidden = items.len().saturating_sub(lines.len());
    if lines.is_empty() {
        lines.push("(none captured yet)".to_string());
    }
    (lines, hidden)
}

const CARD_WIDTH: usize = 900;
const CARD_MARGIN: usize = 24;
const CARD_GUTTER: usize = 24;
const CARD_COLUMN_WIDTH: usize = (CARD_WIDTH - CARD_MARGIN * 2 - CARD_GUTTER) / 2;
const CARD_WRAP_UNITS: usize = 48;
const CARD_LINE_HEIGHT: usize = 17;
const CARD_ROW_GAP: usize = 4;
const CARD_CONTENT_OFFSET: usize = 26;
const CARD_SECTION_GAP: usize = 18;

fn for_each_card_line(line: &str, mut render: impl FnMut(&str)) -> usize {
    let mut remaining = line;
    let mut count = 0;

    if remaining.is_empty() {
        render(remaining);
        return 1;
    }

    while !remaining.is_empty() {
        let mut units = 0;
        let mut hard_end = remaining.len();
        let mut last_space = None;

        for (index, character) in remaining.char_indices() {
            let width = if character.is_ascii() { 1 } else { 2 };
            if units + width > CARD_WRAP_UNITS {
                hard_end = index;
                break;
            }
            units += width;
            if character.is_whitespace() {
                last_space = Some((index, character.len_utf8()));
            }
        }

        if hard_end == remaining.len() {
            render(remaining);
            count += 1;
            break;
        }

        let (end, next) = match last_space.filter(|(index, _)| *index > 0) {
            Some((index, length)) => {
                let mut next = index + length;
                while let Some(character) = remaining[next..]
                    .chars()
                    .next()
                    .filter(|c| c.is_whitespace())
                {
                    next += character.len_utf8();
                }
                (index, next)
            }
            None => (hard_end, hard_end),
        };
        render(&remaining[..end]);
        count += 1;
        remaining = &remaining[next..];
    }

    count
}

fn card_wrapped_line_count(line: &str) -> usize {
    for_each_card_line(line, |_| {})
}

fn card_section_advance(lines: &[String], hidden: usize) -> usize {
    let rows_height: usize = lines
        .iter()
        .map(|line| card_wrapped_line_count(line) * CARD_LINE_HEIGHT + CARD_ROW_GAP)
        .sum();
    let hidden_height = usize::from(hidden > 0) * (CARD_LINE_HEIGHT + CARD_ROW_GAP);
    CARD_CONTENT_OFFSET + rows_height + hidden_height + CARD_SECTION_GAP
}

/// Dynamic SVG listing quarantined, confirmed, suspected and incomplete scans.
fn render_status_card(snapshot: Option<&QuarantineSnapshot>) -> String {
    let empty_packages: Vec<QuarantinedPackage> = Vec::new();
    let empty_confirmed: Vec<ConfirmedFinding> = Vec::new();
    let empty_suspected: Vec<SuspectedFinding> = Vec::new();
    let empty_incomplete: Vec<IncompleteFinding> = Vec::new();
    let packages = snapshot
        .map(|snapshot| &snapshot.packages)
        .unwrap_or(&empty_packages);
    let confirmed = snapshot
        .map(|snapshot| &snapshot.confirmed)
        .unwrap_or(&empty_confirmed);
    let suspected = snapshot
        .map(|snapshot| &snapshot.suspected)
        .unwrap_or(&empty_suspected);
    let scan_incomplete = snapshot
        .map(|snapshot| &snapshot.scan_incomplete)
        .unwrap_or(&empty_incomplete);
    let scan_incomplete_truncated = snapshot
        .map(|snapshot| snapshot.scan_incomplete_truncated)
        .unwrap_or_default();
    let captured_at = snapshot
        .map(|snapshot| snapshot.captured_at.as_str())
        .unwrap_or("no snapshot yet");

    let (quarantine_lines, quarantine_hidden) = card_section(packages, |package| {
        format!(
            "{}@{} · {}d",
            package.name, package.version, package.age_days
        )
    });
    let (confirmed_lines, confirmed_hidden) = card_section(confirmed, |finding| {
        let severity = if finding.severity.is_empty() {
            String::new()
        } else {
            format!("{} ", finding.severity)
        };
        format!(
            "{}@{} · {}{}",
            finding.name, finding.version, severity, finding.advisory
        )
    });
    let (suspected_lines, suspected_hidden) = card_section(suspected, |finding| {
        let rules: Vec<&str> = finding.rules.iter().take(2).map(String::as_str).collect();
        let suffix = if rules.is_empty() {
            String::new()
        } else {
            format!(" · {}", rules.join(", "))
        };
        format!(
            "{}@{} · score {}{}",
            finding.name, finding.version, finding.score, suffix
        )
    });
    let (incomplete_lines, incomplete_hidden) = card_section(scan_incomplete, |finding| {
        format!("{}@{} · scan incomplete", finding.name, finding.version)
    });
    let incomplete_hidden = incomplete_hidden.saturating_add(scan_incomplete_truncated);
    let incomplete_total = scan_incomplete
        .len()
        .saturating_add(scan_incomplete_truncated);

    let sections: [(&str, &str, &Vec<String>, usize, usize); 4] = [
        (
            "#58a6ff",
            "QUARANTINED",
            &quarantine_lines,
            quarantine_hidden,
            packages.len(),
        ),
        (
            "#f85149",
            "CONFIRMED CVE",
            &confirmed_lines,
            confirmed_hidden,
            confirmed.len(),
        ),
        (
            "#d29922",
            "SUSPECTED (SCAN)",
            &suspected_lines,
            suspected_hidden,
            suspected.len(),
        ),
        (
            "#bc8cff",
            "SCAN INCOMPLETE",
            &incomplete_lines,
            incomplete_hidden,
            incomplete_total,
        ),
    ];
    let top_row_advance = card_section_advance(sections[0].2, sections[0].3)
        .max(card_section_advance(sections[1].2, sections[1].3));
    let bottom_row_advance = card_section_advance(sections[2].2, sections[2].3)
        .max(card_section_advance(sections[3].2, sections[3].3));
    let height = 78 + top_row_advance + bottom_row_advance + 24;

    let mut svg = String::new();
    svg.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{CARD_WIDTH}\" height=\"{height}\" viewBox=\"0 0 {CARD_WIDTH} {height}\" role=\"img\" aria-label=\"supply-core package status\">"
    ));
    svg.push_str(&format!(
        "<rect width=\"{CARD_WIDTH}\" height=\"{height}\" rx=\"14\" fill=\"#0d1117\"/>"
    ));
    svg.push_str(&format!(
        "<text x=\"{CARD_MARGIN}\" y=\"40\" fill=\"#f0f6fc\" font-family=\"{CARD_FONT}\" font-size=\"19\" font-weight=\"700\">supply-core · package status</text>"
    ));
    svg.push_str(&format!(
        "<text x=\"{}\" y=\"40\" text-anchor=\"end\" fill=\"#8b949e\" font-family=\"{CARD_FONT}\" font-size=\"12\">{}</text>",
        CARD_WIDTH - CARD_MARGIN,
        xml_escape(captured_at)
    ));

    for (index, (color, title, lines, hidden, total)) in sections.iter().enumerate() {
        let column = index % 2;
        let section_row = index / 2;
        let x = CARD_MARGIN + column * (CARD_COLUMN_WIDTH + CARD_GUTTER);
        let section_y = 78 + usize::from(section_row > 0) * top_row_advance;
        if snapshot.is_some() {
            svg.push_str(&format!(
                "<text x=\"{x}\" y=\"{section_y}\" fill=\"{color}\" font-family=\"{CARD_FONT}\" font-size=\"13\" font-weight=\"700\">{title} ({total})</text>"
            ));
        } else {
            svg.push_str(&format!(
                "<text x=\"{x}\" y=\"{section_y}\" fill=\"{color}\" font-family=\"{CARD_FONT}\" font-size=\"13\" font-weight=\"700\">{title} (unknown)</text>"
            ));
        }

        let mut y = section_y + CARD_CONTENT_OFFSET;
        for line in lines.iter() {
            let aria_label = if line == "(none captured yet)" {
                String::new()
            } else {
                format!(" aria-label=\"{}\"", xml_escape(line))
            };
            svg.push_str(&format!(
                "<text x=\"{x}\" y=\"{y}\"{aria_label} fill=\"#c9d1d9\" font-family=\"{CARD_FONT}\" font-size=\"13\">"
            ));
            let mut first = true;
            let wrapped_lines = for_each_card_line(line, |part| {
                let escaped = xml_escape(part);
                if first {
                    svg.push_str(&format!("<tspan>{escaped}</tspan>"));
                    first = false;
                } else {
                    svg.push_str(&format!(
                        "<tspan x=\"{x}\" dy=\"{CARD_LINE_HEIGHT}\">{escaped}</tspan>"
                    ));
                }
            });
            svg.push_str("</text>");
            y += wrapped_lines * CARD_LINE_HEIGHT + CARD_ROW_GAP;
        }
        if *hidden > 0 {
            svg.push_str(&format!(
                "<text x=\"{x}\" y=\"{y}\" fill=\"#8b949e\" font-family=\"{CARD_FONT}\" font-size=\"13\">+{hidden} more</text>"
            ));
        }
    }
    svg.push_str("</svg>");
    svg
}

async fn status_card(State(state): State<Arc<ServerConfig>>) -> Response {
    let snapshot = read_quarantine_snapshot(state.status_file.as_deref())
        .ok()
        .flatten();
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        render_status_card(snapshot.as_ref()),
    )
        .into_response()
}

async fn publish_quarantine_status(
    headers: HeaderMap,
    State(state): State<Arc<ServerConfig>>,
    Json(snapshot): Json<QuarantineSnapshot>,
) -> Result<StatusCode, (StatusCode, Json<Value>)> {
    check_auth(&state, &headers)?;
    validate_quarantine_snapshot(&snapshot)?;
    let Some(status_file) = state.status_file.as_deref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "quarantine status storage is not configured"})),
        ));
    };
    write_quarantine_snapshot(status_file, &snapshot).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("failed to persist quarantine status: {err}")})),
        )
    })?;
    Ok(StatusCode::NO_CONTENT)
}

fn validate_quarantine_snapshot(
    snapshot: &QuarantineSnapshot,
) -> Result<(), (StatusCode, Json<Value>)> {
    let valid_time = chrono::DateTime::parse_from_rfc3339(&snapshot.captured_at).is_ok();
    let valid_packages = snapshot.packages.len() <= 5_000
        && snapshot.packages.iter().all(|package| {
            !package.name.trim().is_empty()
                && !package.version.trim().is_empty()
                && package.age_days >= 0
                && matches!(package.status.as_str(), "Block" | "Fallback")
        });
    let valid_confirmed = snapshot.confirmed.len() <= 1_000
        && snapshot.confirmed.iter().all(|finding| {
            !finding.name.trim().is_empty()
                && !finding.version.trim().is_empty()
                && finding.advisory.len() <= 256
                && finding.severity.len() <= 32
        });
    let valid_suspected = snapshot.suspected.len() <= 1_000
        && snapshot.suspected.iter().all(|finding| {
            !finding.name.trim().is_empty()
                && !finding.version.trim().is_empty()
                && finding.score <= 10
                && finding.rules.len() <= 16
                && finding.rules.iter().all(|rule| rule.len() <= 120)
        });
    let valid_incomplete = snapshot.scan_incomplete.len() <= MAX_INCOMPLETE_FINDINGS
        && snapshot.scan_incomplete.iter().all(|finding| {
            !finding.name.trim().is_empty()
                && finding.name.len() <= 256
                && !finding.version.trim().is_empty()
                && finding.version.len() <= 256
                && finding.verdict == "scan_incomplete"
        });
    let valid_scan = snapshot
        .scan
        .as_ref()
        .map(valid_scan_summary)
        .unwrap_or(true);
    if valid_time
        && valid_packages
        && valid_confirmed
        && valid_suspected
        && valid_incomplete
        && valid_scan
    {
        Ok(())
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid quarantine snapshot"})),
        ))
    }
}

fn valid_scan_identity(value: &str, allow_scope: bool) -> bool {
    let path_prefix = value
        .get(..2)
        .map(|prefix| prefix.as_bytes()[0].is_ascii_alphabetic() && prefix.as_bytes()[1] == b':')
        .unwrap_or(false);
    if value.trim().is_empty()
        || value.len() > MAX_SCAN_FIELD_BYTES
        || value.chars().any(char::is_control)
        || value.starts_with('/')
        || value.starts_with('\\')
        || value.contains('\\')
        || path_prefix
        || value
            .get(..5)
            .map(|prefix| prefix.eq_ignore_ascii_case("file:"))
            .unwrap_or(false)
    {
        return false;
    }
    if value.contains('/') {
        if !allow_scope || !value.starts_with('@') || value.matches('/').count() != 1 {
            return false;
        }
        let Some((scope, package)) = value.split_once('/') else {
            return false;
        };
        if scope.len() <= 1 || package.is_empty() {
            return false;
        }
    }
    true
}

fn valid_scan_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SCAN_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}

fn valid_scan_score(value: &str) -> bool {
    if value.len() > MAX_SCAN_SCORE_BYTES {
        return false;
    }
    let (negative, unsigned) = match value.strip_prefix('-') {
        Some(unsigned) => (true, unsigned),
        None => (false, value),
    };
    let (integer, fraction) = match unsigned.split_once('.') {
        Some((integer, fraction)) if !fraction.is_empty() => (integer, fraction),
        Some(_) => return false,
        None => (unsigned, ""),
    };
    if integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 28
        || integer.len() + fraction.len() > 29
    {
        return false;
    }
    let integer = integer.trim_start_matches('0');
    let integer = if integer.is_empty() { "0" } else { integer };
    let fraction_is_zero = fraction.bytes().all(|byte| byte == b'0');
    let in_range = match integer.len() {
        1 => true,
        2 => integer == "10" && fraction_is_zero,
        _ => false,
    };
    in_range && (!negative || (integer == "0" && fraction_is_zero))
}

fn valid_scan_summary(scan: &ScanSummary) -> bool {
    chrono::DateTime::parse_from_rfc3339(&scan.captured_at).is_ok()
        && scan.captured_at.len() <= 64
        && scan.candidate_count <= MAX_SCAN_CANDIDATES
        && scan.error_count <= MAX_SCAN_ERRORS
        && scan.scanned.len() <= MAX_SCAN_ROWS
        && scan.candidate_count >= scan.scanned.len()
        && scan.scanned.iter().all(|row| {
            valid_scan_identity(&row.name, true)
                && valid_scan_identity(&row.version, false)
                && matches!(
                    row.decision.as_str(),
                    "pass" | "review" | "block" | "incomplete"
                )
                && matches!(row.coverage.as_str(), "complete" | "partial" | "unknown")
                && row.findings <= MAX_SCAN_FINDINGS
                && row
                    .score
                    .as_ref()
                    .is_none_or(|score| valid_scan_score(score))
                && row.rules.len() <= MAX_SCAN_IDENTIFIERS
                && row.rules.iter().all(|rule| valid_scan_identifier(rule))
                && row.sources.len() <= MAX_SCAN_IDENTIFIERS
                && row
                    .sources
                    .iter()
                    .all(|source| valid_scan_identifier(source))
                && row.reasons.len() <= MAX_SCAN_IDENTIFIERS
                && row
                    .reasons
                    .iter()
                    .all(|reason| valid_scan_identifier(reason))
        })
}

fn read_quarantine_snapshot(path: Option<&Path>) -> Result<Option<QuarantineSnapshot>> {
    let Some(path) = path else {
        return Ok(None);
    };
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn write_quarantine_snapshot(path: &Path, snapshot: &QuarantineSnapshot) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("quarantine status path has no parent directory"))?;
    std::fs::create_dir_all(parent)?;
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, serde_json::to_vec(snapshot)?)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

async fn health_check(State(state): State<Arc<ServerConfig>>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": state.service_name,
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn detailed_health(State(state): State<Arc<ServerConfig>>) -> Json<Value> {
    let mut document = json!({
        "status": "ok",
        "service": state.service_name,
        "version": env!("CARGO_PKG_VERSION"),
        "features": [
            "azure-pipelines-scan",
            "github-actions-scan",
            "artifact-distribution",
            "policy-validation",
            "status-card"
        ],
        "artifacts_dir_configured": state.artifacts_dir.is_some(),
        "auth_configured": state.auth_token.is_some()
    });
    if let Some(domain) = &state.tailnet_domain {
        document["tailnet"] = json!(domain);
    }
    Json(document)
}

async fn version_info(State(state): State<Arc<ServerConfig>>) -> Json<Value> {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "service": state.service_name,
        "repository": "https://github.com/jakubkrzysztofsikora/supply-core",
        "download_base": "/api/v1/download",
        "artifacts": [
            "supply-core-linux-x86_64",
            "supply-core-darwin-arm64"
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
        match std::fs::symlink_metadata(&file_path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return StatusCode::NOT_FOUND.into_response();
            }
            Ok(_) => {
                match std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&file_path)
                {
                    Ok(mut file) => {
                        let mut bytes = Vec::new();
                        if file.read_to_end(&mut bytes).is_ok() {
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
                    Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                        return StatusCode::NOT_FOUND.into_response();
                    }
                    Err(_) => {}
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {}
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

    #[test]
    fn empty_auth_token_is_not_configured() {
        assert_eq!(configured_token(Some(String::new())), None);
        assert_eq!(configured_token(Some("   ".into())), None);
        assert_eq!(configured_token(None), None);
        assert_eq!(
            configured_token(Some(" token ".into())),
            Some("token".into())
        );
    }

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
    async fn detailed_health_reports_configured_tailnet_only() {
        let app = app_with_config(ServerConfig {
            tailnet_domain: None,
            ..ServerConfig::default()
        });
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .body(axum::body::Body::empty())
                    .unwrap_or_else(|_| panic!("valid request")),
            )
            .await
            .unwrap_or_else(|_| panic!("request succeeds"));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap_or_else(|_| panic!("body"));
        let document: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or_else(|_| panic!("json"));
        assert!(
            document.get("tailnet").is_none(),
            "unset deployment domain must not be reported"
        );

        let app = app_with_config(ServerConfig {
            tailnet_domain: Some("example.ts.net".into()),
            ..ServerConfig::default()
        });
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .body(axum::body::Body::empty())
                    .unwrap_or_else(|_| panic!("valid request")),
            )
            .await
            .unwrap_or_else(|_| panic!("request succeeds"));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap_or_else(|_| panic!("body"));
        let document: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or_else(|_| panic!("json"));
        assert_eq!(document["tailnet"], "example.ts.net");
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
    async fn published_quarantine_snapshot_is_returned_by_public_status() {
        let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("temporary directory"));
        let app = app_with_config(ServerConfig {
            auth_token: Some("test-token".into()),
            status_file: Some(directory.path().join("quarantine-status.json")),
            ..ServerConfig::default()
        });
        let snapshot = json!({
            "captured_at": "2026-09-08T08:15:00Z",
            "packages": [{
                "name": "next",
                "version": "16.3.4",
                "age_days": 6,
                "status": "Block"
            }],
            "scan_incomplete": [
                {"name": "pkg", "version": "1.0.0", "verdict": "scan_incomplete"}
            ],
            "scan_incomplete_truncated": 1
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/status/quarantine")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(axum::body::Body::from(snapshot.to_string()))
                    .unwrap_or_else(|_| panic!("valid request")),
            )
            .await
            .unwrap_or_else(|_| panic!("request succeeds"));
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap_or_else(|_| panic!("response body is readable"));
        let status: Value =
            serde_json::from_slice(&body).unwrap_or_else(|_| panic!("response is JSON"));
        assert_eq!(status["quarantine"]["captured_at"], "2026-09-08T08:15:00Z");
        assert_eq!(status["quarantine"]["packages"], snapshot["packages"]);
        assert_eq!(
            status["quarantine"]["scan_incomplete"],
            snapshot["scan_incomplete"]
        );
        assert_eq!(status["quarantine"]["scan_incomplete_truncated"], 1);
        assert_eq!(status["scan"], Value::Null);
    }

    #[test]
    fn card_lists_sections_and_escapes_markup() {
        let snapshot = QuarantineSnapshot {
            captured_at: "2026-09-13T08:15:00Z".into(),
            packages: vec![QuarantinedPackage {
                name: "react<&>".into(),
                version: "19.3.0".into(),
                age_days: 0,
                status: "Block".into(),
            }],
            confirmed: vec![ConfirmedFinding {
                name: "lodash".into(),
                version: "4.17.20".into(),
                advisory: "GHSA-35jh".into(),
                severity: "high".into(),
            }],
            suspected: vec![SuspectedFinding {
                name: "odd".into(),
                version: "1.0.0".into(),
                score: 8,
                rules: vec!["ai-prompt-injection".into()],
            }],
            scan_incomplete: vec![IncompleteFinding {
                name: "unscored<&>".into(),
                version: "2.0.0".into(),
                verdict: "scan_incomplete".into(),
            }],
            scan_incomplete_truncated: 0,
            scan: None,
        };
        let svg = render_status_card(Some(&snapshot));
        assert!(svg.starts_with("<svg"), "card must be an SVG document");
        assert!(svg.contains("QUARANTINED (1)"));
        assert!(svg.contains("CONFIRMED CVE (1)"));
        assert!(svg.contains("SUSPECTED (SCAN) (1)"));
        assert!(svg.contains("SCAN INCOMPLETE (1)"));
        assert!(svg.contains("unscored&lt;&amp;&gt;@2.0.0 · scan incomplete"));
        assert!(svg.contains("react&lt;&amp;&gt;@19.3.0"), "{svg}");
        assert!(svg.contains("high GHSA-35jh"));
        assert!(svg.contains("ai-prompt-injection"));
        assert!(svg.contains("2026-09-13T08:15:00Z"));
    }

    #[test]
    fn card_replaces_invalid_xml_characters() {
        let invalid = [
            '\0', '\u{1}', '\u{8}', '\u{b}', '\u{c}', '\u{e}', '\u{1f}', '\u{fffe}', '\u{ffff}',
        ];
        let name = format!(
            "left{}right<&>é🦀\t\n\r\u{7f}\u{85}",
            invalid.iter().collect::<String>()
        );
        let snapshot: QuarantineSnapshot = serde_json::from_value(json!({
            "captured_at": "2026-11-22T00:00:00Z",
            "packages": [{"name": name, "version": "1.0.0", "age_days": 0, "status": "Block"}]
        }))
        .unwrap_or_else(|_| panic!("valid snapshot"));
        assert!(validate_quarantine_snapshot(&snapshot).is_ok());

        let svg = render_status_card(Some(&snapshot));
        for character in invalid {
            assert!(
                !svg.contains(character),
                "invalid XML character {character:?}"
            );
        }
        assert!(svg.contains("right&lt;&amp;&gt;é🦀\t\n\r\u{7f}\u{85}"));

        let mut reader = quick_xml::Reader::from_str(&svg);
        reader.config_mut().enable_all_checks(true);
        let mut saw_root = false;
        loop {
            match reader
                .read_event()
                .unwrap_or_else(|err| panic!("invalid SVG: {err}"))
            {
                quick_xml::events::Event::Start(element) if element.name().as_ref() == "svg" => {
                    saw_root = true;
                }
                quick_xml::events::Event::Eof => break,
                _ => {}
            }
        }
        assert!(saw_root, "SVG root missing");
    }

    #[test]
    fn card_reports_incomplete_snapshot_truncation() {
        let snapshot: QuarantineSnapshot = serde_json::from_value(json!({
            "captured_at": "2026-11-14T00:00:00Z",
            "packages": [],
            "scan_incomplete": [
                {"name": "pkg", "version": "1.0.0", "verdict": "scan_incomplete"}
            ],
            "scan_incomplete_truncated": 1
        }))
        .unwrap_or_else(|_| panic!("valid truncated snapshot"));

        assert!(validate_quarantine_snapshot(&snapshot).is_ok());
        let svg = render_status_card(Some(&snapshot));
        assert!(svg.contains("SCAN INCOMPLETE (2)"), "{svg}");
        assert!(svg.contains("+1 more"), "{svg}");
    }

    #[test]
    fn card_empty_state_is_explicit() {
        let svg = render_status_card(None);
        assert_eq!(svg.matches("(none captured yet)").count(), 4);
        assert!(svg.contains("no snapshot yet"));
    }

    #[test]
    fn card_distinguishes_missing_and_empty_snapshots() {
        let snapshot = QuarantineSnapshot {
            captured_at: "2026-11-22T00:00:00Z".into(),
            packages: Vec::new(),
            confirmed: Vec::new(),
            suspected: Vec::new(),
            scan_incomplete: Vec::new(),
            scan_incomplete_truncated: 0,
            scan: None,
        };
        let missing = render_status_card(None);
        let empty = render_status_card(Some(&snapshot));

        for title in [
            "QUARANTINED",
            "CONFIRMED CVE",
            "SUSPECTED (SCAN)",
            "SCAN INCOMPLETE",
        ] {
            assert!(missing.contains(&format!("{title} (unknown)")), "{missing}");
            assert!(empty.contains(&format!("{title} (0)")), "{empty}");
        }
    }

    #[tokio::test]
    async fn status_card_route_serves_svg() {
        let app = app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status/card.svg")
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
            Some("image/svg+xml; charset=utf-8")
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap_or_else(|_| panic!("body"));
        let svg = String::from_utf8_lossy(&body);
        assert!(svg.contains("<svg"), "expected an SVG body, got {svg}");
    }

    #[tokio::test]
    async fn public_reads_allow_any_origin_but_writes_do_not() {
        let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("temporary directory"));
        let send = |request: Request<axum::body::Body>| {
            app_with_config(ServerConfig {
                status_file: Some(directory.path().join("status.json")),
                auth_token: Some("token".into()),
                ..ServerConfig::default()
            })
            .oneshot(request)
        };
        let allow_origin = |response: &Response| {
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };

        for uri in ["/api/v1/status", "/api/v1/health", "/api/v1/version"] {
            let response = send(
                Request::builder()
                    .uri(uri)
                    .header(header::ORIGIN, "https://supply-core.jakub.team")
                    .body(axum::body::Body::empty())
                    .unwrap_or_else(|_| panic!("valid request")),
            )
            .await
            .unwrap_or_else(|_| panic!("request succeeds"));
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            assert_eq!(allow_origin(&response).as_deref(), Some("*"), "{uri}");
        }

        let preflight = send(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/api/v1/status/quarantine")
                .header(header::ORIGIN, "https://evil.example")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PUT")
                .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
                .body(axum::body::Body::empty())
                .unwrap_or_else(|_| panic!("valid request")),
        )
        .await
        .unwrap_or_else(|_| panic!("request succeeds"));
        assert_eq!(allow_origin(&preflight), None);
    }

    #[tokio::test]
    async fn publish_accepts_and_returns_confirmed_suspected_and_incomplete() {
        let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("temporary directory"));
        let app = app_with_config(ServerConfig {
            auth_token: Some("test-token".into()),
            status_file: Some(directory.path().join("quarantine-status.json")),
            ..ServerConfig::default()
        });
        let snapshot = json!({
            "captured_at": "2026-09-13T08:15:00Z",
            "packages": [{"name": "next", "version": "16.3.4", "age_days": 6, "status": "Block"}],
            "confirmed": [{"name": "lodash", "version": "4.17.20", "advisory": "GHSA-x", "severity": "high"}],
            "suspected": [{"name": "odd", "version": "1.0.0", "score": 8, "rules": ["ai-prompt-injection"]}],
            "scan_incomplete": [{"name": "missing-score", "version": "1.0.0", "verdict": "scan_incomplete"}]
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/status/quarantine")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(axum::body::Body::from(snapshot.to_string()))
                    .unwrap_or_else(|_| panic!("valid request")),
            )
            .await
            .unwrap_or_else(|_| panic!("request succeeds"));
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .body(axum::body::Body::empty())
                    .unwrap_or_else(|_| panic!("valid request")),
            )
            .await
            .unwrap_or_else(|_| panic!("request succeeds"));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap_or_else(|_| panic!("body"));
        let status: Value =
            serde_json::from_slice(&body).unwrap_or_else(|_| panic!("response is JSON"));
        assert_eq!(status["quarantine"]["confirmed"][0]["advisory"], "GHSA-x");
        assert_eq!(status["quarantine"]["suspected"][0]["score"], 8);
        assert_eq!(
            status["quarantine"]["scan_incomplete"],
            json!([{"name": "missing-score", "version": "1.0.0", "verdict": "scan_incomplete"}])
        );
        assert!(status["quarantine"]["scan_incomplete"][0]
            .get("score")
            .is_none());
    }

    #[tokio::test]
    async fn published_scan_details_project_blocked_rows_and_keep_scores_exact() {
        let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("temporary directory"));
        let app = app_with_config(ServerConfig {
            auth_token: Some("test-token".into()),
            status_file: Some(directory.path().join("quarantine-status.json")),
            ..ServerConfig::default()
        });
        let blocked = json!({
            "name": "@scope/evil",
            "version": "1.0.0",
            "decision": "block",
            "coverage": "partial",
            "findings": 2,
            "score": "8.1234567890123456789012345678",
            "rules": ["install-script-pipe"],
            "sources": ["static-heuristics"],
            "reasons": ["guarddog:engine_revision_unverified"]
        });
        let passed = json!({
            "name": "clean",
            "version": "2.0.0",
            "decision": "pass",
            "coverage": "complete",
            "findings": 0,
            "score": "0",
            "rules": [],
            "sources": []
        });
        let snapshot = json!({
            "captured_at": "2026-11-15T08:30:00Z",
            "packages": [],
            "scan": {
                "captured_at": "2026-11-15T08:31:00Z",
                "candidate_count": 3,
                "scanned": [blocked.clone(), passed.clone()],
                "error_count": 1
            }
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/status/quarantine")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(axum::body::Body::from(snapshot.to_string()))
                    .unwrap_or_else(|_| panic!("valid request")),
            )
            .await
            .unwrap_or_else(|_| panic!("request succeeds"));
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .body(axum::body::Body::empty())
                    .unwrap_or_else(|_| panic!("valid request")),
            )
            .await
            .unwrap_or_else(|_| panic!("request succeeds"));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap_or_else(|_| panic!("body"));
        let status: Value =
            serde_json::from_slice(&body).unwrap_or_else(|_| panic!("response is JSON"));

        assert_eq!(status["scan"]["captured_at"], "2026-11-15T08:31:00Z");
        assert_eq!(status["scan"]["candidate_count"], 3);
        assert_eq!(status["scan"]["scanned_count"], 2);
        assert_eq!(status["scan"]["blocked_count"], 1);
        assert_eq!(status["scan"]["error_count"], 1);
        let mut legacy_passed = passed.clone();
        legacy_passed["reasons"] = json!([]);
        assert_eq!(
            status["scan"]["scanned"],
            json!([blocked.clone(), legacy_passed])
        );
        assert_eq!(status["scan"]["blocked"], json!([blocked.clone()]));
        assert!(status["scan"].get("errors").is_none());

        let mut leaking = blocked;
        leaking["reasons"] = json!(["guarddog:/Users/private/secret.log"]);
        let response = app_with_config(ServerConfig {
            auth_token: Some("test-token".into()),
            status_file: Some(directory.path().join("quarantine-status.json")),
            ..ServerConfig::default()
        })
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/status/quarantine")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer test-token")
                .body(axum::body::Body::from(
                    json!({
                        "captured_at": "2026-11-15T08:30:00Z",
                        "packages": [],
                        "scan": {
                            "captured_at": "2026-11-15T08:31:00Z",
                            "candidate_count": 1,
                            "scanned": [leaking],
                            "error_count": 0
                        }
                    })
                    .to_string(),
                ))
                .unwrap_or_else(|_| panic!("valid request")),
        )
        .await
        .unwrap_or_else(|_| panic!("request succeeds"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn publish_rejects_unlisted_scan_tool_output() {
        let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("temporary directory"));
        let app = app_with_config(ServerConfig {
            auth_token: Some("test-token".into()),
            status_file: Some(directory.path().join("quarantine-status.json")),
            ..ServerConfig::default()
        });
        let snapshot = json!({
            "captured_at": "2026-11-15T08:30:00Z",
            "packages": [],
            "scan": {
                "captured_at": "2026-11-15T08:31:00Z",
                "candidate_count": 1,
                "scanned": [{
                    "name": "pkg",
                    "version": "1.0.0",
                    "decision": "block",
                    "coverage": "complete",
                    "findings": 1,
                    "score": "8",
                    "rules": ["malware-rule"],
                    "sources": ["static-heuristics"],
                    "tool_output": "/Users/private/source.tar"
                }],
                "error_count": 0
            }
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/status/quarantine")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(axum::body::Body::from(snapshot.to_string()))
                    .unwrap_or_else(|_| panic!("valid request")),
            )
            .await
            .unwrap_or_else(|_| panic!("request succeeds"));

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn publish_rejects_oversized_scan_detail_lists() {
        let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("temporary directory"));
        let app = app_with_config(ServerConfig {
            auth_token: Some("test-token".into()),
            status_file: Some(directory.path().join("quarantine-status.json")),
            ..ServerConfig::default()
        });
        let row = json!({
            "name": "pkg",
            "version": "1.0.0",
            "decision": "block",
            "coverage": "complete",
            "findings": 1,
            "score": "8",
            "rules": ["malware-rule"],
            "sources": ["static-heuristics"]
        });
        let snapshot = json!({
            "captured_at": "2026-11-15T08:30:00Z",
            "packages": [],
            "scan": {
                "captured_at": "2026-11-15T08:31:00Z",
                "candidate_count": MAX_SCAN_CANDIDATES,
                "scanned": vec![row; MAX_SCAN_ROWS + 1],
                "error_count": 0
            }
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/status/quarantine")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(axum::body::Body::from(snapshot.to_string()))
                    .unwrap_or_else(|_| panic!("valid request")),
            )
            .await
            .unwrap_or_else(|_| panic!("request succeeds"));

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn publish_rejects_out_of_range_suspected_score() {
        let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("temporary directory"));
        let app = app_with_config(ServerConfig {
            auth_token: Some("test-token".into()),
            status_file: Some(directory.path().join("quarantine-status.json")),
            ..ServerConfig::default()
        });
        let snapshot = json!({
            "captured_at": "2026-09-13T08:15:00Z",
            "packages": [],
            "suspected": [{"name": "odd", "version": "1.0.0", "score": 11, "rules": []}]
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/status/quarantine")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(axum::body::Body::from(snapshot.to_string()))
                    .unwrap_or_else(|_| panic!("valid request")),
            )
            .await
            .unwrap_or_else(|_| panic!("request succeeds"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn incomplete_findings_require_fixed_verdict_and_bounded_names() {
        let mut snapshot: QuarantineSnapshot = serde_json::from_value(json!({
            "captured_at": "2026-09-13T08:15:00Z",
            "packages": [],
            "scan_incomplete": [{"name": "pkg", "version": "1.0", "verdict": "scan_incomplete"}]
        }))
        .unwrap_or_else(|_| panic!("valid incomplete finding"));
        assert!(validate_quarantine_snapshot(&snapshot).is_ok());

        snapshot.scan_incomplete[0].verdict = "suspected".into();
        assert!(validate_quarantine_snapshot(&snapshot).is_err());

        snapshot.scan_incomplete[0].verdict = "scan_incomplete".into();
        snapshot.scan_incomplete[0].name = "x".repeat(257);
        assert!(validate_quarantine_snapshot(&snapshot).is_err());

        snapshot.scan_incomplete = vec![
            IncompleteFinding {
                name: "pkg".into(),
                version: "1.0".into(),
                verdict: "scan_incomplete".into(),
            };
            1_001
        ];
        assert!(validate_quarantine_snapshot(&snapshot).is_err());
        assert!(serde_json::from_value::<IncompleteFinding>(
            json!({"name": "pkg", "version": "1.0", "verdict": "scan_incomplete", "score": 0})
        )
        .is_err());
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
