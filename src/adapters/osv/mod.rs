use crate::{domain::*, ports::VulnerabilitySource};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

/// No-op source: returns no findings. Useful for tests and offline runs.
pub struct NoopVulnerabilitySource;
impl VulnerabilitySource for NoopVulnerabilitySource {
    fn query(
        &self,
        _: Ecosystem,
        _: &str,
        _: &PackageVersionId,
    ) -> Result<Vec<VulnerabilityFinding>> {
        Ok(vec![])
    }
    fn query_version(&self, _: Ecosystem, _: &str, _: &str) -> Result<Vec<VulnerabilityFinding>> {
        Ok(vec![])
    }
}

/// HTTP POST contract used by [`OsvVulnerabilitySource`]. Isolated as a
/// trait so unit tests can substitute a fixture without hitting the
/// network.
pub trait OsvTransport: Send + Sync {
    fn post_json(&self, url: &str, body: &serde_json::Value) -> Result<serde_json::Value>;
}

impl<T: Fn(&str, &serde_json::Value) -> Result<serde_json::Value> + Send + Sync> OsvTransport
    for T
{
    fn post_json(&self, url: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        (self)(url, body)
    }
}

/// Real `api.osv.dev` transport backed by `reqwest::blocking`. The
/// default timeout is intentionally tight; a slow OSV should not stall
/// the daily capture for an unrelated dep.
pub struct ReqwestOsvTransport {
    client: reqwest::blocking::Client,
}
impl ReqwestOsvTransport {
    pub fn new() -> Result<Self> {
        Self::with_timeout(std::time::Duration::from_secs(8))
    }

    fn with_timeout(timeout: std::time::Duration) -> Result<Self> {
        Ok(Self {
            client: reqwest::blocking::Client::builder()
                .timeout(timeout)
                .build()
                .context("create OSV client")?,
        })
    }
}
const OSV_ATTEMPTS: u32 = 3;

impl ReqwestOsvTransport {
    fn post_once(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> std::result::Result<serde_json::Value, (anyhow::Error, bool)> {
        let resp = self.client.post(url).json(body).send().map_err(|error| {
            let retryable = error.is_timeout() || error.is_connect();
            (
                anyhow::Error::new(error).context("OSV request failed"),
                retryable,
            )
        })?;
        let status = resp.status();
        if !status.is_success() {
            let retryable = status.is_server_error() || status.as_u16() == 429;
            return Err((anyhow::anyhow!("OSV returned non-2xx: {status}"), retryable));
        }
        resp.json().map_err(|error| {
            let retryable = error.is_timeout();
            let context = if error.is_timeout() {
                "OSV response body timed out"
            } else {
                "OSV returned non-JSON"
            };
            (anyhow::Error::new(error).context(context), retryable)
        })
    }
}
impl OsvTransport for ReqwestOsvTransport {
    fn post_json(&self, url: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        let mut attempt = 1;
        loop {
            match self.post_once(url, body) {
                Ok(value) => return Ok(value),
                Err((_, true)) if attempt < OSV_ATTEMPTS => {
                    std::thread::sleep(std::time::Duration::from_millis(500 * u64::from(attempt)));
                    attempt += 1;
                }
                Err((error, _)) => return Err(error),
            }
        }
    }
}

/// File-backed cache + transport wrapper.
///
/// On each `query`, returns the cached findings if the entry is younger
/// than `ttl`. On miss / expiry, calls the underlying transport, writes
/// the result back, and returns it.
///
/// Failures from the upstream transport are surfaced (the firewall
/// cannot silently swallow unknown vulnerability state for a
/// block-by-severity policy). Cache is best-effort: a missing or
/// unwritable cache directory degrades to "always fetch".
pub struct OsvVulnerabilitySource {
    transport: Box<dyn OsvTransport>,
    cache_dir: Option<PathBuf>,
    ttl: std::time::Duration,
    url: String,
}
impl OsvVulnerabilitySource {
    /// Defaults: 24h TTL, no cache.
    pub fn new(transport: Box<dyn OsvTransport>) -> Self {
        Self {
            transport,
            cache_dir: None,
            ttl: std::time::Duration::from_secs(24 * 3600),
            url: "https://api.osv.dev/v1/query".to_string(),
        }
    }
    pub fn with_cache(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cache_dir = Some(dir.into());
        self
    }
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = url.into();
        self
    }

    fn cache_path(
        &self,
        ecosystem: &Ecosystem,
        name: &str,
        version: &PackageVersionId,
    ) -> Option<PathBuf> {
        let dir = self.cache_dir.as_ref()?;
        // Key on (ecosystem, name, version) with a stable hash so weird
        // scoped names don't escape the cache root.
        let key = format!(
            "v2|{}|{}|{}",
            ecosystem_label(ecosystem),
            name,
            version.canonical()
        );
        let mut hasher = sha2::Sha256::new();
        hasher.update(key.as_bytes());
        let digest = hex::encode(hasher.finalize());
        Some(dir.join(format!("{digest}.json")))
    }
}
fn ecosystem_label(e: &Ecosystem) -> &'static str {
    match *e {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPi => "PyPI",
        Ecosystem::NuGet => "NuGet",
        Ecosystem::DockerImage => "docker",
        Ecosystem::GitHubActions => "github",
        Ecosystem::AzurePipelines => "azure",
    }
}

#[derive(Serialize, Deserialize)]
struct CachedQuery {
    fetched_at: chrono::DateTime<chrono::Utc>,
    findings: Vec<VulnerabilityFinding>,
}

impl VulnerabilitySource for OsvVulnerabilitySource {
    fn query(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &PackageVersionId,
    ) -> Result<Vec<VulnerabilityFinding>> {
        self.query_version(ecosystem, name, version.upstream())
    }
    fn query_version(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
    ) -> Result<Vec<VulnerabilityFinding>> {
        if matches!(
            ecosystem,
            Ecosystem::GitHubActions | Ecosystem::AzurePipelines | Ecosystem::DockerImage
        ) {
            return Ok(vec![]);
        }
        let version_id = PackageVersionId::parse(&ecosystem, version)?;
        let path = self.cache_path(&ecosystem, name, &version_id);
        if let Some(p) = path.as_ref() {
            if fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()) {
                anyhow::bail!("OSV cache entry must not be a symlink");
            }
            if let Ok(bytes) = fs::read(p) {
                if let Ok(cached) = serde_json::from_slice::<CachedQuery>(&bytes) {
                    let age = chrono::Utc::now()
                        .signed_duration_since(cached.fetched_at)
                        .to_std()
                        .unwrap_or(std::time::Duration::from_secs(u64::MAX));
                    if age < self.ttl {
                        return Ok(cached.findings);
                    }
                }
            }
        }

        let body = serde_json::json!({
            "package": {"name": name, "ecosystem": ecosystem_label(&ecosystem)},
            "version": version,
        });
        let raw = self.transport.post_json(&self.url, &body)?;
        anyhow::ensure!(raw.is_object(), "invalid OSV response");
        anyhow::ensure!(
            raw.get("next_page_token").is_none(),
            "paginated OSV response requires continuation"
        );
        if let Some(vulns) = raw.get("vulns") {
            anyhow::ensure!(vulns.is_array(), "invalid OSV vulns list");
        }
        let findings = parse_osv_response(&raw);

        if let Some(p) = path.as_ref() {
            if let Some(parent) = p.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let cached = CachedQuery {
                fetched_at: chrono::Utc::now(),
                findings: findings.clone(),
            };
            let temporary = p.with_extension(format!("{}.tmp", std::process::id()));
            if let Ok(mut f) = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
            {
                if f.write_all(serde_json::to_vec(&cached)?.as_slice()).is_ok() {
                    let _ = fs::rename(&temporary, p);
                }
                let _ = fs::remove_file(&temporary);
            }
        }
        Ok(findings)
    }
}

/// Translate an OSV `/v1/query` response into our domain findings.
///
/// OSV response shape (relevant bits):
///   { "vulns": [ { "id": "GHSA-...", "summary": "...", "severity": [
///       { "type": "CVSS_V3", "score": "9.8" } ] }, ... ] }
///
/// We:
///   - Skip vulns without an id.
///   - Take the highest CVSS score across severity entries; fall back
///     to the GHSA database_specific severity when no CVSS is given.
///   - Map score to our enum via [`score_to_severity`].
pub fn parse_osv_response(raw: &serde_json::Value) -> Vec<VulnerabilityFinding> {
    let Some(vulns) = raw.get("vulns").and_then(|v| v.as_array()) else {
        return vec![];
    };
    let mut out = vec![];
    for v in vulns {
        let Some(id) = v.get("id").and_then(|x| x.as_str()) else {
            continue;
        };
        let summary = v
            .get("summary")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let severity = best_severity(v).unwrap_or(Severity::Critical);
        out.push(VulnerabilityFinding {
            source: "OSV".into(),
            id: id.to_string(),
            aliases: v
                .get("aliases")
                .and_then(|aliases| aliases.as_array())
                .into_iter()
                .flatten()
                .filter_map(|alias| alias.as_str())
                .map(str::to_string)
                .collect(),
            severity,
            summary,
            modified: advisory_date(v, "modified"),
            withdrawn: advisory_date(v, "withdrawn"),
        });
    }
    out
}

fn advisory_date(
    vulnerability: &serde_json::Value,
    field: &str,
) -> Option<chrono::DateTime<chrono::Utc>> {
    vulnerability
        .get(field)
        .and_then(|value| value.as_str())
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|date| date.with_timezone(&chrono::Utc))
}
fn best_severity(vuln: &serde_json::Value) -> Option<Severity> {
    if let Some(sev) = vuln.get("severity").and_then(|x| x.as_array()) {
        let mut best: Option<Severity> = None;
        for entry in sev {
            if let Some(score) = entry.get("score").and_then(|x| x.as_str()) {
                if let Some(parsed) = parse_cvss_score(score) {
                    best = Some(match best {
                        Some(b) if b.rank() >= parsed.rank() => b,
                        _ => parsed,
                    });
                }
            }
        }
        if best.is_some() {
            return best;
        }
    }
    if let Some(ds) = vuln
        .get("database_specific")
        .and_then(|x| x.get("severity"))
    {
        if let Some(s) = ds.as_str() {
            return match s.to_ascii_uppercase().as_str() {
                "CRITICAL" => Some(Severity::Critical),
                "HIGH" => Some(Severity::High),
                "MEDIUM" => Some(Severity::Medium),
                "LOW" => Some(Severity::Low),
                _ => None,
            };
        }
    }
    None
}

/// Parse a CVSS vector string like `CVSS:3.1/AV:N/AC:L/...` or a raw
/// score like `9.8`. OSV returns vectors; some mirrors return numbers.
pub fn parse_cvss_score(s: &str) -> Option<Severity> {
    let s = s.trim();
    if let Ok(n) = s.parse::<f64>() {
        if !n.is_finite() || !(0.0..=10.0).contains(&n) {
            return None;
        }
        return Some(score_to_severity(n));
    }
    None
}

pub fn score_to_severity(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn vectors_use_database_severity_or_conservative_unknown() {
        let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
        assert_eq!(parse_cvss_score(vector), None);
        assert_eq!(parse_cvss_score("NaN"), None);
        let raw = serde_json::json!({"vulns": [{"id":"test", "severity":[{"type":"CVSS_V3", "score":vector}], "database_specific":{"severity":"HIGH"}}]});
        assert_eq!(parse_osv_response(&raw)[0].severity, Severity::High);
        let raw = serde_json::json!({"vulns": [{"id":"test", "severity":[{"type":"CVSS_V3", "score":vector}]}]});
        assert_eq!(parse_osv_response(&raw)[0].severity, Severity::Critical);
    }

    #[test]
    fn parse_empty_response() {
        let v = serde_json::json!({});
        assert!(parse_osv_response(&v).is_empty());
        let v = serde_json::json!({"vulns": []});
        assert!(parse_osv_response(&v).is_empty());
    }

    #[test]
    fn parse_with_cvss_vector_and_numeric_score() {
        let v = serde_json::json!({"vulns": [
            {"id": "GHSA-aaaa-bbbb-cccc", "summary": "RCE", "severity": [
                {"type": "CVSS_V3", "score": "9.8"}
            ]},
            {"id": "GHSA-xxxx", "summary": "info", "severity": [
                {"type": "CVSS_V3", "score": "5.4"}
            ]}
        ]});
        let f = parse_osv_response(&v);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[1].severity, Severity::Medium);
    }
    #[test]
    fn parse_preserves_aliases_and_advisory_lifecycle() {
        let raw = serde_json::json!({"vulns": [
            {
                "id": "GHSA-active",
                "aliases": ["CVE-2026-1234", "GHSA-alias"],
                "modified": "2026-10-12T10:30:00Z",
                "severity": [{"type": "CVSS_V3", "score": "7.5"}]
            },
            {
                "id": "GHSA-withdrawn",
                "withdrawn": "2026-10-13T10:30:00Z",
                "summary": "corrected"
            }
        ]});

        let findings = parse_osv_response(&raw);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].aliases, vec!["CVE-2026-1234", "GHSA-alias"]);
        assert_eq!(
            findings[0].modified,
            Some("2026-10-12T10:30:00Z".parse().unwrap())
        );
        assert_eq!(
            findings[0].withdrawn, None,
            "active advisory must stay active"
        );
        assert_eq!(
            findings[1].withdrawn,
            Some("2026-10-13T10:30:00Z".parse().unwrap())
        );
    }

    #[test]
    fn parse_with_database_specific_severity() {
        let v = serde_json::json!({"vulns": [
            {"id": "GHSA-db", "database_specific": {"severity": "HIGH"}, "summary": ""}
        ]});
        let f = parse_osv_response(&v);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn skips_vulns_without_id() {
        let v = serde_json::json!({"vulns": [
            {"summary": "no id"},
            {"id": "GHSA-ok", "severity": [{"type": "CVSS_V3", "score": "9.9"}]}
        ]});
        let f = parse_osv_response(&v);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "GHSA-ok");
    }

    #[test]
    fn score_band_mapping() {
        assert_eq!(score_to_severity(9.1), Severity::Critical);
        assert_eq!(score_to_severity(7.0), Severity::High);
        assert_eq!(score_to_severity(6.9), Severity::Medium);
        assert_eq!(score_to_severity(4.0), Severity::Medium);
        assert_eq!(score_to_severity(3.9), Severity::Low);
    }

    #[test]
    fn nuget_four_part_version_is_forwarded_unmodified_to_osv() {
        let request = std::sync::Arc::new(std::sync::Mutex::new(None));
        let captured = request.clone();
        let transport = move |_: &str, body: &serde_json::Value| -> Result<serde_json::Value> {
            *captured.lock().unwrap() = Some(body.clone());
            Ok(serde_json::json!({}))
        };
        let source = OsvVulnerabilitySource::new(Box::new(transport));

        source
            .query_version(Ecosystem::NuGet, "Example", "1.2.3.4")
            .unwrap();

        assert_eq!(
            request.lock().unwrap().as_ref().unwrap()["version"],
            "1.2.3.4"
        );
    }

    #[test]
    fn cache_hit_skips_transport() {
        let dir = tempfile::tempdir().unwrap();
        // Seed cache with a known response.
        let cached = CachedQuery {
            fetched_at: chrono::Utc::now(),
            findings: vec![VulnerabilityFinding {
                source: "OSV".into(),
                id: "GHSA-cached".into(),
                aliases: vec![],
                severity: Severity::Critical,
                summary: "cached".into(),
                modified: None,
                withdrawn: None,
            }],
        };
        let key = "v2|npm|lodash|4.17.20";
        let mut h = sha2::Sha256::new();
        h.update(key.as_bytes());
        let path = dir
            .path()
            .join(format!("{}.json", hex::encode(h.finalize())));
        std::fs::write(&path, serde_json::to_vec(&cached).unwrap()).unwrap();

        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls2 = calls.clone();
        let transport = move |_: &str, _: &serde_json::Value| -> Result<serde_json::Value> {
            calls2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(serde_json::json!({}))
        };
        let src = OsvVulnerabilitySource::new(Box::new(transport)).with_cache(dir.path());
        let v = PackageVersionId::parse(&Ecosystem::Npm, "4.17.20").unwrap();
        let f = src.query(Ecosystem::Npm, "lodash", &v).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "GHSA-cached");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn cache_miss_calls_transport_and_writes_back() {
        let dir = tempfile::tempdir().unwrap();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls2 = calls.clone();
        let transport = move |_: &str, _: &serde_json::Value| -> Result<serde_json::Value> {
            calls2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(serde_json::json!({"vulns": [
                {"id": "GHSA-fresh", "severity": [{"type": "CVSS_V3", "score": "7.5"}]}
            ]}))
        };
        let src = OsvVulnerabilitySource::new(Box::new(transport)).with_cache(dir.path());
        let v = PackageVersionId::parse(&Ecosystem::Npm, "1.0.0").unwrap();
        let f = src.query(Ecosystem::Npm, "demo", &v).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        // Second call should be a cache hit.
        let f2 = src.query(Ecosystem::Npm, "demo", &v).unwrap();
        assert_eq!(f2.len(), 1);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn github_actions_ecosystem_skips_request() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls2 = calls.clone();
        let transport = move |_: &str, _: &serde_json::Value| -> Result<serde_json::Value> {
            calls2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(serde_json::json!({}))
        };
        let src = OsvVulnerabilitySource::new(Box::new(transport));
        let v = PackageVersionId::parse(&Ecosystem::GitHubActions, "v1").unwrap();
        let f = src
            .query(Ecosystem::GitHubActions, "actions/checkout", &v)
            .unwrap();
        assert!(f.is_empty());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn transport_respects_native_roots_without_accepting_untrusted_certificates() -> Result<()> {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::process::{Command, Stdio};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        const URL_ENV: &str = "SUPPLY_CORE_TEST_OSV_TLS_URL";
        const TRUSTED_ENV: &str = "SUPPLY_CORE_TEST_OSV_TLS_TRUSTED";
        if let Ok(url) = std::env::var(URL_ENV) {
            let result = ReqwestOsvTransport::with_timeout(Duration::from_secs(3))?
                .post_once(&url, &serde_json::json!({}));
            if std::env::var_os(TRUSTED_ENV).is_some() {
                assert_eq!(result.map_err(|(error, _)| error)?, serde_json::json!({}));
            } else {
                let (error, _) = result.unwrap_err();
                assert!(
                    error.chain().any(|cause| {
                        let mut inner = Some(cause);
                        while let Some(current) = inner {
                            if matches!(
                                current.downcast_ref::<rustls::Error>(),
                                Some(rustls::Error::InvalidCertificate(_))
                            ) {
                                return true;
                            }
                            inner = current
                                .downcast_ref::<std::io::Error>()
                                .and_then(std::io::Error::get_ref)
                                .map(|error| error as &(dyn std::error::Error + 'static));
                        }
                        false
                    }),
                    "{error:#}"
                );
            }
            return Ok(());
        }

        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()])?;
        let other = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()])?;
        let directory = tempfile::tempdir()?;
        let trusted_ca = directory.path().join("trusted.pem");
        let untrusted_ca = directory.path().join("untrusted.pem");
        std::fs::write(&trusted_ca, cert.pem())?;
        std::fs::write(&untrusted_ca, other.cert.pem())?;
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
        )?;

        for (ca, trusted) in [(&trusted_ca, true), (&untrusted_ca, false)] {
            let listener = TcpListener::bind(("127.0.0.1", 0))?;
            listener.set_nonblocking(true)?;
            let url = format!("https://{}/v1/query", listener.local_addr()?);
            let config = Arc::new(config.clone());
            let server = std::thread::spawn(move || -> Result<()> {
                let deadline = Instant::now() + Duration::from_secs(10);
                let socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => return Err(error.into()),
                    }
                };
                socket.set_nonblocking(false)?;
                socket.set_read_timeout(Some(Duration::from_secs(3)))?;
                let connection = rustls::ServerConnection::new(config)?;
                let mut stream = rustls::StreamOwned::new(connection, socket);
                let mut request = Vec::new();
                let mut buffer = [0; 4096];
                loop {
                    let length = match stream.read(&mut buffer) {
                        Ok(length) => length,
                        Err(error) if trusted => return Err(error.into()),
                        Err(_) => break,
                    };
                    if length == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..length]);
                    if request.windows(6).any(|chunk| chunk == b"\r\n\r\n{}") {
                        stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        )?;
                        stream.flush()?;
                        break;
                    }
                }
                Ok(())
            });
            let mut command = Command::new(std::env::current_exe()?);
            command
                .arg("--exact")
                .arg("adapters::osv::tests::transport_respects_native_roots_without_accepting_untrusted_certificates")
                .env(URL_ENV, &url)
                .env("SSL_CERT_FILE", ca)
                .env_remove("SSL_CERT_DIR");
            if trusted {
                command.env(TRUSTED_ENV, "1");
            } else {
                command.env_remove(TRUSTED_ENV);
            }
            let mut child = command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            let deadline = Instant::now() + Duration::from_secs(15);
            let timed_out = loop {
                if child.try_wait()?.is_some() {
                    break false;
                }
                if Instant::now() >= deadline {
                    child.kill()?;
                    break true;
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            let output = child.wait_with_output()?;
            let server_result = server
                .join()
                .map_err(|_| anyhow::anyhow!("TLS server panicked"))?;
            assert!(
                !timed_out && output.status.success(),
                "child test failed or timed out:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            server_result?;
        }
        Ok(())
    }

    fn serve_sequence(
        responses: Vec<&'static str>,
    ) -> Result<(String, std::thread::JoinHandle<usize>)> {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        let url = format!("http://{}/v1/query", listener.local_addr()?);
        let handle = std::thread::spawn(move || {
            let mut served = 0;
            for response in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buffer = [0u8; 4096];
                let _ = stream.read(&mut buffer);
                let _ = stream.write_all(response.as_bytes());
                served += 1;
            }
            served
        });
        Ok((url, handle))
    }

    #[test]
    fn transport_retries_server_errors_then_returns_the_answer() -> Result<()> {
        let (url, server) = serve_sequence(vec![
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        ])?;
        let value = ReqwestOsvTransport::new()?.post_json(&url, &serde_json::json!({}))?;
        assert_eq!(value, serde_json::json!({}));
        assert_eq!(server.join().map_err(|_| anyhow::anyhow!("server"))?, 2);
        Ok(())
    }

    #[test]
    fn transport_retries_a_response_body_that_stalls() -> Result<()> {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        let url = format!("http://{}/v1/query", listener.local_addr()?);
        let server = std::thread::spawn(move || {
            let mut stalled = Vec::new();
            for attempt in 0..2 {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buffer = [0u8; 4096];
                let _ = stream.read(&mut buffer);
                if attempt == 0 {
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{",
                    );
                    let _ = stream.flush();
                    stalled.push(stream);
                } else {
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                    );
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
            stalled.len()
        });
        let transport = ReqwestOsvTransport::with_timeout(std::time::Duration::from_millis(400))?;
        let value = transport.post_json(&url, &serde_json::json!({}))?;
        assert_eq!(value, serde_json::json!({}));
        assert_eq!(server.join().map_err(|_| anyhow::anyhow!("server"))?, 1);
        Ok(())
    }

    #[test]
    fn transport_does_not_retry_client_errors() -> Result<()> {
        let (url, server) = serve_sequence(vec![
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        ])?;
        let error = ReqwestOsvTransport::new()?
            .post_json(&url, &serde_json::json!({}))
            .unwrap_err();
        assert!(format!("{error:#}").contains("400"));
        drop(server);
        Ok(())
    }
}
