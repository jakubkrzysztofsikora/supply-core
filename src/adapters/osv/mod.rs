use crate::{domain::*, ports::VulnerabilitySource};
use anyhow::{Context, Result};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

/// No-op source: returns no findings. Useful for tests and offline runs.
pub struct NoopVulnerabilitySource;
impl VulnerabilitySource for NoopVulnerabilitySource {
    fn query(&self, _: Ecosystem, _: &str, _: &Version) -> Result<Vec<VulnerabilityFinding>> {
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
        Ok(Self {
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(8))
                .build()
                .context("create OSV client")?,
        })
    }
}
impl OsvTransport for ReqwestOsvTransport {
    fn post_json(&self, url: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        let resp = self
            .client
            .post(url)
            .json(body)
            .send()
            .context("OSV request failed")?
            .error_for_status()
            .context("OSV returned non-2xx")?;
        resp.json().context("OSV returned non-JSON")
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

    fn cache_path(&self, ecosystem: &Ecosystem, name: &str, version: &Version) -> Option<PathBuf> {
        let dir = self.cache_dir.as_ref()?;
        // Key on (ecosystem, name, version) with a stable hash so weird
        // scoped names don't escape the cache root.
        let key = format!("v2|{}|{}|{}", ecosystem_label(ecosystem), name, version);
        let mut hasher = sha2::Sha256::new();
        hasher.update(key.as_bytes());
        let digest = hex::encode(hasher.finalize());
        Some(dir.join(format!("{digest}.json")))
    }
}
fn ecosystem_label(e: &Ecosystem) -> &'static str {
    match *e {
        Ecosystem::Npm => "npm",
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
        version: &Version,
    ) -> Result<Vec<VulnerabilityFinding>> {
        if matches!(
            ecosystem,
            Ecosystem::GitHubActions | Ecosystem::AzurePipelines
        ) {
            // OSV does not index Actions or Pipelines; the firewall does not act on
            // them. Return empty rather than spending a request.
            return Ok(vec![]);
        }
        let path = self.cache_path(&ecosystem, name, version);
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
            "version": version.to_string(),
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
            // Replace atomically; never truncate a caller-planted destination.
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
            severity,
            summary,
        });
    }
    out
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
    fn cache_hit_skips_transport() {
        let dir = tempfile::tempdir().unwrap();
        // Seed cache with a known response.
        let cached = CachedQuery {
            fetched_at: chrono::Utc::now(),
            findings: vec![VulnerabilityFinding {
                source: "OSV".into(),
                id: "GHSA-cached".into(),
                severity: Severity::Critical,
                summary: "cached".into(),
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
        let v = semver::Version::parse("4.17.20").unwrap();
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
        let v = semver::Version::parse("1.0.0").unwrap();
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
        let v = semver::Version::parse("1.0.0").unwrap();
        let f = src
            .query(Ecosystem::GitHubActions, "actions/checkout", &v)
            .unwrap();
        assert!(f.is_empty());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
