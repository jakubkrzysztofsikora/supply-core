use crate::domain::{ContentFinding, Ecosystem};
use crate::ports::ContentScanner;
use anyhow::{Context, Result};
use chrono::Utc;
use semver::Version;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_MAX_OUTPUT: usize = 8 * 1024 * 1024;
const DRAIN_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// `command <ecosystem> <archive>` with `{"score","rules","summary"}` JSON.
    Normalized,
    /// `command <ecosystem> scan <archive> --output-format json`, GuardDog v3.
    GuardDog,
}

fn scanner_args(format: ReportFormat, ecosystem: &Ecosystem, archive: &Path) -> Vec<String> {
    let archive = archive.to_string_lossy().to_string();
    match format {
        ReportFormat::Normalized => vec![ecosystem_label(ecosystem).to_string(), archive],
        ReportFormat::GuardDog => vec![
            ecosystem_label(ecosystem).to_string(),
            "scan".to_string(),
            archive,
            "--output-format".to_string(),
            "json".to_string(),
        ],
    }
}

/// Maps a real GuardDog v3 report (risk_score/results/errors) into a finding.
pub fn finding_from_guarddog(
    payload: &serde_json::Value,
    ecosystem: &Ecosystem,
    name: &str,
    version: &Version,
) -> Result<Option<ContentFinding>> {
    if let Some(errors) = payload.get("errors").and_then(|errors| errors.as_object()) {
        if !errors.is_empty() {
            anyhow::bail!(
                "guarddog reported scan errors: {}",
                serde_json::to_string(errors)?
            );
        }
    }
    let score = payload
        .get("risk_score")
        .and_then(|risk| risk.get("score"))
        .and_then(|score| score.as_f64())
        .context("guarddog report is missing risk_score.score")?
        .round()
        .clamp(0.0, 10.0) as u8;
    if score == 0 {
        return Ok(None);
    }
    let results = payload
        .get("results")
        .and_then(|results| results.as_object());
    let mut rules: Vec<String> = results
        .map(|results| {
            results
                .iter()
                .filter(|(_, hits)| hits.as_array().is_some_and(|hits| !hits.is_empty()))
                .map(|(rule, _)| rule.clone())
                .collect()
        })
        .unwrap_or_default();
    rules.sort();
    let label = payload
        .get("risk_score")
        .and_then(|risk| risk.get("label"))
        .and_then(|label| label.as_str())
        .unwrap_or("risk");
    let top_message = results
        .and_then(|results| {
            let threat = results
                .iter()
                .filter(|(rule, _)| rule.starts_with("threat-"))
                .find_map(|(_, hits)| first_message(hits));
            threat.or_else(|| results.values().find_map(first_message))
        })
        .unwrap_or("guarddog flagged this package");
    Ok(Some(ContentFinding {
        ecosystem: ecosystem.clone(),
        package: name.to_string(),
        version: version.clone(),
        source: "guarddog".to_string(),
        score,
        rules,
        summary: format!("{label}: {top_message}"),
        detected_at: Utc::now(),
    }))
}

fn first_message(hits: &serde_json::Value) -> Option<&str> {
    hits.as_array()?.first()?.get("message")?.as_str()
}

fn kill_process_group(pid: i32) {
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
}

/// Runs an external analyzer against a package archive and expects a
/// normalized JSON report on stdout: `{"score": 0-10, "rules": [...],
/// "summary": "..."}`. This keeps the firewall engine independent of any
/// single tool's output schema; GuardDog, for example, can be wrapped by a
/// small script that prints this shape.
pub struct CommandScanner {
    pub command: PathBuf,
    pub source: String,
    pub timeout: Duration,
    pub max_output_bytes: usize,
    pub format: ReportFormat,
}

impl CommandScanner {
    pub fn new(command: impl Into<PathBuf>, source: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            source: source.into(),
            timeout: DEFAULT_TIMEOUT,
            max_output_bytes: DEFAULT_MAX_OUTPUT,
            format: ReportFormat::Normalized,
        }
    }

    pub fn guarddog(command: impl Into<PathBuf>) -> Self {
        Self {
            command: command.into(),
            source: "guarddog".to_string(),
            timeout: DEFAULT_TIMEOUT,
            max_output_bytes: DEFAULT_MAX_OUTPUT,
            format: ReportFormat::GuardDog,
        }
    }

    pub fn with_format(mut self, format: ReportFormat) -> Self {
        self.format = format;
        self
    }

    pub fn with_limits(mut self, timeout: Duration, max_output_bytes: usize) -> Self {
        self.timeout = timeout;
        self.max_output_bytes = max_output_bytes;
        self
    }

    fn run(&self, ecosystem: &Ecosystem, archive: &Path) -> Result<String> {
        use std::os::unix::process::CommandExt;
        let mut child = Command::new(&self.command);
        for argument in scanner_args(self.format, ecosystem, archive) {
            child.arg(argument);
        }
        let mut child = child
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to run {}", self.command.display()))?;
        let pid = child.id() as i32;
        let stdout = child.stdout.take().context("scanner stdout missing")?;
        let stderr = child.stderr.take().context("scanner stderr missing")?;
        let limit = self.max_output_bytes;
        let (out_tx, out_rx) = std::sync::mpsc::channel();
        let (err_tx, err_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = out_tx.send(read_capped(stdout, limit));
        });
        std::thread::spawn(move || {
            let _ = err_tx.send(read_capped(stderr, limit));
        });

        let deadline = Instant::now() + self.timeout;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                kill_process_group(pid);
                let _ = child.wait();
                anyhow::bail!(
                    "{} timed out after {:?}",
                    self.command.display(),
                    self.timeout
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        };

        // The direct child can exit while a background grandchild still holds
        // the pipe descriptors open; both drains share one grace window.
        let drain_deadline = deadline.min(Instant::now() + DRAIN_GRACE);
        let (stdout_bytes, stdout_truncated) =
            match out_rx.recv_timeout(drain_deadline.saturating_duration_since(Instant::now())) {
                Ok(result) => result,
                Err(_) => {
                    kill_process_group(pid);
                    anyhow::bail!(
                        "{} timed out while draining scanner output",
                        self.command.display()
                    );
                }
            };
        let (stderr_bytes, stderr_truncated) =
            match err_rx.recv_timeout(drain_deadline.saturating_duration_since(Instant::now())) {
                Ok(result) => result,
                Err(_) => {
                    kill_process_group(pid);
                    anyhow::bail!(
                        "{} timed out while draining scanner output",
                        self.command.display()
                    );
                }
            };
        if stdout_truncated || stderr_truncated {
            anyhow::bail!(
                "{} output exceeded {} bytes",
                self.command.display(),
                self.max_output_bytes
            );
        }
        if !status.success() {
            anyhow::bail!(
                "{} exited with {}: {}",
                self.command.display(),
                status,
                String::from_utf8_lossy(&stderr_bytes).trim()
            );
        }
        Ok(String::from_utf8_lossy(&stdout_bytes).to_string())
    }
}

fn read_capped(mut reader: impl Read, limit: usize) -> (Vec<u8>, bool) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return (buffer, false),
            Ok(read) => {
                if buffer.len() + read > limit {
                    let remaining = limit.saturating_sub(buffer.len());
                    buffer.extend_from_slice(&chunk[..remaining]);
                    return (buffer, true);
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            Err(_) => return (buffer, false),
        }
    }
}

impl ContentScanner for CommandScanner {
    fn scan_archive(
        &self,
        ecosystem: &Ecosystem,
        archive: &Path,
        name: &str,
        version: &Version,
    ) -> Result<Option<ContentFinding>> {
        let stdout = self.run(ecosystem, archive)?;
        let report: serde_json::Value =
            serde_json::from_str(stdout.trim()).context("scanner report is not valid JSON")?;
        if self.format == ReportFormat::GuardDog {
            return finding_from_guarddog(&report, ecosystem, name, version);
        }
        let score = report
            .get("score")
            .and_then(|score| score.as_u64())
            .context("scanner report is missing a numeric score")?
            .min(10) as u8;
        if score == 0 {
            return Ok(None);
        }
        let rules = report
            .get("rules")
            .and_then(|rules| rules.as_array())
            .map(|rules| {
                rules
                    .iter()
                    .filter_map(|rule| rule.as_str())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let summary = report
            .get("summary")
            .and_then(|summary| summary.as_str())
            .unwrap_or("external scanner reported risk")
            .to_string();
        Ok(Some(ContentFinding {
            ecosystem: ecosystem.clone(),
            package: name.to_string(),
            version: version.clone(),
            source: self.source.clone(),
            score,
            rules,
            summary,
            detected_at: Utc::now(),
        }))
    }
}

fn ecosystem_label(ecosystem: &Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPi => "pypi",
        Ecosystem::NuGet => "nuget",
        _ => "unknown",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    /// Writes a shell body file. The file is handed to `sh` by the stable
    /// dispatcher below and is never executed directly, so a fresh write can
    /// never race `execve` into ETXTBSY on parallel Linux test threads.
    fn script(body: &str) -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("case.sh");
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "{body}").unwrap();
        file.sync_all().unwrap();
        (directory, path)
    }

    /// One executable script per test binary (created once, never rewritten)
    /// that runs the body file passed as the second argument.
    fn dispatcher() -> PathBuf {
        static DISPATCHER: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        DISPATCHER
            .get_or_init(|| {
                let directory = tempfile::tempdir().unwrap();
                let path = directory.path().join("dispatcher.sh");
                let mut file = std::fs::File::create(&path).unwrap();
                write!(file, "#!/bin/sh\nexec /bin/sh \"$2\"\n").unwrap();
                file.sync_all().unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
                std::mem::forget(directory);
                path
            })
            .clone()
    }

    fn version() -> Version {
        Version::parse("1.2.3").unwrap()
    }

    #[test]
    fn parses_real_guarddog_report() {
        let payload: serde_json::Value = serde_json::from_str(GUARDDOG_EVIL).unwrap();
        let finding = finding_from_guarddog(&payload, &Ecosystem::Npm, "evil", &version())
            .unwrap()
            .unwrap();
        assert_eq!(finding.score, 8);
        assert!(finding
            .rules
            .contains(&"capability-network-download".to_string()));
        assert!(finding
            .rules
            .contains(&"threat-network-exfiltration".to_string()));
        assert!(finding.summary.contains("high_risk"), "{}", finding.summary);
        assert!(
            finding.summary.contains("exfiltration"),
            "{}",
            finding.summary
        );
        assert_eq!(finding.source, "guarddog");
    }

    #[test]
    fn guarddog_clean_report_is_not_a_finding() {
        let payload: serde_json::Value = serde_json::from_str(GUARDDOG_CLEAN).unwrap();
        assert!(
            finding_from_guarddog(&payload, &Ecosystem::Npm, "lib", &version())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn guarddog_errors_fail_closed() {
        let payload: serde_json::Value =
            serde_json::from_str(r#"{"risk_score": {"score": 3.0}, "errors": {"a": "boom"}}"#)
                .unwrap();
        assert!(finding_from_guarddog(&payload, &Ecosystem::Npm, "odd", &version()).is_err());
    }

    #[test]
    fn guarddog_missing_score_is_an_error() {
        let payload: serde_json::Value = serde_json::from_str(r#"{"results": {}}"#).unwrap();
        assert!(finding_from_guarddog(&payload, &Ecosystem::Npm, "odd", &version()).is_err());
    }

    #[test]
    fn guarddog_arguments_include_scan_and_json_output() {
        let args = scanner_args(
            ReportFormat::GuardDog,
            &Ecosystem::Npm,
            Path::new("/tmp/evil.tgz"),
        );
        assert_eq!(
            args,
            vec!["npm", "scan", "/tmp/evil.tgz", "--output-format", "json"]
        );
        let args = scanner_args(
            ReportFormat::Normalized,
            &Ecosystem::PyPi,
            Path::new("/tmp/x.tgz"),
        );
        assert_eq!(args, vec!["pypi", "/tmp/x.tgz"]);
    }

    const GUARDDOG_EVIL: &str = r#"{
      "package": "/tmp/evil.tgz",
      "results": {
        "capability-network-download": [{"location": "package/beacon.js:1", "match": "https.get(", "message": "Detects downloading files from network"}],
        "capability-process-hooks": [{"location": "package/package.json:1", "match": "postinstall", "message": "has_npm_hook rule matched"}],
        "threat-network-exfil-messenger": [{"location": "package/beacon.js:1", "match": "discord.com/api/webhooks/1/", "message": "Detects hardcoded messaging platform tokens/webhooks used for data exfiltration"}],
        "threat-network-exfiltration": [{"location": "package/beacon.js:1", "match": "discord.com/api/webhooks", "message": "Detects URLs to suspicious domains often used for exfiltration or C2"}],
        "threat-process-hooks": [{"location": "package/package.json:1", "match": "postinstall", "message": "hook threat"}]
      },
      "risk_score": {"score": 8.0, "label": "high_risk", "findings_count": 6, "score_breakdown": {}},
      "risks": [{"name": "risk.network.outbound", "severity": "high"}],
      "issues": 7,
      "errors": {}
    }"#;

    const GUARDDOG_CLEAN: &str = r#"{
      "package": "/tmp/benign.tgz",
      "results": {"capability-network-download": {}, "threat-network-exfiltration": {}},
      "risk_score": {"score": 0.0, "label": "no_risks_detected", "findings_count": 0, "score_breakdown": {}},
      "risks": [],
      "issues": 0,
      "errors": {}
    }"#;

    #[test]
    fn parses_normalized_report_into_finding() {
        let (_directory, path) = script(
            r#"cat <<'EOF'
{"score": 9, "rules": ["install-script-network"], "summary": "postinstall beacon"}
EOF"#,
        );
        let scanner = CommandScanner::new(dispatcher(), "guarddog");
        let finding = scanner
            .scan_archive(&Ecosystem::Npm, &path, "evil", &version())
            .unwrap()
            .unwrap();
        assert_eq!(finding.score, 9);
        assert_eq!(finding.rules, vec!["install-script-network"]);
        assert_eq!(finding.summary, "postinstall beacon");
        assert_eq!(finding.source, "guarddog");
        assert_eq!(finding.package, "evil");
    }

    #[test]
    fn zero_score_is_not_a_finding() {
        let (_directory, path) = script(
            r#"cat <<'EOF'
{"score": 0, "rules": [], "summary": ""}
EOF"#,
        );
        let scanner = CommandScanner::new(dispatcher(), "guarddog");
        let finding = scanner
            .scan_archive(&Ecosystem::Npm, &path, "clean", &version())
            .unwrap();
        assert!(finding.is_none());
    }

    #[test]
    fn score_above_ten_is_clamped() {
        let (_directory, path) = script(
            r#"cat <<'EOF'
{"score": 42, "rules": ["x"], "summary": "over"}
EOF"#,
        );
        let scanner = CommandScanner::new(dispatcher(), "guarddog");
        let finding = scanner
            .scan_archive(&Ecosystem::Npm, &path, "odd", &version())
            .unwrap()
            .unwrap();
        assert_eq!(finding.score, 10);
    }

    #[test]
    fn invalid_json_is_an_error() {
        let (_directory, path) = script("echo not-json");
        let scanner = CommandScanner::new(dispatcher(), "guarddog");
        assert!(scanner
            .scan_archive(&Ecosystem::Npm, &path, "odd", &version())
            .is_err());
    }

    #[test]
    fn drain_honours_a_single_grace_window() {
        // stdout closes at ~1s; stderr is held until ~2.4s. With one 2s
        // grace window computed up front the stderr wait must time out; with
        // a fresh per-stream window the call would incorrectly succeed.
        let (_directory, path) = script(
            "(sleep 1; echo '{\"score\":0,\"rules\":[],\"summary\":\"\"}') 2>/dev/null & (sleep 2.4; echo x 1>&2) 1>/dev/null & exit 0",
        );
        let scanner = CommandScanner::new(dispatcher(), "guarddog")
            .with_limits(std::time::Duration::from_secs(30), 1024 * 1024);
        let error = scanner
            .scan_archive(&Ecosystem::Npm, &path, "odd", &version())
            .unwrap_err()
            .to_string();
        assert!(error.contains("timed out"), "{error}");
    }

    #[test]
    fn background_pipe_holder_cannot_hang_the_scan() {
        let (_directory, path) = script("sleep 300 & exit 0");
        let scanner = CommandScanner::new(dispatcher(), "guarddog")
            .with_limits(std::time::Duration::from_secs(30), 1024 * 1024);
        let started = std::time::Instant::now();
        let error = scanner
            .scan_archive(&Ecosystem::Npm, &path, "odd", &version())
            .unwrap_err()
            .to_string();
        assert!(error.contains("timed out"), "{error}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "drain blocked for {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn timeout_kills_a_hung_scanner() {
        let (_directory, path) = script("sleep 5");
        let scanner = CommandScanner::new(dispatcher(), "guarddog")
            .with_limits(std::time::Duration::from_millis(250), 1024 * 1024);
        let error = scanner
            .scan_archive(&Ecosystem::Npm, &path, "odd", &version())
            .unwrap_err()
            .to_string();
        assert!(error.contains("timed out"), "{error}");
    }

    #[test]
    fn oversized_output_is_rejected() {
        let (_directory, path) = script("head -c 4096 /dev/zero | tr '\\0' 'a'");
        let scanner = CommandScanner::new(dispatcher(), "guarddog")
            .with_limits(std::time::Duration::from_secs(10), 1024);
        let error = scanner
            .scan_archive(&Ecosystem::Npm, &path, "odd", &version())
            .unwrap_err()
            .to_string();
        assert!(error.contains("output"), "{error}");
    }

    #[test]
    fn non_zero_exit_is_an_error() {
        let (_directory, path) = script("echo boom >&2; exit 3");
        let scanner = CommandScanner::new(dispatcher(), "guarddog");
        let error = scanner
            .scan_archive(&Ecosystem::Npm, &path, "odd", &version())
            .unwrap_err()
            .to_string();
        assert!(error.contains("exited"), "{error}");
    }
}
