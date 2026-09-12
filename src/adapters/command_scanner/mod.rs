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
}

impl CommandScanner {
    pub fn new(command: impl Into<PathBuf>, source: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            source: source.into(),
            timeout: DEFAULT_TIMEOUT,
            max_output_bytes: DEFAULT_MAX_OUTPUT,
        }
    }

    pub fn with_limits(mut self, timeout: Duration, max_output_bytes: usize) -> Self {
        self.timeout = timeout;
        self.max_output_bytes = max_output_bytes;
        self
    }

    fn run(&self, ecosystem: &Ecosystem, archive: &Path) -> Result<String> {
        use std::os::unix::process::CommandExt;
        let mut child = Command::new(&self.command)
            .arg(ecosystem_label(ecosystem))
            .arg(archive)
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
