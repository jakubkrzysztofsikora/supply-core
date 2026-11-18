use crate::domain::{Ecosystem, PackageCoordinate, PackageVersion, PackageVersionId};
use crate::ports::UpstreamNpmRegistry;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
pub struct HttpNpmRegistry {
    pub base_url: String,
    pub client: reqwest::blocking::Client,
}
impl HttpNpmRegistry {
    pub fn new() -> Result<Self> {
        Ok(Self {
            base_url: "https://registry.npmjs.org".into(),
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        })
    }
}
impl UpstreamNpmRegistry for HttpNpmRegistry {
    fn metadata(&self, package: &str) -> Result<serde_json::Value> {
        let url = format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            urlencoding::encode(package)
        );
        Ok(self.client.get(url).send()?.error_for_status()?.json()?)
    }
    fn tarball(&self, url: &str) -> Result<Box<dyn std::io::Read + Send>> {
        Ok(Box::new(self.client.get(url).send()?.error_for_status()?))
    }
}
pub fn rewrite_tarball_urls(
    mut metadata: serde_json::Value,
    proxy_base: &str,
) -> serde_json::Value {
    let package_name = metadata
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("package")
        .to_string();
    let tarball_name = package_name
        .rsplit('/')
        .next()
        .unwrap_or("package")
        .to_string();
    if let Some(versions) = metadata.get_mut("versions").and_then(|v| v.as_object_mut()) {
        for (version, obj) in versions.iter_mut() {
            if let Some(dist) = obj.get_mut("dist").and_then(|d| d.as_object_mut()) {
                dist.insert(
                    "tarball".into(),
                    serde_json::Value::String(format!(
                        "{}/{}/-/{}-{}.tgz",
                        proxy_base.trim_end_matches('/'),
                        package_name,
                        tarball_name,
                        version
                    )),
                );
            }
        }
    }
    metadata
}

pub fn package_version_from_metadata(
    metadata: &serde_json::Value,
    package: &str,
    version: &PackageVersionId,
) -> Result<PackageVersion> {
    let entry = metadata
        .get("versions")
        .and_then(|versions| versions.get(version.upstream()))
        .or_else(|| metadata.get("dist").map(|_| metadata))
        .ok_or_else(|| anyhow::anyhow!("{package}@{version} not found in registry metadata"))?;
    let dist = entry
        .get("dist")
        .ok_or_else(|| anyhow::anyhow!("{package}@{version} has no dist object"))?;
    let integrity = dist
        .get("integrity")
        .and_then(|i| i.as_str())
        .map(str::to_string);
    let tarball_url = dist
        .get("tarball")
        .and_then(|t| t.as_str())
        .map(str::to_string);
    let published_at = metadata
        .get("time")
        .and_then(|time| {
            time.get(version.upstream())
                .and_then(serde_json::Value::as_str)
                .or_else(|| time.as_str())
        })
        .map(DateTime::parse_from_rfc3339)
        .transpose()?
        .map(|t| t.with_timezone(&Utc));
    Ok(PackageVersion {
        package: PackageCoordinate {
            ecosystem: Ecosystem::Npm,
            name: package.to_string(),
        },
        version: version.clone(),
        published_at,
        integrity,
        tarball_url,
    })
}
fn terminate_process_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let process_group = child.id() as libc::pid_t;
        unsafe {
            libc::kill(-process_group, libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
}

fn run_bounded_command(
    command: &mut std::process::Command,
    operation: &str,
    timeout: std::time::Duration,
) -> Result<std::process::Output> {
    use std::io::Read;

    const OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("start {operation}"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("capture {operation} output"))?;
    let (reader_tx, reader_rx) = std::sync::mpsc::channel();
    let _reader = std::thread::spawn(move || {
        let result = (|| {
            let mut output = Vec::new();
            let mut oversized = false;
            let mut buffer = [0_u8; 8192];
            loop {
                let count = stdout.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                let stored = count.min(OUTPUT_LIMIT.saturating_sub(output.len()));
                output.extend_from_slice(&buffer[..stored]);
                oversized |= stored < count;
            }
            Ok::<_, std::io::Error>((output, oversized))
        })();
        let _ = reader_tx.send(result);
    });
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Ok(None) => {
                terminate_process_group(&mut child);
                child
                    .wait()
                    .with_context(|| format!("reap {operation} after timeout"))?;
                anyhow::bail!("{operation} timed out");
            }
            Err(error) => {
                terminate_process_group(&mut child);
                let _ = child.wait();
                return Err(error).with_context(|| format!("wait for {operation}"));
            }
        }
    };
    let (stdout, oversized) = match reader_rx
        .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
    {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            terminate_process_group(&mut child);
            return Err(error).with_context(|| format!("read {operation} output"));
        }
        Err(_) => {
            terminate_process_group(&mut child);
            anyhow::bail!("{operation} timed out while reading output");
        }
    };
    if oversized {
        anyhow::bail!("{operation} output exceeded limit");
    }
    Ok(std::process::Output {
        status,
        stdout,
        stderr: Vec::new(),
    })
}

fn run_npm(args: &[&str], cwd: &std::path::Path, operation: &str) -> Result<std::process::Output> {
    let mut command = std::process::Command::new("npm");
    command.args(args).current_dir(cwd);
    run_bounded_command(&mut command, operation, std::time::Duration::from_secs(30))
}

pub fn exact_metadata(
    package: &str,
    version: &str,
    cwd: &std::path::Path,
) -> Result<serde_json::Value> {
    let package_version = format!("{package}@{version}");
    let output = run_npm(
        &["view", &package_version, "dist", "time", "--json"],
        cwd,
        "npm view",
    )?;
    if !output.status.success() {
        anyhow::bail!("npm view failed for requested package version");
    }
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("npm returned invalid metadata JSON")?;
    if let Some(array) = metadata.as_array_mut() {
        if array.len() != 1 {
            anyhow::bail!("npm returned unexpected result count");
        }
        metadata = array.remove(0);
    }
    let dist = metadata
        .get("dist")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("npm metadata lacks dist"))?;
    let time = metadata
        .get("time")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("npm metadata lacks publication time"))?;
    Ok(serde_json::json!({ "dist": dist, "time": time }))
}

pub fn configured_registry(package: &str, cwd: &std::path::Path) -> Result<String> {
    let setting = package
        .split('/')
        .next()
        .filter(|part| part.starts_with('@'))
        .map(|scope| format!("{scope}:registry"));
    let value = if let Some(key) = setting {
        let scoped = run_npm(&["config", "get", &key], cwd, "npm config")?;
        let scoped_value = String::from_utf8_lossy(&scoped.stdout).trim().to_string();
        if scoped.status.success() && !scoped_value.is_empty() && scoped_value != "undefined" {
            scoped_value
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    let registry = if value.is_empty() {
        let output = run_npm(&["config", "get", "registry"], cwd, "npm config")?;
        if !output.status.success() {
            anyhow::bail!("cannot resolve configured npm registry");
        }
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        value
    };
    let url = reqwest::Url::parse(&registry).context("invalid npm registry configuration")?;
    if url.scheme() != "https" || url.host_str().is_none() {
        anyhow::bail!("npm registry must use HTTPS");
    }
    Ok(url.to_string())
}
pub fn validate_locked_registry_source(
    resolved: Option<&str>,
    registry: &str,
    package: &str,
) -> Result<String> {
    let registry_url =
        reqwest::Url::parse(registry).context("invalid npm registry configuration")?;
    if registry_url.scheme() != "https"
        || registry_url.host_str().is_none()
        || !registry_url.username().is_empty()
        || registry_url.password().is_some()
        || registry_url.query().is_some()
        || registry_url.fragment().is_some()
    {
        anyhow::bail!("npm registry must be an HTTPS URL without credentials or query data");
    }
    let registry_origin = registry_url.origin().ascii_serialization();
    let Some(resolved) = resolved.filter(|value| !value.is_empty()) else {
        return Ok(registry_url.to_string());
    };
    let tarball_url = reqwest::Url::parse(resolved).context("invalid locked npm tarball URL")?;
    if tarball_url.scheme() != "https"
        || !tarball_url.username().is_empty()
        || tarball_url.password().is_some()
        || tarball_url.query().is_some()
        || tarball_url.fragment().is_some()
    {
        anyhow::bail!(
            "locked npm tarball URL must use HTTPS without credentials or query data for {package}"
        );
    }
    if tarball_url.origin().ascii_serialization() != registry_origin {
        anyhow::bail!("locked npm tarball source does not match configured registry for {package}");
    }
    let registry_path = registry_url.path().trim_end_matches('/');
    if !registry_path.is_empty()
        && !tarball_url
            .path()
            .strip_prefix(registry_path)
            .is_some_and(|suffix| suffix.starts_with('/'))
    {
        anyhow::bail!("locked npm tarball path does not match configured registry for {package}");
    }
    Ok(registry_url.to_string())
}

pub fn integrity_for(metadata: &serde_json::Value, version: &str) -> Option<String> {
    metadata
        .get("versions")
        .and_then(|versions| versions.get(version))
        .and_then(|entry| entry.get("dist"))
        .and_then(|dist| dist.get("integrity"))
        .and_then(|integrity| integrity.as_str())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn locked_tarball_must_match_https_registry_source() -> Result<()> {
        assert_eq!(
            validate_locked_registry_source(
                Some("https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz"),
                "https://registry.npmjs.org/",
                "left-pad",
            )?,
            "https://registry.npmjs.org/"
        );
        assert_eq!(
            validate_locked_registry_source(
                Some("https://npm.example.test/scoped/pkg/-/pkg-1.0.0.tgz"),
                "https://npm.example.test/scoped/",
                "pkg",
            )?,
            "https://npm.example.test/scoped/"
        );
        assert_eq!(
            validate_locked_registry_source(None, "https://registry.npmjs.org/", "left-pad")?,
            "https://registry.npmjs.org/"
        );
        assert!(validate_locked_registry_source(
            Some("http://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz"),
            "https://registry.npmjs.org/",
            "left-pad",
        )
        .is_err());
        assert!(validate_locked_registry_source(
            Some("https://registry.example/left-pad/-/left-pad-1.0.0.tgz"),
            "https://registry.npmjs.org/",
            "left-pad",
        )
        .is_err());
        assert!(validate_locked_registry_source(
            Some("https://npm.example.test/other/pkg.tgz"),
            "https://npm.example.test/scoped/",
            "@circit/pkg",
        )
        .is_err());
        Ok(())
    }
    #[test]
    fn extracts_integrity_for_a_version() {
        let metadata =
            serde_json::json!({"versions": {"1.3.0": {"dist": {"integrity": "sha512-abc"}}}});
        assert_eq!(
            integrity_for(&metadata, "1.3.0").as_deref(),
            Some("sha512-abc")
        );
        assert_eq!(integrity_for(&metadata, "9.9.9"), None);
    }
    #[test]
    fn rewrites() {
        let v = serde_json::json!({"name":"left-pad","versions":{"1.0.0":{"dist":{"tarball":"https://x"}}}});
        let r = rewrite_tarball_urls(v, "http://localhost:4873");
        assert_eq!(
            r["versions"]["1.0.0"]["dist"]["tarball"],
            "http://localhost:4873/left-pad/-/left-pad-1.0.0.tgz"
        );
    }
    #[test]
    fn maps_registry_metadata_to_domain() -> Result<()> {
        let meta = serde_json::json!({
            "name": "left-pad",
            "versions": {"1.3.0": {"dist": {
                "integrity": "sha512-abc",
                "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
            }}},
            "time": {"1.3.0": "2018-02-05T02:27:32.476Z"}
        });
        let pv = package_version_from_metadata(
            &meta,
            "left-pad",
            &PackageVersionId::parse(&Ecosystem::Npm, "1.3.0")?,
        )?;
        assert_eq!(pv.integrity.as_deref(), Some("sha512-abc"));
        assert!(pv
            .tarball_url
            .as_deref()
            .is_some_and(|u| u.ends_with("1.3.0.tgz")));
        assert!(pv.published_at.is_some());
        Ok(())
    }
    #[test]
    fn tarball_returns_before_the_response_body_finishes() -> Result<()> {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            sync::mpsc,
            thread,
            time::Duration,
        };

        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let (started_tx, started_rx) = mpsc::channel();
        let (continue_tx, continue_rx) = mpsc::channel();
        let server = thread::spawn(move || -> Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request)?;
            stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nabc",
            )?;
            stream.flush()?;
            started_tx.send(())?;
            continue_rx
                .recv_timeout(Duration::from_secs(2))
                .map_err(|error| anyhow::anyhow!("test did not release response: {error}"))?;
            let _ = stream.write_all(b"def");
            let _ = stream.flush();
            Ok(())
        });
        let registry = HttpNpmRegistry {
            base_url: String::new(),
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(2))
                .build()?,
        };
        let url = format!("http://{address}/tarball");
        let (returned_tx, returned_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let client = thread::spawn(move || {
            let result = registry.tarball(&url).and_then(|mut body| {
                returned_tx.send(())?;
                let mut bytes = Vec::new();
                body.read_to_end(&mut bytes)?;
                Ok(bytes)
            });
            let _ = result_tx.send(result);
        });

        started_rx
            .recv_timeout(Duration::from_secs(2))
            .map_err(|error| anyhow::anyhow!("server did not start response: {error}"))?;
        let early = returned_rx.recv_timeout(Duration::from_secs(1));
        continue_tx.send(())?;
        let bytes = result_rx
            .recv_timeout(Duration::from_secs(2))
            .map_err(|error| anyhow::anyhow!("client did not finish response: {error}"))??;
        client
            .join()
            .map_err(|_| anyhow::anyhow!("client thread panicked"))?;
        server
            .join()
            .map_err(|_| anyhow::anyhow!("server thread panicked"))??;

        assert!(
            early.is_ok(),
            "tarball call buffered the complete response body"
        );
        assert_eq!(bytes, b"abcdef");
        Ok(())
    }
    #[test]
    fn unknown_version_errors() -> Result<()> {
        let meta = serde_json::json!({"versions": {}});
        let v = PackageVersionId::parse(&Ecosystem::Npm, "9.9.9")?;
        assert!(package_version_from_metadata(&meta, "x", &v).is_err());
        Ok(())
    }
    #[test]
    fn maps_exact_version_view_metadata() -> Result<()> {
        let metadata = serde_json::json!({
            "dist": {
                "integrity": "sha512-abc",
                "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
            },
            "time": "2018-02-05T02:27:32.476Z"
        });
        let version = PackageVersionId::parse(&Ecosystem::Npm, "1.3.0")?;
        let package = package_version_from_metadata(&metadata, "left-pad", &version)?;

        assert_eq!(package.integrity.as_deref(), Some("sha512-abc"));
        assert_eq!(
            package
                .published_at
                .map(|time| time.to_rfc3339())
                .as_deref(),
            Some("2018-02-05T02:27:32.476+00:00")
        );
        Ok(())
    }

    #[cfg(unix)]
    fn run_script_with_deadline(script_body: &str) -> Result<std::process::Output> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let script = directory.path().join("npm");
        std::fs::write(&script, script_body)?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))?;
        let mut command = std::process::Command::new(script);
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(run_bounded_command(
                &mut command,
                "npm config",
                std::time::Duration::from_millis(50),
            ));
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .context("command left stdout reader blocked past test deadline")?
    }

    #[cfg(unix)]
    #[test]
    fn bounded_npm_command_times_out_on_background_stdout_holder() -> Result<()> {
        let started = std::time::Instant::now();
        let error = match run_script_with_deadline(
            r#"#!/usr/bin/env python3
import os
import time
pid = os.fork()
if pid == 0:
    time.sleep(2)
    os._exit(0)
os.waitpid(pid, 0)
"#,
        ) {
            Ok(_) => anyhow::bail!("command with background process unexpectedly returned"),
            Err(error) => error,
        };

        assert!(format!("{error:#}").contains("npm config timed out"));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn bounded_npm_command_times_out_when_parent_exits_before_stdout_holder() -> Result<()> {
        let started = std::time::Instant::now();
        let error = match run_script_with_deadline(
            r#"#!/usr/bin/env python3
import os
import time
pid = os.fork()
if pid == 0:
    time.sleep(2)
    os._exit(0)
os._exit(0)
"#,
        ) {
            Ok(_) => anyhow::bail!("background stdout holder unexpectedly completed"),
            Err(error) => error,
        };

        assert!(format!("{error:#}").contains("npm config timed out"));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn bounded_npm_command_kills_a_hung_process() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let script = directory.path().join("npm");
        std::fs::write(&script, "#!/bin/sh\nexec sleep 30\n")?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))?;
        let mut command = std::process::Command::new(script);
        let started = std::time::Instant::now();

        let error = match run_bounded_command(
            &mut command,
            "npm config",
            std::time::Duration::from_millis(50),
        ) {
            Ok(_) => anyhow::bail!("hung npm command unexpectedly returned"),
            Err(error) => error,
        };

        assert!(format!("{error:#}").contains("timed out"));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        Ok(())
    }
}
