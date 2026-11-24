#![allow(clippy::unwrap_used)]

use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha512};
use std::{fs, path::PathBuf, process::Command};
use tempfile::tempdir;

#[derive(Deserialize)]
struct Report {
    inputs: Vec<Input>,
    packages: Vec<serde_json::Value>,
    errors: Vec<String>,
    complete: bool,
}

#[derive(Deserialize)]
struct Input {
    path: String,
    sha256: String,
}

fn policy_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/supply-core.yml")
}

fn signed_test_nupkg() -> anyhow::Result<(Vec<u8>, usize)> {
    let files: [(&[u8], &[u8]); 2] = [
        (b"lib/net10.0/Sample.txt", b"payload-content"),
        (b".signature.p7s", b"signature-bytes"),
    ];
    let mut archive = Vec::new();
    let mut central_records = Vec::new();
    let mut payload_offset = 0;

    for (name, data) in files {
        let local_offset = u32::try_from(archive.len())?;
        if name == b"lib/net10.0/Sample.txt" {
            payload_offset = archive.len() + 30 + name.len();
        }
        let checksum = crc32(data);
        push_u32(&mut archive, 0x0403_4b50);
        push_u16(&mut archive, 20);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u32(&mut archive, checksum);
        push_u32(&mut archive, u32::try_from(data.len())?);
        push_u32(&mut archive, u32::try_from(data.len())?);
        push_u16(&mut archive, u16::try_from(name.len())?);
        push_u16(&mut archive, 0);
        archive.extend_from_slice(name);
        archive.extend_from_slice(data);

        let mut central = Vec::new();
        push_u32(&mut central, 0x0201_4b50);
        push_u16(&mut central, 20);
        push_u16(&mut central, 20);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u32(&mut central, checksum);
        push_u32(&mut central, u32::try_from(data.len())?);
        push_u32(&mut central, u32::try_from(data.len())?);
        push_u16(&mut central, u16::try_from(name.len())?);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u32(&mut central, 0);
        push_u32(&mut central, local_offset);
        central.extend_from_slice(name);
        central_records.push(central);
    }

    let central_offset = u32::try_from(archive.len())?;
    for record in &central_records {
        archive.extend_from_slice(record);
    }
    let central_size = u32::try_from(archive.len())? - central_offset;
    push_u32(&mut archive, 0x0605_4b50);
    push_u16(&mut archive, 0);
    push_u16(&mut archive, 0);
    push_u16(&mut archive, u16::try_from(central_records.len())?);
    push_u16(&mut archive, u16::try_from(central_records.len())?);
    push_u32(&mut archive, central_size);
    push_u32(&mut archive, central_offset);
    push_u16(&mut archive, 0);
    Ok((archive, payload_offset))
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut checksum = u32::MAX;
    for byte in bytes {
        checksum ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(checksum & 1);
            checksum = (checksum >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !checksum
}
#[test]
fn malformed_npm_lock_returns_hashed_incomplete_json() -> anyhow::Result<()> {
    let temp = tempdir()?;
    let lock = temp.path().join("package-lock.json");
    let bytes = b"{not-json";
    fs::write(&lock, bytes)?;

    let output = Command::new(env!("CARGO_BIN_EXE_supply-core"))
        .args([
            "scan-packages",
            "--npm-lock",
            lock.to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 fixture path"))?,
            "--policy",
            policy_path()
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 policy path"))?,
            "--json",
        ])
        .output()?;

    assert_eq!(output.status.code(), Some(1));
    let report: Report = serde_json::from_slice(&output.stdout)?;
    assert!(!report.complete);
    assert!(report.packages.is_empty());
    assert_eq!(report.inputs.len(), 1);
    assert_eq!(report.inputs[0].path, lock.display().to_string());
    assert_eq!(report.inputs[0].sha256, hex::encode(Sha256::digest(bytes)));
    assert!(report
        .errors
        .iter()
        .any(|error| error.contains("malformed npm lock JSON")));
    Ok(())
}

#[test]
#[ignore = "requires bubblewrap sandbox; unavailable in the supply-core-runner container"]
fn insecure_npm_tarball_source_is_reported_incomplete() -> anyhow::Result<()> {
    let temp = tempdir()?;
    let lock = temp.path().join("package-lock.json");
    fs::write(
        &lock,
        r#"{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.0.0","resolved":"http://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz","integrity":"sha512-expected"}}}"#,
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_supply-core"))
        .args([
            "scan-packages",
            "--npm-lock",
            lock.to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 fixture path"))?,
            "--policy",
            policy_path()
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 policy path"))?,
            "--json",
        ])
        .env("npm_config_registry", "https://registry.npmjs.org/")
        .output()?;

    assert_eq!(output.status.code(), Some(1));
    let report: Report = serde_json::from_slice(&output.stdout)?;
    assert!(!report.complete);
    assert_eq!(report.inputs.len(), 1);
    assert!(report
        .errors
        .iter()
        .any(|error| error.contains("must use HTTPS")));
    Ok(())
}

#[test]
fn missing_lock_inputs_return_incomplete_json() -> anyhow::Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_supply-core"))
        .args([
            "scan-packages",
            "--policy",
            policy_path()
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 policy path"))?,
            "--json",
        ])
        .output()?;

    assert_eq!(output.status.code(), Some(1));
    let report: Report = serde_json::from_slice(&output.stdout)?;
    assert!(!report.complete);
    assert!(report.inputs.is_empty());
    assert!(report.packages.is_empty());
    assert!(report
        .errors
        .iter()
        .any(|error| error == "at least one lockfile is required"));
    Ok(())
}

#[test]
fn all_local_and_dependency_free_inputs_are_incomplete() -> anyhow::Result<()> {
    let temp = tempdir()?;
    let npm_lock = temp.path().join("package-lock.json");
    fs::write(
        &npm_lock,
        serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "workspace"},
                "node_modules/local": {"link": true, "resolved": "packages/local"},
                "packages/local": {"name": "local", "version": "1.0.0"}
            }
        })
        .to_string(),
    )?;
    let nuget_lock = temp.path().join("packages.lock.json");
    fs::write(
        &nuget_lock,
        serde_json::json!({"version":1,"dependencies":{}}).to_string(),
    )?;
    let nuget_packages = temp.path().join("packages");
    fs::create_dir(&nuget_packages)?;

    let output = Command::new(env!("CARGO_BIN_EXE_supply-core"))
        .args([
            "scan-packages",
            "--npm-lock",
            npm_lock
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 npm lock path"))?,
            "--nuget-lock",
            nuget_lock
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 NuGet lock path"))?,
            "--nuget-packages",
            nuget_packages
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 NuGet cache path"))?,
            "--policy",
            policy_path()
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 policy path"))?,
            "--json",
        ])
        .output()?;

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["complete"], false);
    assert!(report["errors"].as_array().is_some_and(|errors| errors
        .iter()
        .any(|error| error == "no registry package resolutions found")));
    let packages = report["packages"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("package list missing"))?;
    assert_eq!(packages.len(), 2);
    assert!(packages
        .iter()
        .all(|package| package["status"] == "not-applicable"));
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("flagged=0"), "{stderr}");
    Ok(())
}

#[test]
fn dependency_free_npm_lock_is_incomplete() -> anyhow::Result<()> {
    let temp = tempdir()?;
    let lock = temp.path().join("package-lock.json");
    fs::write(
        &lock,
        serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "workspace", "version": "1.0.0"}
            }
        })
        .to_string(),
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_supply-core"))
        .args([
            "scan-packages",
            "--npm-lock",
            lock.to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 lock path"))?,
            "--policy",
            policy_path()
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 policy path"))?,
            "--json",
        ])
        .output()?;

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["complete"], false);
    assert!(report["errors"].as_array().is_some_and(|errors| errors
        .iter()
        .any(|error| error == "no registry package resolutions found")));
    assert_eq!(report["inputs"].as_array().map(Vec::len), Some(1));
    Ok(())
}

#[cfg(unix)]
#[test]
fn root_level_npm_lock_can_run_registry_lookup() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir()?;
    let bin = temp.path().join("bin");
    fs::create_dir(&bin)?;
    let trace = temp.path().join("npm-trace");
    let npm = bin.join("npm");
    fs::write(
        &npm,
        "#!/bin/sh\nprintf '%s %s %s\\n' \"$1\" \"${2:-}\" \"${3:-}\" >> \"$TRACE_FILE\"\nif [ \"$1\" = config ]; then printf 'https://registry.npmjs.org\\n'; exit 0; fi\nexit 1\n",
    )?;
    fs::set_permissions(&npm, fs::Permissions::from_mode(0o755))?;

    fs::write(
        temp.path().join("package-lock.json"),
        serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "fixture"},
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-c2VmdGVzdA=="
                }
            }
        })
        .to_string(),
    )?;

    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_supply-core"))
        .args([
            "scan-packages",
            "--npm-lock",
            "package-lock.json",
            "--policy",
            policy_path()
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 policy path"))?,
            "--json",
        ])
        .current_dir(temp.path())
        .env("PATH", path)
        .env("TRACE_FILE", &trace)
        .output()?;

    assert_eq!(output.status.code(), Some(1));
    let calls = fs::read_to_string(trace)?;
    assert!(calls.lines().any(|line| line == "config get registry"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn npm_metadata_requests_deduplicate_identical_nested_pins() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir()?;
    let bin = temp.path().join("bin");
    let cache = temp.path().join("osv-cache");
    fs::create_dir_all(&bin)?;
    fs::create_dir_all(&cache)?;
    let trace = temp.path().join("npm-trace");
    let npm = bin.join("npm");
    let integrity = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode([0_u8; 64])
    );
    let registry_metadata = serde_json::json!({
        "dist": {
            "integrity": integrity.clone(),
            "tarball": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"
        },
        "time": "2020-01-01T00:00:00Z"
    });
    fs::write(
        &npm,
        format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> "$TRACE_FILE"
if [ "$1" = "config" ]; then
  printf 'https://registry.npmjs.org\n'
  exit 0
fi
if [ "$1" = "view" ]; then
  printf '%s\n' '{}'
  exit 0
fi
exit 1
"#,
            registry_metadata
        ),
    )?;
    fs::set_permissions(&npm, fs::Permissions::from_mode(0o755))?;
    let lock = temp.path().join("package-lock.json");
    fs::write(
        &lock,
        serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "fixture"},
                "node_modules/demo": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
                    "integrity": integrity.clone()
                },
                "node_modules/parent/node_modules/demo": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
                    "integrity": integrity
                }
            }
        })
        .to_string(),
    )?;
    let cache_key = "v2|npm|demo|1.0.0";
    fs::write(
        cache.join(format!("{}.json", hex::encode(Sha256::digest(cache_key)))),
        serde_json::json!({"fetched_at": chrono::Utc::now(), "findings": []}).to_string(),
    )?;
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = Command::new(env!("CARGO_BIN_EXE_supply-core"))
        .args([
            "scan-packages",
            "--npm-lock",
            lock.to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 lock path"))?,
            "--policy",
            policy_path()
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 policy path"))?,
            "--osv-cache",
            cache
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 cache path"))?,
            "--json",
        ])
        .env("PATH", path)
        .env("TRACE_FILE", &trace)
        .output()?;

    assert_eq!(output.status.code(), Some(0));
    let report: Report = serde_json::from_slice(&output.stdout)?;
    assert!(report.complete);
    assert_eq!(report.packages.len(), 1);
    let lookups = fs::read_to_string(trace)?
        .lines()
        .filter(|line| line.starts_with("view "))
        .count();
    assert_eq!(lookups, 1);
    Ok(())
}

#[cfg(unix)]
#[test]
fn npm_same_host_feeds_assess_their_own_publication_dates() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir()?;
    let bin = temp.path().join("bin");
    let cache = temp.path().join("osv-cache");
    let feed_one = temp.path().join("feed-one-root");
    let feed_two = temp.path().join("feed-two-root");
    fs::create_dir_all(&bin)?;
    fs::create_dir_all(&cache)?;
    fs::create_dir_all(&feed_one)?;
    fs::create_dir_all(&feed_two)?;
    let integrity = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode([0_u8; 64])
    );
    let old_metadata = serde_json::json!({
        "dist": {"integrity": integrity, "tarball": "https://npm.example/feed-one/demo/-/demo-1.0.0.tgz"},
        "time": "2020-01-01T00:00:00Z"
    });
    let recent_metadata = serde_json::json!({
        "dist": {"integrity": integrity, "tarball": "https://npm.example/feed-two/demo/-/demo-1.0.0.tgz"},
        "time": chrono::Utc::now().to_rfc3339()
    });
    let npm = bin.join("npm");
    fs::write(
        &npm,
        format!(
            r#"#!/bin/sh
if [ "$1" = "config" ]; then
  case "$PWD" in
    *feed-one-root*) printf '%s\n' 'https://npm.example/feed-one/' ;;
    *feed-two-root*) printf '%s\n' 'https://npm.example/feed-two/' ;;
  esac
  exit 0
fi
if [ "$1" = "view" ]; then
  case "$PWD" in
    *feed-one-root*) printf '%s\n' '{}' ;;
    *feed-two-root*) printf '%s\n' '{}' ;;
  esac
  exit 0
fi
exit 1
"#,
            old_metadata, recent_metadata
        ),
    )?;
    fs::set_permissions(&npm, fs::Permissions::from_mode(0o755))?;
    for (root, feed, integrity) in [
        (&feed_one, "feed-one", integrity.clone()),
        (&feed_two, "feed-two", integrity),
    ] {
        fs::write(
            root.join("package-lock.json"),
            serde_json::json!({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "fixture"},
                    "node_modules/demo": {
                        "version": "1.0.0",
                        "resolved": format!("https://npm.example/{feed}/demo/-/demo-1.0.0.tgz"),
                        "integrity": integrity
                    }
                }
            })
            .to_string(),
        )?;
    }
    let cache_key = "v2|npm|demo|1.0.0";
    fs::write(
        cache.join(format!("{}.json", hex::encode(Sha256::digest(cache_key)))),
        serde_json::json!({"fetched_at": chrono::Utc::now(), "findings": []}).to_string(),
    )?;
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_supply-core"))
        .args([
            "scan-packages",
            "--npm-lock",
            feed_one
                .join("package-lock.json")
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 first lock path"))?,
            "--npm-lock",
            feed_two
                .join("package-lock.json")
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 second lock path"))?,
            "--policy",
            policy_path()
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 policy path"))?,
            "--osv-cache",
            cache
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 cache path"))?,
            "--json",
        ])
        .current_dir(temp.path())
        .env("PATH", path)
        .output()?;

    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["complete"], true);
    let packages = report["packages"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("package report is missing"))?;
    assert_eq!(packages.len(), 2);
    let mut statuses = packages
        .iter()
        .map(|package| package["status"].as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    statuses.sort();
    assert_eq!(statuses, vec!["allow", "block"]);
    let mut sources = packages
        .iter()
        .map(|package| package["source"].as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    sources.sort();
    assert_eq!(
        sources,
        vec![
            "https://npm.example/feed-one/",
            "https://npm.example/feed-two/"
        ]
    );

    Ok(())
}

#[cfg(unix)]
#[test]
fn tampered_nuget_archive_with_recomputed_sidecar_is_rejected() -> anyhow::Result<()> {
    use std::{
        net::TcpListener,
        thread,
        time::{Duration, Instant},
    };

    let temp = tempdir()?;
    let (mut archive, payload_offset) = signed_test_nupkg()?;
    archive[payload_offset] ^= 1;
    let archive_hash = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&archive));
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let source = format!(
        "https://127.0.0.1:{}/v3/index.json",
        listener.local_addr()?.port()
    );
    let (connected_tx, connected_rx) = std::sync::mpsc::channel();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            match listener.accept() {
                Ok(_) => {
                    let _ = connected_tx.send(true);
                    return;
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                _ => {
                    let _ = connected_tx.send(false);
                    return;
                }
            }
        }
    });

    let expected_content_hash =
        "QTxE1Prpu+BbZeqkiC4RIVJDF/Q4Toxn2JuQg+yaEnLpmxrIkwj+HnKtrMoq554chPk1yuRkgkAB/H6dkeWi6g==";
    let package_dir = temp.path().join("nuget/locked.package/1.0.0");
    fs::create_dir_all(&package_dir)?;
    fs::write(package_dir.join("locked.package.1.0.0.nupkg"), archive)?;
    fs::write(
        package_dir.join("locked.package.1.0.0.nupkg.sha512"),
        archive_hash,
    )?;
    fs::write(
        package_dir.join(".nupkg.metadata"),
        serde_json::json!({
            "contentHash": expected_content_hash,
            "source": source
        })
        .to_string(),
    )?;
    let lock = temp.path().join("packages.lock.json");
    fs::write(
        &lock,
        serde_json::json!({
            "version": 2,
            "dependencies": {
                "net10.0": {
                    "Locked.Package": {
                        "type": "Direct",
                        "resolved": "1.0.0",
                        "contentHash": expected_content_hash
                    }
                }
            }
        })
        .to_string(),
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_supply-core"))
        .args([
            "scan-packages",
            "--nuget-lock",
            lock.to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 lock path"))?,
            "--nuget-packages",
            temp.path()
                .join("nuget")
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 cache path"))?,
            "--policy",
            policy_path()
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 policy path"))?,
            "--json",
        ])
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .output()?;

    let connected = connected_rx.recv_timeout(Duration::from_secs(1))?;
    server
        .join()
        .map_err(|_| anyhow::anyhow!("NuGet feed probe panicked"))?;
    assert!(
        !connected,
        "tampered package must fail before registry lookup"
    );
    assert_eq!(output.status.code(), Some(1));
    let report: Report = serde_json::from_slice(&output.stdout)?;
    assert!(!report.complete);
    assert!(report
        .errors
        .iter()
        .any(|error| error.contains("NuGet package bytes do not match lock contentHash")));
    Ok(())
}
