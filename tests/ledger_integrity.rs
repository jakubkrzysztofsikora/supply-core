use anyhow::Result;
use rusqlite::{params, Connection};
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};
use supply_core::application::ledger::{
    DiscoveredBody, LedgerEvent, LedgerEventDetails, LedgerIdentity, LedgerRecorder,
    LedgerSourceKind, PackageEvidence,
};
use supply_core::domain::Ecosystem;

fn ledger_with_entries() -> Result<(tempfile::TempDir, PathBuf)> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("ledger.sqlite");
    let recorder = LedgerRecorder::open(&database)?;
    for version in ["4.17.21", "4.17.20", "4.17.19", "4.17.18", "4.17.17"] {
        let event = LedgerEvent::new(
            "npm",
            LedgerIdentity {
                observation_id: Some(format!("integrity-{version}")),
                stage: Some("discovery".to_string()),
                ecosystem: Some(Ecosystem::Npm),
                name: Some("lodash".to_string()),
                version: Some(version.to_string()),
                artifact_identity: Some(format!("lodash-{version}.tgz")),
                generation: Some("1".to_string()),
                engine_policy_revision: Some("a".repeat(64)),
            },
            None,
            LedgerEventDetails::Discovered(DiscoveredBody {
                evidence: PackageEvidence {
                    source_kind: Some(LedgerSourceKind::Registry),
                    ..PackageEvidence::default()
                },
            }),
        )?;
        recorder.record_observation(&event, serde_json::json!({}))?;
    }
    drop(recorder);
    Ok((directory, database))
}

fn verify(database: &Path) -> Result<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_supply-core"))
        .args(["ledger", "verify", "--ledger-db"])
        .arg(database)
        .output()?)
}
fn verify_valid(database: &Path) -> Result<()> {
    let output = verify(database)?;
    assert!(
        output.status.success(),
        "ledger verify failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("integrity=valid tree_size=5"));
    Ok(())
}

#[test]
fn ledger_verify_rejects_a_tampered_root() -> Result<()> {
    let (_directory, database) = ledger_with_entries()?;
    verify_valid(&database)?;
    let connection = Connection::open(&database)?;
    connection.execute(
        "UPDATE ledger_state SET root = ?1 WHERE singleton = 1",
        params![vec![0u8; 32]],
    )?;
    drop(connection);

    let corrupted = verify(&database)?;
    assert!(!corrupted.status.success());
    Ok(())
}

#[test]
fn ledger_verify_rejects_a_tampered_merkle_node() -> Result<()> {
    let (_directory, database) = ledger_with_entries()?;
    verify_valid(&database)?;
    let connection = Connection::open(&database)?;
    connection.execute(
        "UPDATE ledger_nodes SET hash = ?1 WHERE level = 0 AND node_index = 0",
        params![vec![0u8; 32]],
    )?;
    drop(connection);

    let corrupted = verify(&database)?;
    assert!(!corrupted.status.success());
    Ok(())
}

#[test]
fn ledger_verify_rejects_a_tampered_upper_merkle_node() -> Result<()> {
    let (_directory, database) = ledger_with_entries()?;
    verify_valid(&database)?;
    let connection = Connection::open(&database)?;
    connection.execute(
        "UPDATE ledger_nodes SET hash = ?1 WHERE level = 2 AND node_index = 0",
        params![vec![0u8; 32]],
    )?;
    drop(connection);

    let corrupted = verify(&database)?;
    assert!(!corrupted.status.success());
    Ok(())
}

#[test]
fn ledger_verify_does_not_create_a_missing_database() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("missing.sqlite");

    let output = verify(&database)?;
    assert!(!output.status.success());
    assert!(!database.exists());
    Ok(())
}
#[test]
fn ledger_verify_does_not_change_an_existing_database() -> Result<()> {
    let (_directory, database) = ledger_with_entries()?;
    let connection = Connection::open(&database)?;
    let mode: String = connection.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
    assert_eq!(mode, "delete");
    drop(connection);
    let original = std::fs::read(&database)?;

    verify_valid(&database)?;

    assert_eq!(std::fs::read(&database)?, original);
    let connection = Connection::open(&database)?;
    let mode: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    assert_eq!(mode, "delete");
    Ok(())
}
