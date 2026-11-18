use crate::application::ledger::{
    LedgerEvent, LedgerEventDetails, RuleApprovedBody, SemanticLedgerEventBytes,
    LEDGER_EVENT_SCHEMA,
};
use anyhow::{ensure, Result};
use chrono::{DateTime, Utc};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path, time::Duration};

const PRIVATE_ENVELOPE_SCHEMA: &str = "supply-ledger.private-envelope.v1";
const MIN_SQLITE_VERSION: i32 = 3_051_003;
const MAX_PAGE_SIZE: usize = 1000;

#[cfg(unix)]
fn ensure_private_database_file(path: &Path, create: bool) -> Result<()> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    if create {
        options.create(true);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "ledger database must be a regular file");
    ensure!(
        metadata.permissions().mode() & 0o777 == 0o600,
        "ledger database must have mode 0600"
    );
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_database_file(path: &Path, create: bool) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true);
    if create {
        options.create(true);
    }
    ensure!(
        options.open(path)?.metadata()?.is_file(),
        "ledger database must be a regular file"
    );
    Ok(())
}

pub struct LedgerStore {
    connection: Connection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerOutboxJob {
    pub job_key: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerOutboxItem {
    pub job_key: String,
    pub event_position: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalLedgerHead {
    pub tree_size: u64,
    pub root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrivateEnvelopeBytes(Vec<u8>);

impl PrivateEnvelopeBytes {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the planned ledger replication endpoint"
    )
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LedgerReplicationEntry {
    pub(crate) position: u64,
    pub(crate) private_envelope: PrivateEnvelopeBytes,
    pub(crate) privacy_nonce: [u8; 16],
    pub(crate) leaf_hash: [u8; 32],
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the planned ledger replication endpoint"
    )
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LedgerReplicationPage {
    pub(crate) local_head: LocalLedgerHead,
    pub(crate) from: u64,
    pub(crate) upper_bound: u64,
    pub(crate) entries: Vec<LedgerReplicationEntry>,
}

#[derive(Serialize)]
struct PrivateLedgerEnvelope<'a> {
    schema: &'static str,
    event: &'a LedgerEvent,
    privacy_nonce: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateLedgerEnvelopeOwned {
    schema: String,
    event: LedgerEvent,
    privacy_nonce: String,
}

struct RawLedgerEntry {
    position: i64,
    event_id: String,
    private_envelope: Vec<u8>,
    semantic_payload: Vec<u8>,
    privacy_nonce: Vec<u8>,
    leaf_hash: Vec<u8>,
}

struct StoredLedgerEntry {
    position: u64,
    event: LedgerEvent,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "consumed by the planned ledger replication endpoint"
        )
    )]
    private_envelope: PrivateEnvelopeBytes,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "consumed by the planned ledger replication endpoint"
        )
    )]
    privacy_nonce: [u8; 16],
    leaf_hash: [u8; 32],
}

impl LedgerStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        verify_sqlite_version()?;
        ensure_private_database_file(path.as_ref(), true)?;
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        ensure!(
            journal_mode.eq_ignore_ascii_case("wal"),
            "SQLite WAL mode is required"
        );
        connection.execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")?;
        Self::initialize(connection)
    }

    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self> {
        verify_sqlite_version()?;
        ensure_private_database_file(path.as_ref(), false)?;
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA query_only=ON; PRAGMA foreign_keys=ON;")?;
        Ok(Self { connection })
    }

    pub fn open_in_memory() -> Result<Self> {
        verify_sqlite_version()?;
        let connection = Connection::open_in_memory()?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")?;
        Self::initialize(connection)
    }

    fn initialize(connection: Connection) -> Result<Self> {
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS ledger_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                tree_size INTEGER NOT NULL CHECK (tree_size >= 0),
                root BLOB NOT NULL CHECK (length(root) = 32)
            );
            CREATE TABLE IF NOT EXISTS ledger_events (
                position INTEGER PRIMARY KEY CHECK (position >= 0),
                event_id TEXT NOT NULL UNIQUE,
                private_envelope BLOB NOT NULL,
                semantic_payload BLOB NOT NULL,
                privacy_nonce BLOB NOT NULL CHECK (length(privacy_nonce) = 16),
                leaf_hash BLOB NOT NULL CHECK (length(leaf_hash) = 32)
            );
            CREATE TABLE IF NOT EXISTS ledger_nodes (
                level INTEGER NOT NULL CHECK (level >= 0),
                node_index INTEGER NOT NULL CHECK (node_index >= 0),
                hash BLOB NOT NULL CHECK (length(hash) = 32),
                PRIMARY KEY (level, node_index)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS ledger_outbox (
                job_key TEXT PRIMARY KEY,
                event_position INTEGER NOT NULL REFERENCES ledger_events(position),
                payload BLOB NOT NULL,
                delivered INTEGER NOT NULL DEFAULT 0 CHECK (delivered IN (0, 1))
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS ledger_outbox_pending
                ON ledger_outbox (delivered, event_position, job_key);
            CREATE TABLE IF NOT EXISTS rule_approvals (
                event_position INTEGER PRIMARY KEY REFERENCES ledger_events(position),
                artifact_sha256 TEXT NOT NULL CHECK (length(artifact_sha256) = 64),
                finding_id TEXT NOT NULL CHECK (length(finding_id) = 64),
                policy_sha256 TEXT NOT NULL CHECK (length(policy_sha256) = 64),
                expires_at_micros INTEGER NOT NULL
            ) WITHOUT ROWID;",
        )?;
        let empty_root = rfc6962_empty_root();
        connection.execute(
            "INSERT OR IGNORE INTO ledger_state (singleton, tree_size, root)
             VALUES (1, 0, ?1)",
            params![empty_root.as_slice()],
        )?;
        Ok(Self { connection })
    }

    pub fn append(&mut self, event: &LedgerEvent) -> Result<u64> {
        self.append_inner(event, None)
    }

    pub fn append_and_enqueue(
        &mut self,
        event: &LedgerEvent,
        job: &LedgerOutboxJob,
    ) -> Result<u64> {
        validate_job_key(&job.job_key)?;
        let payload = serde_json_canonicalizer::to_vec(&job.payload)?;
        self.append_inner(event, Some((&job.job_key, &payload)))
    }

    fn append_inner(&mut self, event: &LedgerEvent, job: Option<(&str, &[u8])>) -> Result<u64> {
        event.validate()?;
        let semantic_payload = event.semantic_payload()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(i64, Vec<u8>)> = transaction
            .query_row(
                "SELECT position, semantic_payload FROM ledger_events WHERE event_id = ?1",
                params![event.event_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let position = match existing {
            Some((position, stored_payload)) => {
                ensure!(
                    stored_payload.as_slice() == semantic_payload.as_bytes(),
                    "ledger event ID conflicts with stored semantic payload"
                );
                u64::try_from(position)?
            }
            None => append_new_event(&transaction, event, &semantic_payload)?,
        };
        if let LedgerEventDetails::RuleApproved(approval) = &event.body.details {
            index_rule_approval(&transaction, position, approval)?;
        }

        if let Some((job_key, payload)) = job {
            enqueue_job(&transaction, position, job_key, payload)?;
        }
        transaction.commit()?;
        Ok(position)
    }

    pub(crate) fn event_at(&self, position: u64) -> Result<Option<LedgerEvent>> {
        let entries = self.read_entries(position, 1)?;
        Ok(entries.into_iter().next().map(|entry| entry.event))
    }

    pub(crate) fn events_from(&self, from: u64, limit: usize) -> Result<Vec<LedgerEvent>> {
        Ok(self
            .read_entries(from, limit)?
            .into_iter()
            .map(|entry| entry.event)
            .collect())
    }

    pub fn local_head(&self) -> Result<LocalLedgerHead> {
        let (tree_size, root): (i64, Vec<u8>) = self.connection.query_row(
            "SELECT tree_size, root FROM ledger_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(LocalLedgerHead {
            tree_size: u64::try_from(tree_size)?,
            root: array_from_slice(&root, "stored root")?,
        })
    }
    pub fn verify_integrity(&self) -> Result<LocalLedgerHead> {
        let transaction = self.connection.unchecked_transaction()?;
        let mut statement = transaction.prepare(
            "SELECT position, event_id, private_envelope, semantic_payload, privacy_nonce, leaf_hash
             FROM ledger_events
             ORDER BY position",
        )?;
        let mut rows = statement.query([])?;
        let mut leaf_node_statement = transaction.prepare(
            "SELECT node_index, hash FROM ledger_nodes
             WHERE level = 0
             ORDER BY node_index",
        )?;
        let mut leaf_node_rows = leaf_node_statement.query([])?;
        let mut frontier = MerkleFrontier::default();
        while let Some(row) = rows.next()? {
            let entry = decode_entry(RawLedgerEntry {
                position: row.get(0)?,
                event_id: row.get(1)?,
                private_envelope: row.get(2)?,
                semantic_payload: row.get(3)?,
                privacy_nonce: row.get(4)?,
                leaf_hash: row.get(5)?,
            })?;
            ensure!(
                entry.position == frontier.size,
                "ledger event positions are not contiguous"
            );
            ensure!(
                next_tree_node(&mut leaf_node_rows, frontier.size)? == entry.leaf_hash,
                "persisted Merkle node hash is inconsistent"
            );
            frontier.push(entry.leaf_hash)?;
        }
        drop(rows);
        drop(statement);
        ensure!(
            leaf_node_rows.next()?.is_none(),
            "unexpected persisted Merkle node"
        );
        drop(leaf_node_rows);
        drop(leaf_node_statement);

        let head = self.local_head()?;
        ensure!(
            head.tree_size == frontier.size,
            "ledger state size does not match stored events"
        );
        ensure!(
            head.root == frontier.root(),
            "ledger state root does not match stored events"
        );
        self.verify_tree_nodes(frontier.size)?;
        transaction.commit()?;
        Ok(head)
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "consumed by the planned ledger replication endpoint"
        )
    )]
    pub(crate) fn replication_page(
        &self,
        from: u64,
        upper_bound: u64,
        limit: usize,
    ) -> Result<LedgerReplicationPage> {
        let limit = validate_page_size(limit)?;
        ensure!(
            from <= upper_bound,
            "replication page starts after upper bound"
        );
        let from_i64 = i64::try_from(from)?;
        let transaction = self.connection.unchecked_transaction()?;
        let (tree_size, root): (i64, Vec<u8>) = transaction.query_row(
            "SELECT tree_size, root FROM ledger_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let local_head = LocalLedgerHead {
            tree_size: u64::try_from(tree_size)?,
            root: array_from_slice(&root, "stored root")?,
        };
        ensure!(
            upper_bound <= local_head.tree_size,
            "replication upper bound exceeds local tree size"
        );

        let page_end = from
            .checked_add(u64::try_from(limit)?)
            .ok_or_else(|| anyhow::anyhow!("replication page range overflow"))?
            .min(upper_bound);
        let expected_count = usize::try_from(page_end - from)?;
        let raw_entries = if expected_count == 0 {
            Vec::new()
        } else {
            read_raw_entries(
                &transaction,
                from_i64,
                i64::try_from(page_end)?,
                i64::try_from(expected_count)?,
            )?
        };
        ensure!(
            raw_entries.len() == expected_count,
            "replication page contains a position gap"
        );
        let entries = raw_entries
            .into_iter()
            .enumerate()
            .map(|(offset, raw)| {
                let entry = decode_entry(raw)?;
                let expected_position = from
                    .checked_add(u64::try_from(offset)?)
                    .ok_or_else(|| anyhow::anyhow!("replication position overflow"))?;
                ensure!(
                    entry.position == expected_position,
                    "replication page positions are not contiguous"
                );
                Ok(LedgerReplicationEntry {
                    position: entry.position,
                    private_envelope: entry.private_envelope,
                    privacy_nonce: entry.privacy_nonce,
                    leaf_hash: entry.leaf_hash,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        transaction.commit()?;
        Ok(LedgerReplicationPage {
            local_head,
            from,
            upper_bound,
            entries,
        })
    }

    pub fn active_rule_approvals(
        &self,
        artifact_sha256: &str,
        policy_sha256: &str,
        now: DateTime<Utc>,
    ) -> Result<BTreeSet<String>> {
        let entries = {
            let mut statement = self.connection.prepare(
                "SELECT event_position, artifact_sha256, finding_id, policy_sha256,
                        expires_at_micros
                 FROM rule_approvals
                 WHERE artifact_sha256 = ?1 AND policy_sha256 = ?2
                 ORDER BY event_position",
            )?;
            let rows = statement.query_map(params![artifact_sha256, policy_sha256], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut finding_ids = BTreeSet::new();
        for (position, indexed_artifact, finding_id, indexed_policy, expires_at_micros) in entries {
            let event = self
                .event_at(u64::try_from(position)?)?
                .ok_or_else(|| anyhow::anyhow!("rule approval event is missing"))?;
            let LedgerEventDetails::RuleApproved(approval) = event.body.details else {
                anyhow::bail!("rule approval index references a non-approval event");
            };
            ensure!(
                approval.artifact_sha256 == indexed_artifact
                    && approval.finding_id == finding_id
                    && approval.policy_sha256 == indexed_policy
                    && approval.expires_at.timestamp_micros() == expires_at_micros,
                "rule approval index does not match ledger event"
            );
            if expires_at_micros > now.timestamp_micros() {
                finding_ids.insert(finding_id);
            }
        }
        Ok(finding_ids)
    }

    pub fn pending_jobs(&self, limit: usize) -> Result<Vec<LedgerOutboxItem>> {
        let limit = validate_page_size(limit)?;
        let mut statement = self.connection.prepare(
            "SELECT job_key, event_position, payload
             FROM ledger_outbox
             WHERE delivered = 0
             ORDER BY event_position, job_key
             LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        rows.map(|row| {
            let (job_key, event_position, payload) = row?;
            Ok(LedgerOutboxItem {
                job_key,
                event_position: u64::try_from(event_position)?,
                payload,
            })
        })
        .collect()
    }

    pub fn mark_job_delivered(&mut self, job_key: &str) -> Result<bool> {
        let changed = self.connection.execute(
            "UPDATE ledger_outbox SET delivered = 1 WHERE job_key = ?1 AND delivered = 0",
            params![job_key],
        )?;
        Ok(changed == 1)
    }

    fn read_entries(&self, from: u64, limit: usize) -> Result<Vec<StoredLedgerEntry>> {
        let limit = validate_page_size(limit)?;
        let raw_entries =
            read_raw_entries(&self.connection, i64::try_from(from)?, i64::MAX, limit)?;
        raw_entries.into_iter().map(decode_entry).collect()
    }
    fn verify_tree_nodes(&self, tree_size: u64) -> Result<()> {
        let mut level = 1u64;
        let mut child_count = tree_size;
        while child_count >= 2 {
            let node_count = child_count / 2;
            self.verify_tree_level(level, child_count, node_count)?;
            child_count = node_count;
            level = level
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("Merkle level overflow"))?;
        }

        let unexpected_level: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM ledger_nodes WHERE level < 0 OR level >= ?1)",
            params![i64::try_from(level)?],
            |row| row.get(0),
        )?;
        ensure!(!unexpected_level, "unexpected persisted Merkle node level");
        Ok(())
    }

    fn verify_tree_level(&self, level: u64, child_count: u64, node_count: u64) -> Result<()> {
        ensure!(
            node_count == child_count / 2,
            "invalid Merkle verification level"
        );
        let child_level = level
            .checked_sub(1)
            .ok_or_else(|| anyhow::anyhow!("invalid Merkle verification level"))?;
        let mut child_statement = self.connection.prepare(
            "SELECT node_index, hash FROM ledger_nodes
             WHERE level = ?1
             ORDER BY node_index",
        )?;
        let mut child_rows = child_statement.query(params![i64::try_from(child_level)?])?;
        let mut parent_statement = self.connection.prepare(
            "SELECT node_index, hash FROM ledger_nodes
             WHERE level = ?1
             ORDER BY node_index",
        )?;
        let mut parent_rows = parent_statement.query(params![i64::try_from(level)?])?;

        for parent_index in 0..node_count {
            let left_index = parent_index
                .checked_mul(2)
                .ok_or_else(|| anyhow::anyhow!("Merkle node index overflow"))?;
            let right_index = left_index
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("Merkle node index overflow"))?;
            let left_hash = next_tree_node(&mut child_rows, left_index)?;
            let right_hash = next_tree_node(&mut child_rows, right_index)?;
            let expected_hash = rfc6962_node_hash(&left_hash, &right_hash);
            ensure!(
                next_tree_node(&mut parent_rows, parent_index)? == expected_hash,
                "persisted Merkle node hash is inconsistent"
            );
        }

        if child_count & 1 == 1 {
            let last_child_index = node_count
                .checked_mul(2)
                .ok_or_else(|| anyhow::anyhow!("Merkle node index overflow"))?;
            next_tree_node(&mut child_rows, last_child_index)?;
        }
        ensure!(
            child_rows.next()?.is_none(),
            "unexpected persisted Merkle node"
        );
        ensure!(
            parent_rows.next()?.is_none(),
            "unexpected persisted Merkle node"
        );
        Ok(())
    }
}

fn index_rule_approval(
    transaction: &Transaction<'_>,
    position: u64,
    approval: &RuleApprovedBody,
) -> Result<()> {
    let position = i64::try_from(position)?;
    let expires_at_micros = approval.expires_at.timestamp_micros();
    transaction.execute(
        "INSERT OR IGNORE INTO rule_approvals
            (event_position, artifact_sha256, finding_id, policy_sha256, expires_at_micros)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            position,
            approval.artifact_sha256,
            approval.finding_id,
            approval.policy_sha256,
            expires_at_micros
        ],
    )?;
    let stored: (String, String, String, i64) = transaction.query_row(
        "SELECT artifact_sha256, finding_id, policy_sha256, expires_at_micros
         FROM rule_approvals WHERE event_position = ?1",
        params![position],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    ensure!(
        stored
            == (
                approval.artifact_sha256.clone(),
                approval.finding_id.clone(),
                approval.policy_sha256.clone(),
                expires_at_micros,
            ),
        "stored rule approval index conflicts with ledger event"
    );
    Ok(())
}

fn next_tree_node(rows: &mut rusqlite::Rows<'_>, expected_index: u64) -> Result<[u8; 32]> {
    let row = rows
        .next()?
        .ok_or_else(|| anyhow::anyhow!("missing persisted Merkle node"))?;
    ensure!(
        row.get::<_, i64>(0)? == i64::try_from(expected_index)?,
        "persisted Merkle node position is inconsistent"
    );
    let hash: Vec<u8> = row.get(1)?;
    array_from_slice(&hash, "Merkle node")
}

fn read_raw_entries(
    connection: &Connection,
    from: i64,
    upper_bound: i64,
    limit: i64,
) -> Result<Vec<RawLedgerEntry>> {
    let mut statement = connection.prepare(
        "SELECT position, event_id, private_envelope, semantic_payload, privacy_nonce, leaf_hash
         FROM ledger_events
         WHERE position >= ?1 AND position < ?2
         ORDER BY position
         LIMIT ?3",
    )?;
    let rows = statement.query_map(params![from, upper_bound, limit], |row| {
        Ok(RawLedgerEntry {
            position: row.get(0)?,
            event_id: row.get(1)?,
            private_envelope: row.get(2)?,
            semantic_payload: row.get(3)?,
            privacy_nonce: row.get(4)?,
            leaf_hash: row.get(5)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn verify_sqlite_version() -> Result<()> {
    ensure!(
        rusqlite::version_number() >= MIN_SQLITE_VERSION,
        "SQLite 3.51.3 or newer is required"
    );
    Ok(())
}

fn append_new_event(
    transaction: &Transaction<'_>,
    event: &LedgerEvent,
    semantic_payload: &SemanticLedgerEventBytes,
) -> Result<u64> {
    let tree_size: i64 = transaction.query_row(
        "SELECT tree_size FROM ledger_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let position = u64::try_from(tree_size)?;
    let new_size = position
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("ledger tree size overflow"))?;
    let mut privacy_nonce = [0; 16];
    getrandom::fill(&mut privacy_nonce)?;
    let sequenced_event = event.sequenced_at(Utc::now())?;
    let private_envelope =
        PrivateEnvelopeBytes(serde_json_canonicalizer::to_vec(&PrivateLedgerEnvelope {
            schema: PRIVATE_ENVELOPE_SCHEMA,
            event: &sequenced_event,
            privacy_nonce: hex::encode(privacy_nonce),
        })?);
    let leaf_hash = rfc6962_leaf_hash(&private_envelope);

    transaction.execute(
        "INSERT INTO ledger_events
            (position, event_id, private_envelope, semantic_payload, privacy_nonce, leaf_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            tree_size,
            event.event_id,
            private_envelope.as_bytes(),
            semantic_payload.as_bytes(),
            privacy_nonce.as_slice(),
            leaf_hash.as_slice()
        ],
    )?;
    persist_tree_nodes(transaction, position, &leaf_hash)?;
    let root = merkle_root(transaction, new_size)?;
    transaction.execute(
        "UPDATE ledger_state SET tree_size = ?1, root = ?2 WHERE singleton = 1",
        params![i64::try_from(new_size)?, root.as_slice()],
    )?;
    Ok(position)
}

fn enqueue_job(
    transaction: &Transaction<'_>,
    event_position: u64,
    job_key: &str,
    payload: &[u8],
) -> Result<()> {
    let event_position = i64::try_from(event_position)?;
    let existing: Option<(i64, Vec<u8>)> = transaction
        .query_row(
            "SELECT event_position, payload FROM ledger_outbox WHERE job_key = ?1",
            params![job_key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((stored_position, stored_payload)) = existing {
        ensure!(
            stored_position == event_position && stored_payload == payload,
            "outbox job key conflicts with stored job"
        );
        return Ok(());
    }
    transaction.execute(
        "INSERT INTO ledger_outbox (job_key, event_position, payload)
         VALUES (?1, ?2, ?3)",
        params![job_key, event_position, payload],
    )?;
    Ok(())
}

fn persist_tree_nodes(
    transaction: &Transaction<'_>,
    position: u64,
    leaf_hash: &[u8; 32],
) -> Result<()> {
    transaction.execute(
        "INSERT INTO ledger_nodes (level, node_index, hash) VALUES (0, ?1, ?2)",
        params![i64::try_from(position)?, leaf_hash.as_slice()],
    )?;

    let mut node_index = position;
    let mut level = 0i64;
    let mut current_hash = *leaf_hash;
    while node_index & 1 == 1 {
        let left_hash = node_hash_at(transaction, level, node_index - 1)?;
        current_hash = rfc6962_node_hash(&left_hash, &current_hash);
        node_index /= 2;
        level += 1;
        transaction.execute(
            "INSERT INTO ledger_nodes (level, node_index, hash) VALUES (?1, ?2, ?3)",
            params![level, i64::try_from(node_index)?, current_hash.as_slice()],
        )?;
    }
    Ok(())
}

fn merkle_root(transaction: &Transaction<'_>, size: u64) -> Result<[u8; 32]> {
    if size == 0 {
        return Ok(rfc6962_empty_root());
    }
    merkle_root_range(transaction, 0, size)
}

fn merkle_root_range(transaction: &Transaction<'_>, start: u64, size: u64) -> Result<[u8; 32]> {
    if size.is_power_of_two() {
        return node_hash_at(
            transaction,
            i64::from(size.trailing_zeros()),
            start
                .checked_div(size)
                .ok_or_else(|| anyhow::anyhow!("invalid empty Merkle range"))?,
        );
    }
    let left_size = 1u64 << (63 - size.leading_zeros());
    let left = merkle_root_range(transaction, start, left_size)?;
    let right_start = start
        .checked_add(left_size)
        .ok_or_else(|| anyhow::anyhow!("Merkle range overflow"))?;
    let right = merkle_root_range(transaction, right_start, size - left_size)?;
    Ok(rfc6962_node_hash(&left, &right))
}

fn node_hash_at(transaction: &Transaction<'_>, level: i64, node_index: u64) -> Result<[u8; 32]> {
    let node_index = i64::try_from(node_index)?;
    let hash: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT hash FROM ledger_nodes WHERE level = ?1 AND node_index = ?2",
            params![level, node_index],
            |row| row.get(0),
        )
        .optional()?;
    let hash = hash.ok_or_else(|| anyhow::anyhow!("missing persisted Merkle node"))?;
    array_from_slice(&hash, "Merkle node")
}

fn decode_entry(raw: RawLedgerEntry) -> Result<StoredLedgerEntry> {
    let envelope: PrivateLedgerEnvelopeOwned = serde_json::from_slice(&raw.private_envelope)?;
    ensure!(
        envelope.schema == PRIVATE_ENVELOPE_SCHEMA,
        "unsupported private ledger envelope schema"
    );
    ensure!(
        serde_json_canonicalizer::to_vec(&envelope)? == raw.private_envelope,
        "stored private ledger envelope is not canonical JCS"
    );
    envelope.event.validate_committed()?;
    ensure!(
        envelope.event.schema == LEDGER_EVENT_SCHEMA && envelope.event.event_id == raw.event_id,
        "stored ledger event identity is inconsistent"
    );
    ensure!(
        envelope.event.semantic_payload()?.as_bytes() == raw.semantic_payload.as_slice(),
        "stored ledger semantic payload is inconsistent"
    );
    let nonce_bytes = hex::decode(&envelope.privacy_nonce)?;
    let privacy_nonce: [u8; 16] = array_from_slice(&nonce_bytes, "privacy nonce")?;
    ensure!(
        hex::encode(privacy_nonce) == envelope.privacy_nonce,
        "privacy nonce must use lowercase hexadecimal"
    );
    ensure!(
        privacy_nonce.as_slice() == raw.privacy_nonce.as_slice(),
        "stored privacy nonce is inconsistent"
    );
    let private_envelope = PrivateEnvelopeBytes(raw.private_envelope);
    let leaf_hash = array_from_slice(&raw.leaf_hash, "leaf hash")?;
    ensure!(
        rfc6962_leaf_hash(&private_envelope) == leaf_hash,
        "stored leaf hash is inconsistent"
    );
    Ok(StoredLedgerEntry {
        position: u64::try_from(raw.position)?,
        event: envelope.event,
        private_envelope,
        privacy_nonce,
        leaf_hash,
    })
}

fn validate_job_key(job_key: &str) -> Result<()> {
    ensure!(
        !job_key.is_empty() && job_key.len() <= 512 && !job_key.chars().any(char::is_control),
        "invalid outbox job key"
    );
    Ok(())
}

fn validate_page_size(limit: usize) -> Result<i64> {
    ensure!(
        (1..=MAX_PAGE_SIZE).contains(&limit),
        "ledger page size must be between 1 and 1000"
    );
    Ok(i64::try_from(limit)?)
}

fn array_from_slice<const N: usize>(bytes: &[u8], field: &str) -> Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field} must contain exactly {N} bytes"))
}

fn rfc6962_empty_root() -> [u8; 32] {
    Sha256::digest([]).into()
}

fn rfc6962_leaf_hash(data: &PrivateEnvelopeBytes) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update([0]);
    hash.update(data.as_bytes());
    hash.finalize().into()
}

fn rfc6962_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update([1]);
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
}

#[cfg(test)]
fn rfc6962_root(leaf_hashes: &[[u8; 32]]) -> [u8; 32] {
    match leaf_hashes.len() {
        0 => rfc6962_empty_root(),
        1 => leaf_hashes[0],
        size => {
            let left_size = 1usize << (usize::BITS - 1 - (size - 1).leading_zeros());
            rfc6962_node_hash(
                &rfc6962_root(&leaf_hashes[..left_size]),
                &rfc6962_root(&leaf_hashes[left_size..]),
            )
        }
    }
}

#[derive(Default)]
struct MerkleFrontier {
    levels: Vec<Option<[u8; 32]>>,
    size: u64,
}

impl MerkleFrontier {
    fn push(&mut self, mut hash: [u8; 32]) -> Result<()> {
        let mut position = self.size;
        let mut level = 0usize;
        while position & 1 == 1 {
            let left_hash = self
                .levels
                .get_mut(level)
                .and_then(Option::take)
                .ok_or_else(|| anyhow::anyhow!("incomplete Merkle frontier"))?;
            hash = rfc6962_node_hash(&left_hash, &hash);
            position >>= 1;
            level += 1;
        }
        if self.levels.len() <= level {
            self.levels.resize(level + 1, None);
        }
        ensure!(
            self.levels[level].is_none(),
            "Merkle frontier level is occupied"
        );
        self.levels[level] = Some(hash);
        self.size = self
            .size
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("ledger tree size overflow"))?;
        Ok(())
    }

    fn root(&self) -> [u8; 32] {
        let mut root = None;
        for subtree in self.levels.iter().flatten() {
            root = Some(match root {
                Some(right_subtree) => rfc6962_node_hash(subtree, &right_subtree),
                None => *subtree,
            });
        }
        root.unwrap_or_else(rfc6962_empty_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        application::ledger::{
            DiscoveredBody, LedgerEvent, LedgerEventDetails, LedgerIdentity, PackageEvidence,
        },
        domain::Ecosystem,
    };
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    fn event(observation_id: &str) -> Result<LedgerEvent> {
        LedgerEvent::new(
            "npm",
            LedgerIdentity {
                observation_id: Some(observation_id.to_string()),
                stage: Some("discovery".to_string()),
                ecosystem: Some(Ecosystem::Npm),
                name: Some("lodash".to_string()),
                version: Some("4.17.21".to_string()),
                artifact_identity: Some("lodash-4.17.21.tgz".to_string()),
                generation: Some("1".to_string()),
                engine_policy_revision: Some("a".repeat(64)),
            },
            None,
            LedgerEventDetails::Discovered(DiscoveredBody {
                evidence: PackageEvidence {
                    source_kind: Some(crate::application::ledger::LedgerSourceKind::Registry),
                    ..PackageEvidence::default()
                },
            }),
        )
    }

    fn leaf_hash(bytes: &[u8]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update([0]);
        hash.update(bytes);
        hash.finalize().into()
    }

    fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update([1]);
        hash.update(left);
        hash.update(right);
        hash.finalize().into()
    }

    #[test]
    fn rfc6962_hash_vectors_and_c2sp_root_encoding_are_stable() -> Result<()> {
        assert_eq!(
            hex::encode(rfc6962_empty_root()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex::encode(rfc6962_leaf_hash(&PrivateEnvelopeBytes(Vec::new()))),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
        let c2sp_root = "CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=";
        let decoded = STANDARD.decode(c2sp_root)?;
        assert_eq!(decoded.len(), 32);
        assert_eq!(STANDARD.encode(decoded), c2sp_root);
        Ok(())
    }

    #[test]
    fn file_store_requires_wal_full_sync_and_supported_sqlite() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = LedgerStore::open(directory.path().join("ledger.sqlite"))?;
        let journal_mode: String =
            store
                .connection
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        let synchronous: i64 = store
            .connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))?;
        assert_eq!(journal_mode, "wal");
        assert_eq!(synchronous, 2);
        Ok(())
    }

    #[test]
    fn local_head_returns_size_and_root_together() -> Result<()> {
        let store = LedgerStore::open_in_memory()?;
        let head = store.local_head()?;
        assert_eq!(head.tree_size, 0);
        let empty_root: [u8; 32] = Sha256::digest([]).into();
        assert_eq!(head.root, empty_root);
        Ok(())
    }

    #[test]
    fn replication_pages_stay_within_pinned_bound_and_are_contiguous() -> Result<()> {
        let mut store = LedgerStore::open_in_memory()?;
        store.append(&event("registry-revision-1")?)?;
        store.append(&event("registry-revision-2")?)?;
        store.append(&event("registry-revision-3")?)?;

        let first_page = store.replication_page(0, 2, 1)?;
        assert_eq!(first_page.local_head.tree_size, 3);
        assert_eq!(first_page.from, 0);
        assert_eq!(first_page.upper_bound, 2);
        assert_eq!(first_page.entries.len(), 1);
        assert_eq!(first_page.entries[0].position, 0);

        let second_page = store.replication_page(1, 2, 10)?;
        assert_eq!(
            second_page
                .entries
                .iter()
                .map(|entry| entry.position)
                .collect::<Vec<_>>(),
            vec![1]
        );
        assert!(store.replication_page(2, 2, 10)?.entries.is_empty());
        assert!(store.replication_page(0, 4, 10).is_err());
        store
            .connection
            .execute("DELETE FROM ledger_events WHERE position = 1", [])?;
        assert!(store.replication_page(0, 2, 2).is_err());
        Ok(())
    }

    #[test]
    fn replay_rejects_committed_envelopes_without_recorded_at() -> Result<()> {
        let event = event("registry-revision-1")?;
        let privacy_nonce = [7; 16];
        let private_envelope = serde_json_canonicalizer::to_vec(&PrivateLedgerEnvelope {
            schema: PRIVATE_ENVELOPE_SCHEMA,
            event: &event,
            privacy_nonce: hex::encode(privacy_nonce),
        })?;
        let semantic_payload = event.semantic_payload()?.as_bytes().to_vec();
        let raw = RawLedgerEntry {
            position: 0,
            event_id: event.event_id.clone(),
            private_envelope: private_envelope.clone(),
            semantic_payload,
            privacy_nonce: privacy_nonce.to_vec(),
            leaf_hash: leaf_hash(&private_envelope).to_vec(),
        };
        assert!(decode_entry(raw).is_err());
        Ok(())
    }

    #[test]
    fn append_deduplicates_before_assigning_time_and_nonce() -> Result<()> {
        let mut store = LedgerStore::open_in_memory()?;
        let event = event("registry-revision-1")?;
        assert_eq!(store.append(&event)?, 0);
        let original = store.replication_page(0, 1, 1)?;
        assert_eq!(store.append(&event)?, 0);
        let replayed = store.replication_page(0, 1, 1)?;
        assert_eq!(
            original.entries[0].private_envelope,
            replayed.entries[0].private_envelope
        );
        assert_eq!(
            original.entries[0].privacy_nonce,
            replayed.entries[0].privacy_nonce
        );
        assert!(store
            .event_at(0)?
            .ok_or_else(|| anyhow::anyhow!("missing event"))?
            .recorded_at
            .is_some());
        assert_eq!(store.events_from(0, 10)?.len(), 1);
        Ok(())
    }

    #[test]
    fn conflicting_semantic_payload_for_same_event_id_fails() -> Result<()> {
        let mut store = LedgerStore::open_in_memory()?;
        let original = event("registry-revision-1")?;
        store.append(&original)?;
        let mut conflicting = original.clone();
        if let LedgerEventDetails::Discovered(body) = &mut conflicting.body.details {
            body.evidence.artifact_filename = Some("different.tgz".to_string());
        }
        assert_eq!(original.event_id, conflicting.event_id);
        assert!(store.append(&conflicting).is_err());
        assert_eq!(store.events_from(0, 10)?.len(), 1);
        Ok(())
    }

    #[test]
    fn append_assigns_zero_based_positions_and_rfc6962_roots() -> Result<()> {
        let mut store = LedgerStore::open_in_memory()?;
        let empty_root: [u8; 32] = Sha256::digest([]).into();
        assert_eq!(store.local_head()?.root, empty_root);

        let first = event("registry-revision-1")?;
        let second = event("registry-revision-2")?;
        let third = event("registry-revision-3")?;
        assert_eq!(store.append(&first)?, 0);
        let first_page = store.replication_page(0, 1, 1)?;
        assert_eq!(store.local_head()?.root, first_page.entries[0].leaf_hash);
        assert_eq!(
            first_page.entries[0].leaf_hash,
            leaf_hash(first_page.entries[0].private_envelope.as_bytes())
        );

        assert_eq!(store.append(&second)?, 1);
        assert_eq!(store.append(&third)?, 2);
        let page = store.replication_page(0, 3, 3)?;
        let entries = page.entries;
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.position)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        for entry in &entries {
            assert_eq!(
                entry.leaf_hash,
                *sigstore_merkle::hash_leaf(entry.private_envelope.as_bytes()).as_bytes()
            );
        }
        let left = node_hash(&entries[0].leaf_hash, &entries[1].leaf_hash);
        let expected_root = node_hash(&left, &entries[2].leaf_hash);
        let sigstore_left = sigstore_merkle::hash_children(
            &sigstore_merkle::hash_leaf(entries[0].private_envelope.as_bytes()),
            &sigstore_merkle::hash_leaf(entries[1].private_envelope.as_bytes()),
        );
        let sigstore_root = sigstore_merkle::hash_children(
            &sigstore_left,
            &sigstore_merkle::hash_leaf(entries[2].private_envelope.as_bytes()),
        );
        assert_eq!(store.local_head()?.root, expected_root);
        assert_eq!(store.local_head()?.root, *sigstore_root.as_bytes());
        Ok(())
    }

    #[test]
    fn merkle_frontier_matches_rfc6962_roots_for_uneven_sizes() -> Result<()> {
        let leaves: Vec<[u8; 32]> = (0..=128u64)
            .map(|index| Sha256::digest(index.to_be_bytes()).into())
            .collect();
        for size in 0..=leaves.len() {
            let mut frontier = MerkleFrontier::default();
            for leaf in &leaves[..size] {
                frontier.push(*leaf)?;
            }
            assert_eq!(frontier.size, size as u64);
            assert_eq!(frontier.root(), rfc6962_root(&leaves[..size]));
        }
        Ok(())
    }

    #[test]
    fn integrity_check_handles_empty_singleton_and_uneven_tree_sizes() -> Result<()> {
        let mut store = LedgerStore::open_in_memory()?;
        assert_eq!(store.verify_integrity()?.tree_size, 0);

        for size in 1..=17u64 {
            let ledger_event = event(&format!("integrity-shape-{size}"))?;
            store.append(&ledger_event)?;
            assert_eq!(store.verify_integrity()?.tree_size, size);
        }
        Ok(())
    }

    #[test]
    fn privacy_nonce_is_random_private_and_bound_into_leaf_bytes() -> Result<()> {
        let mut store = LedgerStore::open_in_memory()?;
        store.append(&event("registry-revision-1")?)?;
        store.append(&event("registry-revision-2")?)?;
        let entries = store.replication_page(0, 2, 2)?.entries;
        let replayed = store.replication_page(0, 2, 2)?.entries;
        assert_ne!(entries[0].privacy_nonce, entries[1].privacy_nonce);
        assert_eq!(entries[0].privacy_nonce, replayed[0].privacy_nonce);
        let nonce_hex = hex::encode(entries[0].privacy_nonce);
        let envelope: serde_json::Value =
            serde_json::from_slice(entries[0].private_envelope.as_bytes())?;
        assert_eq!(envelope["privacy_nonce"], nonce_hex);
        assert_eq!(
            entries[0].leaf_hash,
            leaf_hash(entries[0].private_envelope.as_bytes())
        );
        let public_event = store
            .event_at(0)?
            .ok_or_else(|| anyhow::anyhow!("missing event"))?;
        let public_bytes = public_event.public_projection()?.to_jcs()?;
        let public_text = std::str::from_utf8(&public_bytes)?;
        assert!(!public_text.contains(&nonce_hex));
        assert!(!public_text.contains(&public_event.event_id));
        Ok(())
    }

    #[test]
    fn append_and_enqueue_commits_atomically_and_is_idempotent() -> Result<()> {
        let mut store = LedgerStore::open_in_memory()?;
        let first = event("registry-revision-1")?;
        let job = LedgerOutboxJob {
            job_key: "scan:lodash:4.17.21:1".to_string(),
            payload: json!({"ecosystem": "npm", "name": "lodash", "version": "4.17.21"}),
        };
        assert_eq!(store.append_and_enqueue(&first, &job)?, 0);
        assert_eq!(store.append_and_enqueue(&first, &job)?, 0);
        let pending = store.pending_jobs(10)?;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].job_key, job.job_key);
        assert_eq!(
            pending[0].payload,
            serde_json_canonicalizer::to_vec(&job.payload)?
        );

        let root_before_conflict = store.local_head()?.root;
        let conflicting_job = LedgerOutboxJob {
            job_key: job.job_key,
            payload: json!({"version": "different"}),
        };
        assert!(store
            .append_and_enqueue(&event("registry-revision-2")?, &conflicting_job)
            .is_err());
        assert_eq!(store.events_from(0, 10)?.len(), 1);
        assert_eq!(store.local_head()?.root, root_before_conflict);
        assert!(store.mark_job_delivered(&pending[0].job_key)?);
        assert!(store.pending_jobs(10)?.is_empty());
        Ok(())
    }
}
#[cfg(test)]
mod approval_schema_tests {
    use super::*;
    use rusqlite::OptionalExtension;

    #[test]
    fn approval_index_table_is_initialized() -> Result<()> {
        let store = LedgerStore::open_in_memory()?;
        let table = store
            .connection
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'rule_approvals'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;

        assert_eq!(table, Some(1));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn ledger_file_is_private_and_broad_existing_file_is_refused() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let private_path = directory.path().join("private.sqlite");
        let store = LedgerStore::open(&private_path)?;
        drop(store);
        assert_eq!(
            std::fs::metadata(&private_path)?.permissions().mode() & 0o777,
            0o600
        );

        let broad_path = directory.path().join("broad.sqlite");
        std::fs::write(&broad_path, [])?;
        std::fs::set_permissions(&broad_path, std::fs::Permissions::from_mode(0o644))?;
        assert!(LedgerStore::open(&broad_path).is_err());
        assert_eq!(
            std::fs::metadata(&broad_path)?.permissions().mode() & 0o777,
            0o644
        );
        Ok(())
    }
    #[test]
    fn approval_index_requires_exact_key_and_unexpired_ledger_event() -> Result<()> {
        let mut store = LedgerStore::open_in_memory()?;
        let now = Utc::now();
        let artifact_sha256 = "a".repeat(64);
        let finding_id = "b".repeat(64);
        let policy_sha256 = "c".repeat(64);
        let approval_event = |observation_id: &str, expires_at| {
            LedgerEvent::new(
                "operator",
                crate::application::ledger::LedgerIdentity {
                    observation_id: Some(observation_id.to_string()),
                    engine_policy_revision: Some(policy_sha256.clone()),
                    ..crate::application::ledger::LedgerIdentity::default()
                },
                Some(now),
                LedgerEventDetails::RuleApproved(RuleApprovedBody {
                    artifact_sha256: artifact_sha256.clone(),
                    finding_id: finding_id.clone(),
                    policy_sha256: policy_sha256.clone(),
                    expires_at,
                    reason: "reviewed".to_string(),
                }),
            )
        };
        store.append(&approval_event(
            "active-rule",
            now + chrono::Duration::minutes(1),
        )?)?;
        store.append(&approval_event(
            "expired-rule",
            now - chrono::Duration::seconds(1),
        )?)?;

        assert_eq!(
            store.active_rule_approvals(&artifact_sha256, &policy_sha256, now)?,
            BTreeSet::from([finding_id.clone()])
        );
        assert!(store
            .active_rule_approvals(&"d".repeat(64), &policy_sha256, now)?
            .is_empty());
        assert!(store
            .active_rule_approvals(&artifact_sha256, &"e".repeat(64), now)?
            .is_empty());

        store.connection.execute(
            "UPDATE rule_approvals SET finding_id = ?1 WHERE event_position = 0",
            params!["f".repeat(64)],
        )?;
        assert!(store
            .active_rule_approvals(&artifact_sha256, &policy_sha256, now)
            .is_err());
        Ok(())
    }
}
