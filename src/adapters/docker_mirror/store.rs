use super::graph::{Object, Verdict};
use super::{digest, valid_digest, MirrorError, Result};
use anyhow::{ensure, Context};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

const MAX_CACHE_BYTES: i64 = 20 * 1024 * 1024 * 1024;
const SCAN_TTL_SECONDS: i64 = 24 * 60 * 60;
pub(super) const MAX_METADATA_IMAGES: i64 = 4096;
pub(super) const MAX_METADATA_TAGS: i64 = 8192;
pub(super) const METADATA_RETENTION_SECONDS: i64 = 90 * 24 * 60 * 60;
const IMAGE_PENDING: i64 = 0;
const IMAGE_SCANNED: i64 = 1;
const IMAGE_EVICTED: i64 = 2;
const IMAGE_LEGACY_UNCACHED: i64 = 3;

pub(super) struct Store {
    db: Mutex<Connection>,
    dir: PathBuf,
    _lock: File,
}

pub(super) struct Release {
    pub directory: PathBuf,
    pub object: Object,
}

impl Store {
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        fs::create_dir_all(dir)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("lock"))?;
        lock.try_lock()
            .context("Docker mirror cache already in use")?;
        let db = Connection::open(dir.join("state.db"))?;
        db.execute_batch(
            "
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS images (
                repository TEXT NOT NULL,
                digest TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                cache_key TEXT UNIQUE,
                size INTEGER NOT NULL DEFAULT 0,
                scanned_at INTEGER,
                policy TEXT,
                vulnerable INTEGER,
                scan_state INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (repository, digest)
            );
            CREATE TABLE IF NOT EXISTS objects (
                cache_key TEXT NOT NULL REFERENCES images(cache_key) ON DELETE CASCADE,
                digest TEXT NOT NULL,
                manifest INTEGER NOT NULL,
                media_type TEXT NOT NULL,
                size INTEGER NOT NULL,
                PRIMARY KEY (cache_key, digest)
            );
            CREATE INDEX IF NOT EXISTS objects_digest ON objects (digest, manifest);
            CREATE TABLE IF NOT EXISTS tags (
                repository TEXT NOT NULL,
                tag TEXT NOT NULL,
                digest TEXT NOT NULL,
                PRIMARY KEY (repository, tag)
            );
        ",
        )?;
        let has_scan_state = {
            let mut statement = db.prepare("PRAGMA table_info(images)")?;
            let mut rows = statement.query([])?;
            let mut found = false;
            while let Some(row) = rows.next()? {
                if row.get_ref(1)?.as_str()? == "scan_state" {
                    found = true;
                    break;
                }
            }
            found
        };
        if !has_scan_state {
            db.execute(
                "ALTER TABLE images ADD COLUMN scan_state INTEGER NOT NULL DEFAULT 3",
                [],
            )?;
            db.execute(
                "UPDATE images SET scan_state=?1 WHERE cache_key IS NOT NULL",
                [IMAGE_SCANNED],
            )?;
        }
        let objects = dir.join("objects");
        fs::create_dir_all(&objects)?;
        let mut referenced =
            db.prepare("SELECT cache_key FROM images WHERE cache_key IS NOT NULL")?;
        let keys = referenced
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<std::collections::HashSet<_>>>()?;
        for entry in objects.read_dir()? {
            let entry = entry?;
            if entry.file_type()?.is_dir()
                && !keys.contains(entry.file_name().to_str().unwrap_or_default())
            {
                fs::remove_dir_all(entry.path())?;
            }
        }
        drop(referenced);
        Ok(Self {
            db: Mutex::new(db),
            dir: dir.to_owned(),
            _lock: lock,
        })
    }

    fn db(&self) -> anyhow::Result<MutexGuard<'_, Connection>> {
        self.db
            .lock()
            .map_err(|_| anyhow::anyhow!("mirror database lock poisoned"))
    }

    pub fn root(&self) -> &Path {
        &self.dir
    }
    pub fn has_image(&self, repo: &str, digest: &str) -> anyhow::Result<bool> {
        Ok(self.db()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM images WHERE repository=?1 AND digest=?2)",
            params![repo, digest],
            |row| row.get(0),
        )?)
    }
    pub fn discard_pending(&self, repo: &str, digest: &str) -> anyhow::Result<()> {
        let mut db = self.db()?;
        let tx = db.transaction()?;
        tx.execute(
            "DELETE FROM tags WHERE repository=?1 AND digest=?2 AND EXISTS (
                SELECT 1 FROM images WHERE repository=?1 AND digest=?2 AND cache_key IS NULL AND scan_state=?3
            )",
            params![repo, digest, IMAGE_PENDING],
        )?;
        tx.execute(
            "DELETE FROM images WHERE repository=?1 AND digest=?2 AND cache_key IS NULL AND scan_state=?3",
            params![repo, digest, IMAGE_PENDING],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn observe(
        &self,
        repo: &str,
        digest: &str,
        tag: Option<&str>,
        now: DateTime<Utc>,
    ) -> anyhow::Result<DateTime<Utc>> {
        let mut db = self.db()?;
        let tx = db.transaction()?;
        // Metadata for an observed digest is kept even when no released copy
        // exists: it anchors the quarantine window and a known rejection. That
        // retention is bounded here, not in commit, so a caller polling
        // unique digests cannot grow the database between successful scans.
        // Pruning restarts the window for a re-observed digest: fail closed.
        tx.execute(
            "DELETE FROM images WHERE cache_key IS NULL AND first_seen < ?1",
            params![now.timestamp() - METADATA_RETENTION_SECONDS],
        )?;
        tx.execute(
            "DELETE FROM tags WHERE NOT EXISTS (SELECT 1 FROM images WHERE images.repository = tags.repository AND images.digest = tags.digest)",
            [],
        )?;
        let known: Option<i64> = tx
            .query_row(
                "SELECT first_seen FROM images WHERE repository=?1 AND digest=?2",
                [repo, digest],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let ts = match known {
            Some(first_seen) => first_seen,
            None => {
                let mut pending: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM images WHERE cache_key IS NULL",
                    [],
                    |row| row.get::<_, i64>(0),
                )?;
                while pending >= MAX_METADATA_IMAGES {
                    let oldest: Option<i64> = tx
                        .query_row(
                            "SELECT rowid FROM images
                             WHERE cache_key IS NULL AND scan_state IN (?1,?2)
                             ORDER BY first_seen,repository,digest LIMIT 1",
                            [IMAGE_EVICTED, IMAGE_LEGACY_UNCACHED],
                            |row| row.get(0),
                        )
                        .optional()?;
                    let Some(oldest) = oldest else {
                        anyhow::bail!("mirror image capacity reached");
                    };
                    tx.execute(
                        "DELETE FROM tags WHERE EXISTS (
                            SELECT 1 FROM images
                            WHERE images.rowid=?1
                              AND images.repository=tags.repository
                              AND images.digest=tags.digest
                        )",
                        [oldest],
                    )?;
                    tx.execute("DELETE FROM images WHERE rowid=?1", [oldest])?;
                    pending -= 1;
                }
                let first_seen = now.timestamp();
                tx.execute(
                    "INSERT INTO images (repository,digest,first_seen,scan_state) VALUES (?1,?2,?3,?4)",
                    params![repo, digest, first_seen, IMAGE_PENDING],
                )?;
                first_seen
            }
        };
        if let Some(tag) = tag {
            let counted: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM tags WHERE repository=?1 AND tag=?2)",
                params![repo, tag],
                |row| row.get::<_, bool>(0),
            )?;
            if counted {
                tx.execute(
                    "UPDATE tags SET digest=?3 WHERE repository=?1 AND tag=?2",
                    params![repo, tag, digest],
                )?;
            } else {
                let tags: i64 =
                    tx.query_row("SELECT COUNT(*) FROM tags", [], |row| row.get::<_, i64>(0))?;
                if tags < MAX_METADATA_TAGS {
                    tx.execute(
                        "INSERT INTO tags VALUES (?1,?2,?3)",
                        params![repo, tag, digest],
                    )?;
                }
            }
        }
        tx.commit()?;
        DateTime::from_timestamp(ts, 0).context("invalid first seen time")
    }

    pub fn verdict(
        &self,
        repo: &str,
        digest: &str,
        policy: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<Option<Verdict>> {
        let row = self
            .db()?
            .query_row(
                "SELECT cache_key, vulnerable FROM images WHERE repository=?1 AND digest=?2
             AND policy=?3 AND scanned_at BETWEEN ?4 AND ?5",
                params![
                    repo,
                    digest,
                    policy,
                    now.timestamp() - SCAN_TTL_SECONDS,
                    now.timestamp()
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?;
        Ok(row
            .filter(|(key, _)| self.dir.join("objects").join(key).is_dir())
            .map(|(_, vulnerable)| {
                if vulnerable {
                    Verdict::Vulnerable
                } else {
                    Verdict::Clean
                }
            }))
    }

    pub fn released(
        &self,
        repo: &str,
        digest: &str,
        manifest: bool,
        policy: &str,
        now: DateTime<Utc>,
        aged_by: i64,
    ) -> anyhow::Result<Option<Release>> {
        self.db()?.query_row(
            "SELECT o.cache_key,o.media_type,o.size FROM objects o
             JOIN images i USING (cache_key) WHERE i.repository=?1 AND o.digest=?2 AND o.manifest=?3
             AND i.policy=?4 AND i.vulnerable=0 AND i.scanned_at BETWEEN ?5 AND ?6 AND i.first_seen<=?7
             ORDER BY i.scanned_at DESC LIMIT 1",
            params![repo,digest,manifest,policy,now.timestamp()-SCAN_TTL_SECONDS,now.timestamp(),aged_by],
            |row| Ok(Release {
                directory: self.dir.join("objects").join(row.get::<_, String>(0)?),
                object: Object { digest: digest.to_owned(), manifest, media_type: row.get(1)?, size: row.get::<_, i64>(2)? as u64 },
            }),
        ).optional().map_err(Into::into)
    }

    pub fn commit(&self, entry: ScannedImage<'_>) -> anyhow::Result<()> {
        let ScannedImage {
            repo,
            hash,
            policy,
            now,
            staging,
            size,
            verdict,
            objects,
        } = entry;
        ensure!(valid_digest(hash), "invalid cached digest");
        // Use a new cache directory for each commit so an older reader can safely
        // hold an open file while the release transaction replaces its record.
        let nonce = staging
            .path()
            .file_name()
            .context("missing staging name")?
            .to_string_lossy();
        let key = digest(format!("{repo}/{hash}/{nonce}").as_bytes())["sha256:".len()..].to_owned();
        let target = self.dir.join("objects").join(&key);
        let mut db = self.db()?;
        let tx = db.transaction()?;
        let old = tx.query_row(
            "SELECT cache_key FROM images WHERE repository=?1 AND digest=?2",
            [repo, hash],
            |row| row.get::<_, Option<String>>(0),
        )?;
        let mut remove = Vec::new();
        if let Some(old) = old {
            forget(&tx, &old)?;
            remove.push(old);
        }
        let size = i64::try_from(size)?;
        let mut used: i64 =
            tx.query_row("SELECT COALESCE(SUM(size),0) FROM images", [], |row| {
                row.get(0)
            })?;
        let mut query = tx.prepare(
            "SELECT cache_key,size FROM images WHERE cache_key IS NOT NULL ORDER BY scanned_at",
        )?;
        let mut victims = query.query([])?;
        while used + size > MAX_CACHE_BYTES {
            let row = victims
                .next()?
                .context("image exceeds mirror cache capacity")?;
            let victim: String = row.get(0)?;
            used -= row.get::<_, i64>(1)?;
            remove.push(victim);
        }
        drop(victims);
        drop(query);
        for victim in &remove {
            forget(&tx, victim)?;
        }
        fs::rename(staging.path(), &target)?;
        let recorded = (|| -> anyhow::Result<()> {
            tx.execute(
                "UPDATE images SET cache_key=?3,size=?4,scanned_at=?5,policy=?6,vulnerable=?7,scan_state=?8 WHERE repository=?1 AND digest=?2",
                params![repo,hash,key,size,now.timestamp(),policy,verdict == Verdict::Vulnerable,IMAGE_SCANNED],
            )?;
            if verdict == Verdict::Clean {
                let mut insert = tx.prepare("INSERT INTO objects VALUES (?1,?2,?3,?4,?5)")?;
                for object in objects {
                    insert.execute(params![
                        key,
                        object.digest,
                        object.manifest,
                        object.media_type,
                        i64::try_from(object.size)?
                    ])?;
                }
            }
            Ok(tx.commit()?)
        })();
        if recorded.is_err() {
            let _ = fs::remove_dir_all(target);
        }
        recorded?;
        drop(db);
        for victim in remove {
            let _ = fs::remove_dir_all(self.dir.join("objects").join(victim));
        }
        Ok(())
    }

    pub fn list(
        &self,
        repository: Option<&str>,
        policy: &str,
        now: DateTime<Utc>,
        aged_by: i64,
        after: &str,
        limit: u32,
    ) -> Result<Vec<String>> {
        let query = match repository {
            Some(_) => "SELECT tag FROM tags JOIN images USING (repository,digest)
                        WHERE repository=?1 AND policy=?2 AND vulnerable=0 AND scanned_at BETWEEN ?3 AND ?4
                        AND first_seen<=?5 AND tag>?6 ORDER BY tag LIMIT ?7",
            None => "SELECT DISTINCT repository FROM images WHERE ?1 IS NULL AND policy=?2 AND vulnerable=0
                     AND scanned_at BETWEEN ?3 AND ?4 AND first_seen<=?5 AND repository>?6 ORDER BY repository LIMIT ?7",
        };
        let db = self.db().map_err(MirrorError::internal)?;
        if let Some(repository) = repository {
            let available = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM images WHERE repository=?1 AND policy=?2
                 AND vulnerable=0 AND scanned_at BETWEEN ?3 AND ?4 AND first_seen<=?5)",
                    params![
                        repository,
                        policy,
                        now.timestamp() - SCAN_TTL_SECONDS,
                        now.timestamp(),
                        aged_by
                    ],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(MirrorError::internal)?;
            if !available {
                return Err(MirrorError::NameUnknown);
            }
        }
        let mut statement = db.prepare(query).map_err(MirrorError::internal)?;
        let rows = statement
            .query_map(
                params![
                    repository,
                    policy,
                    now.timestamp() - SCAN_TTL_SECONDS,
                    now.timestamp(),
                    aged_by,
                    after,
                    limit
                ],
                |row| row.get(0),
            )
            .map_err(MirrorError::internal)?;
        rows.collect::<rusqlite::Result<_>>()
            .map_err(MirrorError::internal)
    }
}

fn forget(tx: &rusqlite::Transaction<'_>, key: &str) -> rusqlite::Result<()> {
    tx.execute("DELETE FROM objects WHERE cache_key=?1", [key])?;
    tx.execute(
        "UPDATE images SET cache_key=NULL,size=0,policy=NULL,vulnerable=NULL,scan_state=?2 WHERE cache_key=?1",
        params![key, IMAGE_EVICTED],
    )?;
    Ok(())
}

pub(super) struct ScannedImage<'a> {
    pub repo: &'a str,
    pub hash: &'a str,
    pub policy: &'a str,
    pub now: DateTime<Utc>,
    pub staging: tempfile::TempDir,
    pub size: u64,
    pub verdict: Verdict,
    pub objects: &'a [Object],
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicted_first_seen_survives_failure_and_prunes_capacity() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = Store::open(dir.path())?;
        let now = Utc::now();
        let evicted = digest(b"evicted");
        store.observe("r", &evicted, Some("evicted"), now)?;
        let staging = tempfile::tempdir_in(store.root().join("objects"))?;
        store.commit(ScannedImage {
            repo: "r",
            hash: &evicted,
            policy: "test",
            now,
            staging,
            size: MAX_CACHE_BYTES as u64,
            verdict: Verdict::Clean,
            objects: &[],
        })?;

        let retained = digest(b"retained");
        store.observe("r", &retained, None, now)?;
        let later = now + chrono::TimeDelta::seconds(1);
        let staging = tempfile::tempdir_in(store.root().join("objects"))?;
        store.commit(ScannedImage {
            repo: "r",
            hash: &retained,
            policy: "test",
            now: later,
            staging,
            size: 1,
            verdict: Verdict::Clean,
            objects: &[],
        })?;
        store.discard_pending("r", &evicted)?;
        assert!(store.has_image("r", &evicted)?);
        let observed_evicted = store.observe("r", &evicted, Some("evicted"), later)?;
        assert_eq!(observed_evicted.timestamp(), now.timestamp());

        for index in 0..(MAX_METADATA_IMAGES - 1) {
            store.observe(
                "r",
                &digest(format!("pending:{index}").as_bytes()),
                None,
                later,
            )?;
        }
        let observed = store.observe("r", &digest(b"incoming"), None, later)?;
        assert_eq!(observed.timestamp(), later.timestamp());
        assert!(!store.has_image("r", &evicted)?);
        let db = Connection::open(store.root().join("state.db"))?;
        let evicted_tags: i64 = db.query_row(
            "SELECT COUNT(*) FROM tags WHERE repository=?1 AND tag=?2",
            ["r", "evicted"],
            |row| row.get(0),
        )?;
        assert_eq!(evicted_tags, 0);
        Ok(())
    }

    #[test]
    fn legacy_uncached_metadata_is_pruned_after_migration() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let first_seen = Utc::now() - chrono::TimeDelta::seconds(2);
        let legacy = digest(b"legacy");
        let db = Connection::open(dir.path().join("state.db"))?;
        db.execute_batch(
            "
            CREATE TABLE images (
                repository TEXT NOT NULL,
                digest TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                cache_key TEXT UNIQUE,
                size INTEGER NOT NULL DEFAULT 0,
                scanned_at INTEGER,
                policy TEXT,
                vulnerable INTEGER,
                PRIMARY KEY (repository, digest)
            );
            ",
        )?;
        db.execute(
            "INSERT INTO images (repository,digest,first_seen) VALUES (?1,?2,?3)",
            params!["r", legacy, first_seen.timestamp()],
        )?;
        drop(db);

        let store = Store::open(dir.path())?;
        let later = first_seen + chrono::TimeDelta::seconds(1);
        store.observe("r", &legacy, Some("legacy"), first_seen)?;
        for index in 0..(MAX_METADATA_IMAGES - 1) {
            store.observe(
                "r",
                &digest(format!("pending:{index}").as_bytes()),
                None,
                later,
            )?;
        }
        let incoming = digest(b"incoming");
        store.observe("r", &incoming, None, later)?;
        assert!(!store.has_image("r", &legacy)?);
        assert!(store.has_image("r", &incoming)?);
        let db = Connection::open(store.root().join("state.db"))?;
        let tag_count: i64 = db.query_row(
            "SELECT COUNT(*) FROM tags WHERE repository=?1 AND tag=?2",
            ["r", "legacy"],
            |row| row.get(0),
        )?;
        assert_eq!(tag_count, 0);
        Ok(())
    }

    #[test]
    fn pending_scan_failure_after_restart_clears_metadata() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let pending = digest(b"pending");
        let now = Utc::now();

        {
            let store = Store::open(dir.path())?;
            store.observe("r", &pending, Some("pending"), now)?;
        }

        let store = Store::open(dir.path())?;
        store.discard_pending("r", &pending)?;
        assert!(!store.has_image("r", &pending)?);
        let db = Connection::open(store.root().join("state.db"))?;
        let tag_count: i64 = db.query_row(
            "SELECT COUNT(*) FROM tags WHERE repository=?1 AND tag=?2",
            ["r", "pending"],
            |row| row.get(0),
        )?;
        assert_eq!(tag_count, 0);
        Ok(())
    }
}
