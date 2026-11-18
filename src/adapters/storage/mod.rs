use crate::{
    domain::*,
    ports::{ArtifactStore, MetadataStore},
};
use anyhow::{ensure, Result};
use node_semver::Range;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};
pub mod ledger;

/// The store directory must be writable only by trusted local processes.
/// Canonical-path checks do not protect against concurrent filesystem changes.
pub struct FsArtifactStore {
    pub root: PathBuf,
}
fn sanitize_package_name(name: &str) -> Result<String> {
    let valid_segment = |segment: &str| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b))
    };
    let valid = if let Some(scoped) = name.strip_prefix('@') {
        scoped
            .split_once('/')
            .is_some_and(|(scope, package)| valid_segment(scope) && valid_segment(package))
    } else {
        valid_segment(name)
    };
    if !valid {
        anyhow::bail!("invalid package name: {name:?}");
    }
    Ok(name.replace('/', "+").replace('@', ""))
}
fn ensure_directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    if !fs::symlink_metadata(path)?.file_type().is_dir() {
        anyhow::bail!(
            "artifact directory is not a plain directory: {}",
            path.display()
        );
    }
    Ok(())
}
impl FsArtifactStore {
    fn root_directory(&self) -> Result<PathBuf> {
        fs::create_dir_all(&self.root)?;
        Ok(self.root.canonicalize()?)
    }

    fn artifacts_directory(&self) -> Result<PathBuf> {
        let path = self.root_directory()?.join("artifacts");
        ensure_directory(&path)?;
        Ok(path)
    }

    fn objects_directory(&self) -> Result<PathBuf> {
        let path = self.artifacts_directory()?.join("sha256");
        ensure_directory(&path)?;
        Ok(path)
    }

    fn object_path(&self, digest: &str) -> Result<PathBuf> {
        ensure!(is_sha256(digest), "invalid SHA-256 digest");
        Ok(self.objects_directory()?.join(digest))
    }

    fn index_connection(&self) -> Result<Connection> {
        let path = self.root_directory()?.join("artifact-index.sqlite");
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            ensure!(
                metadata.file_type().is_file(),
                "artifact index is not a regular file"
            );
        }
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.execute_batch(
            "PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS artifact_mappings (
                 source TEXT NOT NULL,
                 ecosystem TEXT NOT NULL,
                 name TEXT NOT NULL,
                 version TEXT NOT NULL,
                 filename TEXT NOT NULL,
                 sha256 TEXT NOT NULL,
                 PRIMARY KEY (source, ecosystem, name, version, filename)
             ) WITHOUT ROWID;",
        )?;
        Ok(connection)
    }

    fn legacy_path(&self, key: &ArtifactKey) -> Result<PathBuf> {
        let safe = sanitize_package_name(&key.name)?;
        let version = key.version.to_string();
        ensure!(
            !version.is_empty()
                && version != "."
                && version != ".."
                && !version.contains('/')
                && !version.contains('\\'),
            "legacy artifact version is not a path component"
        );
        Ok(self
            .artifacts_directory()?
            .join(safe)
            .join(format!("{version}.tgz")))
    }

    fn confined_file(&self, path: &Path) -> Result<PathBuf> {
        let artifacts_root = self.artifacts_directory()?.canonicalize()?;
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.file_type().is_file(),
            "legacy artifact is not a regular file"
        );
        let canonical = path.canonicalize()?;
        ensure!(
            canonical.starts_with(&artifacts_root),
            "legacy artifact escapes store root: {}",
            canonical.display()
        );
        Ok(canonical)
    }

    fn digest_for(&self, key: &ArtifactKey) -> Result<Option<String>> {
        key.validate()?;
        let connection = self.index_connection()?;
        let digest = connection
            .query_row(
                "SELECT sha256 FROM artifact_mappings
                 WHERE source = ?1 AND ecosystem = ?2 AND name = ?3
                   AND version = ?4 AND filename = ?5",
                params![
                    key.source,
                    ecosystem_key(&key.ecosystem),
                    key.name,
                    key.version.canonical(),
                    key.filename
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(digest) = &digest {
            ensure!(
                is_sha256(digest),
                "artifact index contains an invalid digest"
            );
        }
        Ok(digest)
    }

    fn store_reader(
        &self,
        reader: &mut dyn Read,
        max_bytes: u64,
        expected_digest: Option<&str>,
    ) -> Result<crate::ports::StoredArtifact> {
        if let Some(expected_digest) = expected_digest {
            ensure!(is_sha256(expected_digest), "invalid SHA-256 digest");
        }
        let (temporary, digest) = self.stage_reader(reader, max_bytes)?;
        if let Some(expected_digest) = expected_digest {
            ensure!(
                digest == expected_digest,
                "artifact bytes do not match the expected digest"
            );
        }
        self.publish_object(&temporary.0, &digest)?;
        let path = self.object_path(&digest)?.canonicalize()?;
        let file = self
            .open_verified_object(&digest)?
            .ok_or_else(|| anyhow::anyhow!("published artifact object is missing"))?;
        Ok(crate::ports::StoredArtifact {
            sha256: digest,
            path: path.display().to_string(),
            file,
        })
    }

    fn stage_reader(
        &self,
        reader: &mut dyn Read,
        max_bytes: u64,
    ) -> Result<(TemporaryArtifact, String)> {
        let directory = self.objects_directory()?;
        let mut staged = None;
        for _ in 0..16 {
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce)?;
            let path = directory.join(format!(".tmp-{}", hex::encode(nonce)));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => {
                    staged = Some((TemporaryArtifact(path), file));
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let (temporary, mut file) = staged
            .ok_or_else(|| anyhow::anyhow!("could not create private artifact staging file"))?;
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let remaining = max_bytes.saturating_sub(size);
            let read_limit = usize::try_from(remaining.saturating_add(1).min(buffer.len() as u64))?;
            let count = reader.read(&mut buffer[..read_limit])?;
            if count == 0 {
                break;
            }
            size = size
                .checked_add(u64::try_from(count)?)
                .ok_or_else(|| anyhow::anyhow!("artifact size overflow"))?;
            ensure!(size <= max_bytes, "artifact exceeds its size limit");
            hasher.update(&buffer[..count]);
            file.write_all(&buffer[..count])?;
        }
        file.sync_all()?;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_readonly(true);
        file.set_permissions(permissions)?;
        drop(file);
        Ok((temporary, hex::encode(hasher.finalize())))
    }

    fn publish_object(&self, temporary: &Path, digest: &str) -> Result<()> {
        let path = self.object_path(digest)?;
        match fs::hard_link(temporary, &path) {
            Ok(()) => {
                #[cfg(unix)]
                File::open(self.objects_directory()?)?.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.verify_object(&path, digest)?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn map_artifact(&self, key: &ArtifactKey, digest: &str) -> Result<()> {
        let mut connection = self.index_connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction
            .query_row(
                "SELECT sha256 FROM artifact_mappings
                 WHERE source = ?1 AND ecosystem = ?2 AND name = ?3
                   AND version = ?4 AND filename = ?5",
                params![
                    key.source,
                    ecosystem_key(&key.ecosystem),
                    key.name,
                    key.version.canonical(),
                    key.filename
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.as_deref().is_some_and(|stored| stored != digest) {
            anyhow::bail!(
                "artifact identity conflict for {} {}@{} ({})",
                key.source,
                key.name,
                key.version,
                key.filename
            );
        }
        if existing.is_none() {
            transaction.execute(
                "INSERT INTO artifact_mappings
                 (source, ecosystem, name, version, filename, sha256)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    key.source,
                    ecosystem_key(&key.ecosystem),
                    key.name,
                    key.version.canonical(),
                    key.filename,
                    digest
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn verify_object(&self, path: &Path, digest: &str) -> Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.file_type().is_file(),
            "artifact object is not a regular file"
        );
        let mut file = File::open(path)?;
        ensure!(
            digest_reader(&mut file)? == digest,
            "artifact object content does not match its digest"
        );
        Ok(())
    }

    fn open_verified_object(&self, digest: &str) -> Result<Option<File>> {
        let path = self.object_path(digest)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) => ensure!(
                metadata.file_type().is_file(),
                "artifact object is not a regular file"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        let objects_root = self.objects_directory()?.canonicalize()?;
        let canonical = path.canonicalize()?;
        ensure!(
            canonical.starts_with(&objects_root),
            "artifact object escapes store root: {}",
            canonical.display()
        );
        let mut file = OpenOptions::new().read(true).open(canonical)?;
        ensure!(
            digest_reader(&mut file)? == digest,
            "artifact object content does not match its digest"
        );
        file.seek(SeekFrom::Start(0))?;
        Ok(Some(file))
    }
}

fn ecosystem_key(ecosystem: &Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPi => "pypi",
        Ecosystem::NuGet => "nuget",
        Ecosystem::DockerImage => "docker-image",
        Ecosystem::GitHubActions => "github-actions",
        Ecosystem::AzurePipelines => "azure-pipelines",
    }
}

fn is_sha256(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest_reader(reader: &mut impl Read) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

struct TemporaryArtifact(PathBuf);

impl Drop for TemporaryArtifact {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

impl ArtifactStore for FsArtifactStore {
    fn put(&self, reader: &mut dyn Read, max_bytes: u64) -> Result<crate::ports::StoredArtifact> {
        self.store_reader(reader, max_bytes, None)
    }

    fn map(&self, key: &ArtifactKey, sha256: &str) -> Result<()> {
        key.validate()?;
        ensure!(is_sha256(sha256), "invalid SHA-256 digest");
        let file = self
            .open_verified_object(sha256)?
            .ok_or_else(|| anyhow::anyhow!("artifact object is missing"))?;
        drop(file);
        self.map_artifact(key, sha256)
    }

    fn resolve(&self, key: &ArtifactKey) -> Result<Option<String>> {
        let Some(digest) = self.digest_for(key)? else {
            return Ok(None);
        };
        let Some(file) = self.open_verified_object(&digest)? else {
            anyhow::bail!("indexed artifact object is missing");
        };
        drop(file);
        let path = self.object_path(&digest)?.canonicalize()?;
        let objects_root = self.objects_directory()?.canonicalize()?;
        ensure!(
            path.starts_with(&objects_root),
            "artifact object escapes store root: {}",
            path.display()
        );
        Ok(Some(path.display().to_string()))
    }

    fn open(&self, key: &ArtifactKey) -> Result<Option<File>> {
        let Some(digest) = self.digest_for(key)? else {
            return Ok(None);
        };
        self.open_verified_object(&digest)?
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("indexed artifact object is missing"))
    }

    fn import_legacy(&self, key: &ArtifactKey, expected_sha256: &str) -> Result<String> {
        key.validate()?;
        ensure!(
            is_sha256(expected_sha256),
            "invalid expected SHA-256 digest"
        );
        let legacy = self.confined_file(&self.legacy_path(key)?)?;
        let mut source = File::open(legacy)?;
        let stored = self.store_reader(&mut source, u64::MAX, Some(expected_sha256))?;
        self.map(key, &stored.sha256)?;
        Ok(stored.path)
    }
}

#[derive(Default)]
pub struct MemoryMetadataStore {
    frozen: Mutex<Vec<FrozenArtifact>>,
    decisions: Mutex<Vec<Decision>>,
    findings: Mutex<Vec<ContentFinding>>,
}
impl MetadataStore for MemoryMetadataStore {
    fn save_content_finding(&self, finding: &ContentFinding) -> Result<()> {
        let mut findings = self
            .findings
            .lock()
            .map_err(|_| anyhow::anyhow!("lock poisoned"))?;
        findings.retain(|existing| {
            !(existing.package == finding.package
                && existing.ecosystem == finding.ecosystem
                && existing.version == finding.version
                && existing.source == finding.source)
        });
        findings.push(finding.clone());
        Ok(())
    }

    fn content_finding(
        &self,
        ecosystem: &Ecosystem,
        name: &str,
        version: &PackageVersionId,
    ) -> Result<Option<ContentFinding>> {
        Ok(self
            .findings
            .lock()
            .map_err(|_| anyhow::anyhow!("lock poisoned"))?
            .iter()
            .filter(|finding| {
                finding.ecosystem == *ecosystem
                    && finding.package == name
                    && finding.version == *version
            })
            .max_by_key(|finding| {
                (
                    finding.scan_incomplete || finding.score.is_none(),
                    finding.score,
                )
            })
            .cloned())
    }

    fn save_decision(&self, d: &Decision) -> Result<()> {
        self.decisions
            .lock()
            .map_err(|_| anyhow::anyhow!("lock poisoned"))?
            .push(d.clone());
        Ok(())
    }
    fn latest_frozen_satisfying(
        &self,
        source: &str,
        ecosystem: &Ecosystem,
        name: &str,
        requested: Option<&Range>,
    ) -> Result<Option<FrozenArtifact>> {
        let frozen = self
            .frozen
            .lock()
            .map_err(|_| anyhow::anyhow!("lock poisoned"))?;
        let mut latest: Option<&FrozenArtifact> = None;
        for artifact in frozen.iter().filter(|artifact| {
            artifact.key.source == source
                && artifact.key.ecosystem == *ecosystem
                && artifact.key.name == name
        }) {
            if let Some(range) = requested {
                if *ecosystem != Ecosystem::Npm || !artifact.version.satisfies_npm_range(range) {
                    continue;
                }
            }
            let Some(current) = latest else {
                latest = Some(artifact);
                continue;
            };
            let order = artifact.version.precedence_cmp(&current.version)?;
            let order = if order.is_eq() {
                artifact
                    .version
                    .canonical()
                    .cmp(current.version.canonical())
                    .then_with(|| artifact.key.filename.cmp(&current.key.filename))
            } else {
                order
            };
            if order.is_gt() {
                latest = Some(artifact);
            }
        }
        Ok(latest.cloned())
    }

    fn get_frozen(&self, key: &ArtifactKey) -> Result<Option<FrozenArtifact>> {
        Ok(self
            .frozen
            .lock()
            .map_err(|_| anyhow::anyhow!("lock poisoned"))?
            .iter()
            .find(|artifact| artifact.key == *key)
            .cloned())
    }

    fn put_frozen(&self, artifact: FrozenArtifact) -> Result<()> {
        artifact.key.validate()?;
        ensure!(
            artifact.key.ecosystem == artifact.package.ecosystem
                && artifact.key.name == artifact.package.name
                && artifact.key.version == artifact.version,
            "frozen artifact fields do not match its identity key"
        );
        let mut frozen = self
            .frozen
            .lock()
            .map_err(|_| anyhow::anyhow!("lock poisoned"))?;
        if let Some(existing) = frozen.iter().find(|existing| existing.key == artifact.key) {
            ensure!(
                existing.sha256 == artifact.sha256,
                "frozen artifact identity maps to conflicting digests"
            );
            return Ok(());
        }
        frozen.push(artifact);
        Ok(())
    }
}

/// Parse findings from either a JSON array or JSON Lines content.
pub fn parse_findings(content: &str) -> Result<Vec<ContentFinding>> {
    if content.trim_start().starts_with('[') {
        return Ok(serde_json::from_str(content)?);
    }
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(Into::into))
        .collect()
}

/// File-backed persistence for content findings.
pub struct FindingFile {
    path: PathBuf,
}
impl FindingFile {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn append(&self, finding: &ContentFinding) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        // Serialize the read/truncate/append sequence across processes; a
        // torn-tail truncation based on a stale snapshot must not delete a
        // record another process just wrote.
        let lock_path = self.path.with_extension("lock");
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)?;
        {
            use std::os::unix::io::AsRawFd;
            loop {
                let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) };
                if result == 0 {
                    break;
                }
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error.into());
                }
            }
        }
        let result = self.append_locked(finding);
        drop(lock);
        result
    }

    fn append_locked(&self, finding: &ContentFinding) -> Result<()> {
        use std::io::Write;
        let mut existing = std::fs::read_to_string(&self.path).unwrap_or_default();
        if existing.trim_start().starts_with('[') {
            let mut findings = parse_findings(&existing)?;
            findings.push(finding.clone());
            let mut staged = String::new();
            for item in &findings {
                staged.push_str(&serde_json::to_string(item)?);
                staged.push('\n');
            }
            let temporary = self.path.with_extension("rewrite.tmp");
            let mut file = std::fs::File::create(&temporary)?;
            file.write_all(staged.as_bytes())?;
            file.sync_data()?;
            std::fs::rename(&temporary, &self.path)?;
            return Ok(());
        }
        let mut record = serde_json::to_string(finding)?;
        record.push('\n');
        if !existing.is_empty() && !existing.ends_with('\n') {
            let file = std::fs::OpenOptions::new().write(true).open(&self.path)?;
            let length = match existing.rfind('\n') {
                Some(index) => (index + 1) as u64,
                None => 0,
            };
            file.set_len(length)?;
            file.sync_data()?;
            existing.truncate(length as usize);
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(record.as_bytes())?;
        file.sync_data()?;
        Ok(())
    }

    pub fn load_into(&self, store: &MemoryMetadataStore) -> Result<usize> {
        let mut content = std::fs::read_to_string(&self.path)?;
        if !content.trim_start().starts_with('[') && !content.is_empty() && !content.ends_with('\n')
        {
            match content.rfind('\n') {
                Some(index) => content.truncate(index + 1),
                None => content.clear(),
            }
        }
        let findings = parse_findings(&content)?;
        for finding in &findings {
            store.save_content_finding(finding)?;
        }
        Ok(findings.len())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rust_decimal::Decimal;
    fn npm_version(raw: &str) -> PackageVersionId {
        PackageVersionId::parse(&Ecosystem::Npm, raw).unwrap()
    }

    fn artifact_key(url: &str, name: &str, version: &str) -> ArtifactKey {
        ArtifactKey::from_tarball_url(url, &Ecosystem::Npm, name, &npm_version(version)).unwrap()
    }
    use std::io::Cursor;

    fn put_bytes(
        store: &FsArtifactStore,
        key: &ArtifactKey,
        bytes: &[u8],
    ) -> Result<crate::ports::StoredArtifact> {
        let mut reader = Cursor::new(bytes);
        let stored = store.put(&mut reader, 64 * 1024 * 1024)?;
        store.map(key, &stored.sha256)?;
        Ok(stored)
    }

    fn put_path(store: &FsArtifactStore, key: &ArtifactKey, bytes: &[u8]) -> Result<String> {
        Ok(put_bytes(store, key, bytes)?.path)
    }

    #[test]
    fn finding_file_round_trips_jsonl_and_array() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("findings.jsonl");
        let file = FindingFile::new(&path);
        let finding = |package: &str| ContentFinding {
            ecosystem: Ecosystem::Npm,
            package: package.to_string(),
            version: npm_version("1.0.0"),
            source: "static-heuristics".to_string(),
            score: Some(Decimal::from(9)),
            scan_incomplete: false,
            rules: vec![],
            summary: package.to_string(),
            detected_at: chrono::Utc::now(),
        };
        file.append(&finding("a")).unwrap();
        file.append(&finding("b")).unwrap();

        let store = MemoryMetadataStore::default();
        assert_eq!(file.load_into(&store).unwrap(), 2);
        assert!(store
            .content_finding(&Ecosystem::Npm, "a", &npm_version("1.0.0"))
            .unwrap()
            .is_some());
        assert!(store
            .content_finding(&Ecosystem::Npm, "b", &npm_version("1.0.0"))
            .unwrap()
            .is_some());

        let array_path = directory.path().join("array.json");
        std::fs::write(
            &array_path,
            format!("[{}]", serde_json::to_string(&finding("c")).unwrap()),
        )
        .unwrap();
        let store = MemoryMetadataStore::default();
        assert_eq!(FindingFile::new(&array_path).load_into(&store).unwrap(), 1);
        assert!(store
            .content_finding(&Ecosystem::Npm, "c", &npm_version("1.0.0"))
            .unwrap()
            .is_some());
    }

    #[test]
    fn append_to_array_file_migrates_to_jsonl() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("findings.json");
        let finding = |package: &str| ContentFinding {
            ecosystem: Ecosystem::Npm,
            package: package.to_string(),
            version: npm_version("1.0.0"),
            source: "static-heuristics".to_string(),
            score: Some(Decimal::from(9)),
            scan_incomplete: false,
            rules: vec![],
            summary: package.to_string(),
            detected_at: chrono::Utc::now(),
        };
        std::fs::write(
            &path,
            format!("[{}]", serde_json::to_string(&finding("a")).unwrap()),
        )
        .unwrap();
        let file = FindingFile::new(&path);
        file.append(&finding("b")).unwrap();
        let store = MemoryMetadataStore::default();
        assert_eq!(file.load_into(&store).unwrap(), 2);
    }

    #[test]
    fn torn_final_jsonl_line_is_recovered() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("findings.jsonl");
        let file = FindingFile::new(&path);
        let finding = ContentFinding {
            ecosystem: Ecosystem::Npm,
            package: "a".to_string(),
            version: npm_version("1.0.0"),
            source: "static-heuristics".to_string(),
            score: Some(Decimal::from(9)),
            scan_incomplete: false,
            rules: vec![],
            summary: "a".to_string(),
            detected_at: chrono::Utc::now(),
        };
        file.append(&finding).unwrap();
        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push_str("{\"ecosystem\":\"Npm\",\"package\":\"b\"");
        std::fs::write(&path, content).unwrap();
        let store = MemoryMetadataStore::default();
        assert_eq!(file.load_into(&store).unwrap(), 1);
        assert!(store
            .content_finding(&Ecosystem::Npm, "a", &npm_version("1.0.0"))
            .unwrap()
            .is_some());
    }

    #[test]
    fn append_after_torn_tail_keeps_both_findings() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("findings.jsonl");
        let file = FindingFile::new(&path);
        let finding = |package: &str| ContentFinding {
            ecosystem: Ecosystem::Npm,
            package: package.to_string(),
            version: npm_version("1.0.0"),
            source: "static-heuristics".to_string(),
            score: Some(Decimal::from(9)),
            scan_incomplete: false,
            rules: vec![],
            summary: package.to_string(),
            detected_at: chrono::Utc::now(),
        };
        file.append(&finding("a")).unwrap();
        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push_str("{\"partial\"");
        std::fs::write(&path, content).unwrap();
        file.append(&finding("b")).unwrap();
        let store = MemoryMetadataStore::default();
        assert_eq!(file.load_into(&store).unwrap(), 2);
    }

    #[test]
    fn concurrent_appends_are_serialized() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("findings.jsonl");
        let mut handles = Vec::new();
        for thread in 0..8 {
            let path = path.clone();
            handles.push(std::thread::spawn(move || {
                let file = FindingFile::new(&path);
                for index in 0..20 {
                    let finding = ContentFinding {
                        ecosystem: Ecosystem::Npm,
                        package: format!("pkg-{thread}-{index}"),
                        version: npm_version("1.0.0"),
                        source: "static-heuristics".to_string(),
                        score: Some(Decimal::from(9)),
                        scan_incomplete: false,
                        rules: vec![],
                        summary: "concurrent".to_string(),
                        detected_at: chrono::Utc::now(),
                    };
                    file.append(&finding).unwrap();
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        let store = MemoryMetadataStore::default();
        assert_eq!(FindingFile::new(&path).load_into(&store).unwrap(), 160);
    }

    #[test]
    fn finding_file_missing_or_malformed_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        assert!(FindingFile::new(directory.path().join("missing.jsonl"))
            .load_into(&MemoryMetadataStore::default())
            .is_err());
        std::fs::write(directory.path().join("bad.jsonl"), "not json\n").unwrap();
        assert!(FindingFile::new(directory.path().join("bad.jsonl"))
            .load_into(&MemoryMetadataStore::default())
            .is_err());
    }

    #[test]
    fn parse_findings_handles_array_and_jsonl() {
        let one = r#"{"ecosystem":"Npm","package":"a","version":{"ecosystem":"Npm","upstream":"1.0.0","canonical":"1.0.0"},"source":"s","score":9,"rules":[],"summary":"x"}"#;
        assert_eq!(parse_findings(&format!("[{one}]")).unwrap().len(), 1);
        assert_eq!(parse_findings(one).unwrap().len(), 1);
        assert_eq!(parse_findings(&format!("{one}\n{one}")).unwrap().len(), 2);
        assert!(parse_findings("broken").is_err());
    }

    #[test]
    fn findings_from_multiple_sources_keep_the_highest_score() {
        let store = MemoryMetadataStore::default();
        let finding = |source: &str, score: u8| ContentFinding {
            ecosystem: Ecosystem::Npm,
            package: "evil".to_string(),
            version: npm_version("1.0.0"),
            source: source.to_string(),
            score: Some(score.into()),
            scan_incomplete: false,
            rules: vec![],
            summary: source.to_string(),
            detected_at: chrono::Utc::now(),
        };
        store
            .save_content_finding(&finding("static-heuristics", 9))
            .unwrap();
        store.save_content_finding(&finding("guarddog", 1)).unwrap();
        let stored = store
            .content_finding(&Ecosystem::Npm, "evil", &npm_version("1.0.0"))
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.score,
            Some(Decimal::from(9)),
            "a later low score must not weaken enforcement"
        );

        let store = MemoryMetadataStore::default();
        store.save_content_finding(&finding("guarddog", 1)).unwrap();
        store
            .save_content_finding(&finding("static-heuristics", 9))
            .unwrap();
        let stored = store
            .content_finding(&Ecosystem::Npm, "evil", &npm_version("1.0.0"))
            .unwrap()
            .unwrap();
        assert_eq!(stored.score, Some(Decimal::from(9)));
    }

    #[test]
    fn incomplete_finding_takes_precedence_over_any_score() {
        let store = MemoryMetadataStore::default();
        let complete = ContentFinding {
            ecosystem: Ecosystem::Npm,
            package: "evil".to_string(),
            version: npm_version("1.0.0"),
            source: "guarddog".to_string(),
            score: Some(Decimal::from(9)),
            scan_incomplete: false,
            rules: vec![],
            summary: "completed scanner finding".to_string(),
            detected_at: chrono::Utc::now(),
        };
        let incomplete = ContentFinding {
            source: "static-heuristics".to_string(),
            score: None,
            scan_incomplete: true,
            summary: "scanner timed out".to_string(),
            ..complete.clone()
        };
        store.save_content_finding(&complete).unwrap();
        store.save_content_finding(&incomplete).unwrap();

        let stored = store
            .content_finding(&Ecosystem::Npm, "evil", &npm_version("1.0.0"))
            .unwrap()
            .unwrap();

        assert!(stored.scan_incomplete);
        assert_eq!(stored.score, None);
        assert_eq!(stored.summary, "scanner timed out");
    }
    #[test]
    fn content_findings_round_trip_and_replace() {
        let store = MemoryMetadataStore::default();
        assert!(store
            .content_finding(&Ecosystem::Npm, "left-pad", &npm_version("2.0.0"))
            .unwrap()
            .is_none());
        let finding = |score: Decimal, summary: &str| ContentFinding {
            ecosystem: Ecosystem::Npm,
            package: "left-pad".to_string(),
            version: npm_version("2.0.0"),
            source: "static-heuristics".to_string(),
            score: Some(score),
            scan_incomplete: false,
            rules: vec!["install-script-network".to_string()],
            summary: summary.to_string(),
            detected_at: chrono::Utc::now(),
        };
        store
            .save_content_finding(&finding(Decimal::new(75, 1), "first"))
            .unwrap();
        let stored = store
            .content_finding(&Ecosystem::Npm, "left-pad", &npm_version("2.0.0"))
            .unwrap()
            .unwrap();
        assert_eq!(stored.score, Some(Decimal::new(75, 1)));
        store
            .save_content_finding(&finding(Decimal::from(9), "updated"))
            .unwrap();
        let stored = store
            .content_finding(&Ecosystem::Npm, "left-pad", &npm_version("2.0.0"))
            .unwrap()
            .unwrap();
        assert_eq!(stored.score, Some(Decimal::from(9)));
        assert_eq!(stored.summary, "updated");
    }
    #[test]
    fn artifact_key_normalizes_registry_origin_and_extracts_filename() {
        let key = artifact_key(
            "HTTP://Registry.Example:80/left-pad/-/left-pad-1.0.0.tgz?download=1",
            "left-pad",
            "1.0.0",
        );
        assert_eq!(key.source, "http://registry.example");
        assert_eq!(key.filename, "left-pad-1.0.0.tgz");
    }

    #[test]
    fn artifact_key_rejects_unverifiable_tarball_urls() {
        for url in [
            "relative.tgz",
            "ftp://registry.example/package.tgz",
            "https://user:secret@registry.example/package.tgz",
            "https://registry.example/",
        ] {
            assert!(
                ArtifactKey::from_tarball_url(
                    url,
                    &Ecosystem::Npm,
                    "left-pad",
                    &npm_version("1.0.0"),
                )
                .is_err(),
                "{url}"
            );
        }
    }

    #[test]
    fn artifact_put_enforces_size_limit_and_returns_readonly_descriptor() -> Result<()> {
        use std::io::{Read, Write};

        let directory = tempfile::tempdir()?;
        let store = FsArtifactStore {
            root: directory.path().to_path_buf(),
        };
        let key = artifact_key(
            "https://registry.example/pkg/-/pkg-1.0.0.tgz",
            "pkg",
            "1.0.0",
        );
        let missing_digest = "a".repeat(64);
        assert!(store.map(&key, &missing_digest).is_err());
        assert_eq!(store.resolve(&key)?, None);
        let mut exact = Cursor::new(b"1234567890");
        let mut stored = store.put(&mut exact, 10)?;
        store.map(&key, &stored.sha256)?;
        assert_eq!(store.resolve(&key)?.as_deref(), Some(stored.path.as_str()));
        assert_eq!(stored.sha256, hex::encode(Sha256::digest(b"1234567890")));
        assert!(stored.file.metadata()?.permissions().readonly());
        let mut bytes = Vec::new();
        stored.file.read_to_end(&mut bytes)?;
        assert_eq!(bytes, b"1234567890");
        assert!(stored.file.write_all(b"overwrite").is_err());

        let oversized = artifact_key(
            "https://registry.example/oversized/-/oversized-1.0.0.tgz",
            "oversized",
            "1.0.0",
        );
        let mut source = std::io::repeat(b'x').take(11);
        assert!(store.put(&mut source, 10).is_err());
        assert_eq!(store.resolve(&oversized)?, None);
        assert_eq!(fs::read_dir(store.objects_directory()?)?.count(), 1);
        Ok(())
    }
    #[test]
    fn content_addressed_put_is_idempotent_and_reuses_identical_bytes() -> Result<()> {
        use std::io::{Read, Write};

        let directory = tempfile::tempdir()?;
        let store = FsArtifactStore {
            root: directory.path().to_path_buf(),
        };
        let first_key = artifact_key(
            "https://registry.example/left-pad/-/left-pad-1.0.0.tgz",
            "left-pad",
            "1.0.0",
        );
        let second_key = artifact_key(
            "https://mirror.example/left-pad/-/left-pad-1.0.0.tgz",
            "left-pad",
            "1.0.0",
        );
        let path = put_path(&store, &first_key, b"same bytes")?;
        assert_eq!(put_path(&store, &first_key, b"same bytes")?, path);
        assert_eq!(put_path(&store, &second_key, b"same bytes")?, path);
        assert_eq!(store.resolve(&first_key)?.as_deref(), Some(path.as_str()));
        let mut handle = store.open(&second_key)?.unwrap();
        let mut bytes = Vec::new();
        handle.read_to_end(&mut bytes)?;
        assert_eq!(bytes, b"same bytes");
        assert!(handle.write_all(b"overwrite").is_err());
        Ok(())
    }

    #[test]
    fn content_addressed_put_rejects_conflicting_bytes_for_same_identity() -> Result<()> {
        use std::io::Read;

        let directory = tempfile::tempdir()?;
        let store = FsArtifactStore {
            root: directory.path().to_path_buf(),
        };
        let key = artifact_key(
            "https://registry.example/left-pad/-/left-pad-1.0.0.tgz",
            "left-pad",
            "1.0.0",
        );
        let path = put_path(&store, &key, b"original")?;
        assert!(put_path(&store, &key, b"replacement").is_err());
        assert_eq!(store.resolve(&key)?.as_deref(), Some(path.as_str()));
        let mut handle = store.open(&key)?.unwrap();
        let mut bytes = Vec::new();
        handle.read_to_end(&mut bytes)?;
        assert_eq!(bytes, b"original");
        Ok(())
    }

    #[test]
    fn artifact_mapping_survives_reopening_and_detects_corruption() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let key = artifact_key(
            "https://registry.example/left-pad/-/left-pad-1.0.0.tgz",
            "left-pad",
            "1.0.0",
        );
        let path = put_path(
            &FsArtifactStore {
                root: directory.path().to_path_buf(),
            },
            &key,
            b"verified bytes",
        )?;
        let reopened = FsArtifactStore {
            root: directory.path().to_path_buf(),
        };
        assert_eq!(reopened.resolve(&key)?.as_deref(), Some(path.as_str()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&path)?.permissions();
            permissions.set_mode(permissions.mode() | 0o200);
            fs::set_permissions(&path, permissions)?;
        }
        #[cfg(not(unix))]
        {
            let mut permissions = fs::metadata(&path)?.permissions();
            permissions.set_readonly(false);
            fs::set_permissions(&path, permissions)?;
        }

        fs::write(&path, b"tampered bytes")?;
        assert!(reopened.resolve(&key).is_err());
        assert!(reopened.open(&key).is_err());
        Ok(())
    }

    #[test]
    fn explicit_legacy_import_verifies_bytes_and_preserves_original_file() -> Result<()> {
        use sha2::Digest;

        let directory = tempfile::tempdir()?;
        let key = artifact_key(
            "https://registry.example/left-pad/-/left-pad-1.0.0.tgz",
            "left-pad",
            "1.0.0",
        );
        let legacy = directory
            .path()
            .join("artifacts")
            .join("left-pad")
            .join("1.0.0.tgz");
        fs::create_dir_all(legacy.parent().unwrap())?;
        fs::write(&legacy, b"legacy bytes")?;
        let store = FsArtifactStore {
            root: directory.path().to_path_buf(),
        };
        assert_eq!(store.resolve(&key)?, None);
        assert!(store.import_legacy(&key, &"0".repeat(64)).is_err());
        assert_eq!(store.resolve(&key)?, None);
        let digest = hex::encode(Sha256::digest(b"legacy bytes"));
        let object = store.import_legacy(&key, &digest)?;
        assert_eq!(store.resolve(&key)?.as_deref(), Some(object.as_str()));
        assert_eq!(fs::read(legacy)?, b"legacy bytes");
        Ok(())
    }

    #[test]
    fn frozen_lookup_is_scoped_by_source_and_ecosystem() {
        let store = MemoryMetadataStore::default();
        let artifact = |source: &str, ecosystem: Ecosystem, version: &str, sha: &str| {
            let package = PackageCoordinate {
                ecosystem: ecosystem.clone(),
                name: "requests".to_string(),
            };
            let version = PackageVersionId::parse(&ecosystem, version).unwrap();
            FrozenArtifact {
                key: ArtifactKey {
                    source: source.to_string(),
                    ecosystem: ecosystem.clone(),
                    name: package.name.clone(),
                    version: version.clone(),
                    filename: format!("requests-{version}.tgz"),
                },
                package,
                version,
                sha256: sha.to_string(),
                integrity: None,
                path: format!("/tmp/{sha}"),
                frozen_at: chrono::Utc::now(),
            }
        };
        store
            .put_frozen(artifact(
                "https://registry.example",
                Ecosystem::Npm,
                "9.9.9",
                "npm",
            ))
            .unwrap();
        store
            .put_frozen(artifact(
                "https://registry.other",
                Ecosystem::Npm,
                "9.9.9",
                "other",
            ))
            .unwrap();
        store
            .put_frozen(artifact(
                "https://registry.example",
                Ecosystem::PyPi,
                "2.32.3",
                "pypi",
            ))
            .unwrap();
        let found = store
            .latest_frozen_satisfying(
                "https://registry.example",
                &Ecosystem::PyPi,
                "requests",
                None,
            )
            .unwrap();
        assert_eq!(
            found.map(|a| a.version.to_string()),
            Some("2.32.3".to_string())
        );
        let found = store
            .latest_frozen_satisfying("https://registry.other", &Ecosystem::Npm, "requests", None)
            .unwrap();
        assert_eq!(found.map(|a| a.sha256), Some("other".to_string()));
        assert!(store
            .latest_frozen_satisfying("https://missing.example", &Ecosystem::Npm, "requests", None,)
            .unwrap()
            .is_none());
        let pypi_key = ArtifactKey::from_tarball_url(
            "https://registry.example/requests-9.9.9.tgz",
            &Ecosystem::PyPi,
            "requests",
            &PackageVersionId::parse(&Ecosystem::PyPi, "9.9.9").unwrap(),
        )
        .unwrap();
        assert!(store.get_frozen(&pypi_key).unwrap().is_none());
    }

    #[test]
    fn frozen_metadata_is_idempotent_for_same_key_and_rejects_digest_conflicts() -> Result<()> {
        let store = MemoryMetadataStore::default();
        let key = artifact_key(
            "https://registry.example/requests/-/requests-2.32.3.tgz",
            "requests",
            "2.32.3",
        );
        let artifact = |sha256: &str| FrozenArtifact {
            package: PackageCoordinate {
                ecosystem: Ecosystem::Npm,
                name: "requests".to_string(),
            },
            version: npm_version("2.32.3"),
            key: key.clone(),
            sha256: sha256.to_string(),
            integrity: None,
            path: "/tmp/artifact".into(),
            frozen_at: chrono::Utc::now(),
        };
        store.put_frozen(artifact("first"))?;
        store.put_frozen(artifact("first"))?;
        assert!(store.put_frozen(artifact("second")).is_err());
        assert_eq!(
            store.get_frozen(&key)?.map(|stored| stored.sha256),
            Some("first".to_string())
        );
        Ok(())
    }

    #[test]
    fn rejects_traversal_names() {
        let store = FsArtifactStore {
            root: tempfile::tempdir().unwrap().keep(),
        };
        let mut key = artifact_key(
            "https://registry.example/pkg/-/pkg-1.0.0.tgz",
            "pkg",
            "1.0.0",
        );
        for name in ["..", "a/../b", "../escape", "a//b", "/abs", "back\\slash"] {
            key.name = name.to_string();
            assert!(put_path(&store, &key, b"x").is_err());
        }
    }

    #[test]
    fn stores_scoped_names_by_content_address() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = FsArtifactStore {
            root: directory.path().to_path_buf(),
        };
        let scoped = artifact_key(
            "https://registry.example/@scope/pkg/-/pkg-1.0.0.tgz",
            "@scope/pkg",
            "1.0.0",
        );
        let unscoped = artifact_key(
            "https://registry.example/scope+pkg/-/scope+pkg-1.0.0.tgz",
            "scope+pkg",
            "1.0.0",
        );
        let path = put_path(&store, &scoped, b"bytes")?;
        assert_eq!(put_path(&store, &unscoped, b"bytes")?, path);
        assert_eq!(store.resolve(&scoped)?.as_deref(), Some(path.as_str()));
        assert_eq!(store.resolve(&unscoped)?.as_deref(), Some(path.as_str()));
        Ok(())
    }

    #[test]
    fn resolves_only_indexed_artifacts_and_opens_readonly_handle() -> Result<()> {
        use std::io::{Read, Write};

        let directory = tempfile::tempdir()?;
        let store = FsArtifactStore {
            root: directory.path().to_path_buf(),
        };
        let key = artifact_key(
            "https://registry.example/pkg/-/pkg-1.0.0.tgz",
            "pkg",
            "1.0.0",
        );
        let path = put_path(&store, &key, b"artifact")?;
        assert_eq!(store.resolve(&key)?, Some(path));
        let mut handle = store.open(&key)?.unwrap();
        let mut bytes = Vec::new();
        handle.read_to_end(&mut bytes)?;
        assert_eq!(bytes, b"artifact");
        assert!(handle.write_all(b"overwrite").is_err());
        let missing = artifact_key(
            "https://registry.example/missing/-/missing-1.0.0.tgz",
            "missing",
            "1.0.0",
        );
        assert_eq!(store.resolve(&missing)?, None);
        assert!(store.open(&missing)?.is_none());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escapes_for_content_writes_and_open() -> Result<()> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let store = FsArtifactStore {
            root: directory.path().to_path_buf(),
        };
        let key = artifact_key(
            "https://registry.example/pkg/-/pkg-1.0.0.tgz",
            "pkg",
            "1.0.0",
        );
        let secret = outside.path().join("secret");
        fs::write(&secret, b"secret")?;
        fs::create_dir(directory.path().join("artifacts"))?;
        symlink(outside.path(), directory.path().join("artifacts/sha256"))?;
        assert!(put_path(&store, &key, b"overwrite").is_err());
        assert_eq!(fs::read(&secret)?, b"secret");

        fs::remove_file(directory.path().join("artifacts/sha256"))?;
        fs::create_dir(directory.path().join("artifacts/sha256"))?;
        let path = put_path(&store, &key, b"verified")?;
        fs::remove_file(&path)?;
        symlink(&secret, &path)?;
        assert!(store.resolve(&key).is_err());
        assert!(store.open(&key).is_err());
        assert_eq!(fs::read(&secret)?, b"secret");
        Ok(())
    }
}
