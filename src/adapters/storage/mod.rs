use crate::{
    domain::*,
    ports::{ArtifactStore, MetadataStore},
};
use anyhow::Result;
use semver::{Version, VersionReq};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

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
    fn confined_file(&self, path: &Path) -> Result<PathBuf> {
        let artifacts_root = self.root.canonicalize()?.join("artifacts");
        if !fs::symlink_metadata(&artifacts_root)?.file_type().is_dir() {
            anyhow::bail!("artifact directory is not a plain directory");
        }
        let canonical = path.canonicalize()?;
        if !canonical.starts_with(&artifacts_root) {
            anyhow::bail!("artifact path escapes store root: {}", canonical.display());
        }
        if !fs::metadata(&canonical)?.is_file() {
            anyhow::bail!(
                "artifact path is not a regular file: {}",
                canonical.display()
            );
        }
        Ok(canonical)
    }
}
impl ArtifactStore for FsArtifactStore {
    fn put(&self, name: &str, version: &Version, bytes: &[u8]) -> Result<String> {
        let safe = sanitize_package_name(name)?;
        fs::create_dir_all(&self.root)?;
        let artifacts_root = self.root.canonicalize()?.join("artifacts");
        ensure_directory(&artifacts_root)?;
        let dir = artifacts_root.join(safe);
        ensure_directory(&dir)?;
        let p = dir.join(format!("{version}.tgz"));
        let mut file = match fs::OpenOptions::new().write(true).create_new(true).open(&p) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                anyhow::bail!("artifact already exists: {}", p.display())
            }
            Err(e) => return Err(e.into()),
        };
        if let Err(error) = file.write_all(bytes) {
            drop(file);
            let _ = fs::remove_file(&p);
            return Err(error.into());
        }
        Ok(p.display().to_string())
    }
    fn resolve(&self, name: &str, version: &Version) -> Result<Option<String>> {
        let safe = match sanitize_package_name(name) {
            Ok(s) => s,
            Err(_) => return Ok(None),
        };
        let p = self
            .root
            .join("artifacts")
            .join(safe)
            .join(format!("{version}.tgz"));
        match fs::symlink_metadata(&p) {
            Ok(_) => Ok(Some(self.confined_file(&p)?.display().to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    fn read(&self, path: &str) -> Result<Vec<u8>> {
        let canonical = self.confined_file(Path::new(path))?;
        Ok(fs::read(&canonical)?)
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
        version: &Version,
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
            .max_by_key(|finding| finding.score)
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
        ecosystem: &Ecosystem,
        name: &str,
        requested: Option<&VersionReq>,
    ) -> Result<Option<FrozenArtifact>> {
        Ok(self
            .frozen
            .lock()
            .map_err(|_| anyhow::anyhow!("lock poisoned"))?
            .iter()
            .filter(|a| a.package.ecosystem == *ecosystem)
            .filter(|a| a.package.name == name)
            .filter(|a| requested.is_none_or(|r| r.matches(&a.version)))
            .max_by(|a, b| a.version.cmp(&b.version))
            .cloned())
    }
    fn get_frozen(
        &self,
        ecosystem: &Ecosystem,
        name: &str,
        version: &Version,
    ) -> Result<Option<FrozenArtifact>> {
        Ok(self
            .frozen
            .lock()
            .map_err(|_| anyhow::anyhow!("lock poisoned"))?
            .iter()
            .find(|a| {
                a.package.ecosystem == *ecosystem && a.package.name == name && a.version == *version
            })
            .cloned())
    }
    fn put_frozen(&self, a: FrozenArtifact) -> Result<()> {
        self.frozen
            .lock()
            .map_err(|_| anyhow::anyhow!("lock poisoned"))?
            .push(a);
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
            unsafe {
                libc::flock(lock.as_raw_fd(), libc::LOCK_EX);
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

    #[test]
    fn finding_file_round_trips_jsonl_and_array() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("findings.jsonl");
        let file = FindingFile::new(&path);
        let finding = |package: &str| ContentFinding {
            ecosystem: Ecosystem::Npm,
            package: package.to_string(),
            version: Version::parse("1.0.0").unwrap(),
            source: "static-heuristics".to_string(),
            score: 9,
            rules: vec![],
            summary: package.to_string(),
            detected_at: chrono::Utc::now(),
        };
        file.append(&finding("a")).unwrap();
        file.append(&finding("b")).unwrap();

        let store = MemoryMetadataStore::default();
        assert_eq!(file.load_into(&store).unwrap(), 2);
        assert!(store
            .content_finding(&Ecosystem::Npm, "a", &Version::parse("1.0.0").unwrap())
            .unwrap()
            .is_some());
        assert!(store
            .content_finding(&Ecosystem::Npm, "b", &Version::parse("1.0.0").unwrap())
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
            .content_finding(&Ecosystem::Npm, "c", &Version::parse("1.0.0").unwrap())
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
            version: Version::parse("1.0.0").unwrap(),
            source: "static-heuristics".to_string(),
            score: 9,
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
            version: Version::parse("1.0.0").unwrap(),
            source: "static-heuristics".to_string(),
            score: 9,
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
            .content_finding(&Ecosystem::Npm, "a", &Version::parse("1.0.0").unwrap())
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
            version: Version::parse("1.0.0").unwrap(),
            source: "static-heuristics".to_string(),
            score: 9,
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
                        version: Version::parse("1.0.0").unwrap(),
                        source: "static-heuristics".to_string(),
                        score: 9,
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
        let one = r#"{"ecosystem":"Npm","package":"a","version":"1.0.0","source":"s","score":9,"rules":[],"summary":"x"}"#;
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
            version: Version::parse("1.0.0").unwrap(),
            source: source.to_string(),
            score,
            rules: vec![],
            summary: source.to_string(),
            detected_at: chrono::Utc::now(),
        };
        store
            .save_content_finding(&finding("static-heuristics", 9))
            .unwrap();
        store.save_content_finding(&finding("guarddog", 1)).unwrap();
        let stored = store
            .content_finding(&Ecosystem::Npm, "evil", &Version::parse("1.0.0").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.score, 9,
            "a later low score must not weaken enforcement"
        );

        let store = MemoryMetadataStore::default();
        store.save_content_finding(&finding("guarddog", 1)).unwrap();
        store
            .save_content_finding(&finding("static-heuristics", 9))
            .unwrap();
        let stored = store
            .content_finding(&Ecosystem::Npm, "evil", &Version::parse("1.0.0").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(stored.score, 9);
    }
    #[test]
    fn content_findings_round_trip_and_replace() {
        let store = MemoryMetadataStore::default();
        assert!(store
            .content_finding(
                &Ecosystem::Npm,
                "left-pad",
                &Version::parse("2.0.0").unwrap()
            )
            .unwrap()
            .is_none());
        let finding = |score: u8, summary: &str| ContentFinding {
            ecosystem: Ecosystem::Npm,
            package: "left-pad".to_string(),
            version: Version::parse("2.0.0").unwrap(),
            source: "static-heuristics".to_string(),
            score,
            rules: vec!["install-script-network".to_string()],
            summary: summary.to_string(),
            detected_at: chrono::Utc::now(),
        };
        store.save_content_finding(&finding(5, "first")).unwrap();
        let stored = store
            .content_finding(
                &Ecosystem::Npm,
                "left-pad",
                &Version::parse("2.0.0").unwrap(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(stored.score, 5);
        store.save_content_finding(&finding(9, "updated")).unwrap();
        let stored = store
            .content_finding(
                &Ecosystem::Npm,
                "left-pad",
                &Version::parse("2.0.0").unwrap(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(stored.score, 9);
        assert_eq!(stored.summary, "updated");
    }
    #[test]
    fn frozen_lookup_is_ecosystem_scoped() {
        let store = MemoryMetadataStore::default();
        let artifact = |ecosystem, version: &str, sha: &str| FrozenArtifact {
            package: PackageCoordinate {
                ecosystem,
                name: "requests".to_string(),
            },
            version: Version::parse(version).unwrap(),
            sha256: sha.to_string(),
            integrity: None,
            path: format!("/tmp/{version}"),
            frozen_at: chrono::Utc::now(),
        };
        store
            .put_frozen(artifact(Ecosystem::Npm, "9.9.9", "npm"))
            .unwrap();
        store
            .put_frozen(artifact(Ecosystem::PyPi, "2.32.3", "pypi"))
            .unwrap();
        let found = store
            .latest_frozen_satisfying(&Ecosystem::PyPi, "requests", None)
            .unwrap();
        assert_eq!(
            found.map(|a| a.version.to_string()),
            Some("2.32.3".to_string()),
            "a pip fallback must never resolve to the npm artifact"
        );
        let found = store
            .latest_frozen_satisfying(&Ecosystem::Npm, "requests", None)
            .unwrap();
        assert_eq!(
            found.map(|a| a.version.to_string()),
            Some("9.9.9".to_string())
        );
        assert!(store
            .get_frozen(
                &Ecosystem::PyPi,
                "requests",
                &Version::parse("9.9.9").unwrap()
            )
            .unwrap()
            .is_none());
    }
    #[test]
    fn rejects_traversal_names() {
        let store = FsArtifactStore {
            root: tempfile::tempdir().unwrap().keep(),
        };
        for name in ["..", "a/../b", "../escape", "a//b", "/abs", "back\\slash"] {
            assert!(store
                .put(name, &Version::parse("1.0.0").unwrap(), b"x")
                .is_err());
        }
    }

    #[test]
    fn stores_scoped_names() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store = FsArtifactStore {
            root: dir.path().to_path_buf(),
        };
        store.put("@scope/pkg", &Version::parse("1.0.0")?, b"bytes")?;
        let written = dir
            .path()
            .join("artifacts")
            .join("scope+pkg")
            .join("1.0.0.tgz");
        assert!(written.exists());
        assert_eq!(store.read(written.to_str().unwrap())?, b"bytes");
        // These previously aliased the scoped package's directory.
        for name in [
            "scope+pkg",
            "scope/pkg",
            "@@scope/pkg",
            "@scope+pkg",
            "Scope",
        ] {
            assert!(store
                .put(name, &Version::parse("1.0.0")?, b"overwrite")
                .is_err());
        }
        assert_eq!(store.read(written.to_str().unwrap())?, b"bytes");
        Ok(())
    }

    #[test]
    fn reads_are_confined_to_regular_artifact_files() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store = FsArtifactStore {
            root: dir.path().to_path_buf(),
        };
        let version = Version::parse("1.0.0")?;
        let path = store.put("pkg", &version, b"artifact")?;
        assert_eq!(store.resolve("pkg", &version)?, Some(path.clone()));
        assert_eq!(store.read(&path)?, b"artifact");
        fs::write(dir.path().join("secret"), b"secret")?;
        for path in [
            dir.path().join("secret"),
            dir.path().join("artifacts/../secret"),
            dir.path().join("artifacts/pkg"),
        ] {
            assert!(store.read(path.to_str().unwrap()).is_err());
        }
        assert_eq!(store.resolve("missing", &version)?, None);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escapes_for_reads_resolution_and_writes() -> Result<()> {
        use std::os::unix::fs::symlink;
        for component in ["artifacts", "artifacts/pkg", "artifacts/pkg/1.0.0.tgz"] {
            let dir = tempfile::tempdir()?;
            let outside = tempfile::tempdir()?;
            let store = FsArtifactStore {
                root: dir.path().to_path_buf(),
            };
            let version = Version::parse("1.0.0")?;
            let link = dir.path().join(component);
            fs::create_dir_all(link.parent().unwrap())?;
            let target = if component.ends_with(".tgz") {
                outside.path().join("1.0.0.tgz")
            } else {
                outside.path().to_path_buf()
            };
            fs::create_dir_all(outside.path().join("pkg"))?;
            fs::write(outside.path().join("1.0.0.tgz"), b"secret")?;
            fs::write(outside.path().join("pkg/1.0.0.tgz"), b"secret")?;
            symlink(&target, &link)?;
            assert!(store.put("pkg", &version, b"overwrite").is_err());
            assert!(store.resolve("pkg", &version).is_err());
            assert!(store
                .read(dir.path().join("artifacts/pkg/1.0.0.tgz").to_str().unwrap())
                .is_err());
            assert_eq!(fs::read(outside.path().join("1.0.0.tgz"))?, b"secret");
            assert_eq!(fs::read(outside.path().join("pkg/1.0.0.tgz"))?, b"secret");
        }
        Ok(())
    }
}
