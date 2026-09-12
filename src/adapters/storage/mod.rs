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
}
impl MetadataStore for MemoryMetadataStore {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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
