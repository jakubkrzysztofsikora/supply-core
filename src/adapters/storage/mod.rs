use crate::{
    domain::*,
    ports::{ArtifactStore, MetadataStore},
};
use anyhow::Result;
use semver::{Version, VersionReq};
use std::{fs, path::PathBuf, sync::Mutex};

pub struct FsArtifactStore {
    pub root: PathBuf,
}
fn sanitize_package_name(name: &str) -> Result<String> {
    if name.contains('\\')
        || name
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        anyhow::bail!("invalid package name: {name:?}");
    }
    Ok(name.replace('/', "+").replace('@', ""))
}
impl ArtifactStore for FsArtifactStore {
    fn put(&self, name: &str, version: &Version, bytes: &[u8]) -> Result<String> {
        let safe = sanitize_package_name(name)?;
        let dir = self.root.join("artifacts").join(safe);
        fs::create_dir_all(&dir)?;
        let p = dir.join(format!("{version}.tgz"));
        fs::write(&p, bytes)?;
        Ok(p.display().to_string())
    }
    fn get(&self, path: &str) -> Result<Vec<u8>> {
        Ok(fs::read(path)?)
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
        name: &str,
        requested: Option<&VersionReq>,
    ) -> Result<Option<FrozenArtifact>> {
        Ok(self
            .frozen
            .lock()
            .map_err(|_| anyhow::anyhow!("lock poisoned"))?
            .iter()
            .filter(|a| a.package.name == name)
            .filter(|a| requested.is_none_or(|r| r.matches(&a.version)))
            .max_by(|a, b| a.version.cmp(&b.version))
            .cloned())
    }
    fn get_frozen(&self, name: &str, version: &Version) -> Result<Option<FrozenArtifact>> {
        Ok(self
            .frozen
            .lock()
            .map_err(|_| anyhow::anyhow!("lock poisoned"))?
            .iter()
            .find(|a| a.package.name == name && a.version == *version)
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
        Ok(())
    }
}
