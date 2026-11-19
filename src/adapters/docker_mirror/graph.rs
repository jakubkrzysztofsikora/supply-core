use super::{valid_digest, MirrorError, Result, MANIFEST_TYPES, MAX_MANIFEST};
use anyhow::{ensure, Context};
use futures_util::{stream, StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use tokio::{fs, io::AsyncWriteExt};

use super::upstream::{Manifest, Repository};

const MAX_OBJECTS: usize = 4096;
const MAX_MANIFESTS: usize = 128;
const MAX_DEPTH: usize = 8;
const MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const ATTESTATION_TYPE: &str = "application/vnd.in-toto+json";

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    media_type: String,
    digest: String,
    size: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    annotations: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Document {
    schema_version: u32,
    media_type: Option<String>,
    manifests: Option<Vec<Descriptor>>,
    config: Option<Descriptor>,
    layers: Option<Vec<Descriptor>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Verdict {
    Clean,
    Vulnerable,
}

#[derive(Clone)]
pub(super) struct Object {
    pub digest: String,
    pub media_type: String,
    pub manifest: bool,
    pub size: u64,
}

struct Leaf {
    manifest: Descriptor,
    blobs: Vec<Descriptor>,
}

pub(super) struct Graph {
    pub objects: Vec<Object>,
    leaves: Vec<Leaf>,
    pub bytes: u64,
}

pub(super) fn object_path(root: &Path, digest: &str) -> PathBuf {
    root.join("blobs/sha256").join(&digest["sha256:".len()..])
}

fn parse(manifest: &Manifest) -> anyhow::Result<Document> {
    let doc: Document = serde_json::from_slice(&manifest.bytes)?;
    ensure!(doc.schema_version == 2, "unsupported manifest schema");
    ensure!(
        doc.media_type
            .as_ref()
            .is_none_or(|kind| kind == &manifest.media_type),
        "manifest type does not match its content"
    );
    Ok(doc)
}

fn descriptor(desc: &Descriptor) -> anyhow::Result<()> {
    ensure!(valid_digest(&desc.digest), "invalid descriptor digest");
    ensure!(desc.size <= MAX_BYTES, "descriptor exceeds size limit");
    Ok(())
}

impl Graph {
    pub async fn fetch(repo: &Repository, root: Manifest, staging: &Path) -> Result<Self> {
        fs::create_dir_all(staging.join("blobs/sha256"))
            .await
            .map_err(MirrorError::internal)?;

        let mut metadata = vec![(root, 0_usize, None::<String>)];
        let mut manifests = BTreeMap::<String, (Object, Option<String>)>::new();
        let mut blobs = BTreeMap::<String, Descriptor>::new();
        let mut leaves = Vec::new();
        let mut attachment_configs = BTreeMap::new();
        let mut predicates = BTreeSet::new();
        let mut bytes = 0;
        let mut discovered = 1;
        while let Some((manifest, depth, subject)) = metadata.pop() {
            if let Some((_, prior_subject)) = manifests.get(&manifest.digest) {
                if prior_subject != &subject {
                    return Err(MirrorError::invalid(anyhow::anyhow!(
                        "conflicting attestation descriptor"
                    )));
                }
                continue;
            }
            let doc = parse(&manifest).map_err(MirrorError::invalid)?;
            let is_index = MANIFEST_TYPES[..2].contains(&manifest.media_type.as_str());
            if is_index {
                let children = doc
                    .manifests
                    .filter(|list| !list.is_empty())
                    .ok_or_else(|| {
                        MirrorError::invalid(anyhow::anyhow!("empty or invalid image index"))
                    })?;
                if depth >= MAX_DEPTH
                    || discovered + children.len() > MAX_MANIFESTS
                    || subject.is_some()
                    || doc.config.is_some()
                    || doc.layers.is_some()
                {
                    return Err(MirrorError::invalid(anyhow::anyhow!(
                        "invalid image index or graph limit exceeded"
                    )));
                }
                discovered += children.len();
                let runnable_children = children
                    .iter()
                    .filter(|child| !child.annotations.contains_key("vnd.docker.reference.type"))
                    .map(|child| child.digest.clone())
                    .collect::<BTreeSet<_>>();
                let mut children_to_fetch = Vec::with_capacity(children.len());
                for child in children {
                    descriptor(&child).map_err(MirrorError::invalid)?;
                    if child.size > MAX_MANIFEST as u64
                        || !MANIFEST_TYPES.contains(&child.media_type.as_str())
                    {
                        return Err(MirrorError::invalid(anyhow::anyhow!(
                            "invalid child manifest"
                        )));
                    }
                    let subject = match child
                        .annotations
                        .get("vnd.docker.reference.type")
                        .map(String::as_str)
                    {
                        None => None,
                        Some("attestation-manifest") => {
                            let linked = child
                                .annotations
                                .get("vnd.docker.reference.digest")
                                .filter(|linked| runnable_children.contains(linked.as_str()))
                                .ok_or_else(|| {
                                    MirrorError::invalid(anyhow::anyhow!(
                                        "attestation subject is absent"
                                    ))
                                })?;
                            Some(linked.clone())
                        }
                        Some(_) => {
                            return Err(MirrorError::invalid(anyhow::anyhow!(
                                "unsupported manifest attachment"
                            )))
                        }
                    };
                    children_to_fetch.push((child, subject));
                }
                let fetched = stream::iter(children_to_fetch)
                    .map(|(child, subject)| {
                        let repo = repo.clone();
                        async move {
                            let fetched = repo.manifest(&child.digest).await?;
                            if fetched.media_type != child.media_type
                                || fetched.bytes.len() as u64 != child.size
                            {
                                return Err(MirrorError::invalid(anyhow::anyhow!(
                                    "child manifest descriptor mismatch"
                                )));
                            }
                            Ok((fetched, depth + 1, subject))
                        }
                    })
                    .buffer_unordered(4)
                    .try_collect::<Vec<_>>()
                    .await?;
                metadata.extend(fetched);
            } else {
                let config = doc.config.ok_or_else(|| {
                    MirrorError::invalid(anyhow::anyhow!("image config is missing"))
                })?;
                let layers = doc.layers.ok_or_else(|| {
                    MirrorError::invalid(anyhow::anyhow!("image layers are missing"))
                })?;
                let valid_config = matches!(
                    config.media_type.as_str(),
                    "application/vnd.oci.image.config.v1+json"
                        | "application/vnd.docker.container.image.v1+json"
                ) || subject.is_some()
                    && config.media_type == "application/vnd.oci.empty.v1+json";
                if doc.manifests.is_some()
                    || !valid_config
                    || config.size > MAX_MANIFEST as u64
                    || layers.len() >= MAX_OBJECTS
                    || (subject.is_some() && layers.is_empty())
                {
                    return Err(MirrorError::invalid(anyhow::anyhow!(
                        "invalid image config or layers"
                    )));
                }
                for layer in &layers {
                    let valid = if subject.is_some() {
                        layer.media_type == ATTESTATION_TYPE && layer.size <= 32 * 1024 * 1024
                    } else {
                        matches!(
                            layer.media_type.as_str(),
                            "application/vnd.oci.image.layer.v1.tar"
                                | "application/vnd.oci.image.layer.v1.tar+gzip"
                                | "application/vnd.oci.image.layer.v1.tar+zstd"
                                | "application/vnd.docker.image.rootfs.diff.tar"
                                | "application/vnd.docker.image.rootfs.diff.tar.gzip"
                        )
                    };
                    if !valid {
                        return Err(MirrorError::invalid(anyhow::anyhow!(
                            "unsupported image layer media type"
                        )));
                    }
                }
                if subject.is_some() {
                    attachment_configs.insert(
                        config.digest.clone(),
                        config.media_type == "application/vnd.oci.empty.v1+json",
                    );
                    predicates.extend(layers.iter().map(|layer| layer.digest.clone()));
                }
                let inputs = std::iter::once(config).chain(layers).collect::<Vec<_>>();
                for blob in &inputs {
                    descriptor(blob).map_err(MirrorError::invalid)?;
                    if let Some(previous) = blobs.get(&blob.digest) {
                        if previous.size != blob.size {
                            return Err(MirrorError::invalid(anyhow::anyhow!(
                                "conflicting blob descriptor"
                            )));
                        }
                    } else {
                        bytes = account(bytes, blob.size)?;
                        blobs.insert(blob.digest.clone(), blob.clone());
                    }
                }
                if subject.is_none() {
                    leaves.push(Leaf {
                        manifest: Descriptor {
                            digest: manifest.digest.clone(),
                            media_type: manifest.media_type.clone(),
                            size: manifest.bytes.len() as u64,
                            annotations: BTreeMap::new(),
                        },
                        blobs: inputs,
                    });
                }
            }
            if manifests.len() + blobs.len() >= MAX_OBJECTS {
                return Err(MirrorError::invalid(anyhow::anyhow!(
                    "too many registry objects"
                )));
            }
            let size = manifest.bytes.len() as u64;
            bytes = account(bytes, size)?;
            fs::write(object_path(staging, &manifest.digest), &manifest.bytes)
                .await
                .map_err(MirrorError::internal)?;
            manifests.insert(
                manifest.digest.clone(),
                (
                    Object {
                        digest: manifest.digest,
                        media_type: manifest.media_type,
                        manifest: true,
                        size,
                    },
                    subject,
                ),
            );
        }
        if leaves.is_empty()
            || manifests.values().any(|(_, subject)| {
                subject.as_ref().is_some_and(|digest| {
                    !leaves.iter().any(|leaf| &leaf.manifest.digest == digest)
                })
            })
        {
            return Err(MirrorError::invalid(anyhow::anyhow!(
                "image graph has no runnable image or has an invalid attestation subject"
            )));
        }
        let mut objects = manifests
            .into_values()
            .map(|(object, _)| object)
            .collect::<Vec<_>>();
        for hash in blobs.keys() {
            if objects.iter().any(|object| &object.digest == hash) {
                return Err(MirrorError::invalid(anyhow::anyhow!(
                    "digest is both a blob and a manifest"
                )));
            }
        }
        let fetched = stream::iter(blobs.into_values())
            .map(|blob| {
                let repo = repo.clone();
                let staging = staging.to_owned();
                async move {
                    fetch_blob(&repo, &staging, &blob).await?;
                    Ok(Object {
                        digest: blob.digest,
                        media_type: "application/octet-stream".into(),
                        manifest: false,
                        size: blob.size,
                    })
                }
            })
            .buffer_unordered(4)
            .try_collect::<Vec<_>>()
            .await?;
        objects.extend(fetched);
        for (hash, empty) in attachment_configs {
            let bytes = fs::read(object_path(staging, &hash))
                .await
                .map_err(MirrorError::internal)?;
            let config: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(MirrorError::invalid)?;
            let valid = if empty {
                config.as_object().is_some_and(serde_json::Map::is_empty)
            } else {
                config
                    .get("architecture")
                    .and_then(serde_json::Value::as_str)
                    == Some("unknown")
                    && config.get("os").and_then(serde_json::Value::as_str) == Some("unknown")
            };
            if !valid {
                return Err(MirrorError::invalid(anyhow::anyhow!(
                    "attestation config describes a runnable image"
                )));
            }
        }
        for hash in predicates {
            let bytes = fs::read(object_path(staging, &hash))
                .await
                .map_err(MirrorError::internal)?;
            let statement: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(MirrorError::invalid)?;
            if statement
                .get("predicateType")
                .and_then(serde_json::Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err(MirrorError::invalid(anyhow::anyhow!(
                    "invalid attestation statement"
                )));
            }
        }
        Ok(Self {
            objects,
            leaves,
            bytes,
        })
    }

    pub fn scan(
        &self,
        staging: &Path,
        scan: impl Fn(&Path) -> anyhow::Result<Verdict>,
    ) -> anyhow::Result<Verdict> {
        for leaf in &self.leaves {
            let layout = tempfile::tempdir_in(staging)?;
            std::fs::create_dir_all(layout.path().join("blobs/sha256"))?;
            std::fs::write(
                layout.path().join("oci-layout"),
                br#"{"imageLayoutVersion":"1.0.0"}"#,
            )?;
            std::fs::write(
                layout.path().join("index.json"),
                serde_json::to_vec(&serde_json::json!({
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "manifests": [&leaf.manifest],
                }))?,
            )?;
            for entry in std::iter::once(&leaf.manifest).chain(&leaf.blobs) {
                let target = object_path(layout.path(), &entry.digest);
                if !target.exists() {
                    std::fs::hard_link(object_path(staging, &entry.digest), target)?;
                }
            }
            if scan(layout.path())? == Verdict::Vulnerable {
                return Ok(Verdict::Vulnerable);
            }
        }
        Ok(Verdict::Clean)
    }
}

fn account(bytes: u64, additional: u64) -> Result<u64> {
    bytes
        .checked_add(additional)
        .filter(|sum| *sum <= MAX_BYTES)
        .ok_or_else(|| MirrorError::invalid(anyhow::anyhow!("image graph exceeds size limit")))
}

async fn fetch_blob(repo: &Repository, staging: &Path, blob: &Descriptor) -> Result<()> {
    let mut response = repo.blob(&blob.digest).await?;
    if response
        .content_length()
        .is_some_and(|size| size != blob.size)
    {
        return Err(MirrorError::invalid(anyhow::anyhow!(
            "blob descriptor size mismatch"
        )));
    }
    let mut writer = fs::File::create(object_path(staging, &blob.digest))
        .await
        .map_err(MirrorError::internal)?;
    let mut sha = Sha256::new();
    let mut size = 0;
    while let Some(chunk) = response.chunk().await.map_err(MirrorError::upstream)? {
        size += chunk.len() as u64;
        if size > blob.size {
            return Err(MirrorError::invalid(anyhow::anyhow!(
                "blob exceeds descriptor size"
            )));
        }
        sha.update(&chunk);
        writer
            .write_all(&chunk)
            .await
            .map_err(MirrorError::internal)?;
    }
    async {
        ensure!(size == blob.size, "blob descriptor size mismatch");
        ensure!(
            format!("sha256:{}", hex::encode(sha.finalize())) == blob.digest,
            "blob digest mismatch"
        );
        writer.sync_data().await.context("sync quarantined blob")
    }
    .await
    .map_err(MirrorError::invalid)
}
