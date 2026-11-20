mod engines;
use crate::application::ledger::{
    engine_policy_revision_sha256, scan_cache_key_sha256, ArtifactReport, Coverage, EngineReport,
    ScanDecision,
};
use crate::application::scanner::{stage_archive_path, StagedArchive};
use crate::domain::{Policy, Severity};
use anyhow::{ensure, Context, Result};
use flate2::read::MultiGzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use tar::Archive;

const MAX_ARCHIVE_ENTRIES: usize = 10_000;
const MAX_IMAGES: usize = 1_000;
const MAX_LAYERS: usize = 10_000;
const MAX_IMAGE_METADATA_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TOTAL_METADATA_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LAYER_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_INDEX_DEPTH: usize = 8;
const ARCHIVE_RULE_REVISION: &str = "supply-core-image-archive-v1";

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    SignatureUnchecked,
    Verified,
    Invalid,
    Incomplete,
}

#[derive(Debug, Serialize)]
pub struct ImageScanReport {
    #[serde(flatten)]
    pub report: ArtifactReport,
    pub signature_status: SignatureStatus,
}

pub struct ImageScanOptions<'a> {
    pub scratch_dir: Option<&'a Path>,
    pub image_ref: Option<&'a str>,
    pub require_signature: bool,
    pub certificate_identity: Option<&'a str>,
    pub certificate_oidc_issuer: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveKind {
    DockerSave,
    Oci,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompressionKind {
    Plain,
    Gzip,
    Zstd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemberKind {
    File,
    Directory,
    Symlink,
    Hardlink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LayerMember {
    path: String,
    kind: MemberKind,
    mode: u32,
    size: u64,
    sha256: String,
    link_target: Option<String>,
    whiteout_target: Option<String>,
    binary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LayerInventory {
    raw_tar_sha256: String,
    raw_tar_size: u64,
    members: Vec<LayerMember>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LayerReference {
    archive_path: String,
    diff_id: String,
    media_type: Option<String>,
}

#[derive(Debug, Clone)]
struct ImageChain {
    config_digest: String,
    config_size: u64,
    layers: Vec<LayerReference>,
    entrypoint: Vec<String>,
}

struct OuterMember {
    size: u64,
    sha256: String,
    directory: bool,
}

struct OuterInventory {
    members: BTreeMap<String, OuterMember>,
    expanded_bytes: u64,
}

struct InspectedImage {
    kind: ArchiveKind,
    chains: Vec<ImageChain>,
    layer_inventories: BTreeMap<String, LayerInventory>,
    layer_roots: Vec<PathBuf>,
    regular_files: u64,
    executable_files: u64,
    manifest_digests: BTreeSet<String>,
}

#[derive(Deserialize)]
struct DockerManifest {
    #[serde(rename = "Config")]
    config: String,
    #[serde(rename = "Layers")]
    layers: Vec<String>,
}

#[derive(Deserialize)]
struct ImageConfig {
    rootfs: RootFs,
    #[serde(default)]
    config: Option<RuntimeConfig>,
}

#[derive(Deserialize)]
struct RootFs {
    #[serde(rename = "type")]
    kind: String,
    diff_ids: Vec<String>,
}

#[derive(Deserialize)]
struct RuntimeConfig {
    #[serde(rename = "Entrypoint", default)]
    entrypoint: Option<Vec<String>>,
    #[serde(rename = "Cmd", default)]
    command: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct OciLayout {
    #[serde(rename = "imageLayoutVersion")]
    image_layout_version: String,
}

#[derive(Deserialize)]
struct OciIndex {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    manifests: Vec<OciDescriptor>,
}

#[derive(Deserialize)]
struct OciManifest {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    config: OciDescriptor,
    layers: Vec<OciDescriptor>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct OciDescriptor {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
    size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OciMetadataKind {
    Index,
    Manifest,
}

pub fn scan_image(
    archive_path: &Path,
    policy: &Policy,
    options: ImageScanOptions<'_>,
) -> Result<ImageScanReport> {
    let mut artifact_sha256 = None;
    let mut signature_status = if options.require_signature {
        SignatureStatus::Incomplete
    } else {
        SignatureStatus::SignatureUnchecked
    };
    let mut engines = Vec::new();
    let mut required_sources = vec!["image-archive", "trivy", "yarahunter"];
    let mut inspected = None;
    let mut staged_archive = None;
    let mut archive_failure = Some("scratch_directory_required");

    if let Some(scratch_dir) = options.scratch_dir {
        match stage_archive_path(archive_path, scratch_dir) {
            Ok(mut staged) => {
                artifact_sha256 = Some(staged.sha256().to_owned());
                match inspect_image(&mut staged) {
                    Ok(image) => {
                        archive_failure = None;
                        inspected = Some(image);
                        staged_archive = Some(staged);
                    }
                    Err(_) => archive_failure = Some("image_archive_invalid"),
                }
            }
            Err(_) => archive_failure = Some("image_archive_unavailable"),
        }
    }

    let image = inspected.as_ref();
    let integrity = if archive_failure.is_none() {
        complete_engine_report(
            "image-archive",
            artifact_sha256.as_deref(),
            image.map_or(1, |_| 1),
            ARCHIVE_RULE_REVISION,
        )
    } else {
        let mut report = failed_engine_report(
            "image-archive",
            artifact_sha256.as_deref(),
            1,
            archive_failure.unwrap_or("image_archive_invalid"),
        );
        if archive_failure == Some("image_archive_invalid") {
            report.coverage = Coverage::Partial;
        }
        report
    };
    engines.push(integrity);

    let regular_files = image.map_or(0, |image| image.regular_files);
    if let (Some(image), Some(staged)) = (image, staged_archive.as_ref()) {
        engines.push(engines::trivy_report(staged, artifact_sha256.as_deref()));
        engines.push(engines::yarahunter_report(
            staged,
            image,
            artifact_sha256.as_deref(),
        ));
    } else {
        let reason = archive_failure.unwrap_or("image_archive_invalid");
        engines.push(failed_engine_report(
            "trivy",
            artifact_sha256.as_deref(),
            1,
            reason,
        ));
        engines.push(failed_engine_report(
            "yarahunter",
            artifact_sha256.as_deref(),
            regular_files,
            reason,
        ));
    }

    let executable_files = image.map_or(0, |image| image.executable_files);
    if executable_files > 0 {
        required_sources.push("capa");
        if let (Some(image), Some(staged)) = (image, staged_archive.as_ref()) {
            engines.push(engines::capa_report(
                staged,
                image,
                artifact_sha256.as_deref(),
            ));
        } else {
            engines.push(failed_engine_report(
                "capa",
                artifact_sha256.as_deref(),
                executable_files,
                archive_failure.unwrap_or("image_archive_invalid"),
            ));
        }
    }

    if options.require_signature {
        required_sources.push("cosign");
        if let (Some(image), Some(staged)) = (image, staged_archive.as_ref()) {
            let (report, status) = engines::cosign_report(
                staged,
                image,
                options.image_ref,
                options.certificate_identity,
                options.certificate_oidc_issuer,
                artifact_sha256.as_deref(),
            );
            engines.push(report);
            signature_status = status;
        } else {
            engines.push(failed_engine_report(
                "cosign",
                artifact_sha256.as_deref(),
                1,
                archive_failure.unwrap_or("image_archive_invalid"),
            ));
        }
    }

    let report = build_artifact_report(policy, artifact_sha256, engines, &required_sources)?;
    Ok(ImageScanReport {
        report,
        signature_status,
    })
}

pub(crate) fn scan_registry_image(
    layout: &Path,
    scratch_parent: &Path,
    cache: &Path,
    binary: &Path,
    policy: &Policy,
) -> Result<bool> {
    let findings = engines::registry_trivy_findings(layout, scratch_parent, cache, binary)?;
    Ok(findings.into_iter().any(|finding| {
        policy.quarantine.cve_keeps_quarantined
            || finding
                .native_severity
                .as_deref()
                .and_then(trivy_severity)
                .is_none_or(|severity| policy.vulnerabilities.blocks_severity(&severity))
    }))
}

fn trivy_severity(raw: &str) -> Option<Severity> {
    if raw.eq_ignore_ascii_case("low") {
        Some(Severity::Low)
    } else if raw.eq_ignore_ascii_case("medium") {
        Some(Severity::Medium)
    } else if raw.eq_ignore_ascii_case("high") {
        Some(Severity::High)
    } else if raw.eq_ignore_ascii_case("critical") {
        Some(Severity::Critical)
    } else {
        None
    }
}

fn build_artifact_report(
    policy: &Policy,
    artifact_sha256: Option<String>,
    engines: Vec<EngineReport>,
    required_sources: &[&str],
) -> Result<ArtifactReport> {
    let coverage = if !engines.is_empty()
        && engines
            .iter()
            .all(|engine| engine.coverage == Coverage::Complete)
    {
        Coverage::Complete
    } else {
        Coverage::Partial
    };
    let findings = engines
        .iter()
        .flat_map(|engine| engine.findings.iter())
        .collect::<Vec<_>>();
    let explicit_block = engines.iter().any(|engine| {
        engine.source == "yarahunter" && !engine.findings.is_empty()
            || engine.source == "trivy"
                && engine.findings.iter().any(|finding| {
                    finding
                        .native_severity
                        .as_deref()
                        .and_then(trivy_severity)
                        .is_some_and(|severity| policy.vulnerabilities.blocks_severity(&severity))
                })
    });
    let score = findings
        .iter()
        .filter_map(|finding| finding.policy_score)
        .max();
    let decision = if explicit_block
        || score.is_some_and(|score| score >= policy.quarantine_scanner.block_score.into())
    {
        ScanDecision::Block
    } else if coverage != Coverage::Complete {
        ScanDecision::Incomplete
    } else if score.is_some_and(|score| score >= policy.quarantine_scanner.review_score.into()) {
        ScanDecision::Review
    } else {
        ScanDecision::Pass
    };
    let policy_sha256 = hex::encode(Sha256::digest(serde_json_canonicalizer::to_vec(policy)?));
    let engine_policy_revision_sha256 = engine_policy_revision_sha256(required_sources, &engines)?;
    let cache_key_sha256 = artifact_sha256
        .as_deref()
        .map(|artifact| {
            scan_cache_key_sha256(artifact, &policy_sha256, &engine_policy_revision_sha256)
        })
        .transpose()?;
    let reason = if coverage == Coverage::Complete {
        None
    } else {
        engines
            .iter()
            .find_map(|engine| engine.reason.clone())
            .or_else(|| Some("incomplete_coverage".to_string()))
    };
    let report = ArtifactReport {
        artifact_sha256,
        policy_sha256: Some(policy_sha256),
        engine_policy_revision_sha256: Some(engine_policy_revision_sha256),
        cache_key_sha256,
        coverage,
        decision,
        engines,
        reason,
    };
    report.validate()?;
    Ok(report)
}

fn complete_engine_report(
    source: &str,
    input_sha256: Option<&str>,
    expected_inputs: u64,
    revision: &str,
) -> EngineReport {
    let rule_bundle_sha256 = hex::encode(Sha256::digest(revision.as_bytes()));
    EngineReport {
        source: source.to_string(),
        version: Some("supply-core/0.3.1".to_string()),
        rule_bundle_sha256: Some(rule_bundle_sha256),
        database_sha256: None,
        input_sha256: input_sha256.map(str::to_string),
        expected_inputs,
        processed_inputs: expected_inputs,
        coverage: Coverage::Complete,
        findings: Vec::new(),
        reason: None,
    }
}

fn failed_engine_report(
    source: &str,
    input_sha256: Option<&str>,
    expected_inputs: u64,
    reason: &str,
) -> EngineReport {
    EngineReport {
        source: source.to_string(),
        version: None,
        rule_bundle_sha256: None,
        database_sha256: None,
        input_sha256: input_sha256.map(str::to_string),
        expected_inputs,
        processed_inputs: 0,
        coverage: Coverage::Unknown,
        findings: Vec::new(),
        reason: Some(reason.to_string()),
    }
}

fn inspect_image(staged: &mut StagedArchive) -> Result<InspectedImage> {
    let outer = inventory_outer(staged)?;
    let docker_manifest = outer.members.contains_key("manifest.json");
    let oci_index = outer.members.contains_key("index.json");
    ensure!(
        docker_manifest ^ oci_index,
        "archive format is ambiguous or unknown"
    );
    let (kind, chains, mut manifest_digests) = if docker_manifest {
        (
            ArchiveKind::DockerSave,
            read_docker_save(staged, &outer)?,
            BTreeSet::new(),
        )
    } else {
        let (chains, digests) = read_oci_archive(staged, &outer)?;
        (ArchiveKind::Oci, chains, digests)
    };
    ensure!(
        !chains.is_empty() && chains.len() <= MAX_IMAGES,
        "image count exceeds limits"
    );
    let mut expanded_total = outer.expanded_bytes;
    let layer_inventories = scan_layers(staged, &outer, &chains, &mut expanded_total, None, None)?;
    validate_image_chains(&chains, &layer_inventories)?;
    let mut layer_roots = Vec::new();
    let mut layer_paths = BTreeMap::new();
    for (index, path) in layer_inventories.keys().enumerate() {
        let relative = format!("image/layers/{index:04}");
        let root = staged.create_directory(&relative)?;
        layer_roots.push(root);
        layer_paths.insert(path.clone(), relative);
    }
    let staged_inventories = scan_layers(
        staged,
        &outer,
        &chains,
        &mut expanded_total,
        Some(&layer_paths),
        Some(&layer_inventories),
    )?;
    ensure!(
        staged_inventories == layer_inventories,
        "layer content changed between verification passes"
    );
    let mut regular_files = 0u64;
    let mut executable_files = 0u64;
    for inventory in layer_inventories.values() {
        for member in &inventory.members {
            if member.kind == MemberKind::File && member.whiteout_target.is_none() {
                regular_files = regular_files
                    .checked_add(1)
                    .context("layer file count overflow")?;
                if member.binary {
                    executable_files = executable_files
                        .checked_add(1)
                        .context("executable file count overflow")?;
                }
            }
        }
    }
    ensure!(
        regular_files <= MAX_ARCHIVE_ENTRIES as u64,
        "layer file count exceeds limits"
    );
    staged.verify_scratch_space()?;
    if kind == ArchiveKind::DockerSave {
        manifest_digests.clear();
    }

    Ok(InspectedImage {
        kind,
        chains,
        layer_inventories,
        layer_roots,
        regular_files,
        executable_files,
        manifest_digests,
    })
}

fn inventory_outer(staged: &mut StagedArchive) -> Result<OuterInventory> {
    let mut archive = Archive::new(staged.clone_reader()?);
    let mut members = BTreeMap::new();
    let mut expanded_bytes = 0u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = normalize_archive_path(
            entry
                .path()?
                .to_str()
                .context("archive path is not UTF-8")?,
            entry.header().entry_type().is_dir(),
        )?;
        let entry_type = entry.header().entry_type();
        let directory = entry_type.is_dir();
        ensure!(
            directory || entry_type.is_file(),
            "outer archive contains a non-file member"
        );
        if path.is_empty() {
            ensure!(directory, "outer archive contains an empty file path");
            continue;
        }
        ensure!(
            members.len() < MAX_ARCHIVE_ENTRIES,
            "outer archive has too many members"
        );
        ensure!(
            !members.contains_key(&path),
            "outer archive contains duplicate paths"
        );
        let size = entry.size();
        ensure!(
            directory || size <= MAX_LAYER_BYTES,
            "outer member exceeds size limits"
        );
        if directory {
            ensure!(size == 0, "outer directory has data");
            members.insert(
                path,
                OuterMember {
                    size: 0,
                    sha256: hex::encode(Sha256::digest([])),
                    directory: true,
                },
            );
        } else {
            staged.reserve_expanded(size, &mut expanded_bytes)?;
            let (actual_size, digest, _) = hash_reader(&mut entry, size)?;
            ensure!(actual_size == size, "outer member size mismatch");
            members.insert(
                path,
                OuterMember {
                    size,
                    sha256: digest,
                    directory: false,
                },
            );
        }
    }
    Ok(OuterInventory {
        members,
        expanded_bytes,
    })
}

fn read_docker_save(staged: &StagedArchive, outer: &OuterInventory) -> Result<Vec<ImageChain>> {
    let manifest_path = "manifest.json".to_string();
    let mut metadata_total = 0u64;
    let root = read_outer_members(
        staged,
        outer,
        &BTreeSet::from([manifest_path.clone()]),
        &mut metadata_total,
    )?;
    let manifests: Vec<DockerManifest> = serde_json::from_slice(
        root.get(&manifest_path)
            .context("Docker-save manifest is missing")?,
    )?;
    ensure!(
        !manifests.is_empty() && manifests.len() <= MAX_IMAGES,
        "Docker-save image count exceeds limits"
    );
    let mut config_paths = BTreeSet::new();
    let mut layer_count = 0usize;
    for manifest in &manifests {
        let config_path = normalize_archive_path(&manifest.config, false)?;
        ensure!(
            config_paths.insert(config_path),
            "Docker-save config is duplicated"
        );
        layer_count = layer_count
            .checked_add(manifest.layers.len())
            .context("layer count overflow")?;
    }
    ensure!(
        layer_count <= MAX_LAYERS,
        "Docker-save layer count exceeds limits"
    );
    let configs = read_outer_members(staged, outer, &config_paths, &mut metadata_total)?;
    let mut chains = Vec::with_capacity(manifests.len());
    for manifest in manifests {
        let config_path = normalize_archive_path(&manifest.config, false)?;
        let config_bytes = configs
            .get(&config_path)
            .context("Docker-save image config is missing")?;
        verify_docker_config_name(&config_path, config_bytes)?;
        let config_digest = format!("sha256:{}", hex::encode(Sha256::digest(config_bytes)));
        let config: ImageConfig = serde_json::from_slice(config_bytes)?;
        ensure!(
            config.rootfs.kind == "layers",
            "Docker-save rootfs type is invalid"
        );
        ensure!(
            config.rootfs.diff_ids.len() == manifest.layers.len(),
            "Docker-save layer and diff-id counts differ"
        );
        let mut layers = Vec::with_capacity(manifest.layers.len());
        for (path, diff_id) in manifest.layers.iter().zip(&config.rootfs.diff_ids) {
            let archive_path = normalize_archive_path(path, false)?;
            validate_sha256_ref(diff_id)?;
            require_outer_file(outer, &archive_path)?;
            layers.push(LayerReference {
                archive_path,
                diff_id: diff_id.clone(),
                media_type: None,
            });
        }
        chains.push(ImageChain {
            config_digest,
            config_size: u64::try_from(config_bytes.len())?,
            layers,
            entrypoint: runtime_entrypoint(config.config.as_ref())?,
        });
    }
    Ok(chains)
}

fn verify_docker_config_name(path: &str, bytes: &[u8]) -> Result<()> {
    let digest = hex::encode(Sha256::digest(bytes));
    let expected = format!("{digest}.json");
    ensure!(
        path == expected,
        "Docker-save config digest does not match its path"
    );
    Ok(())
}

fn read_oci_archive(
    staged: &StagedArchive,
    outer: &OuterInventory,
) -> Result<(Vec<ImageChain>, BTreeSet<String>)> {
    let mut metadata_total = 0u64;
    let roots = BTreeSet::from(["oci-layout".to_string(), "index.json".to_string()]);
    let root_members = read_outer_members(staged, outer, &roots, &mut metadata_total)?;
    let layout: OciLayout = serde_json::from_slice(
        root_members
            .get("oci-layout")
            .context("OCI layout marker is missing")?,
    )?;
    ensure!(
        layout.image_layout_version == "1.0.0",
        "OCI layout version is unsupported"
    );
    let root_index_bytes = root_members
        .get("index.json")
        .context("OCI index is missing")?;
    let root_index: OciIndex = serde_json::from_slice(root_index_bytes)?;
    ensure!(
        root_index.schema_version == 2,
        "OCI index schema version is invalid"
    );
    let mut manifest_digests = BTreeSet::from([hex::encode(Sha256::digest(root_index_bytes))]);
    let mut queue = root_index
        .manifests
        .into_iter()
        .map(|descriptor| (descriptor, 0usize))
        .collect::<Vec<_>>();
    let mut visited = BTreeMap::<String, OciDescriptor>::new();
    let mut manifests = Vec::new();
    let mut image_count = 0usize;
    while !queue.is_empty() {
        let mut requested = BTreeSet::new();
        let mut current = Vec::new();
        for (descriptor, depth) in std::mem::take(&mut queue) {
            validate_descriptor(&descriptor)?;
            let kind = oci_metadata_kind(&descriptor.media_type)?;
            if let Some(previous) = visited.get(&descriptor.digest) {
                ensure!(
                    previous == &descriptor,
                    "OCI descriptor conflicts for one digest"
                );
                continue;
            }
            ensure!(depth <= MAX_INDEX_DEPTH, "OCI index nesting exceeds limits");
            let path = blob_path(&descriptor.digest)?;
            verify_descriptor_member(outer, &descriptor, &path)?;
            requested.insert(path.clone());
            current.push((descriptor, depth, path, kind));
        }
        let blobs = read_outer_members(staged, outer, &requested, &mut metadata_total)?;
        for (descriptor, depth, path, kind) in current {
            visited.insert(descriptor.digest.clone(), descriptor.clone());
            manifest_digests.insert(
                descriptor
                    .digest
                    .clone()
                    .trim_start_matches("sha256:")
                    .to_string(),
            );
            let bytes = blobs.get(&path).context("OCI metadata blob is missing")?;
            match kind {
                OciMetadataKind::Index => {
                    let index: OciIndex = serde_json::from_slice(bytes)?;
                    ensure!(
                        index.schema_version == 2,
                        "nested OCI index schema version is invalid"
                    );
                    queue.extend(
                        index
                            .manifests
                            .into_iter()
                            .map(|descriptor| (descriptor, depth + 1)),
                    );
                }
                OciMetadataKind::Manifest => {
                    image_count += 1;
                    ensure!(image_count <= MAX_IMAGES, "OCI image count exceeds limits");
                    let manifest: OciManifest = serde_json::from_slice(bytes)?;
                    ensure!(
                        manifest.schema_version == 2,
                        "OCI manifest schema version is invalid"
                    );
                    validate_config_descriptor(&manifest.config)?;
                    for layer in &manifest.layers {
                        validate_layer_descriptor(layer)?;
                        let path = blob_path(&layer.digest)?;
                        verify_descriptor_member(outer, layer, &path)?;
                    }
                    manifests.push(manifest);
                }
            }
        }
    }
    ensure!(!manifests.is_empty(), "OCI index has no image manifests");
    let config_descriptors = manifests
        .iter()
        .map(|manifest| {
            let digest = manifest.config.digest.clone();
            (digest, manifest.config.clone())
        })
        .collect::<BTreeMap<_, _>>();
    let config_paths = config_descriptors
        .values()
        .map(|descriptor| blob_path(&descriptor.digest))
        .collect::<Result<BTreeSet<_>>>()?;
    for descriptor in config_descriptors.values() {
        verify_descriptor_member(outer, descriptor, &blob_path(&descriptor.digest)?)?;
    }
    let configs = read_outer_members(staged, outer, &config_paths, &mut metadata_total)?;
    let mut layer_count = 0usize;
    let mut chains = Vec::with_capacity(manifests.len());
    for manifest in manifests {
        layer_count = layer_count
            .checked_add(manifest.layers.len())
            .context("OCI layer count overflow")?;
        ensure!(layer_count <= MAX_LAYERS, "OCI layer count exceeds limits");
        let config_path = blob_path(&manifest.config.digest)?;
        let config_digest = manifest.config.digest.clone();
        let config: ImageConfig = serde_json::from_slice(
            configs
                .get(&config_path)
                .context("OCI image config is missing")?,
        )?;
        ensure!(
            config.rootfs.diff_ids.len() == manifest.layers.len(),
            "OCI layer and diff-id counts differ"
        );
        let layers = manifest
            .layers
            .iter()
            .zip(&config.rootfs.diff_ids)
            .map(|(descriptor, diff_id)| {
                validate_sha256_ref(diff_id)?;
                Ok(LayerReference {
                    archive_path: blob_path(&descriptor.digest)?,
                    diff_id: diff_id.clone(),
                    media_type: Some(descriptor.media_type.clone()),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        chains.push(ImageChain {
            config_digest,
            config_size: manifest.config.size,
            layers,
            entrypoint: runtime_entrypoint(config.config.as_ref())?,
        });
    }
    Ok((chains, manifest_digests))
}

fn runtime_entrypoint(config: Option<&RuntimeConfig>) -> Result<Vec<String>> {
    let mut entrypoint = Vec::new();
    if let Some(config) = config {
        for value in config
            .entrypoint
            .iter()
            .flatten()
            .chain(config.command.iter().flatten())
        {
            ensure!(
                value.len() <= 4096 && !value.contains('\0'),
                "image entrypoint is invalid"
            );
            entrypoint.push(value.clone());
            ensure!(
                entrypoint.len() <= 256,
                "image entrypoint has too many values"
            );
        }
    }
    Ok(entrypoint)
}

fn validate_descriptor(descriptor: &OciDescriptor) -> Result<()> {
    validate_sha256_ref(&descriptor.digest)?;
    ensure!(
        descriptor.size > 0 && descriptor.size <= MAX_IMAGE_METADATA_BYTES,
        "OCI metadata descriptor size is invalid"
    );
    Ok(())
}

fn validate_config_descriptor(descriptor: &OciDescriptor) -> Result<()> {
    validate_descriptor(descriptor)?;
    ensure!(
        descriptor.media_type.contains("config") && descriptor.media_type.ends_with("+json"),
        "OCI config media type is unsupported"
    );
    Ok(())
}

fn validate_layer_descriptor(descriptor: &OciDescriptor) -> Result<()> {
    validate_sha256_ref(&descriptor.digest)?;
    ensure!(
        descriptor.size > 0 && descriptor.size <= MAX_LAYER_BYTES,
        "OCI layer descriptor size is invalid"
    );
    ensure!(
        !descriptor.media_type.contains("encrypted"),
        "encrypted OCI layers are unsupported"
    );
    ensure!(
        matches!(
            descriptor.media_type.as_str(),
            "application/vnd.oci.image.layer.v1.tar"
                | "application/vnd.oci.image.layer.v1.tar+gzip"
                | "application/vnd.oci.image.layer.v1.tar+zstd"
                | "application/vnd.docker.image.rootfs.diff.tar"
                | "application/vnd.docker.image.rootfs.diff.tar.gzip"
        ),
        "OCI layer media type is unsupported"
    );
    Ok(())
}

fn oci_metadata_kind(media_type: &str) -> Result<OciMetadataKind> {
    match media_type {
        "application/vnd.oci.image.index.v1+json"
        | "application/vnd.docker.distribution.manifest.list.v2+json" => Ok(OciMetadataKind::Index),
        "application/vnd.oci.image.manifest.v1+json"
        | "application/vnd.docker.distribution.manifest.v2+json" => Ok(OciMetadataKind::Manifest),
        _ => anyhow::bail!("OCI descriptor media type is unsupported"),
    }
}

fn validate_sha256_ref(value: &str) -> Result<&str> {
    let digest = value
        .strip_prefix("sha256:")
        .context("image digest algorithm is unsupported")?;
    ensure!(
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "image sha256 digest is malformed"
    );
    Ok(digest)
}

fn blob_path(digest: &str) -> Result<String> {
    Ok(format!("blobs/sha256/{}", validate_sha256_ref(digest)?))
}

fn verify_descriptor_member(
    outer: &OuterInventory,
    descriptor: &OciDescriptor,
    path: &str,
) -> Result<()> {
    let member = require_outer_file(outer, path)?;
    ensure!(
        member.size == descriptor.size,
        "OCI descriptor size does not match archive member"
    );
    ensure!(
        member.sha256 == validate_sha256_ref(&descriptor.digest)?,
        "OCI descriptor digest does not match archive member"
    );
    Ok(())
}

fn require_outer_file<'a>(outer: &'a OuterInventory, path: &str) -> Result<&'a OuterMember> {
    let member = outer
        .members
        .get(path)
        .context("referenced image member is missing")?;
    ensure!(!member.directory, "referenced image member is not a file");
    Ok(member)
}

fn read_outer_members(
    staged: &StagedArchive,
    outer: &OuterInventory,
    requested: &BTreeSet<String>,
    metadata_total: &mut u64,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut expected = BTreeMap::new();
    for path in requested {
        let member = require_outer_file(outer, path)?;
        ensure!(
            member.size <= MAX_IMAGE_METADATA_BYTES,
            "image metadata exceeds size limits"
        );
        *metadata_total = metadata_total
            .checked_add(member.size)
            .context("image metadata size overflow")?;
        ensure!(
            *metadata_total <= MAX_TOTAL_METADATA_BYTES,
            "image metadata exceeds aggregate limits"
        );
        expected.insert(path.clone(), member);
    }
    let mut result = BTreeMap::new();
    let mut archive = Archive::new(staged.clone_reader()?);
    for entry in archive.entries()? {
        let entry = entry?;
        let path = normalize_archive_path(
            entry
                .path()?
                .to_str()
                .context("archive path is not UTF-8")?,
            entry.header().entry_type().is_dir(),
        )?;
        let Some(metadata) = expected.get(&path) else {
            continue;
        };
        let capacity = usize::try_from(metadata.size)?;
        let mut bytes = Vec::with_capacity(capacity);
        entry.take(metadata.size + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == metadata.size,
            "image metadata member size changed"
        );
        ensure!(
            hex::encode(Sha256::digest(&bytes)) == metadata.sha256,
            "image metadata member digest changed"
        );
        result.insert(path, bytes);
    }
    ensure!(
        result.len() == expected.len(),
        "image metadata member is missing"
    );
    Ok(result)
}

fn scan_layers(
    staged: &mut StagedArchive,
    outer: &OuterInventory,
    chains: &[ImageChain],
    expanded_total: &mut u64,
    staging_paths: Option<&BTreeMap<String, String>>,
    expected_inventories: Option<&BTreeMap<String, LayerInventory>>,
) -> Result<BTreeMap<String, LayerInventory>> {
    let mut references = BTreeMap::<String, LayerReference>::new();
    for chain in chains {
        for layer in &chain.layers {
            if let Some(previous) = references.get(&layer.archive_path) {
                ensure!(previous == layer, "one layer path has conflicting metadata");
            } else {
                references.insert(layer.archive_path.clone(), layer.clone());
            }
        }
    }
    ensure!(
        references.len() <= MAX_LAYERS,
        "image layer count exceeds limits"
    );
    let mut remaining = MAX_LAYER_BYTES.saturating_sub(*expanded_total);
    let mut inventories = BTreeMap::new();
    let mut archive = Archive::new(staged.clone_reader()?);
    for entry in archive.entries()? {
        let entry = entry?;
        let path = normalize_archive_path(
            entry
                .path()?
                .to_str()
                .context("archive path is not UTF-8")?,
            entry.header().entry_type().is_dir(),
        )?;
        let Some(reference) = references.get(&path) else {
            continue;
        };
        let outer_member = require_outer_file(outer, &path)?;
        ensure!(
            entry.header().entry_type().is_file(),
            "image layer is not a regular file"
        );
        ensure!(
            entry.size() == outer_member.size,
            "image layer size changed"
        );
        let (decoder, compression) = decode_layer(entry, reference.media_type.as_deref())?;
        let prefix = staging_paths
            .and_then(|paths| paths.get(&path))
            .map(String::as_str);
        let max_bytes = expected_inventories
            .and_then(|inventories| inventories.get(&path))
            .map_or(remaining, |inventory| inventory.raw_tar_size);
        let inventory = parse_layer(decoder, max_bytes, staged, prefix)?;
        ensure!(
            inventory.raw_tar_sha256 == validate_sha256_ref(&reference.diff_id)?,
            "image layer diff-id does not match"
        );
        if let Some(expected) = expected_inventories.and_then(|inventories| inventories.get(&path))
        {
            ensure!(
                &inventory == expected,
                "layer content changed between verification passes"
            );
        }
        remaining = remaining.saturating_sub(inventory.raw_tar_size);
        if staging_paths.is_none() {
            staged.reserve_expanded(inventory.raw_tar_size, expanded_total)?;
        }
        ensure!(
            compression_matches(reference.media_type.as_deref(), compression),
            "image layer compression does not match its descriptor"
        );
        inventories.insert(path, inventory);
    }
    ensure!(
        inventories.len() == references.len(),
        "an image layer is missing"
    );
    Ok(inventories)
}

fn compression_matches(media_type: Option<&str>, compression: CompressionKind) -> bool {
    match media_type {
        None => true,
        Some(value) if value.ends_with("+gzip") => compression == CompressionKind::Gzip,
        Some(value) if value.ends_with("+zstd") => compression == CompressionKind::Zstd,
        Some(value) if value.ends_with(".tar") => compression == CompressionKind::Plain,
        _ => false,
    }
}

fn decode_layer<'a>(
    reader: impl Read + 'a,
    media_type: Option<&str>,
) -> Result<(Box<dyn Read + 'a>, CompressionKind)> {
    let mut buffered = BufReader::new(reader);
    let magic = buffered
        .fill_buf()?
        .iter()
        .take(4)
        .copied()
        .collect::<Vec<_>>();
    let compression = if magic.starts_with(&[0x1f, 0x8b]) {
        CompressionKind::Gzip
    } else if magic.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        CompressionKind::Zstd
    } else {
        CompressionKind::Plain
    };
    match media_type {
        Some(value) if value.ends_with("+gzip") && compression != CompressionKind::Gzip => {
            anyhow::bail!("gzip layer has invalid compression header")
        }
        Some(value) if value.ends_with("+zstd") && compression != CompressionKind::Zstd => {
            anyhow::bail!("zstd layer has invalid compression header")
        }
        Some(value) if value.ends_with(".tar") && compression != CompressionKind::Plain => {
            anyhow::bail!("uncompressed layer has a compressed payload")
        }
        _ => {}
    }
    let decoded: Box<dyn Read + 'a> = match compression {
        CompressionKind::Plain => Box::new(buffered),
        CompressionKind::Gzip => Box::new(MultiGzDecoder::new(buffered)),
        CompressionKind::Zstd => Box::new(zstd::stream::read::Decoder::new(buffered)?),
    };
    Ok((decoded, compression))
}

fn parse_layer<'a>(
    reader: Box<dyn Read + 'a>,
    max_bytes: u64,
    staged: &mut StagedArchive,
    stage_prefix: Option<&str>,
) -> Result<LayerInventory> {
    let mut tracking = TrackingReader::new(reader, max_bytes);
    let mut members = Vec::new();
    let mut seen = HashSet::new();
    {
        let mut archive = Archive::new(&mut tracking);
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = normalize_archive_path(
                entry.path()?.to_str().context("layer path is not UTF-8")?,
                entry.header().entry_type().is_dir(),
            )?;
            ensure!(
                members.len() < MAX_ARCHIVE_ENTRIES,
                "image layer has too many members"
            );
            ensure!(
                seen.insert(path.clone()),
                "image layer contains duplicate paths"
            );
            let entry_type = entry.header().entry_type();
            let mode = entry.header().mode()?;
            let size = entry.size();
            let (kind, link_target, whiteout_target, digest, binary) = if entry_type.is_file() {
                let whiteout = parse_whiteout(&path, size)?;
                let (digest, binary) = if whiteout.is_none() {
                    if let Some(prefix) = stage_prefix {
                        let relative_path = format!("{prefix}/{path}");
                        let (_, digest, staged_path) =
                            staged.stage_member(&relative_path, &mut entry, size)?;
                        (digest, file_is_pe_or_elf(&staged_path)?)
                    } else {
                        let (_, digest, binary) = hash_reader(&mut entry, size)?;
                        (digest, binary)
                    }
                } else {
                    let (_, digest, binary) = hash_reader(&mut entry, size)?;
                    (digest, binary)
                };
                (MemberKind::File, None, whiteout, digest, binary)
            } else if entry_type.is_dir() {
                ensure!(size == 0, "image layer directory has data");
                (
                    MemberKind::Directory,
                    None,
                    None,
                    hex::encode(Sha256::digest([])),
                    false,
                )
            } else if entry_type.is_symlink() || entry_type.is_hard_link() {
                ensure!(size == 0, "image layer link has data");
                let raw_target = entry
                    .link_name()?
                    .context("image layer link target is missing")?;
                let target = raw_target
                    .to_str()
                    .context("image layer link target is not UTF-8")?;
                let link_kind = if entry_type.is_symlink() {
                    MemberKind::Symlink
                } else {
                    MemberKind::Hardlink
                };
                (
                    link_kind,
                    Some(resolve_link_target(&path, target, link_kind)?),
                    None,
                    hex::encode(Sha256::digest([])),
                    false,
                )
            } else {
                anyhow::bail!("image layer contains an unsupported member type")
            };
            if let Some(target) = &whiteout_target {
                ensure!(size == 0, "OCI whiteout marker has data");
                ensure!(
                    kind == MemberKind::File,
                    "OCI whiteout marker is not a regular file"
                );
                let _ = target;
            }
            members.push(LayerMember {
                path,
                kind,
                mode,
                size,
                sha256: digest,
                link_target,
                whiteout_target,
                binary,
            });
        }
    }
    io::copy(&mut tracking, &mut io::sink())?;
    let (_, raw_tar_sha256, raw_tar_size) = tracking.finish();
    Ok(LayerInventory {
        raw_tar_sha256,
        raw_tar_size,
        members,
    })
}

fn parse_whiteout(path: &str, size: u64) -> Result<Option<String>> {
    let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
    if name == ".wh..wh..opq" {
        return Ok(Some(if parent.is_empty() {
            String::new()
        } else {
            format!("{parent}/")
        }));
    }
    let Some(target_name) = name.strip_prefix(".wh.") else {
        return Ok(None);
    };
    ensure!(!target_name.is_empty(), "OCI whiteout target is empty");
    ensure!(size == 0, "OCI whiteout marker has data");
    Ok(Some(if parent.is_empty() {
        target_name.to_string()
    } else {
        format!("{parent}/{target_name}")
    }))
}

fn resolve_link_target(member_path: &str, target: &str, kind: MemberKind) -> Result<String> {
    ensure!(
        !target.is_empty() && !target.contains('\0') && !target.contains('\\'),
        "image link target is invalid"
    );
    let absolute = target.starts_with('/');
    ensure!(
        kind != MemberKind::Hardlink || !absolute,
        "hardlink target is absolute"
    );
    let mut components = if absolute || kind == MemberKind::Hardlink {
        Vec::new()
    } else {
        member_path
            .rsplit_once('/')
            .map(|(parent, _)| parent.split('/').collect::<Vec<_>>())
            .unwrap_or_default()
    };
    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                ensure!(
                    !components.is_empty(),
                    "image link escapes the root filesystem"
                );
                components.pop();
            }
            value => {
                ensure!(
                    !value.contains(':') && value.len() <= 255,
                    "image link target is invalid"
                );
                components.push(value);
            }
        }
    }
    Ok(components.join("/"))
}

fn validate_image_chains(
    chains: &[ImageChain],
    inventories: &BTreeMap<String, LayerInventory>,
) -> Result<()> {
    for chain in chains {
        ensure!(
            chain.entrypoint.len() <= 256,
            "image entrypoint has too many values"
        );
        let mut state = BTreeMap::<String, LayerMember>::new();
        for layer in &chain.layers {
            let inventory = inventories
                .get(&layer.archive_path)
                .context("image layer inventory is missing")?;
            for member in &inventory.members {
                if let Some(target) = &member.whiteout_target {
                    if target.ends_with('/') {
                        let directory = target.trim_end_matches('/');
                        state.retain(|path, _| {
                            directory.is_empty() || !path.starts_with(&format!("{directory}/"))
                        });
                    } else {
                        state.retain(|path, _| {
                            path != target && !path.starts_with(&format!("{target}/"))
                        });
                    }
                }
            }
            for member in &inventory.members {
                if member.whiteout_target.is_some() {
                    continue;
                }
                if member.kind != MemberKind::Directory {
                    state.retain(|path, _| !path.starts_with(&format!("{}/", member.path)));
                }
                state.insert(member.path.clone(), member.clone());
            }
            for member in state
                .values()
                .filter(|member| member.kind == MemberKind::Hardlink)
            {
                let target = member
                    .link_target
                    .as_deref()
                    .context("hardlink target is missing")?;
                let target_member = state.get(target).context("hardlink target is unresolved")?;
                ensure!(
                    target_member.kind == MemberKind::File,
                    "hardlink target is not a regular file"
                );
            }
        }
        for member in state
            .values()
            .filter(|member| member.kind == MemberKind::Symlink)
        {
            let target = member
                .link_target
                .as_deref()
                .context("symlink target is missing")?;
            ensure!(path_exists(&state, target), "symlink target is unresolved");
            ensure!(
                resolve_symlink_chain(&state, target, &mut BTreeSet::new(), 0)?,
                "symlink target is unresolved"
            );
        }
        for (path, member) in &state {
            let mut parent = Path::new(path).parent();
            while let Some(parent_path) = parent {
                let parent_text = parent_path.to_str().context("image path is not UTF-8")?;
                if parent_text.is_empty() {
                    break;
                }
                if let Some(parent_member) = state.get(parent_text) {
                    ensure!(
                        parent_member.kind == MemberKind::Directory,
                        "image member is below a non-directory"
                    );
                }
                parent = parent_path.parent();
            }
            let _ = member;
        }
    }
    Ok(())
}

fn path_exists(state: &BTreeMap<String, LayerMember>, path: &str) -> bool {
    path.is_empty()
        || state.contains_key(path)
        || state
            .keys()
            .any(|candidate| candidate.starts_with(&format!("{path}/")))
}

fn resolve_symlink_chain(
    state: &BTreeMap<String, LayerMember>,
    path: &str,
    seen: &mut BTreeSet<String>,
    depth: usize,
) -> Result<bool> {
    ensure!(depth <= 40, "symlink chain exceeds limits");
    if path.is_empty() || !path_exists(state, path) {
        return Ok(false);
    }
    if !seen.insert(path.to_string()) {
        anyhow::bail!("symlink chain contains a cycle");
    }
    if let Some(member) = state
        .get(path)
        .filter(|member| member.kind == MemberKind::Symlink)
    {
        let target = member
            .link_target
            .as_deref()
            .context("symlink target is missing")?;
        return resolve_symlink_chain(state, target, seen, depth + 1);
    }
    Ok(true)
}

fn normalize_archive_path(raw_path: &str, allow_root: bool) -> Result<String> {
    ensure!(
        !raw_path.is_empty() && !raw_path.contains('\0'),
        "archive path is invalid"
    );
    let path = raw_path.replace('\\', "/");
    let bytes = path.as_bytes();
    ensure!(
        !path.starts_with('/')
            && !(bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'),
        "archive path is absolute"
    );
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => anyhow::bail!("archive path escapes the image root"),
            value => {
                ensure!(
                    !value.contains(':') && value.len() <= 255,
                    "archive path component is invalid"
                );
                components.push(value);
            }
        }
    }
    let normalized = components.join("/");
    ensure!(
        allow_root || !normalized.is_empty(),
        "archive file path is empty"
    );
    Ok(normalized)
}

fn hash_reader(reader: &mut impl Read, expected_size: u64) -> Result<(u64, String, bool)> {
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut prefix = [0u8; 4];
    let mut prefix_len = 0usize;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(count)?)
            .context("image file size overflow")?;
        ensure!(
            size <= expected_size,
            "image member exceeds its declared size"
        );
        let copy_len = (prefix.len() - prefix_len).min(count);
        prefix[prefix_len..prefix_len + copy_len].copy_from_slice(&buffer[..copy_len]);
        prefix_len += copy_len;
        hasher.update(&buffer[..count]);
    }
    ensure!(
        size == expected_size,
        "image member size does not match its declaration"
    );
    Ok((
        size,
        hex::encode(hasher.finalize()),
        is_pe_or_elf(&prefix[..prefix_len]),
    ))
}

fn file_is_pe_or_elf(path: &Path) -> Result<bool> {
    let mut file = File::open(path)?;
    let mut prefix = [0u8; 4];
    let count = file.read(&mut prefix)?;
    Ok(is_pe_or_elf(&prefix[..count]))
}

fn is_pe_or_elf(prefix: &[u8]) -> bool {
    prefix.starts_with(b"MZ") || prefix.starts_with(b"\x7fELF")
}

struct TrackingReader<R> {
    reader: R,
    hasher: Sha256,
    bytes: u64,
    max_bytes: u64,
}

impl<R> TrackingReader<R> {
    fn new(reader: R, max_bytes: u64) -> Self {
        Self {
            reader,
            hasher: Sha256::new(),
            bytes: 0,
            max_bytes,
        }
    }

    fn finish(self) -> (R, String, u64) {
        (self.reader, hex::encode(self.hasher.finalize()), self.bytes)
    }
}

impl<R: Read> Read for TrackingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.reader.read(buffer)?;
        let next = self
            .bytes
            .checked_add(u64::try_from(count).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("image layer size overflow"))?;
        if next > self.max_bytes {
            return Err(io::Error::other("image layer exceeds expanded-size limit"));
        }
        self.bytes = next;
        self.hasher.update(&buffer[..count]);
        Ok(count)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::ledger::EngineFinding;

    #[test]
    fn trivy_critical_respects_high_severity_threshold() -> Result<()> {
        let input_sha256 = "a".repeat(64);
        let mut trivy = complete_engine_report("trivy", Some(&input_sha256), 1, "trivy-test");
        trivy.findings.push(EngineFinding {
            id: "b".repeat(64),
            rule: "cve-2025-1234".to_string(),
            summary: "Critical vulnerability detected".to_string(),
            location: Some("image/packages/openssl".to_string()),
            native_severity: Some("CRITICAL".to_string()),
            policy_score: None,
        });
        let mut policy = Policy::default();
        policy.vulnerabilities.block_severities = vec![Severity::High];

        let report = build_artifact_report(&policy, Some(input_sha256), vec![trivy], &["trivy"])?;

        assert_eq!(report.decision, ScanDecision::Block);
        Ok(())
    }
}
