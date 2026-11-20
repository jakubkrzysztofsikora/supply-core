use super::{
    failed_engine_report, ArchiveKind, InspectedImage, MemberKind, SignatureStatus,
    MAX_ARCHIVE_ENTRIES, MAX_IMAGE_METADATA_BYTES, MAX_LAYER_BYTES,
};
use crate::adapters::command_scanner::{
    run_isolated_image_tool, run_isolated_tool_with_env, run_networked_isolated_tool,
    BoundedCommandOutput, SandboxMount,
};
use crate::application::ledger::{engine_finding_id, Coverage, EngineFinding, EngineReport};
use crate::application::scanner::StagedArchive;
use anyhow::{ensure, Context, Result};
use rust_decimal::Decimal;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

const OUTPUT_LIMIT: usize = 8 * 1024 * 1024;
const SCANNER_TIMEOUT: Duration = Duration::from_secs(300);
const YARAHUNTER_COMMIT: &str = "8cb5a008056a407cf5a273fabb0ecf6626acd50e";
const YARAHUNTER_PATCH: &str = "supply-core-yarahunter-coverage-v1";
const YARAHUNTER_COVERAGE_ENV: &str = "SUPPLY_CORE_YARAHUNTER_COVERAGE_PATH";

pub(super) fn trivy_report(staged: &StagedArchive, input_sha256: Option<&str>) -> EngineReport {
    let result = (|| -> Result<EngineReport> {
        let binary = required_path("TRIVY_BIN")?;
        let cache = required_path("TRIVY_CACHE_DIR")?;
        let cache_sha256 = hash_tree(&cache)?;
        ensure!(
            cache.join("db/trivy.db").is_file(),
            "Trivy database is missing"
        );
        ensure!(
            cache.join("db/metadata.json").is_file(),
            "Trivy database metadata is missing"
        );
        let version = tool_version(&binary, staged.engine_scratch_root())?;
        let archive_mount = mount(staged.path(), "/scan/image.tar");
        let cache_mount = mount(&cache, "/scan/trivy-cache");
        let args = args([
            "--cache-dir",
            "/scan/trivy-cache",
            "image",
            "--input",
            "/scan/image.tar",
            "--offline-scan",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-version-check",
            "--disable-telemetry",
            "--format",
            "json",
            "--scanners",
            "vuln",
            "--quiet",
        ]);
        let output = run_tool(
            &binary,
            &args,
            &[archive_mount, cache_mount],
            staged.engine_scratch_root(),
            &[],
        )?;
        let findings = parse_trivy(&output.stdout)?;
        let complete = output.complete && output.status.success();
        let reason = if complete {
            None
        } else if !output.complete {
            Some("scanner_output_truncated")
        } else {
            Some("scanner_exit_nonzero")
        };
        Ok(engine_report(
            EngineInput {
                source: "trivy",
                input_sha256,
                expected_inputs: 1,
                processed_inputs: u64::from(complete),
            },
            &version,
            &revision_sha256("trivy-image-vulnerability-json-v1"),
            Some(cache_sha256),
            findings,
            complete,
            reason,
        ))
    })();
    match result {
        Ok(report) => report,
        Err(error) => failed_engine_report("trivy", input_sha256, 1, failure_code(&error)),
    }
}

pub(super) fn registry_trivy_findings(
    layout: &Path,
    scratch_parent: &Path,
    cache: &Path,
    binary: &Path,
) -> Result<Vec<EngineFinding>> {
    let scratch = tempfile::tempdir_in(scratch_parent)?;
    // Both databases must stage: a missing Java DB would silently drop
    // Java-package results while OS or other language results still passed
    // the coverage check below.
    for (database, filename) in [("db", "trivy.db"), ("java-db", "trivy-java.db")] {
        let source = cache.join(database);
        let target = scratch.path().join("trivy-cache").join(database);
        fs::create_dir_all(&target)?;
        for file in [filename, "metadata.json"] {
            fs::copy(source.join(file), target.join(file)).context("stage Trivy database")?;
        }
    }
    let output = run_isolated_image_tool(
        binary,
        &args([
            "--cache-dir",
            "/tmp/trivy-cache",
            "image",
            "--input",
            "/scan/image",
            "--offline-scan",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-version-check",
            "--disable-telemetry",
            "--cache-backend",
            "memory",
            "--parallel",
            "1",
            "--format",
            "json",
            "--scanners",
            "vuln",
            "--quiet",
        ]),
        &[mount(layout, "/scan/image")],
        scratch.path(),
        SCANNER_TIMEOUT,
        OUTPUT_LIMIT,
    )?;
    ensure!(
        output.complete && output.status.success(),
        "Trivy scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
            .chars()
            .filter(|character| !character.is_control() || *character == '\n')
            .take(512)
            .collect::<String>()
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        report
            .get("ArtifactType")
            .and_then(serde_json::Value::as_str)
            == Some("container_image")
            && report
                .get("Results")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|results| {
                    results.iter().any(|result| {
                        matches!(
                            result.get("Class").and_then(serde_json::Value::as_str),
                            Some("os-pkgs" | "lang-pkgs")
                        )
                    })
                }),
        "Trivy did not establish vulnerability scan coverage"
    );
    parse_trivy(&output.stdout)
}

pub(super) fn yarahunter_report(
    staged: &StagedArchive,
    image: &InspectedImage,
    input_sha256: Option<&str>,
) -> EngineReport {
    let expected = image.regular_files;
    if expected == 0 {
        return engine_report(
            EngineInput {
                source: "yarahunter",
                input_sha256,
                expected_inputs: 0,
                processed_inputs: 0,
            },
            "not-required/no-layer-files",
            &revision_sha256(YARAHUNTER_PATCH),
            None,
            Vec::new(),
            true,
            None,
        );
    }
    let result = (|| -> Result<EngineReport> {
        let binary = required_path("YARAHUNTER_BIN")?;
        let rules = required_path("YARAHUNTER_RULES_DIR")?;
        let rules_sha256 = hash_tree(&rules)?;
        let version = tool_version(&binary, staged.engine_scratch_root())?;
        let layer_root = image
            .layer_roots
            .first()
            .and_then(|path| path.parent())
            .context("image layer root is missing")?;
        let sandbox_layer_root = PathBuf::from("/scan/layers");
        let config = staged
            .engine_scratch_root()
            .join("image/scanner/yarahunter.yaml");
        let coverage = staged
            .engine_scratch_root()
            .join("image/scanner/yarahunter-coverage.json");
        fs::create_dir_all(
            config
                .parent()
                .context("scanner config path has no parent")?,
        )?;
        fs::write(
            &config,
            include_str!("../../../config/yarahunter-image.yaml"),
        )?;
        let sandbox_config = scanner_path(staged.engine_scratch_root(), &config)?;
        let sandbox_coverage = scanner_path(staged.engine_scratch_root(), &coverage)?;
        let mounts = [
            mount(layer_root, "/scan/layers"),
            mount(&rules, "/scan/yarahunter-rules"),
        ];
        let args = args([
            "--local",
            "/scan/layers",
            "--rules-path",
            "/scan/yarahunter-rules",
            "--enable-updater=false",
            "--fail-on-rule-compile-warn",
            "--output=json",
            "--config-path",
        ])
        .into_iter()
        .chain([sandbox_config.as_os_str().to_os_string()])
        .collect::<Vec<_>>();
        let environment = [(
            OsString::from(YARAHUNTER_COVERAGE_ENV),
            sandbox_coverage.into_os_string(),
        )];
        let output = run_tool(
            &binary,
            &args,
            &mounts,
            staged.engine_scratch_root(),
            &environment,
        )?;
        let findings = parse_yarahunter(&output.stdout, &sandbox_layer_root)?;
        let coverage_report = read_yarahunter_coverage(&coverage)?;
        ensure!(
            coverage_report.upstream_commit == YARAHUNTER_COMMIT
                && coverage_report.patch_revision == YARAHUNTER_PATCH,
            "YaraHunter coverage runner revision is unsupported"
        );
        let expected_paths = expected_yarahunter_paths(image)?;
        let scanned = normalize_path_list(&coverage_report.scanned_paths, &sandbox_layer_root)?;
        let skipped = normalize_path_list(&coverage_report.skipped_paths, &sandbox_layer_root)?;
        ensure!(
            scanned.len() == coverage_report.scanned_paths.len(),
            "YaraHunter scanned path list has duplicates"
        );
        ensure!(
            skipped.len() == coverage_report.skipped_paths.len(),
            "YaraHunter skipped path list has duplicates"
        );
        ensure!(
            scanned.is_disjoint(&skipped),
            "YaraHunter paths overlap scanned and skipped sets"
        );
        let processed = u64::try_from(scanned.intersection(&expected_paths).count())?;
        let complete = output.complete
            && output.status.success()
            && coverage_report.errors.is_empty()
            && skipped.is_empty()
            && scanned == expected_paths;
        let reason = if complete {
            None
        } else if !output.complete {
            Some("scanner_output_truncated")
        } else if !coverage_report.errors.is_empty() {
            Some("scanner_file_error")
        } else if !skipped.is_empty() || scanned != expected_paths {
            Some("input_coverage_mismatch")
        } else {
            Some("scanner_exit_nonzero")
        };
        Ok(engine_report(
            EngineInput {
                source: "yarahunter",
                input_sha256,
                expected_inputs: expected,
                processed_inputs: processed,
            },
            &version,
            &combine_hashes(&[&rules_sha256, &revision_sha256(YARAHUNTER_PATCH)]),
            None,
            findings,
            complete,
            reason,
        ))
    })();
    match result {
        Ok(report) => report,
        Err(error) => {
            failed_engine_report("yarahunter", input_sha256, expected, failure_code(&error))
        }
    }
}

pub(super) fn capa_report(
    staged: &StagedArchive,
    image: &InspectedImage,
    input_sha256: Option<&str>,
) -> EngineReport {
    let expected = image.executable_files;
    let result = (|| -> Result<EngineReport> {
        let binary = required_path("CAPA_BIN")?;
        let rules = required_path("CAPA_RULES_DIR")?;
        let rules_sha256 = hash_tree(&rules)?;
        let version = tool_version(&binary, staged.engine_scratch_root())?;
        let mut findings = Vec::new();
        let mut processed = 0u64;
        let mut incomplete_reason = None;
        for (layer_index, (root, inventory)) in image
            .layer_roots
            .iter()
            .zip(image.layer_inventories.values())
            .enumerate()
        {
            for member in inventory
                .members
                .iter()
                .filter(|member| member.kind == MemberKind::File && member.binary)
            {
                let path = root.join(&member.path);
                let target = format!("/scan/binary/{layer_index:04}/{}", member.path);
                let args = args(["-j", "-r", "/scan/capa-rules"])
                    .into_iter()
                    .chain([OsString::from(target.as_str())])
                    .collect::<Vec<_>>();
                let output = run_tool(
                    &binary,
                    &args,
                    &[mount(&path, &target), mount(&rules, "/scan/capa-rules")],
                    staged.engine_scratch_root(),
                    &[],
                );
                let output = match output {
                    Ok(output) => output,
                    Err(_) => {
                        incomplete_reason.get_or_insert("scanner_execution_failed");
                        continue;
                    }
                };
                let parsed = match parse_capa(
                    &output.stdout,
                    &format!("{layer_index:04}/{}", member.path),
                ) {
                    Ok(findings) => findings,
                    Err(_) => {
                        incomplete_reason.get_or_insert("scanner_report_invalid");
                        continue;
                    }
                };
                findings.extend(parsed);
                if output.complete && output.status.success() {
                    processed += 1;
                } else if !output.complete {
                    incomplete_reason.get_or_insert("scanner_output_truncated");
                } else {
                    incomplete_reason.get_or_insert("scanner_exit_nonzero");
                }
            }
        }
        ensure!(
            processed <= expected,
            "capa processed input count exceeds inventory"
        );
        let complete = processed == expected && incomplete_reason.is_none();
        let reason = if complete {
            None
        } else {
            incomplete_reason.or(Some("input_coverage_mismatch"))
        };
        Ok(engine_report(
            EngineInput {
                source: "capa",
                input_sha256,
                expected_inputs: expected,
                processed_inputs: processed,
            },
            &version,
            &rules_sha256,
            None,
            findings,
            complete,
            reason,
        ))
    })();
    match result {
        Ok(report) => report,
        Err(error) => failed_engine_report("capa", input_sha256, expected, failure_code(&error)),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyReport {
    schema_version: u32,
    results: Option<Vec<TrivyResult>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyResult {
    target: String,
    vulnerabilities: Option<Vec<TrivyVulnerability>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyVulnerability {
    #[serde(rename = "VulnerabilityID")]
    vulnerability_id: String,
    pkg_name: String,
    severity: String,
}

fn parse_trivy(payload: &[u8]) -> Result<Vec<EngineFinding>> {
    let report: TrivyReport = serde_json::from_slice(payload).context("invalid Trivy JSON")?;
    ensure!(report.schema_version == 2, "unsupported Trivy JSON schema");
    let mut findings = Vec::new();
    let mut seen = BTreeSet::new();
    for result in report.results.into_iter().flatten() {
        ensure!(!result.target.is_empty(), "Trivy result target is missing");
        for vulnerability in result.vulnerabilities.into_iter().flatten() {
            ensure!(
                !vulnerability.vulnerability_id.is_empty()
                    && !vulnerability.pkg_name.is_empty()
                    && !vulnerability.severity.is_empty(),
                "Trivy vulnerability is incomplete"
            );
            let rule = safe_code(&vulnerability.vulnerability_id);
            let location = format!("image/packages/{}", safe_location(&vulnerability.pkg_name));
            let evidence = format!(
                "{}:{}:{}",
                vulnerability.vulnerability_id, vulnerability.pkg_name, result.target
            );
            let id = engine_finding_id("trivy", &rule, &location, &evidence)?;
            if !seen.insert(id.clone()) {
                continue;
            }
            ensure!(findings.len() < 256, "scanner finding count exceeds limit");
            findings.push(EngineFinding {
                id,
                rule,
                summary: format!(
                    "{} vulnerability detected",
                    safe_text(&vulnerability.vulnerability_id, 400)
                ),
                location: Some(location),
                native_severity: Some(vulnerability.severity),
                policy_score: None,
            });
        }
    }
    Ok(findings)
}

fn parse_yarahunter(payload: &[u8], layer_root: &Path) -> Result<Vec<EngineFinding>> {
    let report: serde_json::Value =
        serde_json::from_slice(payload).context("invalid YaraHunter JSON")?;
    let matches = report
        .get("IOC")
        .and_then(serde_json::Value::as_array)
        .context("YaraHunter IOC list is missing")?;
    let mut findings = Vec::new();
    let mut seen = BTreeSet::new();
    for matched in matches {
        let rule = matched
            .get("Matched Rule Name")
            .and_then(serde_json::Value::as_str)
            .context("YaraHunter match has no rule")?;
        let file = matched
            .get("Full File Name")
            .and_then(serde_json::Value::as_str)
            .context("YaraHunter match has no file path")?;
        let location = relative_scanner_path(layer_root, file)?;
        let rule = safe_code(rule);
        let evidence = format!("{}:{location}", rule);
        let id = engine_finding_id("yarahunter", &rule, &location, &evidence)?;
        if !seen.insert(id.clone()) {
            continue;
        }
        ensure!(findings.len() < 256, "scanner finding count exceeds limit");
        findings.push(EngineFinding {
            id,
            rule,
            summary: "YARA malware rule matched".to_string(),
            location: Some(location),
            native_severity: matched
                .get("Severity")
                .and_then(serde_json::Value::as_str)
                .map(safe_code),
            policy_score: Some(Decimal::from(8u32)),
        });
    }
    Ok(findings)
}

fn parse_capa(payload: &[u8], location: &str) -> Result<Vec<EngineFinding>> {
    let report: serde_json::Value = serde_json::from_slice(payload).context("invalid capa JSON")?;
    let rules = report
        .get("rules")
        .and_then(serde_json::Value::as_object)
        .context("capa rules result is missing")?;
    let mut findings = Vec::new();
    for (rule_name, details) in rules {
        ensure!(details.is_object(), "capa rule result is malformed");
        let rule = safe_code(rule_name);
        let id = engine_finding_id("capa", &rule, location, rule_name)?;
        ensure!(findings.len() < 256, "scanner finding count exceeds limit");
        findings.push(EngineFinding {
            id,
            rule,
            summary: "capa capability matched".to_string(),
            location: Some(location.to_string()),
            native_severity: None,
            policy_score: None,
        });
    }
    Ok(findings)
}

pub(super) fn cosign_report(
    staged: &StagedArchive,
    image: &InspectedImage,
    image_ref: Option<&str>,
    certificate_identity: Option<&str>,
    certificate_oidc_issuer: Option<&str>,
    input_sha256: Option<&str>,
) -> (EngineReport, SignatureStatus) {
    let incomplete = |reason| {
        (
            failed_engine_report("cosign", input_sha256, 1, reason),
            SignatureStatus::Incomplete,
        )
    };
    let invalid = |reason| {
        (
            failed_engine_report("cosign", input_sha256, 1, reason),
            SignatureStatus::Invalid,
        )
    };
    let Some(image_ref) = image_ref else {
        return incomplete("signature_image_ref_missing");
    };
    let digest = match image_reference_digest(image_ref) {
        Ok(value) => value,
        Err(_) => return invalid("signature_image_ref_invalid"),
    };
    if image.kind == ArchiveKind::Oci && !image.manifest_digests.contains(&digest) {
        return invalid("signature_digest_not_in_archive");
    }
    if image.chains.len() != 1 {
        return incomplete("signature_scope_multiple_images");
    }
    let Some(identity) = certificate_identity.filter(|value| !value.trim().is_empty()) else {
        return incomplete("signature_policy_incomplete");
    };
    let Some(issuer) = certificate_oidc_issuer.filter(|value| !value.trim().is_empty()) else {
        return incomplete("signature_policy_incomplete");
    };
    let cosign_binary = match required_path("COSIGN_BIN") {
        Ok(path) => path,
        Err(error) => return incomplete(failure_code(&error)),
    };
    let manifest_binary = match required_path("CRANE_BIN") {
        Ok(path) => path,
        Err(_) => return incomplete("signature_manifest_retrieval_unavailable"),
    };
    let version = match tool_version(&cosign_binary, staged.engine_scratch_root()) {
        Ok(version) => version,
        Err(error) => return incomplete(failure_code(&error)),
    };
    let manifest_version = match tool_version_with_args(
        &manifest_binary,
        staged.engine_scratch_root(),
        &[OsString::from("version")],
    ) {
        Ok(version) => version,
        Err(_) => return incomplete("signature_manifest_retrieval_unavailable"),
    };
    let manifest_args = args(["manifest"])
        .into_iter()
        .chain([OsString::from(image_ref)])
        .collect::<Vec<_>>();
    let manifest_output = match run_networked_isolated_tool(
        &manifest_binary,
        &manifest_args,
        staged.engine_scratch_root(),
        SCANNER_TIMEOUT,
        OUTPUT_LIMIT,
    ) {
        Ok(output) => output,
        Err(_) => return incomplete("signature_manifest_retrieval_unavailable"),
    };
    if !manifest_output.complete {
        return incomplete("scanner_output_truncated");
    }
    if !manifest_output.status.success() {
        return incomplete("signature_manifest_retrieval_unavailable");
    }
    match validate_registry_manifest(&manifest_output.stdout, &digest, image) {
        Ok(ManifestEquivalence::Equivalent) => {}
        Ok(ManifestEquivalence::Unproven) => {
            return incomplete("docker_save_equivalence_unproven");
        }
        Err(_) => return invalid("signature_manifest_evidence_invalid"),
    }

    let args = args(["verify", "--output", "json", "--certificate-identity"])
        .into_iter()
        .chain([
            OsString::from(identity),
            OsString::from("--certificate-oidc-issuer"),
            OsString::from(issuer),
            OsString::from(image_ref),
        ])
        .collect::<Vec<_>>();
    let output = match run_networked_isolated_tool(
        &cosign_binary,
        &args,
        staged.engine_scratch_root(),
        SCANNER_TIMEOUT,
        OUTPUT_LIMIT,
    ) {
        Ok(output) => output,
        Err(error) => return incomplete(failure_code(&error)),
    };
    if !output.complete {
        return incomplete("scanner_output_truncated");
    }
    if !output.status.success() {
        return incomplete("signature_verification_failed");
    }
    if validate_cosign_output(&output.stdout, &digest).is_err() {
        return invalid("signature_evidence_invalid");
    }
    (
        engine_report(
            EngineInput {
                source: "cosign",
                input_sha256,
                expected_inputs: 1,
                processed_inputs: 1,
            },
            &version,
            &combine_hashes(&[
                &revision_sha256("cosign-image-signature-json-v2"),
                &revision_sha256(&manifest_version),
            ]),
            None,
            Vec::new(),
            true,
            None,
        ),
        SignatureStatus::Verified,
    )
}

enum ManifestEquivalence {
    Equivalent,
    Unproven,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegistryManifest {
    schema_version: u32,
    media_type: String,
    config: RegistryDescriptor,
    layers: Vec<RegistryDescriptor>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegistryDescriptor {
    media_type: String,
    digest: String,
    size: u64,
}

fn validate_registry_manifest(
    payload: &[u8],
    expected_digest: &str,
    image: &InspectedImage,
) -> Result<ManifestEquivalence> {
    let digest = hex::encode(Sha256::digest(payload));
    ensure!(
        digest == expected_digest,
        "registry manifest does not match the pinned digest"
    );
    if image.kind == ArchiveKind::Oci {
        ensure!(
            image.manifest_digests.contains(expected_digest),
            "registry manifest is not part of the inspected OCI archive"
        );
        return Ok(ManifestEquivalence::Equivalent);
    }
    let manifest: RegistryManifest =
        serde_json::from_slice(payload).context("invalid registry manifest JSON")?;
    ensure!(
        manifest.schema_version == 2
            && matches!(
                manifest.media_type.as_str(),
                "application/vnd.oci.image.manifest.v1+json"
                    | "application/vnd.docker.distribution.manifest.v2+json"
            ),
        "registry image manifest type is unsupported"
    );
    let config_digest = format!(
        "sha256:{}",
        super::validate_sha256_ref(&manifest.config.digest)?.to_ascii_lowercase()
    );
    ensure!(
        matches!(
            manifest.config.media_type.as_str(),
            "application/vnd.oci.image.config.v1+json"
                | "application/vnd.docker.container.image.v1+json"
        ) && manifest.config.size > 0
            && manifest.config.size <= MAX_IMAGE_METADATA_BYTES,
        "registry image config descriptor is invalid"
    );
    let mut layer_digests = Vec::with_capacity(manifest.layers.len());
    for layer in &manifest.layers {
        let digest = super::validate_sha256_ref(&layer.digest)?.to_ascii_lowercase();
        ensure!(
            layer.size > 0
                && layer.size <= MAX_LAYER_BYTES
                && matches!(
                    layer.media_type.as_str(),
                    "application/vnd.oci.image.layer.v1.tar"
                        | "application/vnd.oci.image.layer.v1.tar+gzip"
                        | "application/vnd.oci.image.layer.v1.tar+zstd"
                        | "application/vnd.docker.image.rootfs.diff.tar"
                        | "application/vnd.docker.image.rootfs.diff.tar.gzip"
                ),
            "registry image layer descriptor is invalid"
        );
        layer_digests.push((layer.media_type.as_str(), digest, layer.size));
    }
    let chain = image
        .chains
        .iter()
        .find(|chain| chain.config_digest.eq_ignore_ascii_case(&config_digest))
        .context("registry manifest does not match a scanned image config")?;
    ensure!(
        chain.config_size == manifest.config.size,
        "registry manifest config size differs from scanned image"
    );
    ensure!(
        chain.layers.len() == layer_digests.len(),
        "registry manifest layer count differs from scanned image"
    );
    let mut unproven = false;
    for (local, (media_type, remote_digest, remote_size)) in chain.layers.iter().zip(&layer_digests)
    {
        if matches!(
            *media_type,
            "application/vnd.oci.image.layer.v1.tar"
                | "application/vnd.docker.image.rootfs.diff.tar"
        ) {
            let inventory = image
                .layer_inventories
                .get(&local.archive_path)
                .context("scanned layer inventory is missing")?;
            ensure!(
                inventory.raw_tar_size == *remote_size
                    && local
                        .diff_id
                        .strip_prefix("sha256:")
                        .is_some_and(|diff_id| diff_id.eq_ignore_ascii_case(remote_digest)),
                "registry manifest layer order, size, or digest differs from scanned image"
            );
        } else {
            unproven = true;
        }
    }
    Ok(if unproven {
        ManifestEquivalence::Unproven
    } else {
        ManifestEquivalence::Equivalent
    })
}

fn image_reference_digest(image_ref: &str) -> Result<String> {
    ensure!(
        !image_ref.is_empty()
            && image_ref.len() <= 4096
            && !image_ref.chars().any(char::is_control)
            && !image_ref.chars().any(char::is_whitespace),
        "image reference is invalid"
    );
    let (name, digest) = image_ref
        .rsplit_once("@sha256:")
        .context("image reference must be pinned by sha256 digest")?;
    ensure!(
        !name.is_empty()
            && !name.starts_with('-')
            && !name.ends_with('/')
            && name.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || b"._-/:".contains(&byte)),
        "image reference name is invalid"
    );
    let digest_reference = format!("sha256:{digest}");
    let digest = super::validate_sha256_ref(&digest_reference)?;
    Ok(digest.to_ascii_lowercase())
}

fn validate_cosign_output(payload: &[u8], expected_digest: &str) -> Result<()> {
    let output: serde_json::Value =
        serde_json::from_slice(payload).context("invalid cosign verification JSON")?;
    let entries = output
        .as_array()
        .context("cosign verification JSON is not an array")?;
    ensure!(!entries.is_empty(), "cosign verified no signatures");
    for entry in entries {
        let critical = entry
            .get("critical")
            .or_else(|| entry.get("Critical"))
            .context("cosign signature payload is missing")?;
        let image = critical
            .get("image")
            .or_else(|| critical.get("Image"))
            .context("cosign image claim is missing")?;
        let digest = image
            .get("docker-manifest-digest")
            .or_else(|| image.get("Docker-manifest-digest"))
            .and_then(serde_json::Value::as_str)
            .context("cosign manifest digest is missing")?;
        let digest = digest.strip_prefix("sha256:").unwrap_or(digest);
        ensure!(
            digest.len() == 64
                && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                && digest.eq_ignore_ascii_case(expected_digest),
            "cosign verified an unexpected manifest digest"
        );
        let signature_type = critical
            .get("type")
            .or_else(|| critical.get("Type"))
            .and_then(serde_json::Value::as_str)
            .context("cosign signature type is missing")?;
        ensure!(
            signature_type == "cosign container image signature",
            "cosign signature type is unsupported"
        );
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct YaraHunterCoverage {
    schema_version: u32,
    upstream_commit: String,
    patch_revision: String,
    scanned_paths: Vec<String>,
    skipped_paths: Vec<String>,
    errors: Vec<String>,
}

fn read_yarahunter_coverage(path: &Path) -> Result<YaraHunterCoverage> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file(),
        "YaraHunter coverage is not a regular file"
    );
    ensure!(
        metadata.len() <= MAX_IMAGE_METADATA_BYTES,
        "YaraHunter coverage exceeds size limit"
    );
    let report: YaraHunterCoverage = serde_json::from_slice(&fs::read(path)?)?;
    ensure!(
        report.schema_version == 1,
        "unsupported YaraHunter coverage schema"
    );
    Ok(report)
}

fn expected_yarahunter_paths(image: &InspectedImage) -> Result<BTreeSet<String>> {
    let mut expected = BTreeSet::new();
    for (index, inventory) in image.layer_inventories.values().enumerate() {
        for member in inventory
            .members
            .iter()
            .filter(|member| member.kind == MemberKind::File && member.whiteout_target.is_none())
        {
            expected.insert(format!("{index:04}/{}", member.path));
        }
    }
    ensure!(
        expected.len() as u64 == image.regular_files,
        "image layer file inventory is inconsistent"
    );
    Ok(expected)
}

fn normalize_path_list(paths: &[String], root: &Path) -> Result<BTreeSet<String>> {
    paths
        .iter()
        .map(|path| relative_scanner_path(root, path))
        .collect()
}

fn relative_scanner_path(root: &Path, raw: &str) -> Result<String> {
    let root_text = root.to_string_lossy();
    let relative = if raw.starts_with('/') {
        raw.strip_prefix(root_text.as_ref())
            .and_then(|path| path.strip_prefix('/'))
            .context("scanner reported a path outside its input root")?
    } else {
        raw
    };
    let normalized = super::normalize_archive_path(relative, false)?;
    Ok(normalized)
}

struct EngineInput<'a> {
    source: &'a str,
    input_sha256: Option<&'a str>,
    expected_inputs: u64,
    processed_inputs: u64,
}

fn engine_report(
    input: EngineInput<'_>,
    version: &str,
    rule_bundle_sha256: &str,
    database_sha256: Option<String>,
    findings: Vec<EngineFinding>,
    complete: bool,
    reason: Option<&str>,
) -> EngineReport {
    let reason = if findings.len() > 256 {
        Some("finding_limit")
    } else {
        reason
    };
    EngineReport {
        source: input.source.to_string(),
        version: Some(version.to_string()),
        rule_bundle_sha256: Some(rule_bundle_sha256.to_string()),
        database_sha256,
        input_sha256: input.input_sha256.map(str::to_string),
        expected_inputs: input.expected_inputs,
        processed_inputs: input.processed_inputs.min(input.expected_inputs),
        coverage: if complete && reason.is_none() {
            Coverage::Complete
        } else {
            Coverage::Partial
        },
        findings: findings.into_iter().take(256).collect(),
        reason: reason.map(str::to_string),
    }
}

fn tool_version(binary: &Path, scratch: &Path) -> Result<String> {
    tool_version_with_args(binary, scratch, &[OsString::from("--version")])
}

fn tool_version_with_args(binary: &Path, scratch: &Path, arguments: &[OsString]) -> Result<String> {
    let output = run_tool(binary, arguments, &[], scratch, &[])?;
    ensure!(
        output.complete && output.status.success(),
        "scanner version command failed"
    );
    let text = String::from_utf8_lossy(&output.stdout);
    let version = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .context("scanner version output is empty")?;
    ensure!(
        version.len() <= 128 && !version.chars().any(char::is_control),
        "scanner version is invalid"
    );
    Ok(version.to_string())
}

fn run_tool(
    binary: &Path,
    arguments: &[OsString],
    mounts: &[SandboxMount],
    scratch: &Path,
    environment: &[(OsString, OsString)],
) -> Result<BoundedCommandOutput> {
    run_isolated_tool_with_env(
        binary,
        arguments,
        mounts,
        scratch,
        environment,
        SCANNER_TIMEOUT,
        OUTPUT_LIMIT,
    )
}

fn required_path(name: &str) -> Result<PathBuf> {
    let value = std::env::var_os(name).context("scanner_not_configured")?;
    ensure!(!value.is_empty(), "scanner_not_configured");
    Ok(PathBuf::from(value))
}

fn mount(host_path: &Path, sandbox_path: &str) -> SandboxMount {
    SandboxMount {
        host_path: host_path.to_path_buf(),
        sandbox_path: PathBuf::from(sandbox_path),
    }
}

fn scanner_path(scratch: &Path, path: &Path) -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Ok(Path::new("/tmp").join(path.strip_prefix(scratch)?))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = scratch;
        Ok(path.to_path_buf())
    }
}

fn args<const N: usize>(values: [&str; N]) -> Vec<OsString> {
    values.into_iter().map(OsString::from).collect()
}

fn hash_tree(root: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(root)?;
    ensure!(
        metadata.file_type().is_dir(),
        "scanner data root is not a directory"
    );
    let root = fs::canonicalize(root)?;
    let mut files = Vec::new();
    let mut total = 0u64;
    let mut entries = 0usize;
    for entry in walkdir::WalkDir::new(&root)
        .follow_links(false)
        .max_open(32)
    {
        let entry = entry?;
        entries = entries
            .checked_add(1)
            .context("scanner entry count overflow")?;
        ensure!(
            entries <= MAX_ARCHIVE_ENTRIES,
            "scanner data has too many entries"
        );
        if entry.path() == root {
            continue;
        }
        ensure!(
            !entry.file_type().is_symlink(),
            "scanner data contains a symlink"
        );
        if entry.file_type().is_dir() {
            continue;
        }
        ensure!(
            entry.file_type().is_file(),
            "scanner data contains a special file"
        );
        let relative = entry
            .path()
            .strip_prefix(&root)?
            .to_str()
            .context("scanner data path is not UTF-8")?
            .replace(std::path::MAIN_SEPARATOR, "/");
        let normalized = super::normalize_archive_path(&relative, false)?;
        let mut file = open_regular_file(entry.path())?;
        let (digest, size) = hash_file(&mut file, MAX_LAYER_BYTES.saturating_sub(total))?;
        total = total
            .checked_add(size)
            .context("scanner data size overflow")?;
        files.push((normalized, size, digest));
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hash = Sha256::new();
    for (path, size, digest) in files {
        hash.update(path.as_bytes());
        hash.update([0]);
        hash.update(size.to_be_bytes());
        hash.update(digest.as_bytes());
    }
    Ok(hex::encode(hash.finalize()))
}

fn hash_file(file: &mut File, max_bytes: u64) -> Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let remaining = max_bytes.saturating_sub(size);
        let limit = usize::try_from(remaining.saturating_add(1).min(buffer.len() as u64))?;
        let count = file.read(&mut buffer[..limit])?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(count)?)
            .context("scanner data size overflow")?;
        ensure!(size <= max_bytes, "scanner data exceeds size limit");
        hasher.update(&buffer[..count]);
    }
    Ok((hex::encode(hasher.finalize()), size))
}

fn open_regular_file(path: &Path) -> Result<File> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?
    };
    #[cfg(not(unix))]
    let file = File::open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "scanner data member is not a regular file"
    );
    Ok(file)
}

fn revision_sha256(revision: &str) -> String {
    hex::encode(Sha256::digest(revision.as_bytes()))
}

fn combine_hashes(hashes: &[&str]) -> String {
    let mut hash = Sha256::new();
    for value in hashes {
        hash.update(value.as_bytes());
    }
    hex::encode(hash.finalize())
}

fn safe_code(raw: &str) -> String {
    let mut value = String::with_capacity(raw.len().min(128));
    for character in raw.chars().take(128) {
        let character = character.to_ascii_lowercase();
        value.push(
            if character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '_' | '-')
            {
                character
            } else {
                '_'
            },
        );
    }
    if value.is_empty() {
        "finding".to_string()
    } else {
        value
    }
}

fn safe_location(raw: &str) -> String {
    let mut value = String::with_capacity(raw.len().min(160));
    for character in raw.chars().take(160) {
        value.push(
            if character.is_control() || matches!(character, '\\' | ':' | '?') {
                '_'
            } else {
                character
            },
        );
    }
    if value.split('/').any(|part| part == "..") {
        value = value.replace("..", "__");
    }
    value.trim_matches('/').to_string()
}

fn safe_text(raw: &str, limit: usize) -> String {
    raw.chars()
        .filter(|character| !character.is_control() && !matches!(character, '/' | '\\'))
        .take(limit)
        .collect::<String>()
        .replace("://", ": ")
}

fn failure_code(error: &anyhow::Error) -> &'static str {
    let message = error.to_string();
    if message.contains("scanner_not_configured")
        || message.contains("scanner executable not found")
    {
        "scanner_not_configured"
    } else if message.contains("scanner_memory_limit_unavailable")
        || message.contains("scanner sandbox")
        || message.contains("bubblewrap")
    {
        "scanner_sandbox_unavailable"
    } else if message.contains("database is missing")
        || message.contains("database metadata is missing")
    {
        "scanner_database_missing"
    } else if message.contains("coverage") {
        "scanner_coverage_unavailable"
    } else {
        "scanner_execution_failed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trivy_json_preserves_severity_and_package_location() -> Result<()> {
        let payload = br#"{"SchemaVersion":2,"Results":[{"Target":"image.tar (alpine 3.20)","Vulnerabilities":[{"VulnerabilityID":"CVE-2025-1234","PkgName":"openssl","InstalledVersion":"3.0.1","Severity":"HIGH"}]}]}"#;
        let findings = parse_trivy(payload)?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "cve-2025-1234");
        assert_eq!(
            findings[0].location.as_deref(),
            Some("image/packages/openssl")
        );
        assert_eq!(findings[0].native_severity.as_deref(), Some("HIGH"));
        Ok(())
    }
    #[test]
    fn scanner_finding_limits_reject_truncated_reports() -> Result<()> {
        let trivy_vulnerabilities = (0..257)
            .map(|index| {
                serde_json::json!({
                    "VulnerabilityID": format!("CVE-2025-{index:04}"),
                    "PkgName": "openssl",
                    "Severity": "HIGH"
                })
            })
            .collect::<Vec<_>>();
        let trivy = serde_json::to_vec(&serde_json::json!({
            "SchemaVersion": 2,
            "Results": [{
                "Target": "image.tar",
                "Vulnerabilities": trivy_vulnerabilities
            }]
        }))?;
        assert!(parse_trivy(&trivy).is_err());

        let yara = serde_json::to_vec(&serde_json::json!({
            "IOC": (0..257)
                .map(|index| serde_json::json!({
                    "Matched Rule Name": format!("rule-{index}"),
                    "Full File Name": "/scan/layers/0000/file"
                }))
                .collect::<Vec<_>>()
        }))?;
        assert!(parse_yarahunter(&yara, Path::new("/scan/layers")).is_err());

        let capa = serde_json::to_vec(&serde_json::json!({
            "rules": (0..257)
                .map(|index| (format!("rule-{index}"), serde_json::json!({})))
                .collect::<serde_json::Map<String, serde_json::Value>>()
        }))?;
        assert!(parse_capa(&capa, "0000/file").is_err());
        Ok(())
    }

    #[test]
    fn malformed_trivy_report_does_not_prove_clean_coverage() {
        assert!(parse_trivy(br#"{"SchemaVersion":1,"Results":[]}"#).is_err());
    }

    #[test]
    fn cosign_output_must_match_the_scanned_manifest_digest() -> Result<()> {
        let digest = "a".repeat(64);
        let output = serde_json::to_vec(&serde_json::json!([{
            "critical": {
                "image": { "docker-manifest-digest": format!("sha256:{digest}") },
                "type": "cosign container image signature"
            }
        }]))?;
        assert!(validate_cosign_output(&output, &digest).is_ok());
        let other_digest = "b".repeat(64);
        assert!(validate_cosign_output(&output, &other_digest).is_err());
        let malformed = serde_json::to_vec(&serde_json::json!([{
            "critical": {
                "image": { "docker-manifest-digest": "sha256:invalid" },
                "type": "cosign container image signature"
            }
        }]))?;
        assert!(validate_cosign_output(&malformed, &digest).is_err());
        Ok(())
    }
    #[test]
    fn yarahunter_reports_blocking_matches_with_layer_locations() -> Result<()> {
        let payload = br#"{"IOC":[{"Matched Rule Name":"Malware.Rule","Full File Name":"/scan/layers/0000/usr/bin/fixture","Severity":"high"}]}"#;
        let findings = parse_yarahunter(payload, Path::new("/scan/layers"))?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].policy_score, Some(Decimal::from(8u32)));
        assert_eq!(
            findings[0].location.as_deref(),
            Some("0000/usr/bin/fixture")
        );
        Ok(())
    }

    #[test]
    fn capa_empty_rules_are_valid_clean_results() -> Result<()> {
        assert!(parse_capa(br#"{"meta":{},"rules":{}}"#, "0000/usr/bin/fixture")?.is_empty());
        Ok(())
    }

    #[test]
    fn scanner_paths_outside_layer_root_are_rejected() {
        assert!(relative_scanner_path(Path::new("/scan/layers"), "/tmp/other/file").is_err());
    }
}
