use anyhow::{Context, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::process::{Command, Output};
use tar::{Builder, Header};

fn tar_bytes(entries: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    let mut archive = Builder::new(Vec::new());
    for (path, bytes) in entries {
        let mut header = Header::new_gnu();
        header.set_path(path)?;
        header.set_size(u64::try_from(bytes.len())?);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append(&header, *bytes)?;
    }
    archive.into_inner().map_err(Into::into)
}

struct DockerSaveFixture {
    archive: Vec<u8>,
    #[cfg(target_os = "linux")]
    config_digest: String,
    #[cfg(target_os = "linux")]
    config_size: usize,
    #[cfg(target_os = "linux")]
    layer_diff_ids: Vec<String>,
    #[cfg(target_os = "linux")]
    layer_sizes: Vec<usize>,
}

fn docker_save(layers: &[(&str, &[u8], &[u8])], corrupt_diff_id: bool) -> Result<Vec<u8>> {
    Ok(docker_save_fixture(layers, corrupt_diff_id)?.archive)
}

fn docker_save_fixture(
    layers: &[(&str, &[u8], &[u8])],
    corrupt_diff_id: bool,
) -> Result<DockerSaveFixture> {
    let mut diff_ids = layers
        .iter()
        .map(|(_, _, raw)| format!("sha256:{}", hex::encode(Sha256::digest(raw))))
        .collect::<Vec<_>>();
    if corrupt_diff_id {
        diff_ids[0] = format!("sha256:{}", "0".repeat(64));
    }
    let config = serde_json::to_vec(&serde_json::json!({
        "architecture": "amd64",
        "os": "linux",
        "config": { "Entrypoint": ["/bin/true"] },
        "rootfs": { "type": "layers", "diff_ids": diff_ids },
        "history": [{ "created_by": "fixture" }]
    }))?;
    let config_digest = hex::encode(Sha256::digest(&config));
    let config_name = format!("{config_digest}.json");
    let layer_paths = layers.iter().map(|(path, _, _)| *path).collect::<Vec<_>>();
    let manifest = serde_json::to_vec(&serde_json::json!([{
        "Config": config_name,
        "RepoTags": ["fixture:latest"],
        "Layers": layer_paths
    }]))?;
    let mut entries = vec![
        ("manifest.json", manifest.as_slice()),
        (config_name.as_str(), config.as_slice()),
    ];
    entries.extend(layers.iter().map(|(path, stored, _)| (*path, *stored)));
    let archive = tar_bytes(&entries)?;
    Ok(DockerSaveFixture {
        archive,
        #[cfg(target_os = "linux")]
        config_digest,
        #[cfg(target_os = "linux")]
        config_size: config.len(),
        #[cfg(target_os = "linux")]
        layer_diff_ids: layers
            .iter()
            .map(|(_, _, raw)| format!("sha256:{}", hex::encode(Sha256::digest(raw))))
            .collect(),
        #[cfg(target_os = "linux")]
        layer_sizes: layers.iter().map(|(_, _, raw)| raw.len()).collect(),
    })
}

#[cfg(target_os = "linux")]
fn tool_directory() -> Result<tempfile::TempDir> {
    // The Linux sandbox binds scratch over /tmp, which would shadow tools stored there.
    Ok(tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?)
}

fn scan(archive: &[u8], extra: &[&str]) -> Result<(Output, Value)> {
    let owned = extra
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    scan_with_env(archive, &owned, &[])
}

fn scan_with_env(
    archive: &[u8],
    extra: &[String],
    environment: &[(String, String)],
) -> Result<(Output, Value)> {
    let directory = tempfile::tempdir()?;
    let archive_path = directory.path().join("image.tar");
    std::fs::write(&archive_path, archive)?;
    let scratch = directory.path().join("scratch");
    std::fs::create_dir(&scratch)?;
    let empty_path = directory.path().join("empty-bin");
    std::fs::create_dir(&empty_path)?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_supply-core"));
    command
        .env("PATH", empty_path)
        .args(["scan-image"])
        .arg(&archive_path)
        .args(["--scratch-dir"])
        .arg(&scratch)
        .arg("--json")
        .args(extra);
    for (key, value) in environment {
        command.env(key, value);
    }
    let output = command.output()?;
    let report = serde_json::from_slice(&output.stdout)?;
    Ok((output, report))
}

#[test]
fn scan_image_reports_layer_inventory_and_missing_required_engines() -> Result<()> {
    let layer = tar_bytes(&[("usr/share/fixture.txt", b"historical layer content")])?;
    let archive = docker_save(&[("layer/layer.tar", &layer, &layer)], false)?;

    let (output, report) = scan(&archive, &[])?;

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(report["decision"], "incomplete");
    assert_eq!(
        report["artifact_sha256"],
        hex::encode(Sha256::digest(&archive))
    );
    assert_eq!(report["signature_status"], "signature_unchecked");
    let engines = report["engines"]
        .as_array()
        .context("engine reports missing")?;
    let archive_integrity = engines
        .iter()
        .find(|engine| engine["source"] == "image-archive")
        .context("archive integrity report missing")?;
    assert_eq!(archive_integrity["coverage"], "complete");
    let yarahunter = engines
        .iter()
        .find(|engine| engine["source"] == "yarahunter")
        .context("YaraHunter report missing")?;
    assert_eq!(yarahunter["expected_inputs"], 1);
    assert_eq!(yarahunter["processed_inputs"], 0);
    assert_eq!(yarahunter["coverage"], "unknown");
    Ok(())
}

#[test]
fn scan_image_rejects_a_layer_diff_id_mismatch() -> Result<()> {
    let layer = tar_bytes(&[("usr/share/fixture.txt", b"changed layer content")])?;
    let archive = docker_save(&[("layer/layer.tar", &layer, &layer)], true)?;

    let (output, report) = scan(&archive, &[])?;

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(report["decision"], "incomplete");
    let archive_integrity = report["engines"]
        .as_array()
        .context("engine reports missing")?
        .iter()
        .find(|engine| engine["source"] == "image-archive")
        .context("archive integrity report missing")?;
    assert_eq!(archive_integrity["coverage"], "partial");
    Ok(())
}

#[test]
fn scan_image_checks_gzip_and_zstd_layer_diff_ids() -> Result<()> {
    let layer = tar_bytes(&[("usr/share/fixture.txt", b"compressed layer content")])?;
    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    gzip.write_all(&layer)?;
    let gzip = gzip.finish()?;
    let zstd = zstd::stream::encode_all(layer.as_slice(), 0)?;

    for (path, stored) in [
        ("layer/layer.tar.gz", gzip.as_slice()),
        ("layer/layer.tar.zst", zstd.as_slice()),
    ] {
        let archive = docker_save(&[(path, stored, &layer)], false)?;
        let (output, report) = scan(&archive, &[])?;

        assert_eq!(output.status.code(), Some(3));
        assert_eq!(report["decision"], "incomplete");
        let archive_integrity = report["engines"]
            .as_array()
            .context("engine reports missing")?
            .iter()
            .find(|engine| engine["source"] == "image-archive")
            .context("archive integrity report missing")?;
        assert_eq!(archive_integrity["coverage"], "complete");
    }
    Ok(())
}

#[test]
fn scan_image_requires_an_image_reference_when_signature_policy_is_required() -> Result<()> {
    let layer = tar_bytes(&[("usr/share/fixture.txt", b"signature subject fixture")])?;
    let archive = docker_save(&[("layer/layer.tar", &layer, &layer)], false)?;

    let (output, report) = scan(&archive, &["--require-signature"])?;

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(report["signature_status"], "incomplete");
    assert_eq!(report["decision"], "incomplete");
    Ok(())
}
#[cfg(target_os = "linux")]
struct OciFixture {
    archive: Vec<u8>,
    manifest: Vec<u8>,
    manifest_digest: String,
}

#[cfg(target_os = "linux")]
fn oci_archive_with_stored_layer(
    layer: &[u8],
    stored_layer: &[u8],
    layer_media_type: &str,
) -> Result<OciFixture> {
    let config = serde_json::to_vec(&serde_json::json!({
        "architecture": "amd64",
        "os": "linux",
        "config": { "Entrypoint": [] },
        "rootfs": {
            "type": "layers",
            "diff_ids": [format!("sha256:{}", hex::encode(Sha256::digest(layer)))]
        },
        "history": [{ "created_by": "fixture" }]
    }))?;
    let config_digest = hex::encode(Sha256::digest(&config));
    let layer_digest = hex::encode(Sha256::digest(stored_layer));
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": format!("sha256:{config_digest}"),
            "size": config.len()
        },
        "layers": [{
            "mediaType": layer_media_type,
            "digest": format!("sha256:{layer_digest}"),
            "size": stored_layer.len()
        }]
    }))?;
    let manifest_digest = hex::encode(Sha256::digest(&manifest));
    let index = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": format!("sha256:{manifest_digest}"),
            "size": manifest.len()
        }]
    }))?;
    let config_path = format!("blobs/sha256/{config_digest}");
    let manifest_path = format!("blobs/sha256/{manifest_digest}");
    let layer_path = format!("blobs/sha256/{layer_digest}");
    let entries = [
        (
            "oci-layout",
            br#"{"imageLayoutVersion":"1.0.0"}"#.as_slice(),
        ),
        ("index.json", index.as_slice()),
        (config_path.as_str(), config.as_slice()),
        (manifest_path.as_str(), manifest.as_slice()),
        (layer_path.as_str(), stored_layer),
    ];
    Ok(OciFixture {
        archive: tar_bytes(&entries)?,
        manifest,
        manifest_digest,
    })
}

#[cfg(target_os = "linux")]
fn docker_registry_manifest(
    fixture: &DockerSaveFixture,
    layer_order: &[usize],
    config_digest: Option<&str>,
) -> Result<Vec<u8>> {
    let config_digest = config_digest.unwrap_or(&fixture.config_digest);
    let layers = layer_order
        .iter()
        .map(|index| {
            serde_json::json!({
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar",
                "digest": fixture.layer_diff_ids[*index],
                "size": fixture.layer_sizes[*index]
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "digest": format!("sha256:{config_digest}"),
            "size": fixture.config_size
        },
        "layers": layers
    }))
    .map_err(Into::into)
}

#[cfg(target_os = "linux")]
fn cosign_payload(manifest_digest: &str) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!([{
        "critical": {
            "identity": { "docker-reference": "registry.example/fixture" },
            "image": { "docker-manifest-digest": format!("sha256:{manifest_digest}") },
            "type": "cosign container image signature"
        }
    }]))
    .map_err(Into::into)
}

#[cfg(target_os = "linux")]
fn signature_args(manifest_digest: &str) -> Vec<String> {
    vec![
        "--require-signature".to_string(),
        "--image-ref".to_string(),
        format!("registry.example/fixture@sha256:{manifest_digest}"),
        "--certificate-identity".to_string(),
        "fixture@example.test".to_string(),
        "--certificate-oidc-issuer".to_string(),
        "https://issuer.example".to_string(),
    ]
}

#[cfg(target_os = "linux")]
fn fake_scanner_environment(
    directory: &std::path::Path,
    yara_paths: &[&str],
    yara_matches: &[&str],
    registry_manifest: Option<&[u8]>,
    cosign_output: Option<&[u8]>,
) -> Result<Vec<(String, String)>> {
    use std::os::unix::fs::PermissionsExt;

    fn write_tool(directory: &std::path::Path, name: &str, body: &str) -> Result<String> {
        let path = directory.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n"))?;
        let mut permissions = std::fs::metadata(&path)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions)?;
        Ok(path.to_string_lossy().into_owned())
    }

    fn quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }

    let tools = directory.join("tools");
    std::fs::create_dir_all(&tools)?;
    let cache = directory.join("trivy-cache/db");
    std::fs::create_dir_all(&cache)?;
    std::fs::write(cache.join("trivy.db"), b"offline database")?;
    std::fs::write(cache.join("metadata.json"), b"{}")?;
    let rules = directory.join("yarahunter-rules");
    std::fs::create_dir_all(&rules)?;
    std::fs::write(
        rules.join("fixture.yar"),
        b"rule fixture { condition: true }",
    )?;

    let trivy_json = serde_json::to_string(&serde_json::json!({
        "SchemaVersion": 2,
        "Results": [{
            "Target": "image.tar",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2025-1234",
                "PkgName": "fixture-package",
                "Severity": "CRITICAL"
            }]
        }]
    }))?;
    let trivy = write_tool(
        &tools,
        "trivy",
        &format!(
            "if [ \"$1\" = \"--version\" ]; then printf 'Version: test\\n'; exit 0; fi\n\
             [ \"$3\" = \"image\" ] || exit 2\n\
             if printf x >> /scan/image.tar 2>/dev/null; then exit 31; fi\n\
             printf x > /tmp/trivy-scratch || exit 32\n\
             test -r /scan/image.tar || exit 33\n\
             printf '%s' {}",
            quote(&trivy_json)
        ),
    )?;

    let scanned_paths = yara_paths
        .iter()
        .map(|path| format!("/scan/layers/{path}"))
        .collect::<Vec<_>>();
    let matches = yara_matches
        .iter()
        .map(|path| {
            serde_json::json!({
                "Matched Rule Name": "Fixture.Malware",
                "Full File Name": format!("/scan/layers/{path}"),
                "Severity": "high"
            })
        })
        .collect::<Vec<_>>();
    let yara_json = serde_json::to_string(&serde_json::json!({ "IOC": matches }))?;
    let coverage_json = serde_json::to_string(&serde_json::json!({
        "schema_version": 1,
        "upstream_commit": "8cb5a008056a407cf5a273fabb0ecf6626acd50e",
        "patch_revision": "supply-core-yarahunter-coverage-v1",
        "scanned_paths": scanned_paths,
        "skipped_paths": [],
        "errors": []
    }))?;
    let path_checks = yara_paths
        .iter()
        .map(|path| format!("test -r /scan/layers/{path} || exit 43"))
        .collect::<Vec<_>>()
        .join("\n");
    let yara = write_tool(
        &tools,
        "yarahunter",
        &format!(
            "if [ \"$1\" = \"--version\" ]; then printf 'YaraHunter test\\n'; exit 0; fi\n\
             config=\n\
             while [ \"$#\" -gt 0 ]; do\n\
               if [ \"$1\" = \"--config-path\" ]; then config=\"$2\"; shift 2; else shift; fi\n\
             done\n\
             [ -r \"$config\" ] || exit 41\n\
             printf x > /tmp/yara-scratch || exit 42\n\
             {path_checks}\n\
             printf '%s' {} \n\
             printf '%s' {} > \"$SUPPLY_CORE_YARAHUNTER_COVERAGE_PATH\"",
            quote(&yara_json),
            quote(&coverage_json),
        ),
    )?;

    let mut environment = vec![
        ("TRIVY_BIN".to_string(), trivy),
        (
            "TRIVY_CACHE_DIR".to_string(),
            directory.join("trivy-cache").to_string_lossy().into_owned(),
        ),
        ("YARAHUNTER_BIN".to_string(), yara),
        (
            "YARAHUNTER_RULES_DIR".to_string(),
            rules.to_string_lossy().into_owned(),
        ),
    ];
    if let (Some(manifest), Some(cosign_output)) = (registry_manifest, cosign_output) {
        let manifest_text = std::str::from_utf8(manifest)?;
        let cosign_text = std::str::from_utf8(cosign_output)?;
        let crane = write_tool(
            &tools,
            "crane",
            &format!(
                "if [ \"$1\" = \"version\" ]; then printf 'crane test\\n'; exit 0; fi\n\
                 [ \"$1\" = \"manifest\" ] || exit 51\n\
                 [ -n \"$SSL_CERT_FILE\" ] && [ -s \"$SSL_CERT_FILE\" ] || exit 54\n\
                 printf '%s' {}",
                quote(manifest_text)
            ),
        )?;
        let cosign = write_tool(
            &tools,
            "cosign",
            &format!(
                "if [ \"$1\" = \"--version\" ]; then printf 'cosign test\\n'; exit 0; fi\n\
                 [ \"$1\" = \"verify\" ] || exit 52\n\
                 for arg in \"$@\"; do [ \"$arg\" != \"--check-claims=false\" ] || exit 53; done\n\
                 printf '%s' {}",
                quote(cosign_text)
            ),
        )?;
        environment.push(("CRANE_BIN".to_string(), crane));
        environment.push(("COSIGN_BIN".to_string(), cosign));
    }
    Ok(environment)
}

#[cfg(target_os = "linux")]
fn tar_layer_with_links() -> Result<Vec<u8>> {
    let mut archive = Builder::new(Vec::new());
    let mut file = Header::new_gnu();
    file.set_path("usr/share/fixture.txt")?;
    file.set_size(9);
    file.set_mode(0o644);
    file.set_cksum();
    archive.append(&file, &b"link data"[..])?;
    for (path, target, entry_type) in [
        (
            "usr/share/symlink.txt",
            "fixture.txt",
            tar::EntryType::Symlink,
        ),
        (
            "usr/share/hardlink.txt",
            "usr/share/fixture.txt",
            tar::EntryType::Link,
        ),
    ] {
        let mut link = Header::new_gnu();
        link.set_entry_type(entry_type);
        link.set_path(path)?;
        link.set_link_name(target)?;
        link.set_size(0);
        link.set_mode(0o644);
        link.set_cksum();
        archive.append(&link, std::io::empty())?;
    }
    archive.into_inner().map_err(Into::into)
}

#[cfg(target_os = "linux")]
fn engine_report<'a>(report: &'a Value, source: &str) -> Result<&'a Value> {
    report["engines"]
        .as_array()
        .context("engine reports missing")?
        .iter()
        .find(|engine| engine["source"] == source)
        .with_context(|| format!("{source} report missing"))
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires bubblewrap sandbox; unavailable in the supply-core-runner container"]
fn scan_image_accepts_docker_save_signature_equivalence_with_successful_engines() -> Result<()> {
    let layer = tar_bytes(&[("usr/share/fixture.txt", b"signature fixture")])?;
    let fixture = docker_save_fixture(&[("layer/layer.tar", &layer, &layer)], false)?;
    let manifest = docker_registry_manifest(&fixture, &[0], None)?;
    let digest = hex::encode(Sha256::digest(&manifest));
    let cosign = cosign_payload(&digest)?;
    let tools = tool_directory()?;
    let environment = fake_scanner_environment(
        tools.path(),
        &["0000/usr/share/fixture.txt"],
        &["0000/usr/share/fixture.txt"],
        Some(&manifest),
        Some(&cosign),
    )?;

    let (output, report) = scan_with_env(&fixture.archive, &signature_args(&digest), &environment)?;

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(report["signature_status"], "verified");
    assert_eq!(report["decision"], "block");
    assert_eq!(report["coverage"], "complete");
    assert_eq!(engine_report(&report, "trivy")?["coverage"], "complete");
    assert_eq!(
        engine_report(&report, "yarahunter")?["coverage"],
        "complete"
    );
    assert_eq!(engine_report(&report, "cosign")?["coverage"], "complete");
    assert_eq!(
        engine_report(&report, "yarahunter")?["findings"][0]["location"],
        "0000/usr/share/fixture.txt"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn scan_image_does_not_verify_signature_covering_one_of_several_images() -> Result<()> {
    let signed_layer = tar_bytes(&[("usr/share/signed.txt", b"signed image")])?;
    let signed = docker_save_fixture(&[("signed/layer.tar", &signed_layer, &signed_layer)], false)?;
    let manifest = docker_registry_manifest(&signed, &[0], None)?;
    let digest = hex::encode(Sha256::digest(&manifest));
    let cosign = cosign_payload(&digest)?;

    let unsigned_layer = tar_bytes(&[("usr/share/unsigned.txt", b"unsigned image")])?;
    let config = |layer: &[u8]| {
        serde_json::to_vec(&serde_json::json!({
            "architecture": "amd64",
            "os": "linux",
            "config": { "Entrypoint": ["/bin/true"] },
            "rootfs": {
                "type": "layers",
                "diff_ids": [format!("sha256:{}", hex::encode(Sha256::digest(layer)))]
            },
            "history": [{ "created_by": "fixture" }]
        }))
    };
    let signed_config = config(&signed_layer)?;
    let unsigned_config = config(&unsigned_layer)?;
    let signed_config_name = format!("{}.json", hex::encode(Sha256::digest(&signed_config)));
    let unsigned_config_name = format!("{}.json", hex::encode(Sha256::digest(&unsigned_config)));
    assert_eq!(signed_config_name, format!("{}.json", signed.config_digest));
    let outer_manifest = serde_json::to_vec(&serde_json::json!([
        { "Config": signed_config_name, "RepoTags": ["fixture:signed"], "Layers": ["signed/layer.tar"] },
        { "Config": unsigned_config_name, "RepoTags": ["fixture:unsigned"], "Layers": ["unsigned/layer.tar"] }
    ]))?;
    let archive = tar_bytes(&[
        ("manifest.json", outer_manifest.as_slice()),
        (signed_config_name.as_str(), signed_config.as_slice()),
        (unsigned_config_name.as_str(), unsigned_config.as_slice()),
        ("signed/layer.tar", signed_layer.as_slice()),
        ("unsigned/layer.tar", unsigned_layer.as_slice()),
    ])?;
    let tools = tool_directory()?;
    let environment = fake_scanner_environment(
        tools.path(),
        &["0000/usr/share/signed.txt", "0001/usr/share/unsigned.txt"],
        &[],
        Some(&manifest),
        Some(&cosign),
    )?;

    let (_, report) = scan_with_env(&archive, &signature_args(&digest), &environment)?;

    assert_eq!(report["signature_status"], "incomplete");
    assert_eq!(
        engine_report(&report, "cosign")?["reason"],
        "signature_scope_multiple_images"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires bubblewrap sandbox; unavailable in the supply-core-runner container"]
fn scan_image_keeps_compressed_docker_save_signature_equivalence_incomplete() -> Result<()> {
    let layer = tar_bytes(&[("usr/share/fixture.txt", b"compressed signature fixture")])?;
    let fixture = docker_save_fixture(&[("layer/layer.tar", &layer, &layer)], false)?;
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&docker_registry_manifest(&fixture, &[0], None)?)?;
    manifest["layers"][0]["mediaType"] =
        serde_json::Value::String("application/vnd.docker.image.rootfs.diff.tar.gzip".to_string());
    manifest["layers"][0]["digest"] =
        serde_json::Value::String(format!("sha256:{}", "a".repeat(64)));
    let manifest = serde_json::to_vec(&manifest)?;
    let digest = hex::encode(Sha256::digest(&manifest));
    let cosign = cosign_payload(&digest)?;
    let tools = tool_directory()?;
    let environment = fake_scanner_environment(
        tools.path(),
        &["0000/usr/share/fixture.txt"],
        &["0000/usr/share/fixture.txt"],
        Some(&manifest),
        Some(&cosign),
    )?;

    let (_, report) = scan_with_env(&fixture.archive, &signature_args(&digest), &environment)?;

    assert_eq!(report["signature_status"], "incomplete");
    assert_eq!(
        engine_report(&report, "cosign")?["reason"],
        "docker_save_equivalence_unproven"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn scan_image_without_manifest_retrieval_stays_incomplete() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let layer = tar_bytes(&[("usr/share/fixture.txt", b"missing manifest tool")])?;
    let fixture = docker_save_fixture(&[("layer/layer.tar", &layer, &layer)], false)?;
    let tools = tool_directory()?;
    let cosign = tools.path().join("cosign");
    std::fs::write(
        &cosign,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'cosign test\\n'; exit 0; fi\nexit 4\n",
    )?;
    let mut permissions = std::fs::metadata(&cosign)?.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&cosign, permissions)?;
    let mut environment = fake_scanner_environment(
        tools.path(),
        &["0000/usr/share/fixture.txt"],
        &[],
        None,
        None,
    )?;
    environment.push((
        "COSIGN_BIN".to_string(),
        cosign.to_string_lossy().into_owned(),
    ));
    environment.push(("CRANE_BIN".to_string(), String::new()));

    let (_, report) = scan_with_env(
        &fixture.archive,
        &signature_args(&"1".repeat(64)),
        &environment,
    )?;

    assert_eq!(report["signature_status"], "incomplete");
    assert_eq!(
        engine_report(&report, "cosign")?["reason"],
        "signature_manifest_retrieval_unavailable"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn scan_image_keeps_cosign_verification_failure_incomplete() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let layer = tar_bytes(&[("usr/share/fixture.txt", b"unverified signature")])?;
    let fixture = docker_save_fixture(&[("layer/layer.tar", &layer, &layer)], false)?;
    let manifest = docker_registry_manifest(&fixture, &[0], None)?;
    let digest = hex::encode(Sha256::digest(&manifest));
    let cosign_output = cosign_payload(&digest)?;
    let tools = tool_directory()?;
    let mut environment = fake_scanner_environment(
        tools.path(),
        &["0000/usr/share/fixture.txt"],
        &[],
        Some(&manifest),
        Some(&cosign_output),
    )?;
    let cosign = tools.path().join("cosign-fail");
    std::fs::write(
        &cosign,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'cosign test\\n'; exit 0; fi\n[ \"$1\" = \"verify\" ] || exit 52\nexit 4\n",
    )?;
    let mut permissions = std::fs::metadata(&cosign)?.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&cosign, permissions)?;
    environment.retain(|(name, _)| name != "COSIGN_BIN");
    environment.push((
        "COSIGN_BIN".to_string(),
        cosign.to_string_lossy().into_owned(),
    ));

    let (_, report) = scan_with_env(&fixture.archive, &signature_args(&digest), &environment)?;

    assert_eq!(report["signature_status"], "incomplete");
    assert_eq!(
        engine_report(&report, "cosign")?["reason"],
        "signature_verification_failed"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires bubblewrap sandbox; unavailable in the supply-core-runner container"]
fn scan_image_rejects_registry_manifest_digest_mismatch() -> Result<()> {
    let layer = tar_bytes(&[("usr/share/fixture.txt", b"digest mismatch")])?;
    let fixture = docker_save_fixture(&[("layer/layer.tar", &layer, &layer)], false)?;
    let manifest = docker_registry_manifest(&fixture, &[0], None)?;
    let digest = "0".repeat(64);
    let cosign = cosign_payload(&hex::encode(Sha256::digest(&manifest)))?;
    let tools = tool_directory()?;
    let environment = fake_scanner_environment(
        tools.path(),
        &["0000/usr/share/fixture.txt"],
        &[],
        Some(&manifest),
        Some(&cosign),
    )?;

    let (_, report) = scan_with_env(&fixture.archive, &signature_args(&digest), &environment)?;

    assert_eq!(report["signature_status"], "invalid");
    assert_ne!(engine_report(&report, "cosign")?["coverage"], "complete");
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires bubblewrap sandbox; unavailable in the supply-core-runner container"]
fn scan_image_rejects_docker_save_signature_with_config_mismatch() -> Result<()> {
    let layer = tar_bytes(&[("usr/share/fixture.txt", b"config mismatch")])?;
    let fixture = docker_save_fixture(&[("layer/layer.tar", &layer, &layer)], false)?;
    let manifest = docker_registry_manifest(&fixture, &[0], Some(&"0".repeat(64)))?;
    let digest = hex::encode(Sha256::digest(&manifest));
    let cosign = cosign_payload(&digest)?;
    let tools = tool_directory()?;
    let environment = fake_scanner_environment(
        tools.path(),
        &["0000/usr/share/fixture.txt"],
        &[],
        Some(&manifest),
        Some(&cosign),
    )?;

    let (_, report) = scan_with_env(&fixture.archive, &signature_args(&digest), &environment)?;

    assert_eq!(report["signature_status"], "invalid");
    assert_ne!(engine_report(&report, "cosign")?["coverage"], "complete");
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires bubblewrap sandbox; unavailable in the supply-core-runner container"]
fn scan_image_rejects_docker_save_signature_with_layer_order_mismatch() -> Result<()> {
    let first = tar_bytes(&[("usr/share/first.txt", b"first layer")])?;
    let second = tar_bytes(&[("usr/share/second.txt", b"second layer")])?;
    let fixture = docker_save_fixture(
        &[
            ("layer/first/layer.tar", &first, &first),
            ("layer/second/layer.tar", &second, &second),
        ],
        false,
    )?;
    let manifest = docker_registry_manifest(&fixture, &[1, 0], None)?;
    let digest = hex::encode(Sha256::digest(&manifest));
    let cosign = cosign_payload(&digest)?;
    let tools = tool_directory()?;
    let environment = fake_scanner_environment(
        tools.path(),
        &["0000/usr/share/first.txt", "0001/usr/share/second.txt"],
        &[],
        Some(&manifest),
        Some(&cosign),
    )?;

    let (_, report) = scan_with_env(&fixture.archive, &signature_args(&digest), &environment)?;

    assert_eq!(report["signature_status"], "invalid");
    assert_ne!(engine_report(&report, "cosign")?["coverage"], "complete");
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires bubblewrap sandbox; unavailable in the supply-core-runner container"]
fn scan_image_rejects_malformed_registry_manifest_output() -> Result<()> {
    let layer = tar_bytes(&[("usr/share/fixture.txt", b"malformed manifest")])?;
    let fixture = docker_save_fixture(&[("layer/layer.tar", &layer, &layer)], false)?;
    let malformed = b"not-json";
    let digest = hex::encode(Sha256::digest(malformed));
    let cosign = cosign_payload(&digest)?;
    let tools = tool_directory()?;
    let environment = fake_scanner_environment(
        tools.path(),
        &["0000/usr/share/fixture.txt"],
        &[],
        Some(malformed),
        Some(&cosign),
    )?;

    let (_, report) = scan_with_env(&fixture.archive, &signature_args(&digest), &environment)?;

    assert_eq!(report["signature_status"], "invalid");
    assert_ne!(engine_report(&report, "cosign")?["coverage"], "complete");
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn scan_image_rejects_malformed_cosign_output() -> Result<()> {
    let layer = tar_bytes(&[("usr/share/fixture.txt", b"malformed cosign")])?;
    let fixture = docker_save_fixture(&[("layer/layer.tar", &layer, &layer)], false)?;
    let manifest = docker_registry_manifest(&fixture, &[0], None)?;
    let digest = hex::encode(Sha256::digest(&manifest));
    let tools = tool_directory()?;
    let environment = fake_scanner_environment(
        tools.path(),
        &["0000/usr/share/fixture.txt"],
        &[],
        Some(&manifest),
        Some(b"not-json"),
    )?;

    let (_, report) = scan_with_env(&fixture.archive, &signature_args(&digest), &environment)?;

    assert_eq!(report["signature_status"], "invalid");
    assert_ne!(engine_report(&report, "cosign")?["coverage"], "complete");
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires bubblewrap sandbox; unavailable in the supply-core-runner container"]
fn scan_image_verifies_oci_signature_against_compressed_layer_evidence() -> Result<()> {
    let layer = tar_bytes(&[("usr/share/fixture.txt", b"OCI signature fixture")])?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&layer)?;
    let stored_layer = encoder.finish()?;
    let fixture = oci_archive_with_stored_layer(
        &layer,
        &stored_layer,
        "application/vnd.oci.image.layer.v1.tar+gzip",
    )?;
    let cosign = cosign_payload(&fixture.manifest_digest)?;
    let tools = tool_directory()?;
    let environment = fake_scanner_environment(
        tools.path(),
        &["0000/usr/share/fixture.txt"],
        &["0000/usr/share/fixture.txt"],
        Some(&fixture.manifest),
        Some(&cosign),
    )?;

    let (output, report) = scan_with_env(
        &fixture.archive,
        &signature_args(&fixture.manifest_digest),
        &environment,
    )?;

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(report["signature_status"], "verified");
    assert_eq!(report["coverage"], "complete");
    assert_eq!(
        engine_report(&report, "yarahunter")?["coverage"],
        "complete"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires bubblewrap sandbox; unavailable in the supply-core-runner container"]
fn scan_image_scans_oci_whiteouted_lower_layer_file() -> Result<()> {
    let lower = tar_bytes(&[("usr/share/obsolete.txt", b"deleted but present")])?;
    let upper = tar_bytes(&[
        ("usr/share/.wh.obsolete.txt", b""),
        ("usr/share/current.txt", b"current layer"),
    ])?;
    let fixture = docker_save_fixture(
        &[
            ("layer/lower/layer.tar", &lower, &lower),
            ("layer/upper/layer.tar", &upper, &upper),
        ],
        false,
    )?;
    let tools = tool_directory()?;
    let environment = fake_scanner_environment(
        tools.path(),
        &["0000/usr/share/obsolete.txt", "0001/usr/share/current.txt"],
        &["0000/usr/share/obsolete.txt"],
        None,
        None,
    )?;

    let (output, report) = scan_with_env(&fixture.archive, &[], &environment)?;

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(report["decision"], "block");
    assert_eq!(report["coverage"], "complete");
    assert_eq!(engine_report(&report, "yarahunter")?["expected_inputs"], 2);
    assert_eq!(engine_report(&report, "yarahunter")?["processed_inputs"], 2);
    assert_eq!(
        engine_report(&report, "yarahunter")?["findings"][0]["location"],
        "0000/usr/share/obsolete.txt"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires bubblewrap sandbox; unavailable in the supply-core-runner container"]
fn scan_image_accepts_safe_symlink_and_hardlink_members() -> Result<()> {
    let layer = tar_layer_with_links()?;
    let fixture = docker_save_fixture(&[("layer/layer.tar", &layer, &layer)], false)?;
    let tools = tool_directory()?;
    let environment = fake_scanner_environment(
        tools.path(),
        &["0000/usr/share/fixture.txt"],
        &["0000/usr/share/fixture.txt"],
        None,
        None,
    )?;

    let (output, report) = scan_with_env(&fixture.archive, &[], &environment)?;

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(report["coverage"], "complete");
    assert_eq!(
        engine_report(&report, "image-archive")?["coverage"],
        "complete"
    );
    assert_eq!(engine_report(&report, "yarahunter")?["processed_inputs"], 1);
    Ok(())
}
