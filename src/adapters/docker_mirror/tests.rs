use super::*;
use axum::{
    body::to_bytes, extract::connect_info::MockConnectInfo, extract::Path as AxumPath, routing::get,
};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicUsize, Ordering},
};
use tower::ServiceExt;

const REPO: &str = "library/demo";
const CONFIG_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const LAYER_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

type RegistryObject = (String, Vec<u8>);

#[derive(Clone, Default)]
struct Registry {
    objects: Arc<std::sync::RwLock<HashMap<String, RegistryObject>>>,
}

impl Registry {
    fn insert(&self, kind: &str, media: &str, bytes: Vec<u8>) -> anyhow::Result<String> {
        let hash = digest(&bytes);
        self.set(&format!("{kind}/{hash}"), media, bytes)?;
        Ok(hash)
    }

    fn set(&self, key: &str, media: &str, bytes: Vec<u8>) -> anyhow::Result<()> {
        self.objects
            .write()
            .map_err(|_| anyhow::anyhow!("registry poisoned"))?
            .insert(key.to_owned(), (media.to_owned(), bytes));
        Ok(())
    }

    fn tag(&self, name: &str, hash: &str) -> anyhow::Result<()> {
        let (media, bytes) = self
            .objects
            .read()
            .map_err(|_| anyhow::anyhow!("registry poisoned"))?
            .get(&format!("manifests/{hash}"))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown tag target"))?;
        self.set(&format!("manifests/{name}"), &media, bytes)
    }

    fn image(&self, value: &str) -> anyhow::Result<Image> {
        let config = value.as_bytes().to_vec();
        let config_hash = self.insert("blobs", CONFIG_TYPE, config.clone())?;
        let layer = format!("layer:{value}").into_bytes();
        let layer_hash = self.insert("blobs", LAYER_TYPE, layer.clone())?;
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": MANIFEST_TYPES[2],
            "config": desc(CONFIG_TYPE, &config_hash, config.len()),
            "layers": [desc(LAYER_TYPE, &layer_hash, layer.len())],
        }))?;
        let hash = self.insert("manifests", MANIFEST_TYPES[2], manifest.clone())?;
        Ok(Image {
            hash,
            manifest,
            config_hash,
            layer_hash,
            layer,
        })
    }

    fn index(
        &self,
        images: &[&Image],
        attachment: bool,
    ) -> anyhow::Result<(String, Option<String>)> {
        let mut entries = images
            .iter()
            .map(|image| desc(MANIFEST_TYPES[2], &image.hash, image.manifest.len()))
            .collect::<Vec<_>>();
        let attestation = if attachment {
            let empty = b"{}";
            let empty_type = "application/vnd.oci.empty.v1+json";
            let config_hash = self.insert("blobs", empty_type, empty.to_vec())?;
            let predicate = br#"{"predicateType":"demo"}"#;
            let kind = "application/vnd.in-toto+json";
            let blob = self.insert("blobs", kind, predicate.to_vec())?;
            let content = serde_json::to_vec(&json!({
                "schemaVersion": 2, "mediaType": MANIFEST_TYPES[2],
                "config": desc(empty_type, &config_hash, empty.len()),
                "layers": [desc(kind, &blob, predicate.len())],
            }))?;
            let len = content.len();
            let hash = self.insert("manifests", MANIFEST_TYPES[2], content)?;
            let subject = images
                .first()
                .ok_or_else(|| anyhow::anyhow!("missing subject"))?;
            entries.push(json!({
                "mediaType": MANIFEST_TYPES[2], "digest": hash, "size": len,
                "annotations": {"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": subject.hash},
            }));
            Some(hash)
        } else {
            None
        };
        let bytes = serde_json::to_vec(&json!({
            "schemaVersion": 2, "mediaType": MANIFEST_TYPES[0], "manifests": entries,
        }))?;
        Ok((
            self.insert("manifests", MANIFEST_TYPES[0], bytes)?,
            attestation,
        ))
    }

    async fn serve(self) -> anyhow::Result<(Upstream, tokio::task::JoinHandle<()>)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = reqwest::Url::parse(&format!("http://{}/", listener.local_addr()?))?;
        let server = Router::new()
            .route("/v2/library/demo/*path", get(upstream_object))
            .with_state(self);
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, server).await;
        });
        Ok((Upstream::new(endpoint, None)?, task))
    }
}

async fn upstream_object(
    State(registry): State<Registry>,
    AxumPath(key): AxumPath<String>,
) -> Response {
    if let Ok(objects) = registry.objects.read() {
        if let Some((media, bytes)) = objects.get(&key) {
            return (
                [
                    (header::CONTENT_TYPE, media.as_str()),
                    (
                        "docker-content-digest".parse().unwrap_or(header::ETAG),
                        digest(bytes).as_str(),
                    ),
                ],
                bytes.clone(),
            )
                .into_response();
        }
    }
    StatusCode::NOT_FOUND.into_response()
}

struct Image {
    hash: String,
    manifest: Vec<u8>,
    config_hash: String,
    layer_hash: String,
    layer: Vec<u8>,
}

fn desc(media_type: &str, hash: &str, len: usize) -> serde_json::Value {
    json!({"mediaType": media_type, "digest": hash, "size": len})
}

fn mirror(path: &Path, upstream: Upstream, scan: TestScan) -> anyhow::Result<Arc<Mirror>> {
    let config = Config {
        directory: path.to_owned(),
        trivy: PathBuf::new(),
        external_database: None,
        policy: Policy::default(),
    };
    let mut mirror = Mirror::new(config, upstream)?;
    mirror.test_scan = Some(scan);
    Ok(Arc::new(mirror))
}

async fn request(
    app: &Router,
    method: Method,
    path: &str,
    fields: &[(&str, &str)],
) -> anyhow::Result<Response> {
    let mut request = axum::http::Request::builder().method(method).uri(path);
    for (field, value) in fields {
        request = request.header(*field, *value);
    }
    let response = app.clone().oneshot(request.body(Body::empty())?).await?;
    assert_eq!(
        response
            .headers()
            .get(API_VERSION)
            .and_then(|v| v.to_str().ok()),
        Some("registry/2.0")
    );
    Ok(response)
}

fn uri(kind: &str, reference: &str) -> String {
    format!("/v2/{REPO}/{kind}/{reference}")
}

fn age(path: &Path, hash: &str) -> anyhow::Result<()> {
    let db = rusqlite::Connection::open(path.join("state.db"))?;
    db.execute(
        "UPDATE images SET first_seen=?1 WHERE digest=?2",
        rusqlite::params![(Utc::now() - TimeDelta::days(8)).timestamp(), hash],
    )?;
    Ok(())
}

fn age_pending(path: &Path, repo: &str, hash: &str) -> anyhow::Result<()> {
    let db = rusqlite::Connection::open(path.join("state.db"))?;
    let first_seen = (Utc::now() - TimeDelta::days(8)).timestamp();
    let updated = db.execute(
        "UPDATE images SET first_seen=?1 WHERE repository=?2 AND digest=?3",
        rusqlite::params![first_seen, repo, hash],
    )?;
    if updated == 0 {
        db.execute(
            "INSERT INTO images (repository,digest,first_seen) VALUES (?1,?2,?3)",
            rusqlite::params![repo, hash, first_seen],
        )?;
    }
    Ok(())
}

async fn finish_background(mirror: &Mirror) {
    tokio::task::yield_now().await;
    let _guard = mirror.worker.lock().await;
}

#[tokio::test]
async fn quarantine_release_cache_and_retag() -> anyhow::Result<()> {
    let registry = Registry::default();
    let one = registry.image("one")?;
    let two = registry.image("two")?;
    registry.tag("main", &one.hash)?;
    let dir = tempfile::tempdir()?;
    let scans = Arc::new(AtomicUsize::new(0));
    let scan: TestScan = Arc::new({
        let scans = Arc::clone(&scans);
        move |_| {
            scans.fetch_add(1, Ordering::SeqCst);
            Ok(Verdict::Clean)
        }
    });
    let (upstream, task) = registry.clone().serve().await?;
    let mirror_server = mirror(dir.path(), upstream, Arc::clone(&scan))?;
    let app = router(Arc::clone(&mirror_server));
    assert_eq!(
        request(&app, Method::GET, "/v2/", &[]).await?.status(),
        StatusCode::OK
    );
    assert_eq!(
        request(&app, Method::POST, &uri("blobs", "uploads/"), &[])
            .await?
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        request(&app, Method::GET, &uri("manifests", "main"), &[])
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    finish_background(&mirror_server).await;
    assert_eq!(scans.load(Ordering::SeqCst), 1);
    for method in [Method::GET, Method::HEAD] {
        assert_eq!(
            request(&app, method.clone(), &uri("manifests", &one.hash), &[])
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
        for blob in [&one.config_hash, &one.layer_hash] {
            assert_eq!(
                request(&app, method.clone(), &uri("blobs", blob), &[])
                    .await?
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
    }
    age(dir.path(), &one.hash)?;
    let response = request(&app, Method::HEAD, &uri("manifests", "main"), &[]).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["docker-content-digest"], one.hash);
    assert_eq!(
        response.headers()[header::CONTENT_LENGTH],
        one.manifest.len().to_string()
    );
    assert!(to_bytes(response.into_body(), 100).await?.is_empty());
    let response = request(
        &app,
        Method::GET,
        &uri("manifests", &one.hash),
        &[("Accept", MANIFEST_TYPES[2])],
    )
    .await?;
    assert_eq!(
        to_bytes(response.into_body(), MAX_MANIFEST).await?.as_ref(),
        one.manifest
    );
    assert_eq!(
        request(
            &app,
            Method::GET,
            &uri("manifests", "main"),
            &[("Accept", MANIFEST_TYPES[0])]
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND
    );
    let range = request(
        &app,
        Method::GET,
        &uri("blobs", &one.layer_hash),
        &[("Range", "bytes=1-3")],
    )
    .await?;
    assert_eq!(range.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        range.headers()[header::CONTENT_RANGE],
        format!("bytes 1-3/{}", one.layer.len())
    );
    assert_eq!(
        to_bytes(range.into_body(), 10).await?.as_ref(),
        &one.layer[1..=3]
    );
    assert_eq!(
        request(
            &app,
            Method::GET,
            &uri("blobs", &one.layer_hash),
            &[("If-None-Match", &format!("\"{}\"", one.layer_hash))]
        )
        .await?
        .status(),
        StatusCode::NOT_MODIFIED
    );
    let tags = request(&app, Method::GET, "/v2/library/demo/tags/list", &[]).await?;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&to_bytes(tags.into_body(), 1024).await?)?
            ["tags"],
        json!(["main"])
    );

    registry.tag("main", &two.hash)?;
    assert_eq!(
        request(&app, Method::GET, &uri("manifests", "main"), &[])
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    finish_background(&mirror_server).await;
    assert_eq!(
        request(&app, Method::GET, &uri("blobs", &two.layer_hash), &[])
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(scans.load(Ordering::SeqCst), 2);
    task.abort();
    drop(app);
    drop(mirror_server);
    let dead_upstream = Upstream::new(reqwest::Url::parse("http://127.0.0.1:1/")?, None)?;
    let app = router(mirror(dir.path(), dead_upstream, scan)?);
    assert_eq!(
        request(&app, Method::GET, &uri("manifests", &one.hash), &[])
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(&app, Method::GET, &uri("blobs", &one.layer_hash), &[])
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            Method::GET,
            &format!("/v2/other/demo/blobs/{}", one.layer_hash),
            &[]
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND
    );
    Ok(())
}

#[tokio::test]
async fn index_releases_only_after_every_platform_is_checked() -> anyhow::Result<()> {
    let registry = Registry::default();
    let one = registry.image("amd64")?;
    let two = registry.image("arm64")?;
    let (index, attestation) = registry.index(&[&one, &two], true)?;
    let attestation = attestation.ok_or_else(|| anyhow::anyhow!("missing fixture attestation"))?;
    registry.tag("main", &index)?;
    let dir = tempfile::tempdir()?;
    let outcome = Arc::new(AtomicUsize::new(0));
    let passing_platforms = Arc::new(AtomicUsize::new(0));
    let scan: TestScan = Arc::new({
        let outcome = Arc::clone(&outcome);
        let arm = two.layer_hash.clone();
        let amd = one.layer_hash.clone();
        let passing_platforms = Arc::clone(&passing_platforms);
        move |layout| {
            let is_arm = object_path(layout, &arm).exists();
            let is_amd = object_path(layout, &amd).exists();
            assert_ne!(is_arm, is_amd, "each scan gets exactly one platform");
            match outcome.load(Ordering::SeqCst) {
                0 => anyhow::bail!("scanner offline"),
                1 if is_arm => Ok(Verdict::Vulnerable),
                1 => Ok(Verdict::Clean),
                _ => {
                    passing_platforms.fetch_add(1, Ordering::SeqCst);
                    Ok(Verdict::Clean)
                }
            }
        }
    });
    let (upstream, task) = registry.clone().serve().await?;
    let mirror = mirror(dir.path(), upstream, scan)?;
    let app = router(Arc::clone(&mirror));
    assert_eq!(
        request(&app, Method::HEAD, &uri("manifests", "main"), &[])
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    finish_background(&mirror).await;
    age_pending(dir.path(), REPO, &index)?;
    assert_eq!(
        request(&app, Method::GET, &uri("manifests", "main"), &[])
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    age_pending(dir.path(), REPO, &index)?;
    outcome.store(1, Ordering::SeqCst);
    let held = request(&app, Method::GET, &uri("manifests", "main"), &[]).await?;
    assert_eq!(held.status(), StatusCode::FORBIDDEN);
    finish_background(&mirror).await;
    let denied = request(&app, Method::GET, &uri("manifests", "main"), &[]).await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(
        String::from_utf8_lossy(&to_bytes(denied.into_body(), 512).await?)
            .contains("vulnerability policy")
    );
    assert_eq!(
        request(&app, Method::HEAD, &uri("manifests", &index), &[])
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    for hash in [&one.layer_hash, &two.layer_hash] {
        assert_eq!(
            request(&app, Method::GET, &uri("blobs", hash), &[])
                .await?
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        request(&app, Method::GET, &uri("manifests", &attestation), &[])
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    finish_background(&mirror).await;
    let db = rusqlite::Connection::open(dir.path().join("state.db"))?;
    db.execute("UPDATE images SET scanned_at=0", [])?;
    outcome.store(2, Ordering::SeqCst);
    let released = request(&app, Method::GET, &uri("manifests", "main"), &[]).await?;
    let status = released.status();
    let body = to_bytes(released.into_body(), 1024).await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(passing_platforms.load(Ordering::SeqCst), 2);
    for hash in [&one.hash, &two.hash, &attestation] {
        assert_eq!(
            request(&app, Method::HEAD, &uri("manifests", hash), &[])
                .await?
                .status(),
            StatusCode::OK
        );
    }
    task.abort();
    Ok(())
}

#[tokio::test]
async fn corrupt_blob_never_reaches_scanner() -> anyhow::Result<()> {
    let registry = Registry::default();
    let image = registry.image("tampered")?;
    registry.set(
        &format!("blobs/{}", image.layer_hash),
        LAYER_TYPE,
        vec![b'x'; image.layer.len()],
    )?;
    registry.tag("main", &image.hash)?;
    let dir = tempfile::tempdir()?;
    let (upstream, task) = registry.serve().await?;
    let mirror = mirror(
        dir.path(),
        upstream,
        Arc::new(|_| panic!("must not scan corrupted bytes")),
    )?;
    let app = router(Arc::clone(&mirror));
    assert_eq!(
        request(&app, Method::GET, &uri("manifests", "main"), &[])
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    finish_background(&mirror).await;
    age_pending(dir.path(), REPO, &image.hash)?;
    assert_eq!(
        request(&app, Method::GET, &uri("manifests", "main"), &[])
            .await?
            .status(),
        StatusCode::BAD_GATEWAY
    );
    assert_eq!(
        request(&app, Method::GET, &uri("blobs", &image.layer_hash), &[])
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    task.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "requires a running Docker Engine"]
async fn docker_engine_cannot_pull_until_release() -> anyhow::Result<()> {
    let mut tar = tar::Builder::new(Vec::new());
    let data = b"mirror fixture\n";
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o644);
    header.set_size(data.len() as u64);
    header.set_cksum();
    tar.append_data(&mut header, "mirror-fixture", data.as_slice())?;
    let plain = tar.into_inner()?;
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gzip, &plain)?;
    let layer = gzip.finish()?;
    let registry = Registry::default();
    let layer_hash = registry.insert("blobs", LAYER_TYPE, layer.clone())?;
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        arch => arch,
    };
    let config = serde_json::to_vec(&json!({
        "architecture": arch,
        "os": "linux",
        "rootfs": {"type":"layers", "diff_ids":[digest(&plain)]},
    }))?;
    let config_hash = registry.insert("blobs", CONFIG_TYPE, config.clone())?;
    let manifest = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_TYPES[2],
        "config": desc(CONFIG_TYPE, &config_hash, config.len()),
        "layers": [desc(LAYER_TYPE, &layer_hash, layer.len())],
    }))?;
    let hash = registry.insert("manifests", MANIFEST_TYPES[2], manifest)?;
    registry.tag("main", &hash)?;
    let (upstream, upstream_task) = registry.serve().await?;
    let dir = tempfile::tempdir()?;
    let scans = Arc::new(AtomicUsize::new(0));
    let scan: TestScan = Arc::new({
        let scans = Arc::clone(&scans);
        move |_| {
            scans.fetch_add(1, Ordering::SeqCst);
            Ok(Verdict::Clean)
        }
    });
    let mirror = mirror(dir.path(), upstream, scan)?;
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
    let reference = format!("localhost:{}/{REPO}:main", listener.local_addr()?.port());
    let probe = router(Arc::clone(&mirror));
    let app = probe.clone();
    let mirror_task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let held = tokio::process::Command::new("docker")
        .args(["pull", &reference])
        .output()
        .await?;
    let error = String::from_utf8_lossy(&held.stderr);
    assert!(!held.status.success(), "{error}");
    finish_background(&mirror).await;
    assert_eq!(scans.load(Ordering::SeqCst), 1);
    let denied = request(&probe, Method::GET, &uri("manifests", "main"), &[]).await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    age(dir.path(), &hash)?;
    let released = tokio::process::Command::new("docker")
        .args(["pull", &reference])
        .output()
        .await?;
    let error = String::from_utf8_lossy(&released.stderr);
    assert!(released.status.success(), "{error}");
    assert!(String::from_utf8_lossy(&released.stdout).contains(&hash));
    let _ = tokio::process::Command::new("docker")
        .args(["image", "rm", &reference])
        .output()
        .await;
    mirror_task.abort();
    upstream_task.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker Hub access, Bubblewrap, and a fresh Trivy database"]
async fn docker_hub_cve_keeps_image_quarantined() -> anyhow::Result<()> {
    const ALPINE_AMD64: &str =
        "sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e";
    let dir = tempfile::tempdir()?;
    let mut config = Config::from_env(Policy::default())
        .ok_or_else(|| anyhow::anyhow!("enable the mirror for this test"))?;
    config.directory = dir.path().to_owned();
    anyhow::ensure!(
        config.external_database.is_some(),
        "set TRIVY_CACHE_DIR for this test"
    );
    let mirror = Arc::new(Mirror::new(config, Upstream::docker_hub()?)?);
    let app = router(Arc::clone(&mirror));
    let path = format!("/v2/library/alpine/manifests/{ALPINE_AMD64}");
    let held = request(&app, Method::GET, &path, &[]).await?;
    assert_eq!(held.status(), StatusCode::FORBIDDEN);
    assert!(
        String::from_utf8_lossy(&to_bytes(held.into_body(), 512).await?)
            .contains("quarantine window")
    );
    tokio::time::timeout(Duration::from_secs(360), finish_background(&mirror)).await?;
    age(dir.path(), ALPINE_AMD64)?;
    let held = request(&app, Method::GET, &path, &[]).await?;
    assert_eq!(held.status(), StatusCode::FORBIDDEN);
    assert!(
        String::from_utf8_lossy(&to_bytes(held.into_body(), 512).await?)
            .contains("vulnerability policy")
    );
    let upstream = mirror
        .upstream
        .repository("library/alpine")
        .await
        .map_err(|_| anyhow::anyhow!("Docker Hub token request failed"))?;
    let manifest = upstream
        .manifest(ALPINE_AMD64)
        .await
        .map_err(|_| anyhow::anyhow!("Docker Hub manifest request failed"))?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest.bytes)?;
    let blobs = std::iter::once(&manifest["config"])
        .chain(manifest["layers"].as_array().into_iter().flatten());
    for blob in blobs {
        let hash = blob["digest"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("invalid blob descriptor"))?;
        let path = format!("/v2/library/alpine/blobs/{hash}");
        assert_eq!(
            request(&app, Method::GET, &path, &[]).await?.status(),
            StatusCode::NOT_FOUND
        );
    }
    Ok(())
}

#[tokio::test]
async fn oversized_index_batch_is_rejected_without_scanning() -> anyhow::Result<()> {
    let registry = Registry::default();
    let entries = (0..5)
        .map(|index| {
            // The cap accounts declared descriptor sizes before any fetch,
            // so the children themselves never need to exist upstream.
            desc(
                MANIFEST_TYPES[2],
                &digest(format!("child:{index}").as_bytes()),
                4 * 1024 * 1024,
            )
        })
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&json!({
        "schemaVersion": 2, "mediaType": MANIFEST_TYPES[0], "manifests": entries,
    }))?;
    let hash = registry.insert("manifests", MANIFEST_TYPES[0], bytes)?;
    registry.tag("main", &hash)?;
    let (upstream, task) = registry.serve().await?;
    let dir = tempfile::tempdir()?;
    let scans = Arc::new(AtomicUsize::new(0));
    let scan: TestScan = {
        let scans = Arc::clone(&scans);
        Arc::new(move |_| {
            scans.fetch_add(1, Ordering::SeqCst);
            Ok(Verdict::Clean)
        })
    };
    let mirror = mirror(dir.path(), upstream, scan)?;
    let app = router(Arc::clone(&mirror));
    let response = request(&app, Method::GET, &uri("manifests", "main"), &[]).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    finish_background(&mirror).await;
    let db = rusqlite::Connection::open(dir.path().join("state.db"))?;
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM images WHERE cache_key IS NULL",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    let retry = request(&app, Method::GET, &uri("manifests", "main"), &[]).await?;
    assert_eq!(retry.status(), StatusCode::FORBIDDEN);
    finish_background(&mirror).await;
    assert_eq!(scans.load(Ordering::SeqCst), 0);
    task.abort();
    Ok(())
}

#[tokio::test]
async fn external_cache_requires_both_databases_fresh() -> anyhow::Result<()> {
    fn seed(cache: &Path, directory: &str, file: &str) -> anyhow::Result<()> {
        let path = cache.join(directory);
        std::fs::create_dir_all(&path)?;
        std::fs::write(
            path.join("metadata.json"),
            format!(r#"{{"UpdatedAt":"{}"}}"#, Utc::now().to_rfc3339()),
        )?;
        std::fs::write(path.join(file), b"database")?;
        Ok(())
    }
    let dir = tempfile::tempdir()?;
    let cache = dir.path().join("trivy-cache");
    std::fs::create_dir_all(&cache)?;
    seed(&cache, "db", "trivy.db")?;
    seed(&cache, "java-db", "trivy-java.db")?;
    let config = Config {
        directory: dir.path().join("mirror"),
        trivy: PathBuf::new(),
        external_database: Some(cache.clone()),
        policy: Policy::default(),
    };
    let mirror = Mirror::new(config, Upstream::docker_hub()?)?;
    let accepted = mirror
        .database(dir.path())
        .await
        .map_err(|_| anyhow::anyhow!("a fresh cache was rejected"))?;
    assert_eq!(accepted, cache);
    std::fs::remove_file(cache.join("java-db").join("trivy-java.db"))?;
    assert!(matches!(
        mirror.database(dir.path()).await,
        Err(MirrorError::Scanner(_))
    ));
    Ok(())
}

#[test]
fn metadata_bursts_keep_image_and_tag_state_bounded() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = Store::open(dir.path())?;
    let now = Utc::now();
    for index in 0..store::MAX_METADATA_IMAGES {
        store.observe(
            "r",
            &digest(format!("digest:{index}").as_bytes()),
            None,
            now,
        )?;
    }
    assert!(store.observe("r", &digest(b"overflow"), None, now).is_err());

    let tags = tempfile::tempdir()?;
    let store = Store::open(tags.path())?;
    let shared = digest(b"one-image");
    for index in 0..store::MAX_METADATA_TAGS {
        store.observe("r", &shared, Some(&format!("tag:{index}")), now)?;
    }
    store.observe("r", &shared, Some("overflow"), now)?;
    let db = rusqlite::Connection::open(tags.path().join("state.db"))?;
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM tags", [], |row| row.get::<_, i64>(0))?,
        store::MAX_METADATA_TAGS
    );
    assert!(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM tags WHERE tag='tag:0')",
        [],
        |row| row.get::<_, bool>(0)
    )?);
    assert!(!db.query_row(
        "SELECT EXISTS(SELECT 1 FROM tags WHERE tag='overflow')",
        [],
        |row| row.get::<_, bool>(0)
    )?);
    Ok(())
}

#[test]
fn observation_prunes_orphan_tags_and_aged_metadata() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = Store::open(dir.path())?;
    let now = Utc::now();
    let kept = digest(b"kept");
    store.observe("r", &kept, Some("stable"), now)?;
    {
        let db = rusqlite::Connection::open(dir.path().join("state.db"))?;
        db.execute(
            "INSERT INTO tags VALUES ('r','ghost',?1)",
            ["sha256:deadbeef"],
        )?;
        db.execute(
            "INSERT INTO images (repository,digest,first_seen) VALUES ('old','sha256:beef',?1)",
            [now.timestamp() - store::METADATA_RETENTION_SECONDS - 1],
        )?;
    }
    store.observe("r", &digest(b"fresh"), None, now)?;
    let db = rusqlite::Connection::open(dir.path().join("state.db"))?;
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM tags WHERE NOT EXISTS (SELECT 1 FROM images WHERE images.repository = tags.repository AND images.digest = tags.digest)",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM images WHERE repository='old'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    let first_seen = db.query_row(
        "SELECT first_seen FROM images WHERE repository='r' AND digest=?1",
        [kept],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(first_seen, now.timestamp());
    Ok(())
}
#[tokio::test]
async fn busy_scanner_does_not_admit_new_image_metadata() -> anyhow::Result<()> {
    let registry = Registry::default();
    let first = registry.image("first")?;
    let second = registry.image("second")?;
    registry.tag("first", &first.hash)?;
    registry.tag("second", &second.hash)?;
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let started_tx = Arc::new(std::sync::Mutex::new(Some(started_tx)));
    let release_rx = Arc::new(std::sync::Mutex::new(release_rx));
    let scan: TestScan = Arc::new({
        let started_tx = Arc::clone(&started_tx);
        let release_rx = Arc::clone(&release_rx);
        move |_| {
            let sender = started_tx
                .lock()
                .map_err(|_| anyhow::anyhow!("scan start lock poisoned"))?
                .take()
                .ok_or_else(|| anyhow::anyhow!("scan started more than once"))?;
            sender.send(())?;
            release_rx
                .lock()
                .map_err(|_| anyhow::anyhow!("scan release lock poisoned"))?
                .recv_timeout(Duration::from_secs(5))?;
            Ok(Verdict::Clean)
        }
    });
    let (upstream, task) = registry.serve().await?;
    let dir = tempfile::tempdir()?;
    let mirror = mirror(dir.path(), upstream, scan)?;
    let app = router(Arc::clone(&mirror));
    let first_app = app.clone();
    let first_path = uri("manifests", "first");
    let first_request =
        tokio::spawn(async move { request(&first_app, Method::GET, &first_path, &[]).await });
    tokio::task::spawn_blocking(move || started_rx.recv_timeout(Duration::from_secs(5))).await??;

    let second = request(&app, Method::GET, &uri("manifests", "second"), &[]).await?;
    let db = rusqlite::Connection::open(dir.path().join("state.db"))?;
    let pending: i64 = db.query_row(
        "SELECT COUNT(*) FROM images WHERE cache_key IS NULL",
        [],
        |row| row.get(0),
    )?;
    drop(db);
    release_tx.send(())?;
    let first = first_request.await??;
    finish_background(&mirror).await;
    task.abort();

    assert_eq!(second.status(), StatusCode::FORBIDDEN);
    assert_eq!(pending, 1);
    assert_eq!(first.status(), StatusCode::FORBIDDEN);
    Ok(())
}
#[tokio::test]
async fn failed_scan_removes_pending_image_and_tag() -> anyhow::Result<()> {
    let registry = Registry::default();
    let image = registry.image("failed")?;
    registry.tag("failed", &image.hash)?;
    let (upstream, task) = registry.serve().await?;
    let dir = tempfile::tempdir()?;
    let scan: TestScan = Arc::new(|_| Err(anyhow::anyhow!("scan failed")));
    let mirror = mirror(dir.path(), upstream, scan)?;
    let app = router(Arc::clone(&mirror));
    let response = request(&app, Method::GET, &uri("manifests", "failed"), &[]).await?;
    finish_background(&mirror).await;
    let db = rusqlite::Connection::open(dir.path().join("state.db"))?;
    let pending: i64 = db.query_row(
        "SELECT COUNT(*) FROM images WHERE cache_key IS NULL",
        [],
        |row| row.get(0),
    )?;
    let tags: i64 = db.query_row("SELECT COUNT(*) FROM tags", [], |row| row.get(0))?;
    task.abort();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(pending, 0);
    assert_eq!(tags, 0);
    Ok(())
}

#[tokio::test]
async fn first_scan_admission_limits_per_ip() -> anyhow::Result<()> {
    let (upstream, task) = Registry::default().serve().await?;
    let dir = tempfile::tempdir()?;
    let mirror = mirror(dir.path(), upstream, Arc::new(|_| Ok(Verdict::Clean)))?;
    let attacker: IpAddr = "203.0.113.10".parse()?;
    let other: IpAddr = "198.51.100.20".parse()?;
    for _ in 0..FIRST_SCANS_PER_IP {
        assert!(mirror.admit_first_scan(Some(attacker)));
    }
    assert!(!mirror.admit_first_scan(Some(attacker)));
    assert!(mirror.admit_first_scan(Some(other)));
    assert!(mirror.admit_first_scan(None));
    task.abort();
    Ok(())
}

#[test]
fn client_peer_trusts_forwarded_only_from_loopback() {
    let loopback = SocketAddr::from(([127, 0, 0, 1], 40000));
    assert_eq!(
        Mirror::client_peer(
            Some(SocketAddr::from(([100, 64, 15, 9], 40000))),
            Some(&header::HeaderValue::from_static("9.9.9.9, 100.64.15.1")),
        ),
        Some(IpAddr::from([100, 64, 15, 9])),
        "direct peers must not trust spoofable forwarded headers"
    );
    assert_eq!(
        Mirror::client_peer(
            Some(loopback),
            Some(&header::HeaderValue::from_static("9.9.9.9, 100.64.15.1")),
        ),
        Some(IpAddr::from([100, 64, 15, 1])),
        "proxied loopback requests take the funnel-observed client IP"
    );
    assert_eq!(
        Mirror::client_peer(
            Some(loopback),
            Some(&header::HeaderValue::from_static("not-an-ip")),
        ),
        None
    );
    assert_eq!(Mirror::client_peer(Some(loopback), None), None);
    assert_eq!(Mirror::client_peer(None, None), None);
}

#[tokio::test]
async fn proxied_first_scan_admission_is_per_client_ip() -> anyhow::Result<()> {
    let registry = Registry::default();
    for tag in ["one", "two", "three", "four", "five"] {
        let image = registry.image(tag)?;
        registry.tag(tag, &image.hash)?;
    }
    let (upstream, task) = registry.serve().await?;
    let dir = tempfile::tempdir()?;
    let mirror = mirror(dir.path(), upstream, Arc::new(|_| Ok(Verdict::Clean)))?;
    let app = router(Arc::clone(&mirror))
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let client_a = [("x-forwarded-for", "100.64.10.1")];
    let client_b = [("x-forwarded-for", "100.64.10.2")];
    for tag in ["one", "two", "three", "four"] {
        let response = request(&app, Method::GET, &uri("manifests", tag), &client_a).await?;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "tag {tag} admitted but still quarantined"
        );
        finish_background(&mirror).await;
    }
    let denied = request(&app, Method::GET, &uri("manifests", "five"), &client_a).await?;
    assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);
    let released = request(&app, Method::GET, &uri("manifests", "five"), &client_b).await?;
    assert_eq!(
        released.status(),
        StatusCode::FORBIDDEN,
        "a different proxied client keeps its own budget"
    );
    finish_background(&mirror).await;
    task.abort();
    Ok(())
}
