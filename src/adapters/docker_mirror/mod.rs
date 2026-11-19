mod graph;
mod store;
mod upstream;

use crate::{
    application::image_scanner::scan_registry_image,
    domain::{is_version_quarantined, Policy},
};
use axum::{
    body::Body,
    extract::{OriginalUri, State},
    http::{header, HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use chrono::{DateTime, TimeDelta, Utc};
use graph::{object_path, Graph, Verdict};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use store::{Release, ScannedImage, Store};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt},
    sync::{Mutex, OnceCell},
};
use tokio_util::io::ReaderStream;
use upstream::{Manifest, Repository, Upstream};

const MAX_MANIFEST: usize = 4 * 1024 * 1024;
const MANIFEST_TYPES: [&str; 4] = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];
const API_VERSION: &str = "docker-distribution-api-version";

pub struct Config {
    directory: PathBuf,
    trivy: PathBuf,
    external_database: Option<PathBuf>,
    policy: Policy,
}

impl Config {
    pub fn from_env(policy: Policy) -> Option<Self> {
        if std::env::var("SUPPLY_DOCKER_MIRROR_ENABLED")
            .is_ok_and(|v| v.eq_ignore_ascii_case("false") || v == "0")
        {
            return None;
        }
        Some(Self {
            directory: std::env::var_os("SUPPLY_DOCKER_MIRROR_DIR")
                .map_or_else(|| PathBuf::from("data/docker-mirror"), PathBuf::from),
            trivy: std::env::var_os("TRIVY_BIN")
                .map_or_else(|| PathBuf::from("trivy"), PathBuf::from),
            external_database: std::env::var_os("TRIVY_CACHE_DIR").map(PathBuf::from),
            policy,
        })
    }
}

struct Mirror {
    config: Config,
    upstream: Upstream,
    store: OnceCell<Store>,
    worker: Arc<Mutex<()>>,
    policy_hash: String,
    #[cfg(test)]
    test_scan: Option<TestScan>,
}

#[cfg(test)]
type TestScan = Arc<dyn Fn(&Path) -> anyhow::Result<Verdict> + Send + Sync>;

impl Mirror {
    fn new(config: Config, upstream: Upstream) -> anyhow::Result<Self> {
        let policy_hash = digest(&serde_json::to_vec(&(
            "docker-mirror-trivy-v1",
            &config.policy.quarantine,
            &config.policy.vulnerabilities,
            &config.trivy,
            &config.external_database,
        ))?);
        Ok(Self {
            config,
            upstream,
            store: OnceCell::new(),
            worker: Arc::new(Mutex::new(())),
            policy_hash,
            #[cfg(test)]
            test_scan: None,
        })
    }

    async fn store(&self) -> Result<&Store> {
        self.store
            .get_or_try_init(|| async {
                let dir = self.config.directory.clone();
                tokio::task::spawn_blocking(move || Store::open(&dir))
                    .await
                    .map_err(MirrorError::internal)?
                    .map_err(MirrorError::internal)
            })
            .await
    }

    fn age_cutoff(&self, now: DateTime<Utc>) -> i64 {
        let quarantine = &self.config.policy.quarantine;
        if !quarantine.enabled {
            return now.timestamp();
        }
        TimeDelta::try_days(quarantine.minimum_age_days)
            .and_then(|age| now.checked_sub_signed(age))
            .map_or(i64::MIN, |cutoff| cutoff.timestamp())
    }

    fn released(
        &self,
        store: &Store,
        repo: &str,
        hash: &str,
        manifest: bool,
    ) -> Result<Option<Release>> {
        let now = Utc::now();
        store
            .released(
                repo,
                hash,
                manifest,
                &self.policy_hash,
                now,
                self.age_cutoff(now),
            )
            .map_err(MirrorError::internal)
    }

    async fn manifest(self: Arc<Self>, repo: String, reference: &str) -> Result<Release> {
        let store = self.store().await?;
        let tag = (!valid_digest(reference)).then_some(reference);
        if tag.is_none() {
            if let Some(release) = self.released(store, &repo, reference, true)? {
                return Ok(release);
            }
            // A known digest can be rejected without contacting the upstream again.
            if store
                .verdict(&repo, reference, &self.policy_hash, Utc::now())
                .map_err(MirrorError::internal)?
                == Some(Verdict::Vulnerable)
            {
                return Err(MirrorError::Vulnerable);
            }
        }
        let upstream = self.upstream.repository(&repo).await?;
        let manifest = upstream.manifest(reference).await?;
        let hash = manifest.digest.clone();
        let now = Utc::now();
        let first_seen = store
            .observe(&repo, &hash, tag, now)
            .map_err(MirrorError::internal)?;
        let quarantined =
            is_version_quarantined(Some(first_seen), now, &self.config.policy.quarantine);

        let previous = store
            .verdict(&repo, &hash, &self.policy_hash, now)
            .map_err(MirrorError::internal)?;
        if previous == Some(Verdict::Vulnerable) {
            return Err(MirrorError::Vulnerable);
        }
        if previous.is_none() {
            match Arc::clone(&self.worker).try_lock_owned() {
                Ok(guard) => {
                    let mirror = Arc::clone(&self);
                    let repo = repo.clone();
                    // Once a scan starts, let it finish even if the client
                    // disconnects. Young pulls receive their denial immediately.
                    let worker = tokio::spawn(async move {
                        let _guard = guard;
                        let result = mirror.prepare(&repo, &upstream, manifest).await;
                        if quarantined {
                            if let Err(error) = &result {
                                error.log();
                            }
                        }
                        result
                    });
                    if !quarantined
                        && worker.await.map_err(MirrorError::internal)?? == Verdict::Vulnerable
                    {
                        return Err(MirrorError::Vulnerable);
                    }
                }
                Err(_) if !quarantined => return Err(MirrorError::Busy),
                Err(_) => {}
            }
        }
        if quarantined {
            return Err(MirrorError::Quarantined);
        }
        self.released(store, &repo, &hash, true)?
            .ok_or(MirrorError::ScanIncomplete)
    }

    async fn prepare(
        &self,
        repo: &str,
        upstream: &Repository,
        manifest: Manifest,
    ) -> Result<Verdict> {
        let store = self.store().await?;
        let hash = manifest.digest.clone();
        if let Some(verdict) = store
            .verdict(repo, &hash, &self.policy_hash, Utc::now())
            .map_err(MirrorError::internal)?
        {
            return Ok(verdict);
        }
        let staging =
            tempfile::tempdir_in(store.root().join("objects")).map_err(MirrorError::internal)?;
        let graph = Graph::fetch(upstream, manifest, staging.path()).await?;
        let test_scan = {
            #[cfg(test)]
            {
                self.test_scan.clone()
            }
            #[cfg(not(test))]
            {
                None::<()>
            }
        };
        let cache = if test_scan.is_some() {
            PathBuf::new()
        } else {
            self.database(store.root()).await?
        };
        let binary = self.config.trivy.clone();
        let policy = self.config.policy.clone();
        let (graph, staging, verdict) = tokio::task::spawn_blocking(move || {
            let verdict = graph.scan(staging.path(), |layout| {
                #[cfg(test)]
                if let Some(scan) = &test_scan {
                    return scan(layout);
                }
                let vulnerable =
                    scan_registry_image(layout, staging.path(), &cache, &binary, &policy)?;
                Ok(if vulnerable {
                    Verdict::Vulnerable
                } else {
                    Verdict::Clean
                })
            })?;
            anyhow::Ok((graph, staging, verdict))
        })
        .await
        .map_err(MirrorError::scanner)?
        .map_err(MirrorError::scanner)?;
        store
            .commit(ScannedImage {
                repo,
                hash: &hash,
                policy: &self.policy_hash,
                now: Utc::now(),
                staging,
                size: graph.bytes,
                verdict,
                objects: &graph.objects,
            })
            .map_err(MirrorError::internal)?;
        Ok(verdict)
    }

    async fn database(&self, root: &Path) -> Result<PathBuf> {
        if let Some(cache) = &self.config.external_database {
            if db_fresh(cache, "db", "trivy.db", Duration::from_secs(48 * 3600)).await {
                return Ok(cache.clone());
            }
            return Err(MirrorError::scanner(anyhow::anyhow!(
                "configured Trivy vulnerability database missing or stale"
            )));
        }
        let cache = root.join("trivy-cache");
        for (directory, file, flag, repository_flag, repository, maximum_age) in [
            (
                "db",
                "trivy.db",
                "--download-db-only",
                "--db-repository",
                "ghcr.io/aquasecurity/trivy-db:2",
                24 * 3600,
            ),
            (
                "java-db",
                "trivy-java.db",
                "--download-java-db-only",
                "--java-db-repository",
                "ghcr.io/aquasecurity/trivy-java-db:1",
                7 * 24 * 3600,
            ),
        ] {
            let maximum_age = Duration::from_secs(maximum_age);
            if db_fresh(&cache, directory, file, maximum_age).await {
                continue;
            }
            let mut command = tokio::process::Command::new(&self.config.trivy);
            command
                .arg("--cache-dir")
                .arg(&cache)
                .args([
                    "image",
                    flag,
                    repository_flag,
                    repository,
                    "--skip-version-check",
                    "--disable-telemetry",
                    "--quiet",
                ])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::inherit())
                .kill_on_drop(true);
            let status = tokio::time::timeout(Duration::from_secs(900), command.status())
                .await
                .map_err(MirrorError::scanner)?
                .map_err(MirrorError::scanner)?;
            if !status.success() || !db_fresh(&cache, directory, file, maximum_age).await {
                return Err(MirrorError::scanner(anyhow::anyhow!(
                    "could not refresh Trivy {directory}"
                )));
            }
        }
        Ok(cache)
    }
}

async fn db_fresh(cache: &Path, directory: &str, file: &str, age: Duration) -> bool {
    #[derive(Deserialize)]
    struct Metadata {
        #[serde(rename = "UpdatedAt")]
        updated_at: DateTime<Utc>,
    }
    let path = cache.join(directory);
    let Ok(metadata) = fs::read(path.join("metadata.json")).await else {
        return false;
    };
    let Ok(metadata) = serde_json::from_slice::<Metadata>(&metadata) else {
        return false;
    };
    Utc::now()
        .signed_duration_since(metadata.updated_at)
        .to_std()
        .is_ok_and(|elapsed| elapsed <= age)
        && fs::metadata(path.join(file))
            .await
            .is_ok_and(|meta| meta.is_file() && meta.len() > 0)
}

pub fn routes(config: Config) -> anyhow::Result<Router> {
    Ok(router(Arc::new(Mirror::new(
        config,
        Upstream::docker_hub()?,
    )?)))
}

fn router(mirror: Arc<Mirror>) -> Router {
    Router::new()
        .route("/v2", any(registry))
        .route("/v2/", any(registry))
        .route("/v2/*path", any(registry))
        .with_state(mirror)
}

async fn registry(
    State(mirror): State<Arc<Mirror>>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let mut response = match dispatch(mirror, &uri, &method, &headers).await {
        Ok(response) => response,
        Err(error) => {
            error.log();
            error.response()
        }
    };
    response.headers_mut().insert(
        API_VERSION,
        header::HeaderValue::from_static("registry/2.0"),
    );
    if method == Method::HEAD {
        *response.body_mut() = Body::empty();
    }
    response
}

async fn dispatch(
    mirror: Arc<Mirror>,
    uri: &Uri,
    method: &Method,
    headers: &HeaderMap,
) -> Result<Response> {
    if method != Method::GET && method != Method::HEAD {
        return Err(MirrorError::Unsupported);
    }
    let path = uri
        .path()
        .strip_prefix("/v2")
        .unwrap_or_default()
        .trim_start_matches('/');
    if path.is_empty() {
        return Ok(Json(json!({})).into_response());
    }
    if path == "_catalog" {
        return list(&mirror, uri, None).await;
    }
    if let Some(repo) = path.strip_suffix("/tags/list").and_then(repository) {
        return list(&mirror, uri, Some(&repo)).await;
    }
    let (repo, kind, reference) = path
        .rsplit_once('/')
        .and_then(|(path, reference)| {
            path.rsplit_once('/')
                .map(|(repo, kind)| (repo, kind, reference))
        })
        .ok_or(MirrorError::NameInvalid)?;
    let repo = repository(repo).ok_or(MirrorError::NameInvalid)?;
    match kind {
        "manifests" => {
            if !valid_digest(reference) && !valid_tag(reference) {
                return Err(MirrorError::ManifestUnknown);
            }
            let release = mirror.manifest(repo, reference).await?;
            if !accepts(headers, &release.object.media_type) {
                return Err(MirrorError::ManifestUnknown);
            }
            serve_object(release, method, headers).await
        }
        "blobs" => {
            if !valid_digest(reference) {
                return Err(MirrorError::BlobUnknown);
            }
            let store = mirror.store().await?;
            let release = mirror
                .released(store, &repo, reference, false)?
                .ok_or(MirrorError::BlobUnknown)?;
            serve_object(release, method, headers).await
        }
        "referrers" => Err(MirrorError::ManifestUnknown),
        _ => Err(MirrorError::Unsupported),
    }
}

async fn list(mirror: &Mirror, uri: &Uri, repo: Option<&str>) -> Result<Response> {
    let mut limit = 100_u32;
    let mut last = String::new();
    for (key, value) in reqwest::Url::parse(&format!("https://localhost{uri}"))
        .map_err(|_| MirrorError::NameInvalid)?
        .query_pairs()
    {
        match key.as_ref() {
            "n" => {
                limit = value
                    .parse::<u32>()
                    .map_err(|_| MirrorError::NameInvalid)?
                    .min(1000)
            }
            "last" => last = value.into_owned(),
            _ => {}
        }
    }
    if last.len() > 255 || limit == 0 {
        return Err(MirrorError::NameInvalid);
    }
    let now = Utc::now();
    let mut values = mirror.store().await?.list(
        repo,
        &mirror.policy_hash,
        now,
        mirror.age_cutoff(now),
        &last,
        limit + 1,
    )?;
    let next = if values.len() > limit as usize {
        values.pop();
        values.last().map(|value| {
            format!(
                "<{}?n={limit}&last={}>; rel=\"next\"",
                uri.path(),
                urlencoding::encode(value)
            )
        })
    } else {
        None
    };
    let mut response = Json(match repo {
        Some(repo) => json!({"name": repo, "tags": values}),
        None => json!({"repositories": values}),
    })
    .into_response();
    if let Some(next) = next {
        response
            .headers_mut()
            .insert(header::LINK, next.parse().map_err(MirrorError::internal)?);
    }
    Ok(response)
}

fn accepts(headers: &HeaderMap, media_type: &str) -> bool {
    if !headers.contains_key(header::ACCEPT) {
        return true;
    }
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|entry| {
            let mut fields = entry.split(';');
            let kind = fields.next()?.trim();
            let specificity = if kind.eq_ignore_ascii_case(media_type) {
                2
            } else if kind.eq_ignore_ascii_case("application/*") {
                1
            } else if kind == "*/*" {
                0
            } else {
                return None;
            };
            let quality = match fields.find_map(|parameter| parameter.trim().strip_prefix("q=")) {
                Some(q) => q.parse::<f32>().ok().filter(|q| (0.0..=1.0).contains(q))?,
                None => 1.0,
            };
            Some((specificity, quality))
        })
        .max_by(|(left_kind, left_q), (right_kind, right_q)| {
            left_kind
                .cmp(right_kind)
                .then_with(|| left_q.total_cmp(right_q))
        })
        .is_some_and(|(_, quality)| quality > 0.0)
}

async fn serve_object(release: Release, method: &Method, headers: &HeaderMap) -> Result<Response> {
    let object = release.object;
    let mut file = fs::File::open(object_path(&release.directory, &object.digest))
        .await
        .map_err(MirrorError::internal)?;
    if file.metadata().await.map_err(MirrorError::internal)?.len() != object.size {
        return Err(MirrorError::ScanIncomplete);
    }
    let etag = format!("\"{}\"", object.digest);
    let if_none_match = headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|value| {
            let value = value.trim();
            value == "*" || value.trim_start_matches("W/") == etag
        });
    let mut builder = Response::builder()
        .header("docker-content-digest", &object.digest)
        .header(header::ETAG, &etag)
        .header(header::CACHE_CONTROL, "private, no-cache");
    if if_none_match {
        return builder
            .status(StatusCode::NOT_MODIFIED)
            .body(Body::empty())
            .map_err(MirrorError::internal);
    }
    let mut length = object.size;
    if !object.manifest {
        builder = builder.header(header::ACCEPT_RANGES, "bytes");
        if method == Method::GET
            && headers
                .get(header::IF_RANGE)
                .is_none_or(|value| value == etag.as_str())
        {
            if let Some(range) = headers
                .get(header::RANGE)
                .and_then(|value| value.to_str().ok())
                .filter(|value| value.starts_with("bytes=") && !value.contains(','))
            {
                let Some((start, end)) = byte_range(range, object.size) else {
                    return builder
                        .status(StatusCode::RANGE_NOT_SATISFIABLE)
                        .header(header::CONTENT_RANGE, format!("bytes */{}", object.size))
                        .body(Body::empty())
                        .map_err(MirrorError::internal);
                };
                file.seek(std::io::SeekFrom::Start(start))
                    .await
                    .map_err(MirrorError::internal)?;
                length = end - start + 1;
                builder = builder.status(StatusCode::PARTIAL_CONTENT).header(
                    header::CONTENT_RANGE,
                    format!("bytes {start}-{end}/{}", object.size),
                );
            }
        }
    } else {
        builder = builder.header(header::VARY, "Accept");
    }
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from_stream(ReaderStream::new(file.take(length)))
    };
    builder
        .header(header::CONTENT_TYPE, object.media_type)
        .header(header::CONTENT_LENGTH, length)
        .body(body)
        .map_err(MirrorError::internal)
}

fn byte_range(value: &str, size: u64) -> Option<(u64, u64)> {
    let (start, end) = value.strip_prefix("bytes=")?.split_once('-')?;
    let last = size.checked_sub(1)?;
    if start.is_empty() {
        let suffix: u64 = end.parse().ok()?;
        return (suffix > 0).then_some((size.saturating_sub(suffix), last));
    }
    let start = start.parse().ok()?;
    let end = if end.is_empty() {
        last
    } else {
        last.min(end.parse().ok()?)
    };
    (start <= end).then_some((start, end))
}

fn repository(input: &str) -> Option<String> {
    if input.len() > 255 || input.is_empty() {
        return None;
    }
    // Distribution's repository grammar permits one dot, one or two
    // underscores, or a run of hyphens between lowercase alphanumeric groups.
    static NAME: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        #[allow(clippy::expect_used)]
        regex::Regex::new(r"^[a-z0-9]+(?:(?:\.|_{1,2}|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:\.|_{1,2}|-+)[a-z0-9]+)*)*$").expect("valid repository regex")
    });
    if !NAME.is_match(input) {
        return None;
    }
    Some(if input.contains('/') {
        input.to_owned()
    } else {
        format!("library/{input}")
    })
}

fn valid_tag(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        && !value.starts_with(['.', '-'])
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

type Result<T> = std::result::Result<T, MirrorError>;

enum MirrorError {
    NameInvalid,
    NameUnknown,
    ManifestUnknown,
    BlobUnknown,
    Unsupported,
    Quarantined,
    Vulnerable,
    ScanIncomplete,
    Busy,
    RateLimited,
    Internal(anyhow::Error),
    Invalid(anyhow::Error),
    Upstream(anyhow::Error),
    Scanner(anyhow::Error),
}

impl MirrorError {
    fn internal(error: impl Into<anyhow::Error>) -> Self {
        Self::Internal(error.into())
    }
    fn invalid(error: impl Into<anyhow::Error>) -> Self {
        Self::Invalid(error.into())
    }
    fn upstream(error: impl Into<anyhow::Error>) -> Self {
        Self::Upstream(error.into())
    }
    fn scanner(error: impl Into<anyhow::Error>) -> Self {
        Self::Scanner(error.into())
    }

    fn log(&self) {
        if let Self::Internal(error) | Self::Invalid(error) | Self::Scanner(error) = self {
            eprintln!("Docker mirror: {error:#}");
        }
        // Upstream failures may contain short-lived signed CDN URLs.
        if let Self::Upstream(error) = self {
            let message = error
                .downcast_ref::<reqwest::Error>()
                .map(|error| {
                    if error.is_timeout() {
                        "request timed out"
                    } else if error.is_connect() {
                        "connection failed"
                    } else if error.is_redirect() {
                        "unexpected redirect"
                    } else {
                        "request failed"
                    }
                })
                .unwrap_or("invalid upstream response");
            eprintln!("Docker mirror: {message}");
        }
    }

    fn response(self) -> Response {
        let (status, code, message) = match self {
            Self::NameInvalid => (
                StatusCode::BAD_REQUEST,
                "NAME_INVALID",
                "invalid repository name or request",
            ),
            Self::NameUnknown => (
                StatusCode::NOT_FOUND,
                "NAME_UNKNOWN",
                "repository has no released images",
            ),
            Self::ManifestUnknown => (
                StatusCode::NOT_FOUND,
                "MANIFEST_UNKNOWN",
                "manifest unknown",
            ),
            Self::BlobUnknown => (
                StatusCode::NOT_FOUND,
                "BLOB_UNKNOWN",
                "blob unknown or held in quarantine",
            ),
            Self::Unsupported => (
                StatusCode::METHOD_NOT_ALLOWED,
                "UNSUPPORTED",
                "read-only pull-through mirror",
            ),
            Self::Quarantined => (
                StatusCode::FORBIDDEN,
                "DENIED",
                "image is held in the quarantine window",
            ),
            Self::Vulnerable => (
                StatusCode::FORBIDDEN,
                "DENIED",
                "image is held in quarantine by vulnerability policy",
            ),
            Self::ScanIncomplete | Self::Scanner(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "UNAVAILABLE",
                "image remains in quarantine pending a complete vulnerability scan",
            ),
            Self::Busy => (
                StatusCode::SERVICE_UNAVAILABLE,
                "UNAVAILABLE",
                "image remains in quarantine while the mirror is busy",
            ),
            Self::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "TOOMANYREQUESTS",
                "Docker Hub rate limit reached",
            ),
            Self::Internal(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "UNAVAILABLE",
                "mirror storage is unavailable",
            ),
            Self::Invalid(_) => (
                StatusCode::BAD_GATEWAY,
                "MANIFEST_INVALID",
                "registry content failed integrity or format validation",
            ),
            Self::Upstream(_) => (
                StatusCode::BAD_GATEWAY,
                "UNKNOWN",
                "Docker Hub is currently unavailable",
            ),
        };
        let mut response = (
            status,
            Json(json!({"errors":[{"code":code,"message":message}]})),
        )
            .into_response();
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
        if status == StatusCode::METHOD_NOT_ALLOWED {
            response
                .headers_mut()
                .insert(header::ALLOW, header::HeaderValue::from_static("GET, HEAD"));
        }
        if status == StatusCode::SERVICE_UNAVAILABLE || status == StatusCode::TOO_MANY_REQUESTS {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, header::HeaderValue::from_static("60"));
        }
        response
    }
}

#[cfg(test)]
mod tests;
