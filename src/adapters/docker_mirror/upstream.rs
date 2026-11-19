use super::{digest, valid_digest, MirrorError, Result, MANIFEST_TYPES, MAX_MANIFEST};
use anyhow::{ensure, Context};
use axum::http::{header, StatusCode};
use reqwest::{redirect, Client, Response, Url};
use serde::Deserialize;
use std::time::Duration;

pub(super) struct Upstream {
    client: Client,
    registry: Url,
    tokens: Option<Url>,
}

pub(super) struct Manifest {
    pub digest: String,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

impl Upstream {
    pub fn docker_hub() -> anyhow::Result<Self> {
        Self::new(
            Url::parse("https://registry-1.docker.io/")?,
            Some(Url::parse("https://auth.docker.io/token")?),
        )
    }

    pub(super) fn new(registry: Url, tokens: Option<Url>) -> anyhow::Result<Self> {
        let mut builder = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(300))
            .redirect(redirect::Policy::custom(|attempt| {
                let target = attempt.url();
                let docker_cdn = matches!(
                    target.host_str(),
                    Some("production.cloudflare.docker.com" | "production.cloudfront.docker.com"
                        | "docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com")
                );
                if attempt.previous().len() < 5
                    && target.scheme() == "https"
                    && target.port_or_known_default() == Some(443)
                    && target.username().is_empty()
                    && target.password().is_none()
                    && docker_cdn
                {
                    attempt.follow()
                } else {
                    attempt.error("unexpected Docker Hub redirect")
                }
            }));
        if let Some(bundle) = std::env::var_os("SSL_CERT_FILE") {
            for certificate in reqwest::Certificate::from_pem_bundle(&std::fs::read(bundle)?)? {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let client = builder.build()?;
        Ok(Self {
            client,
            registry,
            tokens,
        })
    }

    pub async fn repository(&self, repository: &str) -> Result<Repository> {
        #[derive(Deserialize)]
        struct Token {
            token: String,
        }
        let token = if let Some(endpoint) = &self.tokens {
            let response = self
                .client
                .get(endpoint.clone())
                .query(&[
                    ("service", "registry.docker.io"),
                    ("scope", &format!("repository:{repository}:pull")),
                ])
                .send()
                .await
                .map_err(MirrorError::upstream)?;
            let response = response.error_for_status().map_err(MirrorError::upstream)?;
            if response.url().origin() != endpoint.origin()
                || response.url().path() != endpoint.path()
            {
                return Err(MirrorError::upstream(anyhow::anyhow!(
                    "token endpoint redirected"
                )));
            }
            let token: Token = serde_json::from_slice(&bounded(response, 64 * 1024).await?)
                .map_err(MirrorError::upstream)?;
            Some(token.token)
        } else {
            None
        };
        Ok(Repository {
            client: self.client.clone(),
            registry: self.registry.clone(),
            repository: repository.to_owned(),
            token,
        })
    }
}

#[derive(Clone)]
pub(super) struct Repository {
    client: Client,
    registry: Url,
    repository: String,
    token: Option<String>,
}

impl Repository {
    async fn get(&self, kind: &str, reference: &str) -> Result<Response> {
        let url = self
            .registry
            .join(&format!("v2/{}/{kind}/{reference}", self.repository))
            .map_err(MirrorError::upstream)?;
        let mut request = self
            .client
            .get(url)
            .header(header::ACCEPT_ENCODING, "identity");
        if kind == "manifests" {
            request = request.header(header::ACCEPT, MANIFEST_TYPES.join(", "));
        }
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.map_err(MirrorError::upstream)?;
        match response.status() {
            StatusCode::OK => Ok(response),
            StatusCode::NOT_FOUND | StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                Err(if kind == "manifests" {
                    MirrorError::ManifestUnknown
                } else {
                    MirrorError::BlobUnknown
                })
            }
            StatusCode::TOO_MANY_REQUESTS => Err(MirrorError::RateLimited),
            status => Err(MirrorError::upstream(anyhow::anyhow!(
                "registry returned {status}"
            ))),
        }
    }

    pub async fn manifest(&self, reference: &str) -> Result<Manifest> {
        let response = self.get("manifests", reference).await?;
        let media_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .unwrap_or_default()
            .trim()
            .to_owned();
        let header_digest = response
            .headers()
            .get("docker-content-digest")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = bounded(response, MAX_MANIFEST).await?;
        let actual = digest(&bytes);
        (|| -> anyhow::Result<()> {
            ensure!(
                MANIFEST_TYPES.contains(&media_type.as_str()),
                "unsupported manifest media type"
            );
            ensure!(
                header_digest
                    .as_ref()
                    .is_none_or(|expected| expected == &actual),
                "registry manifest digest mismatch"
            );
            ensure!(
                !valid_digest(reference) || reference == actual,
                "requested manifest digest mismatch"
            );
            Ok(())
        })()
        .map_err(MirrorError::invalid)?;
        Ok(Manifest {
            digest: actual,
            media_type,
            bytes,
        })
    }

    pub async fn blob(&self, digest: &str) -> Result<Response> {
        self.get("blobs", digest).await
    }
}

async fn bounded(mut response: Response, limit: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|size| size > limit as u64)
    {
        return Err(MirrorError::invalid(anyhow::anyhow!(
            "registry response exceeds size limit"
        )));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("read registry response")
        .map_err(MirrorError::upstream)?
    {
        if chunk.len() > limit - bytes.len() {
            return Err(MirrorError::invalid(anyhow::anyhow!(
                "registry response exceeds size limit"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
