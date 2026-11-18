use crate::domain::{Ecosystem, PackageCoordinate, PackageVersion, PackageVersionId};
use crate::ports::UpstreamNpmRegistry;
use anyhow::Result;
use chrono::{DateTime, Utc};
pub struct HttpNpmRegistry {
    pub base_url: String,
    pub client: reqwest::blocking::Client,
}
impl HttpNpmRegistry {
    pub fn new() -> Result<Self> {
        Ok(Self {
            base_url: "https://registry.npmjs.org".into(),
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        })
    }
}
impl UpstreamNpmRegistry for HttpNpmRegistry {
    fn metadata(&self, package: &str) -> Result<serde_json::Value> {
        let url = format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            urlencoding::encode(package)
        );
        Ok(self.client.get(url).send()?.error_for_status()?.json()?)
    }
    fn tarball(&self, url: &str) -> Result<Box<dyn std::io::Read + Send>> {
        Ok(Box::new(self.client.get(url).send()?.error_for_status()?))
    }
}
pub fn rewrite_tarball_urls(
    mut metadata: serde_json::Value,
    proxy_base: &str,
) -> serde_json::Value {
    let package_name = metadata
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("package")
        .to_string();
    let tarball_name = package_name
        .rsplit('/')
        .next()
        .unwrap_or("package")
        .to_string();
    if let Some(versions) = metadata.get_mut("versions").and_then(|v| v.as_object_mut()) {
        for (version, obj) in versions.iter_mut() {
            if let Some(dist) = obj.get_mut("dist").and_then(|d| d.as_object_mut()) {
                dist.insert(
                    "tarball".into(),
                    serde_json::Value::String(format!(
                        "{}/{}/-/{}-{}.tgz",
                        proxy_base.trim_end_matches('/'),
                        package_name,
                        tarball_name,
                        version
                    )),
                );
            }
        }
    }
    metadata
}

pub fn package_version_from_metadata(
    metadata: &serde_json::Value,
    package: &str,
    version: &PackageVersionId,
) -> Result<PackageVersion> {
    let entry = metadata
        .get("versions")
        .and_then(|v| v.get(version.upstream()))
        .ok_or_else(|| anyhow::anyhow!("{package}@{version} not found in registry metadata"))?;
    let dist = entry
        .get("dist")
        .ok_or_else(|| anyhow::anyhow!("{package}@{version} has no dist object"))?;
    let integrity = dist
        .get("integrity")
        .and_then(|i| i.as_str())
        .map(str::to_string);
    let tarball_url = dist
        .get("tarball")
        .and_then(|t| t.as_str())
        .map(str::to_string);
    let published_at = metadata
        .get("time")
        .and_then(|t| t.get(version.upstream()))
        .and_then(|t| t.as_str())
        .map(DateTime::parse_from_rfc3339)
        .transpose()?
        .map(|t| t.with_timezone(&Utc));
    Ok(PackageVersion {
        package: PackageCoordinate {
            ecosystem: Ecosystem::Npm,
            name: package.to_string(),
        },
        version: version.clone(),
        published_at,
        integrity,
        tarball_url,
    })
}

pub fn integrity_for(metadata: &serde_json::Value, version: &str) -> Option<String> {
    metadata
        .get("versions")
        .and_then(|versions| versions.get(version))
        .and_then(|entry| entry.get("dist"))
        .and_then(|dist| dist.get("integrity"))
        .and_then(|integrity| integrity.as_str())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extracts_integrity_for_a_version() {
        let metadata =
            serde_json::json!({"versions": {"1.3.0": {"dist": {"integrity": "sha512-abc"}}}});
        assert_eq!(
            integrity_for(&metadata, "1.3.0").as_deref(),
            Some("sha512-abc")
        );
        assert_eq!(integrity_for(&metadata, "9.9.9"), None);
    }
    #[test]
    fn rewrites() {
        let v = serde_json::json!({"name":"left-pad","versions":{"1.0.0":{"dist":{"tarball":"https://x"}}}});
        let r = rewrite_tarball_urls(v, "http://localhost:4873");
        assert_eq!(
            r["versions"]["1.0.0"]["dist"]["tarball"],
            "http://localhost:4873/left-pad/-/left-pad-1.0.0.tgz"
        );
    }
    #[test]
    fn maps_registry_metadata_to_domain() -> Result<()> {
        let meta = serde_json::json!({
            "name": "left-pad",
            "versions": {"1.3.0": {"dist": {
                "integrity": "sha512-abc",
                "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
            }}},
            "time": {"1.3.0": "2018-02-05T02:27:32.476Z"}
        });
        let pv = package_version_from_metadata(
            &meta,
            "left-pad",
            &PackageVersionId::parse(&Ecosystem::Npm, "1.3.0")?,
        )?;
        assert_eq!(pv.integrity.as_deref(), Some("sha512-abc"));
        assert!(pv
            .tarball_url
            .as_deref()
            .is_some_and(|u| u.ends_with("1.3.0.tgz")));
        assert!(pv.published_at.is_some());
        Ok(())
    }
    #[test]
    fn tarball_returns_before_the_response_body_finishes() -> Result<()> {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            sync::mpsc,
            thread,
            time::Duration,
        };

        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let (started_tx, started_rx) = mpsc::channel();
        let (continue_tx, continue_rx) = mpsc::channel();
        let server = thread::spawn(move || -> Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request)?;
            stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nabc",
            )?;
            stream.flush()?;
            started_tx.send(())?;
            continue_rx
                .recv_timeout(Duration::from_secs(2))
                .map_err(|error| anyhow::anyhow!("test did not release response: {error}"))?;
            let _ = stream.write_all(b"def");
            let _ = stream.flush();
            Ok(())
        });
        let registry = HttpNpmRegistry {
            base_url: String::new(),
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(2))
                .build()?,
        };
        let url = format!("http://{address}/tarball");
        let (returned_tx, returned_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let client = thread::spawn(move || {
            let result = registry.tarball(&url).and_then(|mut body| {
                returned_tx.send(())?;
                let mut bytes = Vec::new();
                body.read_to_end(&mut bytes)?;
                Ok(bytes)
            });
            let _ = result_tx.send(result);
        });

        started_rx
            .recv_timeout(Duration::from_secs(2))
            .map_err(|error| anyhow::anyhow!("server did not start response: {error}"))?;
        let early = returned_rx.recv_timeout(Duration::from_secs(1));
        continue_tx.send(())?;
        let bytes = result_rx
            .recv_timeout(Duration::from_secs(2))
            .map_err(|error| anyhow::anyhow!("client did not finish response: {error}"))??;
        client
            .join()
            .map_err(|_| anyhow::anyhow!("client thread panicked"))?;
        server
            .join()
            .map_err(|_| anyhow::anyhow!("server thread panicked"))??;

        assert!(
            early.is_ok(),
            "tarball call buffered the complete response body"
        );
        assert_eq!(bytes, b"abcdef");
        Ok(())
    }
    #[test]
    fn unknown_version_errors() -> Result<()> {
        let meta = serde_json::json!({"versions": {}});
        let v = PackageVersionId::parse(&Ecosystem::Npm, "9.9.9")?;
        assert!(package_version_from_metadata(&meta, "x", &v).is_err());
        Ok(())
    }
}
