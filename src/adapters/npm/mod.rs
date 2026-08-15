use crate::ports::UpstreamNpmRegistry;
use anyhow::Result;
pub struct HttpNpmRegistry {
    pub base_url: String,
    pub client: reqwest::blocking::Client,
}
impl Default for HttpNpmRegistry {
    fn default() -> Self {
        Self {
            base_url: "https://registry.npmjs.org".into(),
            client: reqwest::blocking::Client::new(),
        }
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
    fn tarball(&self, url: &str) -> Result<Vec<u8>> {
        Ok(self
            .client
            .get(url)
            .send()?
            .error_for_status()?
            .bytes()?
            .to_vec())
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rewrites() {
        let v = serde_json::json!({"name":"left-pad","versions":{"1.0.0":{"dist":{"tarball":"https://x"}}}});
        let r = rewrite_tarball_urls(v, "http://localhost:4873");
        assert_eq!(
            r["versions"]["1.0.0"]["dist"]["tarball"],
            "http://localhost:4873/left-pad/-/left-pad-1.0.0.tgz"
        );
    }
}
