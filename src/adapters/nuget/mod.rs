use crate::domain::{Ecosystem, PackageCoordinate, PackageVersion};
use crate::ports::UpstreamNuGetRegistry;
use anyhow::{Context, Result};
use chrono::DateTime;
use semver::Version;

pub struct HttpNuGetRegistry {
    pub base_url: String,
    pub client: reqwest::blocking::Client,
}
impl HttpNuGetRegistry {
    pub fn new() -> Result<Self> {
        Ok(Self {
            base_url: "https://api.nuget.org".into(),
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        })
    }
}
fn leaf_url(base: &str, package: &str, version: &str) -> String {
    format!(
        "{}/v3/registration5-semver1/{}/{}.json",
        base.trim_end_matches('/'),
        package.to_ascii_lowercase(),
        urlencoding::encode(version)
    )
}

impl UpstreamNuGetRegistry for HttpNuGetRegistry {
    fn release(&self, package: &str, version: &str) -> Result<serde_json::Value> {
        let leaf_url = leaf_url(&self.base_url, package, version);
        let leaf: serde_json::Value = self
            .client
            .get(leaf_url)
            .send()?
            .error_for_status()?
            .json()?;
        let catalog = match leaf.get("catalogEntry") {
            Some(serde_json::Value::String(url)) => {
                self.client.get(url).send()?.error_for_status()?.json()?
            }
            Some(entry) => entry.clone(),
            None => serde_json::Value::Null,
        };
        Ok(serde_json::json!({
            "published": leaf.get("published").or_else(|| catalog.get("published")),
            "listed": leaf.get("listed"),
            "packageHash": catalog.get("packageHash"),
            "packageHashAlgorithm": catalog.get("packageHashAlgorithm"),
            "packageContent": leaf.get("packageContent"),
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NuGetPin {
    pub name: String,
    pub version: String,
    pub content_hash: Option<String>,
}

pub type ParsedPins = (Vec<NuGetPin>, Vec<String>);

pub fn parse_packages_lock(content: &str) -> Result<ParsedPins> {
    let lock: serde_json::Value =
        serde_json::from_str(content).context("packages.lock.json is not valid JSON")?;
    let targets = lock
        .get("dependencies")
        .and_then(|dependencies| dependencies.as_object())
        .context("packages.lock.json has no dependencies object")?;
    let mut pins: Vec<NuGetPin> = Vec::new();
    let mut gaps = Vec::new();
    for (target, packages) in targets {
        let Some(packages) = packages.as_object() else {
            gaps.push(format!("target {target}: dependencies are not an object"));
            continue;
        };
        for (name, details) in packages {
            match details.get("resolved").and_then(|r| r.as_str()) {
                Some(resolved) if !resolved.is_empty() => {
                    if !pins.iter().any(|pin| pin.name == *name) {
                        pins.push(NuGetPin {
                            name: name.clone(),
                            version: resolved.to_string(),
                            content_hash: details
                                .get("contentHash")
                                .and_then(|hash| hash.as_str())
                                .filter(|hash| !hash.is_empty())
                                .map(str::to_string),
                        });
                    }
                }
                _ => {
                    let kind = details
                        .get("type")
                        .and_then(|t| t.as_str())
                        .unwrap_or("unknown");
                    if kind != "Project" {
                        gaps.push(format!(
                            "target {target}: {name} has no resolved version ({kind})"
                        ));
                    }
                }
            }
        }
    }
    pins.sort_by(|a, b| a.name.cmp(&b.name));
    Ok((pins, gaps))
}

fn strip_sha512_prefix(raw: &str) -> &str {
    raw.strip_prefix("sha512-")
        .or_else(|| raw.strip_prefix("SHA512-"))
        .unwrap_or(raw)
}

pub fn package_version_from_nuget(
    payload: &serde_json::Value,
    name: &str,
    version: &Version,
    lockfile_hash: Option<&str>,
) -> Result<PackageVersion> {
    let catalog_hash = payload
        .get("packageHash")
        .and_then(|hash| hash.as_str())
        .filter(|hash| !hash.is_empty());
    let lock_payload = lockfile_hash
        .map(strip_sha512_prefix)
        .filter(|hash| !hash.is_empty());
    match (lock_payload, catalog_hash) {
        (Some(lock), Some(catalog)) => {
            if lock != catalog {
                anyhow::bail!(
                    "lockfile contentHash does not match registry packageHash for {name}@{version}"
                );
            }
        }
        (Some(_), None) => {
            anyhow::bail!(
                "registry response is missing packageHash for {name}@{version}; cannot verify lockfile contentHash"
            );
        }
        _ => {}
    }
    let listed = payload
        .get("listed")
        .and_then(|listed| listed.as_bool())
        .unwrap_or(true);
    let published_at = if listed {
        payload
            .get("published")
            .and_then(|p| p.as_str())
            .and_then(|p| DateTime::parse_from_rfc3339(p).ok())
            .map(|p| p.with_timezone(&chrono::Utc))
    } else {
        None
    };
    let integrity = match (lock_payload, catalog_hash) {
        (Some(lock), _) => Some(format!("sha512-{lock}")),
        (None, Some(hash)) => Some({
            let algorithm = payload
                .get("packageHashAlgorithm")
                .and_then(|algorithm| algorithm.as_str())
                .unwrap_or("sha512")
                .to_ascii_lowercase();
            format!("{algorithm}-{hash}")
        }),
        (None, None) => None,
    };
    let tarball_url = payload
        .get("packageContent")
        .and_then(|content| content.as_str())
        .map(str::to_string);
    Ok(PackageVersion {
        package: PackageCoordinate {
            ecosystem: Ecosystem::NuGet,
            name: name.to_string(),
        },
        version: version.clone(),
        published_at,
        integrity,
        tarball_url,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn leaf_url_avoids_gzip_only_endpoint() {
        let url = leaf_url("https://api.nuget.org", "Newtonsoft.Json", "13.0.3");
        assert!(url.contains("registration5-semver1"));
        assert!(!url.contains("-gz-"));
        assert!(url.ends_with("/newtonsoft.json/13.0.3.json"));
    }

    #[test]
    fn parses_resolved_pins_from_packages_lock() -> Result<()> {
        let content = r#"{
          "version": 1,
          "dependencies": {
            "net8.0": {
              "Newtonsoft.Json": { "type": "Direct", "requested": "[13.0.3, )", "resolved": "13.0.3", "contentHash": "abc" },
              "MyProject": { "type": "Project" },
              "RangeOnly": { "type": "Direct", "requested": "[1.0.0, )" }
            },
            "net8.0/win-x64": {
              "Newtonsoft.Json": { "type": "Direct", "resolved": "13.0.3" },
              "Serilog": { "type": "Transitive", "resolved": "3.1.1" }
            }
          }
        }"#;
        let (pins, gaps) = parse_packages_lock(content)?;
        assert_eq!(
            pins,
            vec![
                NuGetPin {
                    name: "Newtonsoft.Json".to_string(),
                    version: "13.0.3".to_string(),
                    content_hash: Some("abc".to_string()),
                },
                NuGetPin {
                    name: "Serilog".to_string(),
                    version: "3.1.1".to_string(),
                    content_hash: None,
                },
            ]
        );
        assert_eq!(gaps.len(), 1);
        assert!(gaps[0].contains("RangeOnly"));
        Ok(())
    }

    #[test]
    fn lockfile_hash_must_match_registry_hash() -> Result<()> {
        let version = Version::parse("1.0.0").unwrap();
        let base = serde_json::json!({
            "published": "2023-03-08T07:42:54.647Z",
            "listed": true,
            "packageHash": "AAAA",
            "packageHashAlgorithm": "SHA512",
            "packageContent": "https://x/y.nupkg"
        });
        let matching = package_version_from_nuget(&base, "Example", &version, Some("AAAA"))?;
        assert_eq!(matching.integrity.as_deref(), Some("sha512-AAAA"));
        let prefixed = package_version_from_nuget(&base, "Example", &version, Some("sha512-AAAA"))?;
        assert_eq!(
            prefixed.integrity.as_deref(),
            Some("sha512-AAAA"),
            "a prefixed contentHash must not double the prefix"
        );
        assert!(
            package_version_from_nuget(&base, "Example", &version, Some("BBBB")).is_err(),
            "a lockfile contentHash that disagrees with the registry must fail closed"
        );

        let hashless = serde_json::json!({ "listed": true, "packageContent": "https://x/y.nupkg" });
        assert!(
            package_version_from_nuget(&hashless, "Example", &version, Some("LOCK")).is_err(),
            "when the lockfile asserts a hash the registry hash is mandatory"
        );
        let unlocked = package_version_from_nuget(&hashless, "Example", &version, None)?;
        assert_eq!(unlocked.integrity, None);
        Ok(())
    }

    #[test]
    fn builds_package_version_from_nuget_payload() -> Result<()> {
        let payload = json!({
            "published": "2023-03-08T07:42:54.647Z",
            "listed": true,
            "packageHash": "mbJSvHfRxfX3tR",
            "packageHashAlgorithm": "SHA512",
            "packageContent": "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"
        });
        let version = Version::parse("13.0.3").unwrap();
        let pv = package_version_from_nuget(&payload, "Newtonsoft.Json", &version, None)?;
        assert_eq!(pv.package.ecosystem, Ecosystem::NuGet);
        assert_eq!(pv.integrity.as_deref(), Some("sha512-mbJSvHfRxfX3tR"));
        assert_eq!(
            pv.published_at.map(|t| t.to_rfc3339()),
            Some("2023-03-08T07:42:54.647+00:00".to_string())
        );
        assert!(pv.tarball_url.unwrap_or_default().ends_with(".nupkg"));
        Ok(())
    }

    #[test]
    fn unlisted_versions_have_no_published_date() -> Result<()> {
        let payload = json!({ "listed": false, "packageContent": "https://x/y.nupkg" });
        let version = Version::parse("1.0.0").unwrap();
        let pv = package_version_from_nuget(&payload, "Example", &version, None)?;
        assert!(pv.published_at.is_none());
        Ok(())
    }
}
