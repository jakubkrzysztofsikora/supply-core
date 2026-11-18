use crate::domain::{Ecosystem, PackageCoordinate, PackageVersion, PackageVersionId};
use crate::ports::UpstreamNuGetRegistry;
use anyhow::{Context, Result};
use chrono::DateTime;
mod content_hash;

pub use content_hash::package_content_hash;

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
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }
}

fn registration_leaf_url(
    base: &reqwest::Url,
    package: &str,
    version: &str,
) -> Result<reqwest::Url> {
    let base = base.as_str().trim_end_matches('/');
    let package = package.to_ascii_lowercase();
    let version = version.to_ascii_lowercase();
    reqwest::Url::parse(&format!(
        "{base}/{package}/{}.json",
        urlencoding::encode(&version)
    ))
    .context("invalid NuGet registration leaf URL")
}

fn select_registration_resource(resources: &[serde_json::Value]) -> Option<&str> {
    for resource_type in [
        "RegistrationsBaseUrl/3.6.0",
        "RegistrationsBaseUrl/3.4.0",
        "RegistrationsBaseUrl/3.0.0-rc",
        "RegistrationsBaseUrl/3.0.0-beta",
        "RegistrationsBaseUrl",
    ] {
        if let Some(id) = resources.iter().find_map(|item| {
            let ty = item
                .get("@type")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            if ty == resource_type {
                item.get("@id").and_then(|value| value.as_str())
            } else {
                None
            }
        }) {
            return Some(id);
        }
    }
    None
}

impl UpstreamNuGetRegistry for HttpNuGetRegistry {
    fn release(&self, package: &str, version: &str) -> Result<serde_json::Value> {
        let source = format!("{}/v3/index.json", self.base_url.trim_end_matches('/'));
        release_from_source_with_client(&self.client, &source, package, version, None)
    }
}

pub fn release_from_source(
    source: &str,
    package: &str,
    version: &str,
    token: Option<&str>,
) -> Result<serde_json::Value> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    release_from_source_with_client(&client, source, package, version, token)
}

fn release_from_source_with_client(
    client: &reqwest::blocking::Client,
    source: &str,
    package: &str,
    version: &str,
    token: Option<&str>,
) -> Result<serde_json::Value> {
    let source_url = reqwest::Url::parse(source).context("invalid NuGet source URL")?;
    if source_url.scheme() != "https" {
        anyhow::bail!("NuGet source must use HTTPS");
    }
    let host = source_url.host_str().context("NuGet source has no host")?;
    let is_circit = host == "pkgs.dev.azure.com" && source_url.path().starts_with("/Circit/")
        || host == "circit.pkgs.visualstudio.com";
    if token.is_some() && !is_circit {
        anyhow::bail!("NuGet credentials are not allowed for this source");
    }
    let get = |url: &reqwest::Url| -> Result<serde_json::Value> {
        if url.scheme() != "https" || url.host_str() != Some(host) {
            anyhow::bail!("NuGet source redirected across hosts");
        }
        let mut request = client.get(url.clone());
        if is_circit {
            let credential =
                token.context("SUPPLY_NUGET_TOKEN is required for Circit feed metadata")?;
            request = request.basic_auth("AzureDevOps", Some(credential));
        }
        request
            .send()
            .context("NuGet metadata request failed")?
            .error_for_status()
            .context("NuGet metadata source rejected request")?
            .json()
            .context("NuGet metadata response was invalid")
    };
    let index = get(&source_url)?;
    let resources = index
        .get("resources")
        .and_then(|v| v.as_array())
        .context("NuGet source index lacks resources")?;
    let registration = select_registration_resource(resources)
        .context("NuGet source has no registration resource")?;
    let base = reqwest::Url::parse(registration).context("invalid NuGet registration URL")?;
    let leaf = registration_leaf_url(&base, package, version)?;
    let leaf_value = get(&leaf)?;
    let catalog = match leaf_value.get("catalogEntry") {
        Some(serde_json::Value::String(url)) => {
            let catalog_url = reqwest::Url::parse(url).context("invalid NuGet catalog URL")?;
            match get(&catalog_url) {
                Ok(entry) => entry,
                Err(_) if leaf_value.get("published").is_some() => serde_json::Value::Null,
                Err(error) => return Err(error),
            }
        }
        Some(entry) => entry.clone(),
        None => serde_json::Value::Null,
    };
    Ok(release_metadata(&leaf_value, &catalog))
}

fn release_metadata(
    leaf_value: &serde_json::Value,
    catalog: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "published": leaf_value.get("published").or_else(|| catalog.get("published")),
        "listed": leaf_value.get("listed"),
        "packageHash": catalog.get("packageHash"),
        "packageHashAlgorithm": catalog.get("packageHashAlgorithm"),
        "packageContent": leaf_value.get("packageContent")
    })
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
    let version = lock
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .context("packages.lock.json has no numeric version")?;
    if version != 1 && version != 2 {
        anyhow::bail!("unsupported packages.lock.json version {version}");
    }
    let targets = lock
        .get("dependencies")
        .and_then(|dependencies| dependencies.as_object())
        .context("packages.lock.json has no dependencies object")?;
    let mut pins: Vec<NuGetPin> = Vec::new();
    let mut gaps = Vec::new();
    let mut conflicted: Vec<(String, String)> = Vec::new();
    for (target, packages) in targets {
        let Some(packages) = packages.as_object() else {
            gaps.push(format!("target {target}: dependencies are not an object"));
            continue;
        };
        for (name, details) in packages {
            match details.get("resolved").and_then(|r| r.as_str()) {
                Some(resolved) if !resolved.is_empty() => {
                    let content_hash = details
                        .get("contentHash")
                        .and_then(|hash| hash.as_str())
                        .filter(|hash| !hash.is_empty());
                    let Some(content_hash) = content_hash else {
                        gaps.push(format!(
                            "target {target}: {name} is missing contentHash; not evaluated"
                        ));
                        continue;
                    };
                    let key = (name.clone(), resolved.to_string());
                    if conflicted.contains(&key) {
                        continue;
                    }
                    if let Some(position) = pins
                        .iter()
                        .position(|pin| pin.name == *name && pin.version == resolved)
                    {
                        if pins[position].content_hash.as_deref() == Some(content_hash) {
                            continue;
                        }
                        pins.remove(position);
                        conflicted.push(key);
                        gaps.push(format!(
                            "target {target}: {name} {resolved} has conflicting contentHash across targets; not evaluated"
                        ));
                        continue;
                    }
                    pins.push(NuGetPin {
                        name: name.clone(),
                        version: resolved.to_string(),
                        content_hash: Some(content_hash.to_string()),
                    });
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
    version: &PackageVersionId,
    lockfile_hash: Option<&str>,
    archive_hash: Option<&str>,
) -> Result<PackageVersion> {
    let catalog_hash = payload
        .get("packageHash")
        .and_then(|hash| hash.as_str())
        .filter(|hash| !hash.is_empty());
    let lock_payload = lockfile_hash
        .map(strip_sha512_prefix)
        .filter(|hash| !hash.is_empty());
    if let Some(archive) = archive_hash
        .map(strip_sha512_prefix)
        .filter(|hash| !hash.is_empty())
    {
        let catalog = catalog_hash.context(format!(
            "registry response is missing packageHash for {name}@{version}; cannot verify NuGet archive"
        ))?;
        let algorithm = payload
            .get("packageHashAlgorithm")
            .and_then(|algorithm| algorithm.as_str())
            .unwrap_or("sha512");
        if !algorithm.eq_ignore_ascii_case("sha512") {
            anyhow::bail!(
                "unsupported NuGet registry packageHashAlgorithm {algorithm} for {name}@{version}"
            );
        }
        if archive != catalog {
            anyhow::bail!(
                "NuGet archive hash does not match registry packageHash for {name}@{version}"
            );
        }
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
    fn leaf_publication_survives_unreachable_catalog_entry() {
        let leaf = json!({
            "published": "2024-01-01T00:00:00Z",
            "listed": true,
            "packageContent": "https://feed.test/pkg/1.0.0/nupkg"
        });
        let metadata = release_metadata(&leaf, &serde_json::Value::Null);
        assert_eq!(metadata["published"], "2024-01-01T00:00:00Z");
        assert_eq!(metadata["listed"], true);
        assert_eq!(
            metadata["packageContent"],
            "https://feed.test/pkg/1.0.0/nupkg"
        );
        assert!(metadata["packageHash"].is_null());
    }

    #[test]
    fn catalog_values_override_missing_leaf_fields() {
        let leaf = json!({ "packageContent": "https://feed.test/pkg/1.0.0/nupkg" });
        let catalog = json!({
            "published": "2023-03-08T07:42:54.647Z",
            "packageHash": "HASH",
            "packageHashAlgorithm": "SHA512"
        });
        let metadata = release_metadata(&leaf, &catalog);
        assert_eq!(metadata["published"], "2023-03-08T07:42:54.647Z");
        assert_eq!(metadata["packageHash"], "HASH");
        assert_eq!(metadata["packageHashAlgorithm"], "SHA512");
    }

    #[test]
    fn semver2_registration_resource_beats_older_resource_order() {
        let resources = serde_json::json!([
            {
                "@id": "https://feed.test/registration-semver1/",
                "@type": "RegistrationsBaseUrl"
            },
            {
                "@id": "https://feed.test/registration-gz-semver1/",
                "@type": "RegistrationsBaseUrl/3.4.0"
            },
            {
                "@id": "https://feed.test/registration-gz-semver2/",
                "@type": "RegistrationsBaseUrl/3.6.0"
            }
        ]);

        assert_eq!(
            select_registration_resource(resources.as_array().unwrap()),
            Some("https://feed.test/registration-gz-semver2/")
        );
    }

    #[test]
    fn registration_selection_falls_back_when_semver2_resource_is_absent() {
        let resources = serde_json::json!([
            {
                "@id": "https://feed.test/registration-semver1/",
                "@type": "RegistrationsBaseUrl"
            },
            {
                "@id": "https://feed.test/registration-gz-semver1/",
                "@type": "RegistrationsBaseUrl/3.4.0"
            }
        ]);

        assert_eq!(
            select_registration_resource(resources.as_array().unwrap()),
            Some("https://feed.test/registration-gz-semver1/")
        );
    }

    #[test]
    fn registration_leaf_uses_single_version_segment() -> Result<()> {
        let base = reqwest::Url::parse("https://api.nuget.org/v3/registration5-semver1/")?;
        let leaf = registration_leaf_url(&base, "AngleSharp", "1.6.0")?;
        assert_eq!(
            leaf.path(),
            "/v3/registration5-semver1/anglesharp/1.6.0.json"
        );
        Ok(())
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
              "Newtonsoft.Json": { "type": "Direct", "resolved": "13.0.3", "contentHash": "abc" },
              "Serilog": { "type": "Transitive", "resolved": "3.1.1" }
            }
          }
        }"#;
        let (pins, gaps) = parse_packages_lock(content)?;
        assert_eq!(
            pins,
            vec![NuGetPin {
                name: "Newtonsoft.Json".to_string(),
                version: "13.0.3".to_string(),
                content_hash: Some("abc".to_string()),
            }]
        );
        assert_eq!(gaps.len(), 2);
        assert!(gaps[0].contains("RangeOnly"));
        assert!(gaps.iter().any(|gap| gap.contains("contentHash")));
        Ok(())
    }

    #[test]
    fn unsupported_lock_version_is_rejected_even_without_packages() -> Result<()> {
        let error = match parse_packages_lock(r#"{"version":999,"dependencies":{}}"#) {
            Err(error) => error,
            Ok(_) => anyhow::bail!("unsupported empty lock was accepted"),
        };

        assert!(format!("{error:#}").contains("unsupported packages.lock.json version 999"));
        Ok(())
    }

    #[test]
    fn supported_dependency_free_lock_is_valid() -> Result<()> {
        let (pins, gaps) = parse_packages_lock(r#"{"version":1,"dependencies":{}}"#)?;

        assert!(pins.is_empty());
        assert!(gaps.is_empty());
        Ok(())
    }

    #[test]
    fn conflicting_hashes_across_targets_are_a_gap() -> Result<()> {
        let content = r#"{
          "version": 1,
          "dependencies": {
            "net8.0": { "Foo": { "type": "Direct", "resolved": "1.0.0", "contentHash": "h1" } },
            "net8.0/win-x64": { "Foo": { "type": "Direct", "resolved": "1.0.0", "contentHash": "h2" } }
          }
        }"#;
        let (pins, gaps) = parse_packages_lock(content)?;
        assert!(pins.is_empty(), "pins: {pins:?}");
        assert!(
            gaps.iter().any(|gap| gap.contains("conflicting")),
            "gaps: {gaps:?}"
        );
        Ok(())
    }

    #[test]
    fn missing_content_hash_in_one_target_is_a_gap() -> Result<()> {
        let content = r#"{
          "version": 1,
          "dependencies": {
            "net8.0": { "Foo": { "type": "Direct", "resolved": "1.0.0", "contentHash": "h" } },
            "net8.0/win-x64": { "Foo": { "type": "Direct", "resolved": "1.0.0" } }
          }
        }"#;
        let (pins, gaps) = parse_packages_lock(content)?;
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].content_hash.as_deref(), Some("h"));
        assert!(
            gaps.iter().any(|gap| gap.contains("contentHash")),
            "an entry without a hash must be visible even when another target pinned it"
        );
        Ok(())
    }

    #[test]
    fn signed_package_uses_archive_hash_for_registry_check() -> Result<()> {
        let version = PackageVersionId::parse(&Ecosystem::NuGet, "1.0.0")?;
        let payload = json!({
            "published": "2023-03-08T07:42:54.647Z",
            "listed": true,
            "packageHash": "ARCHIVE",
            "packageHashAlgorithm": "SHA512",
            "packageContent": "https://x/y.nupkg"
        });
        let signed = package_version_from_nuget(
            &payload,
            "Example",
            &version,
            Some("LOCK"),
            Some("ARCHIVE"),
        )?;
        assert_eq!(signed.integrity.as_deref(), Some("sha512-LOCK"));
        let prefixed = package_version_from_nuget(
            &payload,
            "Example",
            &version,
            Some("sha512-LOCK"),
            Some("sha512-ARCHIVE"),
        )?;
        assert_eq!(prefixed.integrity.as_deref(), Some("sha512-LOCK"));
        assert!(package_version_from_nuget(
            &payload,
            "Example",
            &version,
            Some("LOCK"),
            Some("TAMPERED"),
        )
        .is_err());
        let missing_archive_hash =
            json!({ "published": "2023-03-08T07:42:54.647Z", "listed": true });
        assert!(package_version_from_nuget(
            &missing_archive_hash,
            "Example",
            &version,
            Some("LOCK"),
            Some("ARCHIVE"),
        )
        .is_err());
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
        let version = PackageVersionId::parse(&Ecosystem::NuGet, "13.0.3").unwrap();
        let pv = package_version_from_nuget(&payload, "Newtonsoft.Json", &version, None, None)?;
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
        let version = PackageVersionId::parse(&Ecosystem::NuGet, "1.0.0").unwrap();
        let pv = package_version_from_nuget(&payload, "Example", &version, None, None)?;
        assert!(pv.published_at.is_none());
        Ok(())
    }
}
