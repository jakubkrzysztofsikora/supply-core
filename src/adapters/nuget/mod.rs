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
    let mut metadata = release_metadata(&leaf_value, &catalog);
    if is_circit && metadata["packageHash"].is_null() {
        if let Some(content) = leaf_value.get("packageContent").and_then(|v| v.as_str()) {
            let content_url =
                reqwest::Url::parse(content).context("invalid NuGet package content URL")?;
            if content_url.host_str() != Some(host) {
                anyhow::bail!("NuGet source redirected across hosts");
            }
            let credential =
                token.context("SUPPLY_NUGET_TOKEN is required for Circit feed metadata")?;
            metadata["feedContentHash"] = serde_json::Value::String(registry_package_hash(
                client,
                &content_url,
                Some(credential),
                trusted_azure_destination,
            )?);
        }
    }
    Ok(metadata)
}

const MAX_PACKAGE_CONTENT_BYTES: u64 = 512 * 1024 * 1024;
const AZURE_BLOB_SUFFIX: &str = ".blob.core.windows.net";

type DestinationPolicy = fn(&reqwest::Url, bool) -> bool;

fn plain_https(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && matches!(url.port(), None | Some(443))
}

fn trusted_azure_destination(url: &reqwest::Url, is_redirect: bool) -> bool {
    plain_https(url)
        && (!is_redirect
            || url
                .host_str()
                .and_then(|host| host.strip_suffix(AZURE_BLOB_SUFFIX))
                .is_some_and(|account| !account.is_empty()))
}

// The redirect target carries a signed SAS URL: reqwest errors embed request URLs, so every
// failure on this path is rebuilt without them.
fn redacted(context: &str, error: reqwest::Error) -> anyhow::Error {
    anyhow::anyhow!("{context}: {}", error.without_url())
}

// Azure Artifacts registration leaves point catalogEntry at a URL that always 404s, so no
// packageHash is attested. Credentials go to the feed host only; the blob redirect is
// followed once, without them, and only to an Azure Blob Storage host.
fn registry_package_hash(
    client: &reqwest::blocking::Client,
    content_url: &reqwest::Url,
    credential: Option<&str>,
    destination_allowed: DestinationPolicy,
) -> Result<String> {
    use base64::Engine as _;
    use sha2::{Digest, Sha512};
    use std::io::Read;

    if !destination_allowed(content_url, false) {
        anyhow::bail!("NuGet package content must be fetched over plain HTTPS");
    }
    let mut request = client.get(content_url.clone());
    if let Some(credential) = credential {
        request = request.basic_auth("AzureDevOps", Some(credential));
    }
    let mut response = request
        .send()
        .map_err(|error| redacted("NuGet package content request failed", error))?;
    if response.status().is_redirection() {
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .context("NuGet package content redirect has no location")?;
        let target = content_url
            .join(location)
            .map_err(|_| anyhow::anyhow!("invalid NuGet package content redirect"))?;
        if !destination_allowed(&target, true) {
            anyhow::bail!("NuGet package content redirect to an untrusted destination");
        }
        response = client
            .get(target)
            .send()
            .map_err(|error| redacted("NuGet package content redirect request failed", error))?;
    }
    let status = response.status();
    if status.is_redirection() {
        anyhow::bail!("NuGet package content redirected more than once");
    }
    if !status.is_success() {
        anyhow::bail!("NuGet package content source returned HTTP {status}");
    }
    let mut reader = response.take(MAX_PACKAGE_CONTENT_BYTES + 1);
    let mut digest = Sha512::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = reader.read(&mut buffer).map_err(|error| {
            anyhow::anyhow!("NuGet package content download failed: {}", error.kind())
        })?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > MAX_PACKAGE_CONTENT_BYTES {
            anyhow::bail!("NuGet package content exceeds {MAX_PACKAGE_CONTENT_BYTES} bytes");
        }
        digest.update(&buffer[..read]);
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(digest.finalize()))
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

    fn http_allowed(_: &reqwest::Url, _: bool) -> bool {
        true
    }

    fn local_feed_azure_redirect(url: &reqwest::Url, is_redirect: bool) -> bool {
        !is_redirect || trusted_azure_destination(url, true)
    }

    fn serve_once(response: Vec<u8>) -> Result<(String, std::thread::JoinHandle<String>)> {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let handle = std::thread::spawn(move || {
            let mut request = String::new();
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0u8; 4096];
                if let Ok(read) = stream.read(&mut buffer) {
                    request = String::from_utf8_lossy(&buffer[..read]).to_lowercase();
                }
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
            request
        });
        Ok((format!("http://{address}/pkg.nupkg"), handle))
    }

    fn ok_response(body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    fn redirect_response(location: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 303 See Other\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes()
    }

    fn plain_client() -> Result<reqwest::blocking::Client> {
        Ok(reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()?)
    }

    #[test]
    fn registry_package_hash_is_sha512_of_served_bytes_without_following_credentials() -> Result<()>
    {
        use base64::Engine as _;
        use sha2::{Digest, Sha512};
        let body = b"nupkg bytes";
        let (blob_url, blob) = serve_once(ok_response(body))?;
        let (feed_url, feed) = serve_once(redirect_response(&blob_url))?;

        let hash = registry_package_hash(
            &plain_client()?,
            &reqwest::Url::parse(&feed_url)?,
            Some("secret-token"),
            http_allowed,
        )?;

        let expected = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(body));
        assert_eq!(hash, expected);
        let feed_request = feed.join().map_err(|_| anyhow::anyhow!("feed thread"))?;
        let blob_request = blob.join().map_err(|_| anyhow::anyhow!("blob thread"))?;
        assert!(feed_request.contains("authorization: basic"));
        assert!(!blob_request.contains("authorization"));
        Ok(())
    }

    #[test]
    fn registry_package_hash_rejects_second_redirect_and_error_status() -> Result<()> {
        let (second_url, second) = serve_once(redirect_response("http://127.0.0.1:1/x"))?;
        let (feed_url, feed) = serve_once(redirect_response(&second_url))?;
        let error = registry_package_hash(
            &plain_client()?,
            &reqwest::Url::parse(&feed_url)?,
            None,
            http_allowed,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("redirected more than once"));
        let _ = feed.join();
        let _ = second.join();

        let (missing_url, missing) = serve_once(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        )?;
        assert!(registry_package_hash(
            &plain_client()?,
            &reqwest::Url::parse(&missing_url)?,
            None,
            http_allowed,
        )
        .is_err());
        let _ = missing.join();
        Ok(())
    }

    #[test]
    fn registry_package_hash_requires_https_by_default() -> Result<()> {
        let error = registry_package_hash(
            &plain_client()?,
            &reqwest::Url::parse("http://feed.test/pkg.nupkg")?,
            None,
            trusted_azure_destination,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("plain HTTPS"));
        Ok(())
    }

    #[test]
    fn azure_destination_policy_pins_redirects_to_blob_storage_hosts() -> Result<()> {
        let allowed = |url: &str, redirect: bool| -> Result<bool> {
            Ok(trusted_azure_destination(
                &reqwest::Url::parse(url)?,
                redirect,
            ))
        };
        assert!(allowed("https://pkgs.dev.azure.com/Circit/x.nupkg", false)?);
        assert!(allowed(
            "https://s83vsblobprodsu6weus72.blob.core.windows.net/b/x.blob?sig=a",
            true
        )?);
        for rejected in [
            "http://s83.blob.core.windows.net/b/x",
            "https://evil.example/b/x",
            "https://blob.core.windows.net.evil.example/b/x",
            "https://evilblob.core.windows.net/b/x",
            "https://blob.core.windows.net/b/x",
            "https://s83.blob.core.windows.net:8443/b/x",
            "https://user:pw@s83.blob.core.windows.net/b/x",
            "https://169.254.169.254/latest/meta-data",
        ] {
            assert!(!allowed(rejected, true)?, "{rejected} must be rejected");
        }
        Ok(())
    }

    #[test]
    fn registry_package_hash_refuses_redirect_to_untrusted_host_without_leaking_signature(
    ) -> Result<()> {
        let (feed_url, feed) = serve_once(redirect_response(
            "https://evil.example/pkg?sig=SENTINEL-SIGNATURE",
        ))?;
        let error = registry_package_hash(
            &plain_client()?,
            &reqwest::Url::parse(&feed_url)?,
            Some("secret-token"),
            local_feed_azure_redirect,
        )
        .unwrap_err();
        let rendered = format!("{error:?} {error:#}");
        assert!(rendered.contains("untrusted destination"));
        assert!(!rendered.contains("SENTINEL-SIGNATURE"));
        assert!(!rendered.contains("secret-token"));
        let _ = feed.join();
        Ok(())
    }

    #[test]
    fn registry_package_hash_errors_do_not_carry_the_signed_blob_url() -> Result<()> {
        let (dropped_url, dropped) = serve_once(Vec::new())?;
        let signed_dropped = format!("{dropped_url}?sig=SENTINEL-SIGNATURE");
        let (feed_url, feed) = serve_once(redirect_response(&signed_dropped))?;
        let error = registry_package_hash(
            &plain_client()?,
            &reqwest::Url::parse(&feed_url)?,
            None,
            http_allowed,
        )
        .unwrap_err();
        let rendered = format!("{error:?} {error:#}");
        assert!(rendered.contains("redirect request failed"));
        assert!(!rendered.contains("SENTINEL-SIGNATURE"), "{rendered}");
        let _ = (feed.join(), dropped.join());

        let (denied_url, denied) = serve_once(
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        )?;
        let (feed_url, feed) = serve_once(redirect_response(&format!(
            "{denied_url}?sig=SENTINEL-SIGNATURE"
        )))?;
        let error = registry_package_hash(
            &plain_client()?,
            &reqwest::Url::parse(&feed_url)?,
            None,
            http_allowed,
        )
        .unwrap_err();
        let rendered = format!("{error:?} {error:#}");
        assert!(rendered.contains("403"));
        assert!(!rendered.contains("SENTINEL-SIGNATURE"), "{rendered}");
        let _ = (feed.join(), denied.join());
        Ok(())
    }
}
