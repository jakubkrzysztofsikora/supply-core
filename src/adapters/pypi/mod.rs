use crate::domain::{Ecosystem, PackageCoordinate, PackageVersion};
use crate::ports::UpstreamPyPiRegistry;
use anyhow::{Context, Result};
use chrono::DateTime;
use semver::Version;

pub struct HttpPyPiRegistry {
    pub base_url: String,
    pub client: reqwest::blocking::Client,
}
impl HttpPyPiRegistry {
    pub fn new() -> Result<Self> {
        Ok(Self {
            base_url: "https://pypi.org".into(),
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        })
    }
}
impl UpstreamPyPiRegistry for HttpPyPiRegistry {
    fn release(&self, package: &str, version: &str) -> Result<serde_json::Value> {
        let url = format!(
            "{}/pypi/{}/{}/json",
            self.base_url.trim_end_matches('/'),
            urlencoding::encode(package),
            urlencoding::encode(version)
        );
        Ok(self.client.get(url).send()?.error_for_status()?.json()?)
    }
}

pub fn normalize_package_name(raw: &str) -> String {
    let mut normalized = String::with_capacity(raw.len());
    let mut last_dash = false;
    for ch in raw.chars() {
        if matches!(ch, '-' | '_' | '.') {
            if !last_dash {
                normalized.push('-');
                last_dash = true;
            }
        } else {
            normalized.push(ch.to_ascii_lowercase());
            last_dash = false;
        }
    }
    normalized
}

pub fn parse_requirements(content: &str) -> (Vec<(String, String)>, Vec<String>) {
    let mut pins = Vec::new();
    let mut gaps = Vec::new();
    for (index, raw_line) in content.lines().enumerate() {
        let number = index + 1;
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("--hash") {
            continue;
        }
        if line.starts_with('-') {
            gaps.push(format!("line {number}: unsupported option '{line}'"));
            continue;
        }
        if line.contains("://") || line.starts_with('.') || line.starts_with('/') {
            gaps.push(format!("line {number}: non-registry requirement"));
            continue;
        }
        let requirement = line.split(';').next().unwrap_or(line).trim();
        let (name_part, version_part) = if let Some(parts) = requirement.split_once("===") {
            parts
        } else if let Some(parts) = requirement.split_once("==") {
            parts
        } else {
            gaps.push(format!("line {number}: not pinned with == ({requirement})"));
            continue;
        };
        let name = normalize_package_name(name_part.trim().split('[').next().unwrap_or("").trim());
        let version = version_part.trim();
        if name.is_empty() || version.is_empty() || version.contains(char::is_whitespace) {
            gaps.push(format!("line {number}: unparseable pin ({requirement})"));
            continue;
        }
        pins.push((name, version.to_string()));
    }
    (pins, gaps)
}

pub fn package_version_from_pypi(
    payload: &serde_json::Value,
    name: &str,
    version: &Version,
) -> Result<PackageVersion> {
    let files = payload
        .get("urls")
        .and_then(|urls| urls.as_array())
        .context("pypi payload has no urls array")?;
    let file = files
        .iter()
        .find(|file| {
            !file
                .get("yanked")
                .and_then(|y| y.as_bool())
                .unwrap_or(false)
        })
        .or_else(|| files.first())
        .context("pypi payload has no files")?;
    let published_at = file
        .get("upload_time_iso_8601")
        .and_then(|t| t.as_str())
        .or_else(|| file.get("upload_time").and_then(|t| t.as_str()))
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&chrono::Utc));
    let integrity = file
        .get("digests")
        .and_then(|digests| digests.get("sha256"))
        .and_then(|hash| hash.as_str())
        .map(|hash| format!("sha256-{hash}"));
    let tarball_url = file
        .get("url")
        .and_then(|url| url.as_str())
        .map(str::to_string);
    Ok(PackageVersion {
        package: PackageCoordinate {
            ecosystem: Ecosystem::PyPi,
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
    fn parses_exact_pins_and_reports_gaps() {
        let content = "\
# comment
requests==2.32.3
Django[argon2]==4.2.11  # pinned
click == 8.1.7
flask>=3.0 ; python_version >= '3.10'
git+https://example.com/x.git
-r extra.txt
--hash=sha256:abc
urllib3===1.26.18
";
        let (pins, gaps) = parse_requirements(content);
        assert_eq!(
            pins,
            vec![
                ("requests".to_string(), "2.32.3".to_string()),
                ("django".to_string(), "4.2.11".to_string()),
                ("click".to_string(), "8.1.7".to_string()),
                ("urllib3".to_string(), "1.26.18".to_string()),
            ]
        );
        assert_eq!(gaps.len(), 3);
    }

    #[test]
    fn builds_package_version_from_pypi_payload() -> Result<()> {
        let payload = json!({ "urls": [
            {"filename":"x.whl","upload_time_iso_8601":"2024-05-29T15:37:47.027275Z","yanked":false,
             "digests":{"sha256":"70761cfe"},"url":"https://files.example/x.whl"}
        ]});
        let version = Version::parse("2.32.3").unwrap();
        let pv = package_version_from_pypi(&payload, "requests", &version)?;
        assert_eq!(pv.package.ecosystem, Ecosystem::PyPi);
        assert_eq!(pv.integrity.as_deref(), Some("sha256-70761cfe"));
        assert_eq!(
            pv.published_at.map(|t| t.to_rfc3339()),
            Some("2024-05-29T15:37:47.027275+00:00".to_string())
        );
        Ok(())
    }
}
