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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequirementsPin {
    pub name: String,
    pub version: String,
    pub hashes: Vec<String>,
}

pub fn parse_requirements(content: &str) -> (Vec<RequirementsPin>, Vec<String>) {
    let mut pins: Vec<RequirementsPin> = Vec::new();
    let mut gaps = Vec::new();
    let mut pending: Option<usize> = None;
    let mut logical = String::new();
    for (index, raw_line) in content.lines().enumerate() {
        let number = index + 1;
        let mut line = raw_line.split('#').next().unwrap_or("").trim().to_string();
        if line.ends_with('\\') {
            line.pop();
            logical.push_str(line.trim_end());
            logical.push(' ');
            continue;
        }
        if !logical.is_empty() {
            logical.push_str(line.trim());
            line = std::mem::take(&mut logical);
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut hashes = Vec::new();
        let mut requirement_parts = Vec::new();
        let mut unsupported: Option<String> = None;
        for token in line.split_whitespace() {
            if let Some(hash) = token.strip_prefix("--hash=") {
                hashes.push(hash.to_string());
            } else if token.starts_with('-') {
                unsupported = Some(token.to_string());
            } else {
                requirement_parts.push(token);
            }
        }
        if let Some(option) = unsupported {
            gaps.push(format!("line {number}: unsupported option '{option}'"));
            pending = None;
            continue;
        }
        if requirement_parts.is_empty() {
            if let Some(index) = pending {
                pins[index].hashes.extend(hashes);
            }
            continue;
        }
        let requirement = requirement_parts.join(" ");
        if requirement.contains("://")
            || requirement.starts_with('.')
            || requirement.starts_with('/')
        {
            gaps.push(format!("line {number}: non-registry requirement"));
            pending = None;
            continue;
        }
        if requirement.contains(';') {
            gaps.push(format!(
                "line {number}: environment marker not evaluated ({requirement})"
            ));
            pending = None;
            continue;
        }
        let (name_part, version_part) = if let Some(parts) = requirement.split_once("===") {
            parts
        } else if let Some(parts) = requirement.split_once("==") {
            parts
        } else {
            gaps.push(format!("line {number}: not pinned with == ({requirement})"));
            pending = None;
            continue;
        };
        let name = normalize_package_name(name_part.trim().split('[').next().unwrap_or("").trim());
        let version = version_part.trim();
        if name.is_empty() || version.is_empty() || version.contains(char::is_whitespace) {
            gaps.push(format!("line {number}: unparseable pin ({requirement})"));
            pending = None;
            continue;
        }
        pins.push(RequirementsPin {
            name,
            version: version.to_string(),
            hashes,
        });
        pending = Some(pins.len() - 1);
    }
    if !logical.trim().is_empty() {
        gaps.push(format!(
            "end of file: unterminated line continuation ({})",
            logical.trim()
        ));
    }
    (pins, gaps)
}

fn upload_time(file: &serde_json::Value) -> Option<chrono::DateTime<chrono::Utc>> {
    file.get("upload_time_iso_8601")
        .and_then(|t| t.as_str())
        .or_else(|| file.get("upload_time").and_then(|t| t.as_str()))
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
}

pub fn package_version_from_pypi(
    payload: &serde_json::Value,
    name: &str,
    version: &Version,
    expected_hashes: &[String],
) -> Result<PackageVersion> {
    let files = payload
        .get("urls")
        .and_then(|urls| urls.as_array())
        .context("pypi payload has no urls array")?;
    let mut candidates: Vec<&serde_json::Value> = files
        .iter()
        .filter(|file| {
            !file
                .get("yanked")
                .and_then(|y| y.as_bool())
                .unwrap_or(false)
        })
        .collect();
    if candidates.is_empty() {
        candidates = files.iter().collect();
    }
    let file = candidates
        .iter()
        .max_by_key(|file| {
            (
                upload_time(file).map(|t| t.timestamp()).unwrap_or(i64::MIN),
                file.get("filename")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string(),
            )
        })
        .context("pypi payload has no files")?;
    let sha256 = file
        .get("digests")
        .and_then(|digests| digests.get("sha256"))
        .and_then(|hash| hash.as_str());
    if !expected_hashes.is_empty() {
        let mut digests = Vec::new();
        for expected in expected_hashes {
            let Some((algorithm, digest)) = expected.split_once(':') else {
                anyhow::bail!("malformed requirements hash for {name}@{version}");
            };
            if !algorithm.eq_ignore_ascii_case("sha256") {
                anyhow::bail!(
                    "unsupported requirements hash algorithm '{algorithm}' for {name}@{version}"
                );
            }
            digests.push(digest.to_string());
        }
        let Some(hex) = sha256 else {
            anyhow::bail!("no sha256 digest for {name}@{version} while requirements pin hashes");
        };
        if !digests.iter().any(|digest| digest == hex) {
            anyhow::bail!("requirements hash mismatch for {name}@{version}");
        }
    }
    let integrity = sha256.map(|hash| format!("sha256-{hash}"));
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
        published_at: upload_time(file),
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
numpy==1.26.4 ; python_version < '3.13'
git+https://example.com/x.git
-r extra.txt
--hash=sha256:abc
urllib3===1.26.18
";
        let (pins, gaps) = parse_requirements(content);
        assert_eq!(
            pins,
            vec![
                pin("requests", "2.32.3"),
                pin("django", "4.2.11"),
                pin("click", "8.1.7"),
                pin("urllib3", "1.26.18"),
            ]
        );
        assert_eq!(gaps.len(), 4);
        assert!(gaps.iter().any(|gap| gap.contains("marker")));
    }

    fn pin(name: &str, version: &str) -> RequirementsPin {
        RequirementsPin {
            name: name.to_string(),
            version: version.to_string(),
            hashes: vec![],
        }
    }

    #[test]
    fn parses_requirement_hashes_across_continuations() {
        let content = "requests==2.32.3 \\\n    --hash=sha256:aaaa \\\n    --hash=sha256:bbbb\nclick==8.1.7\n--hash=sha256:cccc\n";
        let (pins, gaps) = parse_requirements(content);
        assert!(gaps.is_empty(), "unexpected gaps: {gaps:?}");
        assert_eq!(
            pins,
            vec![
                RequirementsPin {
                    name: "requests".to_string(),
                    version: "2.32.3".to_string(),
                    hashes: vec!["sha256:aaaa".to_string(), "sha256:bbbb".to_string()],
                },
                RequirementsPin {
                    name: "click".to_string(),
                    version: "8.1.7".to_string(),
                    hashes: vec!["sha256:cccc".to_string()],
                },
            ]
        );
    }

    #[test]
    fn selects_newest_artifact_and_validates_hashes() -> Result<()> {
        let payload = json!({ "urls": [
            {"filename":"old.tar.gz","upload_time_iso_8601":"2023-01-01T00:00:00Z","yanked":false,
             "digests":{"sha256":"1111"},"url":"https://files.example/old.tar.gz"},
            {"filename":"new.whl","upload_time_iso_8601":"2026-09-11T00:00:00Z","yanked":false,
             "digests":{"sha256":"bbbb"},"url":"https://files.example/new.whl"},
            {"filename":"yanked.whl","upload_time_iso_8601":"2026-09-12T00:00:00Z","yanked":true,
             "digests":{"sha256":"cccc"},"url":"https://files.example/yanked.whl"}
        ]});
        let version = Version::parse("2.32.3").unwrap();
        let pv = package_version_from_pypi(&payload, "requests", &version, &[])?;
        assert_eq!(
            pv.published_at.map(|t| t.to_rfc3339()),
            Some("2026-09-11T00:00:00+00:00".to_string()),
            "newest non-yanked artifact must drive the age check"
        );
        assert_eq!(pv.integrity.as_deref(), Some("sha256-bbbb"));

        let matching = vec!["sha256:bbbb".to_string()];
        package_version_from_pypi(&payload, "requests", &version, &matching)?;
        let any_of = vec!["sha256:aaaa".to_string(), "sha256:bbbb".to_string()];
        package_version_from_pypi(&payload, "requests", &version, &any_of)?;
        let mismatched = vec!["sha256:dddd".to_string()];
        assert!(package_version_from_pypi(&payload, "requests", &version, &mismatched).is_err());
        let unsupported = vec!["sha512:eeee".to_string()];
        let error = package_version_from_pypi(&payload, "requests", &version, &unsupported)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("unsupported"),
            "non-sha256 hashes must be rejected explicitly, got: {error}"
        );
        Ok(())
    }

    #[test]
    fn unterminated_continuation_is_a_gap() {
        let (pins, gaps) = parse_requirements("requests==2.32.3 \\\n");
        assert!(pins.is_empty());
        assert!(
            gaps.iter().any(|gap| gap.contains("unterminated")),
            "truncated files must surface a gap, got: {gaps:?}"
        );
    }

    #[test]
    fn builds_package_version_from_pypi_payload() -> Result<()> {
        let payload = json!({ "urls": [
            {"filename":"x.whl","upload_time_iso_8601":"2024-05-29T15:37:47.027275Z","yanked":false,
             "digests":{"sha256":"70761cfe"},"url":"https://files.example/x.whl"}
        ]});
        let version = Version::parse("2.32.3").unwrap();
        let pv = package_version_from_pypi(&payload, "requests", &version, &[])?;
        assert_eq!(pv.package.ecosystem, Ecosystem::PyPi);
        assert_eq!(pv.integrity.as_deref(), Some("sha256-70761cfe"));
        assert_eq!(
            pv.published_at.map(|t| t.to_rfc3339()),
            Some("2024-05-29T15:37:47.027275+00:00".to_string())
        );
        Ok(())
    }
}
