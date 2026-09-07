use crate::ports::WorkflowReader;
use anyhow::Result;
use std::{fs, path::Path};
use walkdir::WalkDir;

/// Render findings as GitHub workflow commands. Escape untrusted workflow
/// content before it can become command syntax or start a second command.
pub fn workflow_annotations(report: &crate::application::WorkflowScanReport) -> Vec<String> {
    report
        .findings
        .iter()
        .enumerate()
        .filter(|(_, finding)| matches!(finding.status, crate::domain::DecisionStatus::Block))
        .map(|(index, finding)| {
            let location = report.finding_locations.get(index);
            let properties = location.map_or_else(String::new, |reference| {
                let mut properties = format!(" file={}", escape_property(&reference.file));
                if reference.line > 0 {
                    properties.push_str(&format!(",line={}", reference.line));
                }
                properties
            });
            format!(
                "::error{properties}::{}",
                escape_data(&format!(
                    "{}: {}",
                    finding.package,
                    finding.reasons.join("; ")
                ))
            )
        })
        .collect()
}

fn escape_data(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn escape_property(value: &str) -> String {
    escape_data(value).replace(':', "%3A").replace(',', "%2C")
}

pub struct FsWorkflowReader;
impl WorkflowReader for FsWorkflowReader {
    fn read(&self, root: &Path) -> Result<Vec<(String, String)>> {
        let dir = root.join(".github/workflows");
        if !dir.exists() {
            return Ok(vec![]);
        };
        let mut out = vec![];
        for e in WalkDir::new(&dir)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
        {
            let p = e.path();
            let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
            if matches!(ext, "yml" | "yaml") {
                out.push((
                    p.strip_prefix(root).unwrap_or(p).display().to_string(),
                    fs::read_to_string(p)?,
                ));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        application::WorkflowScanReport,
        domain::{ActionPinKind, Decision, GitHubActionReference},
    };

    #[test]
    fn annotation_escapes_command_injection_and_properties() {
        let report = WorkflowScanReport {
            findings: vec![Decision::block(
                "owner/action@v1\n::warning::injected",
                None,
                "bad pin\r\n::error file=other::injected %0A",
            )],
            references: vec![],
            finding_locations: vec![GitHubActionReference {
                raw: "owner/action@v1".into(),
                file: ".github/workflows/a,b:c%0A\r\n::error::.yml".into(),
                line: 7,
                pin_kind: ActionPinKind::TagOrBranch,
            }],
        };
        let annotations = workflow_annotations(&report);
        assert_eq!(annotations, vec!["::error file=.github/workflows/a%2Cb%3Ac%250A%0D%0A%3A%3Aerror%3A%3A.yml,line=7::owner/action@v1%0A::warning::injected: bad pin%0D%0A::error file=other::injected %250A"]);
        assert_eq!(annotations[0].lines().count(), 1);
    }

    #[test]
    fn annotations_preserve_repeated_action_locations() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::create_dir_all(root.path().join(".github/workflows"))?;
        fs::write(
            root.path().join(".github/workflows/test.yml"),
            "jobs:\n  test:\n    steps:\n      - uses: owner/action@v1\n",
        )?;
        fs::write(
            root.path().join(".github/workflows/other.yml"),
            "jobs:\n  test:\n    steps:\n      - run: echo ok\n      - uses: owner/action@v1\n",
        )?;
        let policy = crate::domain::Policy::default();
        let report = crate::application::GitHubActionsScanner {
            policy: &policy,
            reader: &FsWorkflowReader,
        }
        .scan(root.path())?;
        let annotations = workflow_annotations(&report);
        assert_eq!(annotations.len(), 2);
        assert!(annotations
            .iter()
            .any(|line| line.starts_with("::error file=.github/workflows/test.yml::")));
        assert!(annotations
            .iter()
            .any(|line| line.starts_with("::error file=.github/workflows/other.yml::")));
        assert!(annotations.iter().all(|line| !line.contains(",line=")));
        Ok(())
    }

    #[test]
    fn unlocated_findings_still_emit_an_error() {
        let report = WorkflowScanReport {
            findings: vec![Decision::block("action", None, "blocked")],
            references: vec![],
            finding_locations: vec![],
        };
        assert_eq!(
            workflow_annotations(&report),
            vec!["::error::action: blocked"]
        );
    }
}
