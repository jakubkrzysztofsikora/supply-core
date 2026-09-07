use crate::ports::WorkflowReader;
use anyhow::Result;
use std::{fs, path::Path};
use walkdir::WalkDir;

/// Render findings as Azure DevOps pipeline logging commands. Escape untrusted pipeline
/// content before it can break logging command syntax or inject additional commands.
pub fn pipeline_annotations(report: &crate::application::PipelineScanReport) -> Vec<String> {
    report
        .findings
        .iter()
        .enumerate()
        .filter(|(_, finding)| matches!(finding.status, crate::domain::DecisionStatus::Block))
        .map(|(index, finding)| {
            let location = report.finding_locations.get(index);
            let properties = location.map_or_else(String::new, |reference| {
                let mut properties = format!(";sourcepath={}", escape_property(&reference.file));
                if reference.line > 0 {
                    properties.push_str(&format!(";linenumber={}", reference.line));
                }
                properties
            });
            format!(
                "##vso[task.logissue type=error{properties}]{}",
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
        .replace(']', "%5D")
}

fn escape_property(value: &str) -> String {
    escape_data(value).replace(';', "%3B")
}

pub struct FsAzurePipelineReader;

impl WorkflowReader for FsAzurePipelineReader {
    fn read(&self, root: &Path) -> Result<Vec<(String, String)>> {
        if root.is_file() {
            let ext = root.extension().and_then(|x| x.to_str()).unwrap_or("");
            if matches!(ext, "yml" | "yaml") {
                let rel = root.file_name().unwrap_or_default().to_string_lossy().to_string();
                return Ok(vec![(rel, fs::read_to_string(root)?)]);
            }
            return Ok(vec![]);
        }

        let mut out = vec![];
        let candidate_dirs = [
            root.join("pipelines"),
            root.join(".azure-pipelines"),
            root.join(".pipelines"),
        ];

        let mut found_candidate_dir = false;
        for dir in &candidate_dirs {
            if dir.exists() && dir.is_dir() {
                found_candidate_dir = true;
                collect_yaml_files(dir, root, &mut out)?;
            }
        }

        // Also collect root-level azure-pipelines*.yml / azurepipelines*.yml files
        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if (name.starts_with("azure-pipelines") || name.starts_with("azurepipelines"))
                        && (name.ends_with(".yml") || name.ends_with(".yaml"))
                    {
                        out.push((
                            p.strip_prefix(root).unwrap_or(&p).display().to_string(),
                            fs::read_to_string(&p)?,
                        ));
                    }
                }
            }
        }

        // If no candidate dirs and no root pipeline files were found, walk the root directory directly
        if !found_candidate_dir && out.is_empty() && root.is_dir() {
            collect_yaml_files(root, root, &mut out)?;
        }

        // Sort by path for deterministic scan ordering
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }
}

fn collect_yaml_files(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) -> Result<()> {
    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_str().unwrap_or("");
            !matches!(
                name,
                ".git" | "node_modules" | "target" | "vendor" | "bin" | "obj" | ".idea" | ".vscode"
            )
        })
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let p = entry.path();
        let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
        if matches!(ext, "yml" | "yaml") {
            out.push((
                p.strip_prefix(root).unwrap_or(p).display().to_string(),
                fs::read_to_string(p)?,
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        application::PipelineScanReport,
        domain::{ActionPinKind, Decision, PipelineRefKind, PipelineReference},
    };

    #[test]
    fn annotation_escapes_command_injection_and_properties() {
        let report = PipelineScanReport {
            findings: vec![Decision::block(
                "task@v1\n##vso[injected]",
                None,
                "bad pin\r\n##vso[task.logissue type=error] injected %0A",
            )],
            references: vec![],
            finding_locations: vec![PipelineReference {
                raw: "task@v1".into(),
                file: "pipelines/a;b:c%0A\r\n]test.yml".into(),
                line: 12,
                kind: PipelineRefKind::Task,
                pin_kind: ActionPinKind::TagOrBranch,
            }],
        };
        let annotations = pipeline_annotations(&report);
        assert_eq!(
            annotations,
            vec!["##vso[task.logissue type=error;sourcepath=pipelines/a%3Bb:c%250A%0D%0A%5Dtest.yml;linenumber=12]task@v1%0A##vso[injected%5D: bad pin%0D%0A##vso[task.logissue type=error%5D injected %250A"]
        );
        assert_eq!(annotations[0].lines().count(), 1);
    }

    #[test]
    fn unlocated_findings_still_emit_an_error() {
        let report = PipelineScanReport {
            findings: vec![Decision::block("task", None, "blocked")],
            references: vec![],
            finding_locations: vec![],
        };
        assert_eq!(
            pipeline_annotations(&report),
            vec!["##vso[task.logissue type=error]task: blocked"]
        );
    }

    #[test]
    fn reader_discovers_pipeline_directories() -> Result<()> {
        let root = tempfile::tempdir()?;
        let p_dir = root.path().join("pipelines");
        fs::create_dir_all(&p_dir)?;
        fs::write(p_dir.join("build.yml"), "steps:\n- task: UseNode@1\n")?;
        fs::write(root.path().join("azure-pipelines.yml"), "trigger: none\n")?;

        let reader = FsAzurePipelineReader;
        let files = reader.read(root.path())?;
        assert_eq!(files.len(), 2);
        assert!(files.iter().any(|(path, _)| path == "pipelines/build.yml"));
        assert!(files.iter().any(|(path, _)| path == "azure-pipelines.yml"));
        Ok(())
    }

    #[test]
    fn reader_handles_single_file() -> Result<()> {
        let root = tempfile::tempdir()?;
        let file = root.path().join("my-pipeline.yml");
        fs::write(&file, "steps: []\n")?;

        let reader = FsAzurePipelineReader;
        let files = reader.read(&file)?;
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "my-pipeline.yml");
        Ok(())
    }
}
