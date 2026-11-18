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
        let root_metadata = fs::metadata(root).map_err(|error| {
            anyhow::anyhow!("cannot access scan root {}: {error}", root.display())
        })?;
        if root_metadata.is_file() {
            let ext = root.extension().and_then(|x| x.to_str()).unwrap_or("");
            if matches!(ext, "yml" | "yaml") {
                let rel = root
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                return Ok(vec![(rel, fs::read_to_string(root)?)]);
            }
            return Ok(vec![]);
        }
        if !root_metadata.is_dir() {
            anyhow::bail!("scan root is not a file or directory: {}", root.display());
        }

        let mut out = vec![];
        let candidate_dirs = [
            root.join("pipelines"),
            root.join(".azure-pipelines"),
            root.join(".pipelines"),
        ];

        let mut found_candidate_dir = false;
        for dir in &candidate_dirs {
            match fs::metadata(dir) {
                Ok(metadata) if metadata.is_dir() => {
                    found_candidate_dir = true;
                    collect_yaml_files(dir, root, &mut out)?;
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }

        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let path = entry.path();
            let ext = path.extension().and_then(|x| x.to_str()).unwrap_or("");
            if matches!(ext, "yml" | "yaml") && fs::metadata(&path)?.is_file() {
                push_yaml_file(&path, root, &mut out)?;
            }
        }

        if !found_candidate_dir {
            collect_yaml_files(root, root, &mut out)?;
        }

        out.sort_by(|a, b| a.0.cmp(&b.0));
        out.dedup_by(|left, right| left.0 == right.0);
        Ok(out)
    }
}

fn push_yaml_file(path: &Path, root: &Path, out: &mut Vec<(String, String)>) -> Result<()> {
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string();
    out.push((relative, fs::read_to_string(path)?));
    Ok(())
}

fn collect_yaml_files(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) -> Result<()> {
    for entry in WalkDir::new(dir).into_iter().filter_entry(|e| {
        let name = e.file_name().to_str().unwrap_or("");
        !matches!(
            name,
            ".git" | "node_modules" | "target" | "vendor" | "bin" | "obj" | ".idea" | ".vscode"
        )
    }) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let ext = path.extension().and_then(|x| x.to_str()).unwrap_or("");
        if matches!(ext, "yml" | "yaml") {
            push_yaml_file(path, root, out)?;
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
            files: vec![],
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
            files: vec![],
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
    fn reader_discovers_all_root_yaml_files_with_pipeline_directories() -> Result<()> {
        let root = tempfile::tempdir()?;
        let p_dir = root.path().join("pipelines");
        fs::create_dir_all(&p_dir)?;
        fs::write(p_dir.join("build.yml"), "steps:\n- task: UseNode@1\n")?;
        fs::write(root.path().join("azure-pipelines.yml"), "trigger: none\n")?;
        fs::write(
            root.path().join("ai-orchestrator-ci.yml"),
            "trigger: none\n",
        )?;
        fs::write(root.path().join("ci-config.yaml"), "trigger: none\n")?;

        let reader = FsAzurePipelineReader;
        let files = reader.read(root.path())?;
        assert_eq!(files.len(), 4);
        assert!(files.iter().any(|(path, _)| path == "pipelines/build.yml"));
        assert!(files.iter().any(|(path, _)| path == "azure-pipelines.yml"));
        assert!(files
            .iter()
            .any(|(path, _)| path == "ai-orchestrator-ci.yml"));
        assert!(files.iter().any(|(path, _)| path == "ci-config.yaml"));
        Ok(())
    }
    #[test]
    fn reader_recurses_when_root_yaml_is_unrelated_to_pipelines() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::write(root.path().join("docker-compose.yml"), "services: {}\n")?;
        let nested = root.path().join("ci");
        fs::create_dir_all(&nested)?;
        let content = "steps:\n- checkout: git://External/Repo\n";
        fs::write(nested.join("build.yml"), content)?;

        let files = FsAzurePipelineReader.read(root.path())?;
        assert!(files
            .iter()
            .any(|(path, body)| path == "ci/build.yml" && body == content));
        Ok(())
    }

    #[test]
    fn reader_rejects_a_missing_scan_root() -> Result<()> {
        let root = tempfile::tempdir()?;
        let missing = root.path().join("missing");
        assert!(FsAzurePipelineReader.read(&missing).is_err());
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
