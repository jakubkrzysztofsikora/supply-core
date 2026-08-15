use crate::ports::WorkflowReader;
use anyhow::Result;
use std::{fs, path::Path};
use walkdir::WalkDir;
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
