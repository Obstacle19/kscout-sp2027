//! Persistent summaries used to help later kernel-vulnerability passes avoid
//! rediscovering findings from the same output directory.

use anyhow::Context;
use anyhow::Result;
use std::fs;
use std::path::Path;

const MAX_SUMMARY_CHARS: usize = 2_400;

pub(super) fn refresh_finding_index(candidates_dir: &Path, index_path: &Path) -> Result<()> {
    let mut candidate_dirs = Vec::new();
    for entry in fs::read_dir(candidates_dir)
        .with_context(|| format!("reading candidate directory {}", candidates_dir.display()))?
    {
        let entry =
            entry.with_context(|| format!("reading entries in {}", candidates_dir.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("reading file type for {}", entry.path().display()))?;
        if file_type.is_dir()
            && entry
                .file_name()
                .to_string_lossy()
                .starts_with("candidate-")
        {
            candidate_dirs.push(entry.path());
        }
    }
    candidate_dirs.sort_by(|left, right| left.file_name().cmp(&right.file_name()));

    let mut index = String::from(
        "# Candidate finding exclusion index\n\n\
         Generated from candidate artifacts in this output directory. Read these entries only to exclude duplicate root causes; they are not discovery evidence.\n",
    );

    for candidate_dir in candidate_dirs {
        let fingerprint_path = candidate_dir.join("finding-fingerprint.md");
        let final_path = candidate_dir.join("agent-final.md");
        let report_path = candidate_dir.join("report.md");
        let summary_path = if fingerprint_path.is_file() {
            fingerprint_path
        } else if final_path.is_file() {
            final_path
        } else if report_path.is_file() {
            report_path
        } else {
            continue;
        };
        let summary = fs::read_to_string(&summary_path)
            .with_context(|| format!("reading candidate summary {}", summary_path.display()))?;
        if summary.trim().is_empty() {
            continue;
        }

        let mut chars = summary.chars();
        let excerpt = chars.by_ref().take(MAX_SUMMARY_CHARS).collect::<String>();
        let truncated = chars.next().is_some();
        let candidate_name = candidate_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("candidate");

        index.push_str(&format!("\n\n## {candidate_name}\n\n"));
        index.push_str(&format!("Source: {}\n\n", summary_path.display()));
        index.push_str(excerpt.trim());
        if truncated {
            index.push_str("\n\n[Excerpt truncated; read the source artifact for details.]");
        }
    }

    fs::write(index_path, index)
        .with_context(|| format!("writing finding index {}", index_path.display()))
}
