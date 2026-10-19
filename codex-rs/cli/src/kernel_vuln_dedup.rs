//! Persistent summaries used to help later kernel-vulnerability passes avoid
//! rediscovering findings from the same output directory.

use anyhow::Context;
use anyhow::Result;
use std::collections::HashSet;
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
    let mut seen_findings = HashSet::new();

    for candidate_dir in candidate_dirs {
        let candidate_name = candidate_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("candidate");

        let mut archived_fingerprints = Vec::new();
        collect_archived_fingerprints(&candidate_dir.join("findings"), &mut archived_fingerprints)?;
        let mut summaries = Vec::new();
        let root_fingerprint = candidate_dir.join("finding-fingerprint.md");
        if !archived_fingerprints.is_empty() {
            summaries = archived_fingerprints;
        } else if root_fingerprint.is_file() {
            summaries.push(root_fingerprint);
        } else {
            for name in ["agent-final.md", "report.md"] {
                let path = candidate_dir.join(name);
                if path.is_file() {
                    summaries.push(path);
                    break;
                }
            }
        }
        for (summary_index, summary_path) in summaries.into_iter().enumerate() {
            let summary = fs::read_to_string(&summary_path)
                .with_context(|| format!("reading candidate summary {}", summary_path.display()))?;
            if summary.trim().is_empty() {
                continue;
            }
            let finding_key = finding_key(&summary, &summary_path);
            if !seen_findings.insert(finding_key) {
                continue;
            }
            let mut chars = summary.chars();
            let excerpt = chars.by_ref().take(MAX_SUMMARY_CHARS).collect::<String>();
            let truncated = chars.next().is_some();
            let label = if summary_index == 0 {
                candidate_name.to_string()
            } else {
                format!("{candidate_name} finding {summary_index:03}")
            };

            index.push_str(&format!("\n\n## {label}\n\n"));
            index.push_str(&format!("Source: {}\n\n", summary_path.display()));
            index.push_str(excerpt.trim());
            if truncated {
                index.push_str("\n\n[Excerpt truncated; read the source artifact for details.]");
            }
        }
    }

    fs::write(index_path, index)
        .with_context(|| format!("writing finding index {}", index_path.display()))
}

fn finding_key(summary: &str, path: &Path) -> String {
    let title = summary_field(summary, "Title");
    let root_cause = summary_field(summary, "Root cause/invariant");
    let normalize = |value: &str| {
        value
            .chars()
            .filter(|character| character.is_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect::<String>()
    };
    let title = normalize(&title);
    let root_cause = normalize(&root_cause);
    if title.is_empty() || root_cause.is_empty() {
        path.to_string_lossy().into_owned()
    } else {
        format!("{title}:{root_cause}")
    }
}

fn summary_field(summary: &str, wanted: &str) -> String {
    summary
        .lines()
        .find_map(|line| {
            let (key, value) = line
                .trim()
                .trim_start_matches(['-', '*', ' '])
                .split_once(':')?;
            key.trim()
                .trim_matches('*')
                .eq_ignore_ascii_case(wanted)
                .then(|| value.trim().to_string())
        })
        .unwrap_or_default()
}

fn collect_archived_fingerprints(root: &Path, paths: &mut Vec<std::path::PathBuf>) -> Result<()> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("reading {}", root.display())),
    };
    for entry in entries {
        let entry = entry.with_context(|| format!("reading entries in {}", root.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("reading file type for {}", entry.path().display()))?;
        if file_type.is_dir() {
            let fingerprint = entry.path().join("finding-fingerprint.md");
            if fingerprint.is_file() {
                paths.push(fingerprint);
            } else {
                collect_archived_fingerprints(&entry.path(), paths)?;
            }
        }
    }
    paths.sort();
    Ok(())
}
