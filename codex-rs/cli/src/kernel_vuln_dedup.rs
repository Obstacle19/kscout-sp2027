//! Persistent finding summaries used to help later kernel-vulnerability passes
//! avoid rediscovering findings from current and explicitly imported runs.

use anyhow::Context;
use anyhow::Result;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

const MAX_SUMMARY_CHARS: usize = 2_400;
const MAX_IMPORTED_INDEX_ENTRIES: usize = 12;

#[cfg(test)]
pub(super) fn refresh_finding_index(candidates_dir: &Path, index_path: &Path) -> Result<()> {
    refresh_finding_index_with_prior(candidates_dir, index_path, &[])
}

pub(super) fn refresh_finding_index_with_prior(
    candidates_dir: &Path,
    index_path: &Path,
    prior_indexes: &[PathBuf],
) -> Result<()> {
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
         Generated from this output directory and explicitly imported prior indexes. Read entries only to exclude duplicate root causes; they are not discovery evidence.\n",
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
            let finding_keys = finding_keys(&summary, &summary_path);
            if finding_keys.iter().any(|key| seen_findings.contains(key)) {
                continue;
            }
            seen_findings.extend(finding_keys);
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

    let mut imported = Vec::new();
    for prior_index in prior_indexes {
        let contents = fs::read_to_string(prior_index)
            .with_context(|| format!("reading prior finding index {}", prior_index.display()))?;
        let sections = split_index_sections(&contents);
        for (heading, summary) in sections.into_iter().rev() {
            if summary.trim().is_empty() {
                continue;
            }
            let keys = finding_keys(&summary, prior_index);
            if keys.iter().any(|key| seen_findings.contains(key)) {
                continue;
            }
            seen_findings.extend(keys);
            imported.push((prior_index.clone(), heading, summary));
            if imported.len() == MAX_IMPORTED_INDEX_ENTRIES {
                break;
            }
        }
        if imported.len() == MAX_IMPORTED_INDEX_ENTRIES {
            break;
        }
    }
    imported.reverse();
    for (entry_index, (prior_index, heading, summary)) in imported.into_iter().enumerate() {
        let mut chars = summary.chars();
        let excerpt = chars.by_ref().take(MAX_SUMMARY_CHARS).collect::<String>();
        let truncated = chars.next().is_some();
        index.push_str(&format!(
            "\n\n## Prior finding {:03}: {heading}\n\n",
            entry_index + 1
        ));
        index.push_str(&format!("Imported from: {}\n\n", prior_index.display()));
        index.push_str(excerpt.trim());
        if truncated {
            index.push_str("\n\n[Excerpt truncated; consult the prior index source for details.]");
        }
    }

    fs::write(index_path, index)
        .with_context(|| format!("writing finding index {}", index_path.display()))
}

fn finding_keys(summary: &str, path: &Path) -> Vec<String> {
    let mut keys = Vec::new();
    let lead_id = summary_field(summary, "Lead ID");
    let lead_id = normalize(&lead_id);
    if !lead_id.is_empty() && !matches!(lead_id.as_str(), "none" | "unknown" | "na") {
        keys.push(format!("lead:{lead_id}"));
    }
    let title = summary_field(summary, "Title");
    let root_cause = summary_field(summary, "Root cause/invariant");
    let title = normalize(&title);
    let root_cause = normalize(&root_cause);
    if title.is_empty() || root_cause.is_empty() {
        let content = normalize(summary);
        if content.is_empty() {
            keys.push(path.to_string_lossy().into_owned());
        } else {
            keys.push(format!("{}:{content}", path.display()));
        }
    } else {
        keys.push(format!("claim:{title}:{root_cause}"));
    }
    keys
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn split_index_sections(contents: &str) -> Vec<(String, String)> {
    let mut sections = Vec::new();
    let lines = contents.lines().collect::<Vec<_>>();
    let mut index = 0;
    while index + 1 < lines.len() {
        let Some(heading) = lines[index].strip_prefix("## ") else {
            index += 1;
            continue;
        };
        if !lines[index + 1].starts_with("Source:")
            && !lines[index + 1].starts_with("Imported from:")
        {
            index += 1;
            continue;
        }
        index += 1;
        let mut body = String::new();
        while index < lines.len() {
            if lines[index].starts_with("## ")
                && index + 1 < lines.len()
                && (lines[index + 1].starts_with("Source:")
                    || lines[index + 1].starts_with("Imported from:"))
            {
                break;
            }
            body.push_str(lines[index]);
            body.push('\n');
            index += 1;
        }
        sections.push((heading.trim().to_string(), body));
    }
    sections
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
