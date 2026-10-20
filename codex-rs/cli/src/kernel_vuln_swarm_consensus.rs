//! Lead identity and peer reproduction consensus for swarm findings.

use anyhow::Context;
use anyhow::Result;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

use super::kernel_vuln_usage::read_finding_outcome;

pub(super) struct ArchivedFinding {
    pub(super) agent_name: String,
    pub(super) path: PathBuf,
    locally_reproduced: bool,
    pub(super) swarm_outcome: String,
    lead_ids: BTreeSet<String>,
    pub(super) title: String,
    root_cause: String,
}

pub(super) fn archived_finding(
    agent_name: &str,
    path: PathBuf,
    fingerprint: &Path,
    report: &Path,
) -> Result<ArchivedFinding> {
    let contents = fs::read_to_string(fingerprint)
        .with_context(|| format!("reading finding fingerprint {}", fingerprint.display()))?;
    let report_contents = fs::read_to_string(report)
        .with_context(|| format!("reading candidate report {}", report.display()))?;
    let outcome = read_finding_outcome(fingerprint).unwrap_or_default();
    let mut lead_ids = fingerprint_lead_ids(&contents);
    if lead_ids.is_empty()
        && let Some(finding_dir) = fingerprint.parent()
        && finding_dir
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            == Some("findings")
        && let Some(lead_id) = finding_dir.file_name().and_then(|name| name.to_str())
    {
        let lead_id = normalize_lead_id(lead_id);
        if !lead_id.is_empty()
            && !matches!(lead_id.as_str(), "lead" | "finding" | "none" | "unknown")
        {
            lead_ids.insert(lead_id);
        }
    }
    Ok(ArchivedFinding {
        agent_name: agent_name.to_string(),
        path,
        locally_reproduced: outcome.eq_ignore_ascii_case("confirmed")
            || report_declares_local_reproduction(&report_contents),
        swarm_outcome: String::new(),
        lead_ids,
        title: fingerprint_field(&contents, "Title"),
        root_cause: fingerprint_field(&contents, "Root cause/invariant"),
    })
}

pub(super) fn apply_peer_confirmation_gate(findings: &mut [ArchivedFinding]) -> Result<()> {
    let canonical_lead_ids = canonical_lead_ids(findings);
    let legacy_claim_lead_ids = legacy_claim_lead_ids(findings, &canonical_lead_ids);
    let mut confirming_agents: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for finding in findings.iter().filter(|finding| finding.locally_reproduced) {
        let key = claim_key(finding, &canonical_lead_ids, &legacy_claim_lead_ids);
        if !key.is_empty() {
            confirming_agents
                .entry(key)
                .or_default()
                .insert(finding.agent_name.clone());
        }
    }
    for finding in findings.iter_mut() {
        let key = claim_key(finding, &canonical_lead_ids, &legacy_claim_lead_ids);
        let peers = confirming_agents.get(&key).map_or(0, BTreeSet::len);
        finding.swarm_outcome = if peers >= 2 {
            "confirmed".to_string()
        } else {
            "plausible".to_string()
        };
        let fingerprint_path = finding.path.join("finding-fingerprint.md");
        let mut fingerprint = fs::read_to_string(&fingerprint_path)
            .with_context(|| format!("reading {}", fingerprint_path.display()))?;
        fingerprint.push_str(&format!(
            "\nSwarm consensus outcome: {}\nDistinct participants with a locally reproduced result for this lead: {peers}.\n",
            finding.swarm_outcome,
        ));
        fs::write(&fingerprint_path, fingerprint)
            .with_context(|| format!("updating {}", fingerprint_path.display()))?;
    }
    Ok(())
}

fn report_declares_local_reproduction(report: &str) -> bool {
    let lines = report.lines().collect::<Vec<_>>();
    for (index, line) in lines.iter().enumerate() {
        let line = line.trim();
        if let Some(heading) = line.strip_prefix("## ")
            && matches!(normalize_claim_text(heading).as_str(), "status" | "outcome")
            && report_status_confirms_local_reproduction(&paragraph_after(&lines, index + 1))
        {
            return true;
        }
        let Some((key, value)) = line
            .trim_start_matches(['-', '*', ' ', '`'])
            .split_once(':')
        else {
            continue;
        };
        let key = normalize_claim_text(key);
        if key.starts_with("swarm") {
            continue;
        }
        let local_field = key.starts_with("local");
        let outcome_field = key == "outcome" || key == "status";
        if !local_field && !outcome_field {
            continue;
        }
        let value = paragraph_from_value(&lines, index, value);
        if (local_field && local_field_confirms_reproduction(&value))
            || (outcome_field && report_status_confirms_local_reproduction(&value))
        {
            return true;
        }
    }
    false
}

fn paragraph_after(lines: &[&str], start: usize) -> String {
    let mut paragraph = String::new();
    for line in lines.iter().skip(start) {
        let line = line.trim();
        if line.is_empty() {
            if !paragraph.is_empty() {
                break;
            }
            continue;
        }
        if line.starts_with('#') {
            break;
        }
        if !paragraph.is_empty() {
            paragraph.push(' ');
        }
        paragraph.push_str(line);
    }
    paragraph
}

fn paragraph_from_value(lines: &[&str], index: usize, value: &str) -> String {
    let mut paragraph = value.trim().to_string();
    for line in lines.iter().skip(index + 1) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            break;
        }
        if line.contains(':') {
            break;
        }
        paragraph.push(' ');
        paragraph.push_str(line);
    }
    paragraph
}

fn local_field_confirms_reproduction(value: &str) -> bool {
    let value = value
        .trim()
        .trim_start_matches(['`', '*', ' '])
        .to_ascii_lowercase();
    !local_reproduction_is_negated(&value)
        && (value.starts_with("confirmed")
            || value.starts_with("positive")
            || value.contains("locally reproduced")
            || value.contains("local reproduction")
            || value.contains("local validation")
            || value.contains("deterministic self-reproduction"))
}

fn report_status_confirms_local_reproduction(value: &str) -> bool {
    let value = value
        .trim()
        .trim_start_matches(['`', '*', ' '])
        .to_ascii_lowercase();
    !local_reproduction_is_negated(&value)
        && (value.starts_with("confirmed")
            || (value.starts_with("plausible")
                && (value.contains("locally reproduced")
                    || value.contains("local reproduction")
                    || value.contains("deterministic self-reproduction")
                    || value.contains("deterministic local reproduction")
                    || value.contains("local validation")
                    || value.contains("positive oracle")
                    || value.contains("is confirmed"))))
}

fn local_reproduction_is_negated(value: &str) -> bool {
    [
        "no local reproduction",
        "local reproduction not run",
        "local reproduction was not",
        "local reproduction has not",
        "not locally reproduced",
        "not reproduced locally",
        "could not reproduce",
        "unable to reproduce",
        "failed to reproduce",
        "local validation failed",
        "local validation not run",
        "not confirmed",
    ]
    .iter()
    .any(|phrase| value.contains(phrase))
}

fn fingerprint_lead_ids(fingerprint: &str) -> BTreeSet<String> {
    let mut lead_ids = BTreeSet::new();
    for line in fingerprint.lines() {
        let Some((key, value)) = line
            .trim()
            .trim_start_matches(['-', '*', ' '])
            .split_once(':')
        else {
            continue;
        };
        let key = normalize_claim_text(key);
        if key != "leadid" && key != "stableleadid" {
            continue;
        }
        for part in value.split(['(', ')', ',', ';']) {
            let part = part
                .trim()
                .strip_prefix("alias ")
                .or_else(|| part.trim().strip_prefix("Alias "))
                .unwrap_or(part.trim());
            let id = part
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .trim_matches(['`', '*', ' ', '.', ':']);
            let id = normalize_lead_id(id);
            if !id.is_empty() && !matches!(id.as_str(), "none" | "n/a" | "unknown") {
                lead_ids.insert(id);
            }
        }
    }
    lead_ids
}

fn normalize_lead_id(value: &str) -> String {
    value
        .trim()
        .trim_matches('`')
        .chars()
        .map(|character| match character {
            '_' => '-',
            character => character.to_ascii_lowercase(),
        })
        .collect()
}

fn normalize_claim_text(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn canonical_lead_ids(findings: &[ArchivedFinding]) -> BTreeMap<String, String> {
    let mut components: Vec<BTreeSet<String>> = Vec::new();
    for finding in findings
        .iter()
        .filter(|finding| !finding.lead_ids.is_empty())
    {
        let mut component = finding.lead_ids.clone();
        let mut index = 0;
        while index < components.len() {
            if !components[index].is_disjoint(&component) {
                component.append(&mut components.remove(index));
                index = 0;
            } else {
                index += 1;
            }
        }
        components.push(component);
    }
    components
        .into_iter()
        .flat_map(|component| {
            let canonical = component.iter().next().cloned().unwrap_or_default();
            component
                .into_iter()
                .map(move |lead_id| (lead_id, canonical.clone()))
        })
        .collect()
}

fn legacy_claim_lead_ids(
    findings: &[ArchivedFinding],
    canonical_lead_ids: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut claims: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for finding in findings
        .iter()
        .filter(|finding| !finding.lead_ids.is_empty())
    {
        let Some(lead_id) = finding
            .lead_ids
            .iter()
            .find_map(|lead_id| canonical_lead_ids.get(lead_id))
        else {
            continue;
        };
        let key = text_claim_key(&finding.title, &finding.root_cause);
        if !key.is_empty() {
            claims.entry(key).or_default().insert(lead_id.clone());
        }
    }
    claims
        .into_iter()
        .filter_map(|(claim, lead_ids)| {
            (lead_ids.len() == 1).then(|| (claim, lead_ids.into_iter().next().unwrap_or_default()))
        })
        .collect()
}

fn claim_key(
    finding: &ArchivedFinding,
    canonical_lead_ids: &BTreeMap<String, String>,
    legacy_claim_lead_ids: &BTreeMap<String, String>,
) -> String {
    if let Some(lead_id) = finding
        .lead_ids
        .iter()
        .find_map(|lead_id| canonical_lead_ids.get(lead_id))
    {
        return format!("lead:{lead_id}");
    }
    let text_claim = text_claim_key(&finding.title, &finding.root_cause);
    legacy_claim_lead_ids
        .get(&text_claim)
        .map_or(text_claim.clone(), |lead_id| format!("lead:{lead_id}"))
}

fn text_claim_key(title: &str, root_cause: &str) -> String {
    let title = normalize_claim_text(title);
    let root_cause = normalize_claim_text(root_cause);
    if title.is_empty() || root_cause.is_empty() {
        String::new()
    } else {
        format!("claim:{title}:{root_cause}")
    }
}

pub(super) fn group_findings(findings: &[ArchivedFinding]) -> Vec<Vec<&ArchivedFinding>> {
    let canonical_lead_ids = canonical_lead_ids(findings);
    let legacy_claim_lead_ids = legacy_claim_lead_ids(findings, &canonical_lead_ids);
    let mut groups: BTreeMap<String, Vec<&ArchivedFinding>> = BTreeMap::new();
    for finding in findings {
        let key = claim_key(finding, &canonical_lead_ids, &legacy_claim_lead_ids);
        let key = if key.is_empty() {
            finding.path.to_string_lossy().into_owned()
        } else {
            key
        };
        groups.entry(key).or_default().push(finding);
    }
    groups.into_values().collect()
}

fn fingerprint_field(fingerprint: &str, wanted: &str) -> String {
    fingerprint
        .lines()
        .find_map(|line| {
            let (key, value) = line
                .trim()
                .trim_start_matches(['-', '*', ' '])
                .split_once(':')?;
            (normalize_claim_text(key) == normalize_claim_text(wanted))
                .then(|| value.trim().trim_matches(['`', '*', ' ']).to_string())
        })
        .unwrap_or_default()
}
