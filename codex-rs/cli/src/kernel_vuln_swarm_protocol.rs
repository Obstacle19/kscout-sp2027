//! Parsing of the machine-readable peer update contract.

use std::fs;
use std::path::Component;
use std::path::Path;

#[derive(Default)]
pub(super) struct ChallengeUpdate {
    pub(super) assigned_lead_id: Option<String>,
    pub(super) claim_id: Option<String>,
    pub(super) target_claim_id: Option<String>,
    pub(super) disposition: Option<String>,
    pub(super) independent_reproduction: Option<String>,
    pub(super) independent_analysis: bool,
    pub(super) information_gain: Option<bool>,
    pub(super) evidence_refs: Vec<String>,
    pub(super) audit_outcome: Option<String>,
    pub(super) disputed_claim: Option<String>,
    pub(super) falsifiable_check: Option<String>,
    pub(super) explored_areas: Vec<String>,
    pub(super) suggested_task: Option<String>,
}

pub(super) fn read_challenge_update(path: &Path) -> ChallengeUpdate {
    let Ok(update) = fs::read_to_string(path) else {
        return ChallengeUpdate::default();
    };
    let mut parsed = ChallengeUpdate::default();
    for line in update.lines() {
        let Some((key, value)) = line
            .trim()
            .trim_start_matches(['-', '*', ' ', '`'])
            .split_once(':')
        else {
            continue;
        };
        let key = normalize_swarm_field(key);
        let value = value.trim().trim_matches(['`', '*', ' ']);
        match key.as_str() {
            "assignedleadid" => parsed.assigned_lead_id = Some(value.to_string()),
            "claimid" => parsed.claim_id = nonempty_value(value),
            "targetclaimid" => parsed.target_claim_id = nonempty_value(value),
            "leadchallengeddisposition" => {
                parsed.disposition = match value.to_ascii_lowercase().as_str() {
                    value if value.starts_with("upheld") => Some("upheld".to_string()),
                    value if value.starts_with("rejected") => Some("rejected".to_string()),
                    value if value.starts_with("unresolved") => Some("unresolved".to_string()),
                    _ => None,
                };
            }
            "independentreproduction" => {
                parsed.independent_reproduction = match value.to_ascii_lowercase().as_str() {
                    value if value.starts_with("confirmed") => Some("confirmed".to_string()),
                    value if value.starts_with("failed") => Some("failed".to_string()),
                    value if value.starts_with("notrun") => Some("not-run".to_string()),
                    _ => None,
                };
            }
            "independentanalysis" => {
                parsed.independent_analysis = value.to_ascii_lowercase().starts_with("completed");
            }
            "evidenceprogress" => {
                parsed.information_gain = match value.to_ascii_lowercase().as_str() {
                    value if value.starts_with("new") => Some(true),
                    value if value.starts_with("none") => Some(false),
                    _ => None,
                };
            }
            "evidencerefs" => {
                parsed.evidence_refs = value
                    .split([',', ';'])
                    .map(|reference| reference.trim().trim_matches(['`', ' ']))
                    .filter(|reference| {
                        !reference.is_empty() && !reference.eq_ignore_ascii_case("none")
                    })
                    .map(str::to_string)
                    .collect();
            }
            "auditoutcome" => {
                parsed.audit_outcome = match value.to_ascii_lowercase().as_str() {
                    value if value.starts_with("positive") => Some("positive".to_string()),
                    value if value.starts_with("negative") => Some("negative".to_string()),
                    value if value.starts_with("inconclusive") => Some("inconclusive".to_string()),
                    value if value.starts_with("duplicate") => Some("duplicate".to_string()),
                    _ => None,
                };
            }
            "disputedclaim" => {
                parsed.disputed_claim = nonempty_value(value);
            }
            "falsifiablecheck" | "proposedtest" => {
                parsed.falsifiable_check = nonempty_value(value);
            }
            "exploredareas" | "codeareasreviewed" => {
                parsed.explored_areas = value
                    .split([',', ';'])
                    .filter_map(normalize_source_area)
                    .take(32)
                    .collect();
            }
            "suggestedfollowuptask" | "proposednexttask" => {
                parsed.suggested_task =
                    nonempty_value(value).map(|task| task.chars().take(400).collect());
            }
            _ => {}
        }
    }
    parsed
}

fn nonempty_value(value: &str) -> Option<String> {
    (!value.trim().is_empty() && !value.eq_ignore_ascii_case("none")).then(|| value.to_string())
}

fn normalize_source_area(value: &str) -> Option<String> {
    let area = value.trim().trim_matches(['`', '*', ' ']);
    if area.is_empty()
        || area.len() > 256
        || area.starts_with('/')
        || area.split('/').any(|part| part == "..")
    {
        return None;
    }
    Some(area.to_string())
}

pub(super) fn normalize_swarm_field(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

pub(super) fn validate_evidence_refs(
    workspace: &Path,
    references: &[String],
) -> (Vec<String>, Vec<String>) {
    let Ok(workspace) = fs::canonicalize(workspace) else {
        return (Vec::new(), references.to_vec());
    };
    let mut valid = Vec::new();
    let mut invalid = Vec::new();
    for reference in references {
        let relative = Path::new(reference);
        if relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            invalid.push(reference.clone());
            continue;
        }
        let path = workspace.join(relative);
        let Ok(canonical) = fs::canonicalize(&path) else {
            invalid.push(reference.clone());
            continue;
        };
        if !canonical.starts_with(&workspace) || !canonical.is_file() {
            invalid.push(reference.clone());
            continue;
        }
        valid.push(
            canonical
                .strip_prefix(&workspace)
                .unwrap_or(&canonical)
                .to_string_lossy()
                .into_owned(),
        );
    }
    (valid, invalid)
}
