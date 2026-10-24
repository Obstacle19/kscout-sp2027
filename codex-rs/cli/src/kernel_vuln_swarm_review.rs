//! Offline, evidence-linked reportability and security review for swarm leads.

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewInput {
    schema_version: u32,
    candidate_dir: PathBuf,
    reviewer_id: String,
    independently_reviewed: bool,
    reviewer_blinded_to_architecture: bool,
    assessments: Vec<LeadAssessment>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LeadAssessment {
    lead_id: String,
    reportability: String,
    root_cause_reviewed: bool,
    reproduction_reviewed: bool,
    security_confirmation: String,
    security_impact_class: String,
    security_boundary: Option<String>,
    evidence_refs: Vec<String>,
    review_notes: String,
}

pub(super) fn apply_assessment(input_path: &Path) -> Result<(PathBuf, usize)> {
    let contents = fs::read_to_string(input_path)
        .with_context(|| format!("reading swarm assessment {}", input_path.display()))?;
    let input: ReviewInput = serde_json::from_str(&contents)
        .with_context(|| format!("parsing swarm assessment {}", input_path.display()))?;
    ensure!(
        input.schema_version == 1,
        "unsupported swarm assessment schema"
    );
    ensure!(
        !input.reviewer_id.trim().is_empty(),
        "reviewer_id must not be empty"
    );
    ensure!(
        input.independently_reviewed && input.reviewer_blinded_to_architecture,
        "final assessment requires an independent reviewer blinded to architecture"
    );
    ensure!(
        !input.assessments.is_empty(),
        "assessment must include at least one lead"
    );

    let input_parent = input_path.parent().unwrap_or_else(|| Path::new("."));
    let candidate_dir = if input.candidate_dir.is_absolute() {
        input.candidate_dir.clone()
    } else {
        input_parent.join(&input.candidate_dir)
    };
    let candidate_dir = fs::canonicalize(&candidate_dir)
        .with_context(|| format!("resolving candidate directory {}", candidate_dir.display()))?;
    ensure!(candidate_dir.is_dir(), "candidate_dir is not a directory");
    let index_path = candidate_dir.join("SWARM_INDEX.json");
    let index_contents = fs::read_to_string(&index_path)
        .with_context(|| format!("reading swarm index {}", index_path.display()))?;
    let mut index: Value = serde_json::from_str(&index_contents)
        .with_context(|| format!("parsing swarm index {}", index_path.display()))?;
    let leads = index
        .get_mut("leads")
        .and_then(Value::as_array_mut)
        .context("swarm index does not contain a leads array")?;

    let mut reviewed_ids = BTreeSet::new();
    let mut report_lines = Vec::new();
    for assessment in &input.assessments {
        let normalized_id = normalize_id(&assessment.lead_id);
        ensure!(
            !normalized_id.is_empty(),
            "assessment lead_id must not be empty"
        );
        ensure!(
            reviewed_ids.insert(normalized_id.clone()),
            "assessment repeats lead ID {}",
            assessment.lead_id
        );
        let lead = leads
            .iter_mut()
            .find(|lead| {
                lead.get("lead_id")
                    .and_then(Value::as_str)
                    .is_some_and(|lead_id| normalize_id(lead_id) == normalized_id)
            })
            .with_context(|| {
                format!("lead {} is absent from the swarm index", assessment.lead_id)
            })?;
        validate_assessment(assessment, lead, &candidate_dir)?;
        lead["reportability_review"] = Value::String(assessment.reportability.clone());
        lead["security_confirmation"] = Value::String(assessment.security_confirmation.clone());
        lead["reviewer_assessment"] = serde_json::json!({
            "reviewer_id": input.reviewer_id,
            "independently_reviewed": input.independently_reviewed,
            "reviewer_blinded_to_architecture": input.reviewer_blinded_to_architecture,
            "root_cause_reviewed": assessment.root_cause_reviewed,
            "reproduction_reviewed": assessment.reproduction_reviewed,
            "security_impact_class": assessment.security_impact_class,
            "security_boundary": assessment.security_boundary,
            "evidence_refs": assessment.evidence_refs,
            "review_notes": assessment.review_notes
        });
        report_lines.push(format!(
            "- Lead `{}`: reportability `{}`; security `{}` (`{}`); reviewer `{}`; evidence: {}; {}",
            assessment.lead_id,
            assessment.reportability,
            assessment.security_confirmation,
            assessment.security_impact_class,
            input.reviewer_id,
            assessment.evidence_refs.join(", "),
            assessment.review_notes.replace('\n', " ")
        ));
    }
    index["review_status"] = Value::String("INDEPENDENT_REVIEW_RECORDED".to_string());
    fs::write(
        &index_path,
        serde_json::to_vec_pretty(&index).context("serializing reviewed swarm index")?,
    )
    .with_context(|| format!("updating swarm index {}", index_path.display()))?;

    let review_record = serde_json::json!({
        "schema_version": 1,
        "recorded_at": Utc::now().to_rfc3339(),
        "reviewer_id": input.reviewer_id,
        "independently_reviewed": input.independently_reviewed,
        "reviewer_blinded_to_architecture": input.reviewer_blinded_to_architecture,
        "source_feedback": input_path.file_name().and_then(|name| name.to_str()).unwrap_or("assessment.json"),
        "assessments": input.assessments
    });
    append_review_history(&candidate_dir, review_record)?;
    replace_report_section(&candidate_dir, &report_lines)?;
    update_finding_fingerprints(&candidate_dir, &input.assessments, &input.reviewer_id)?;
    Ok((candidate_dir, report_lines.len()))
}

fn validate_assessment(
    assessment: &LeadAssessment,
    indexed_lead: &Value,
    candidate_dir: &Path,
) -> Result<()> {
    ensure!(
        matches!(
            assessment.reportability.as_str(),
            "REPORTABLE" | "NOT_REPORTABLE" | "UNRESOLVED"
        ),
        "lead {} has an invalid reportability status",
        assessment.lead_id
    );
    ensure!(
        matches!(
            assessment.security_confirmation.as_str(),
            "SECURITY_CONFIRMED" | "NOT_SECURITY_CONFIRMED" | "UNRESOLVED"
        ),
        "lead {} has an invalid security confirmation status",
        assessment.lead_id
    );
    ensure!(
        matches!(
            assessment.security_impact_class.as_str(),
            "security-relevant" | "correctness-only" | "unresolved"
        ),
        "lead {} has an invalid security impact class",
        assessment.lead_id
    );
    let evidence_refs = validate_review_refs(candidate_dir, &assessment.evidence_refs)?;
    ensure!(
        evidence_refs.len() == assessment.evidence_refs.len(),
        "lead {} contains invalid or duplicate evidence references",
        assessment.lead_id
    );
    if assessment.reportability == "REPORTABLE" {
        ensure!(
            assessment.root_cause_reviewed && assessment.reproduction_reviewed,
            "REPORTABLE requires reviewed root cause and reproduction evidence"
        );
        let cross_reproduced = indexed_lead
            .get("evidence_status")
            .and_then(Value::as_str)
            .is_some_and(|status| status == "CROSS_REPRODUCED");
        let runner_verified = indexed_lead
            .get("external_runner_verification")
            .and_then(Value::as_str)
            .is_some_and(|status| status == "RUNNER_VERIFIED");
        let runner_rejected = indexed_lead
            .get("external_runner_verification")
            .and_then(Value::as_str)
            .is_some_and(|status| status == "RUNNER_REJECTED");
        ensure!(
            cross_reproduced || runner_verified,
            "REPORTABLE requires cross-reproduction or independent runner verification"
        );
        ensure!(
            !runner_rejected,
            "REPORTABLE cannot override a clean, evidence-backed RUNNER_REJECTED result"
        );
        ensure!(
            !evidence_refs.is_empty(),
            "REPORTABLE requires evidence references"
        );
    }
    if assessment.security_confirmation == "SECURITY_CONFIRMED" {
        ensure!(
            assessment.reportability == "REPORTABLE",
            "SECURITY_CONFIRMED requires REPORTABLE status"
        );
        ensure!(
            assessment.security_impact_class == "security-relevant",
            "SECURITY_CONFIRMED requires security-relevant impact class"
        );
        ensure!(
            assessment
                .security_boundary
                .as_deref()
                .is_some_and(|boundary| !boundary.trim().is_empty()),
            "SECURITY_CONFIRMED requires a concrete security boundary or protected asset"
        );
        ensure!(
            !evidence_refs.is_empty(),
            "SECURITY_CONFIRMED requires evidence references"
        );
    }
    Ok(())
}

fn validate_review_refs(candidate_dir: &Path, references: &[String]) -> Result<Vec<String>> {
    let mut seen = BTreeSet::new();
    let mut validated = Vec::new();
    for reference in references {
        let relative = Path::new(reference);
        ensure!(
            !relative.is_absolute()
                && !relative.components().any(|component| {
                    matches!(
                        component,
                        Component::ParentDir | Component::RootDir | Component::Prefix(_)
                    )
                }),
            "evidence reference must be relative and stay inside the candidate directory"
        );
        let path = fs::canonicalize(candidate_dir.join(relative))
            .with_context(|| format!("resolving review evidence {reference}"))?;
        ensure!(
            path.starts_with(candidate_dir) && path.is_file(),
            "review evidence must be a file inside the candidate directory: {reference}"
        );
        let normalized = path
            .strip_prefix(candidate_dir)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        ensure!(
            seen.insert(normalized.clone()),
            "duplicate evidence reference {reference}"
        );
        validated.push(normalized);
    }
    Ok(validated)
}

fn append_review_history(candidate_dir: &Path, record: Value) -> Result<()> {
    let path = candidate_dir.join("SWARM_REVIEW.json");
    let mut reviews = if path.is_file() {
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("reading review history {}", path.display()))?;
        let existing: Value = serde_json::from_str(&contents)
            .with_context(|| format!("parsing review history {}", path.display()))?;
        ensure!(
            existing.get("schema_version").and_then(Value::as_u64) == Some(1),
            "unsupported review history schema in {}",
            path.display()
        );
        existing
            .get("reviews")
            .and_then(Value::as_array)
            .cloned()
            .context("review history does not contain a reviews array")?
    } else {
        Vec::new()
    };
    reviews.push(record);
    fs::write(
        &path,
        serde_json::to_vec_pretty(&serde_json::json!({"schema_version": 1, "reviews": reviews}))
            .context("serializing review history")?,
    )
    .with_context(|| format!("writing review history {}", path.display()))
}

fn replace_report_section(candidate_dir: &Path, report_lines: &[String]) -> Result<()> {
    let path = candidate_dir.join("candidate-report.md");
    let mut report = fs::read_to_string(&path)
        .with_context(|| format!("reading candidate report {}", path.display()))?;
    if let Some(start) = report.find("\n## Independent reviewer assessment\n") {
        report.truncate(start);
    }
    report.push_str("\n## Independent reviewer assessment\n\n");
    if report_lines.is_empty() {
        report.push_str("No lead assessments were supplied.\n");
    } else {
        for line in report_lines {
            report.push_str(line);
            report.push('\n');
        }
    }
    fs::write(&path, report)
        .with_context(|| format!("updating candidate report {}", path.display()))
}

fn update_finding_fingerprints(
    candidate_dir: &Path,
    assessments: &[LeadAssessment],
    reviewer_id: &str,
) -> Result<()> {
    let findings_dir = candidate_dir.join("findings");
    if findings_dir.is_dir() {
        for entry in fs::read_dir(&findings_dir)
            .with_context(|| format!("reading finding folders in {}", findings_dir.display()))?
        {
            let entry =
                entry.with_context(|| format!("reading entry in {}", findings_dir.display()))?;
            if !entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
                continue;
            }
            let path = entry.path().join("finding-fingerprint.md");
            let Ok(contents) = fs::read_to_string(&path) else {
                continue;
            };
            let Some(lead_id) = lead_id_from_fingerprint(&contents) else {
                continue;
            };
            let normalized_id = normalize_id(&lead_id);
            let Some(assessment) = assessments
                .iter()
                .find(|assessment| normalize_id(&assessment.lead_id) == normalized_id)
            else {
                continue;
            };
            fs::write(&path, set_review_lines(&contents, assessment, reviewer_id))
                .with_context(|| format!("updating reviewed fingerprint {}", path.display()))?;
        }
    }

    let path = candidate_dir.join("finding-fingerprint.md");
    if let Ok(contents) = fs::read_to_string(&path) {
        let updated = contents.replace(
            "reportability review: NOT_ASSESSED; security confirmation: NOT_ASSESSED.",
            "reportability review: see per-lead statuses in SWARM_INDEX.json; security confirmation: see per-lead statuses in SWARM_INDEX.json.",
        );
        fs::write(&path, updated)
            .with_context(|| format!("updating candidate fingerprint {}", path.display()))?;
    }
    Ok(())
}

fn lead_id_from_fingerprint(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        line.strip_prefix("Lead ID:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn set_review_lines(contents: &str, assessment: &LeadAssessment, reviewer_id: &str) -> String {
    let retained = contents
        .lines()
        .filter(|line| {
            !line.starts_with("Reportability review:")
                && !line.starts_with("Security confirmation:")
                && !line.starts_with("Independent reviewer:")
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "{retained}\nReportability review: {}\nSecurity confirmation: {} ({})\nIndependent reviewer: {}\n",
        assessment.reportability,
        assessment.security_confirmation,
        assessment.security_impact_class,
        reviewer_id
    )
}

fn normalize_id(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}
