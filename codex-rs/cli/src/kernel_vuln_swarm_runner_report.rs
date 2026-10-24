//! Apply external verification records to candidate reports and fingerprints.

use super::kernel_vuln_swarm_consensus::ArchivedFinding;
use super::kernel_vuln_swarm_consensus::triage_leads;
use super::kernel_vuln_swarm_runner::VerificationRecord;
use anyhow::Context;
use anyhow::Result;
use std::fs;
use std::path::Path;

pub(super) fn add_verification_to_reports(
    candidate_dir: &Path,
    findings: &[ArchivedFinding],
    records: &[VerificationRecord],
) -> Result<()> {
    for lead in triage_leads(findings) {
        let Some(record) = records
            .iter()
            .find(|record| normalize_id(&record.lead_id) == normalize_id(&lead.lead_id))
        else {
            continue;
        };
        for finding in findings.iter().filter(|finding| {
            !finding.followup_evidence && lead.evidence_paths.contains(&finding.path)
        }) {
            let fingerprint = finding.path.join("finding-fingerprint.md");
            let Ok(mut contents) = fs::read_to_string(&fingerprint) else {
                continue;
            };
            contents = contents.replace(
                "External runner verification: NOT_RUN",
                &format!("External runner verification: {}", record.status),
            );
            contents.push_str(&format!(
                "Verifier: {}\nVerifier detail: {}\n",
                record.verifier.as_deref().unwrap_or("not configured"),
                record.detail
            ));
            fs::write(&fingerprint, contents).with_context(|| {
                format!("updating verifier status in {}", fingerprint.display())
            })?;
        }
    }
    let report_path = candidate_dir.join("candidate-report.md");
    let mut report = fs::read_to_string(&report_path)
        .with_context(|| format!("reading candidate report {}", report_path.display()))?;
    report.push_str("\n\n## Independent runner verification\n\n");
    if records.is_empty() {
        report.push_str("No candidate lead was available to send to the verifier.\n");
    } else {
        for record in records {
            report.push_str(&format!(
                "- Lead `{}`: `{}`; verifier: {}; isolation: {}; clean setup: {}; positive repetitions: {}; negative controls: {}; VM queue: {} s; VM execution: {} s; revision: {}; config SHA-256: {}; evidence: {}; {}\n",
                record.lead_id,
                record.status,
                record.verifier.as_deref().unwrap_or("not configured"),
                record.isolation.as_deref().unwrap_or("unknown"),
                record.clean_setup.map_or("unknown".to_string(), |value| value.to_string()),
                record.positive_repetitions.map_or("unknown".to_string(), |value| value.to_string()),
                record.negative_controls.map_or("unknown".to_string(), |value| value.to_string()),
                record.vm_queue_seconds.map_or("unknown".to_string(), |value| format!("{value:.3}")),
                record.vm_execution_seconds.map_or("unknown".to_string(), |value| format!("{value:.3}")),
                record.kernel_revision.as_deref().unwrap_or("unknown"),
                record.kernel_config_sha256.as_deref().unwrap_or("unknown"),
                if record.evidence_refs.is_empty() { "none".to_string() } else { record.evidence_refs.join(", ") },
                record.detail
            ));
        }
    }
    fs::write(&report_path, report)
        .with_context(|| format!("adding verifier results to {}", report_path.display()))?;

    let fingerprint_path = candidate_dir.join("finding-fingerprint.md");
    let mut fingerprint = fs::read_to_string(&fingerprint_path).with_context(|| {
        format!(
            "reading candidate fingerprint {}",
            fingerprint_path.display()
        )
    })?;
    let top_level = if records
        .iter()
        .any(|record| record.status == "RUNNER_VERIFIED")
    {
        "PARTIAL_OR_FULL_RUNNER_VERIFICATION"
    } else if records.iter().all(|record| record.status == "NOT_RUN") {
        "NOT_RUN"
    } else {
        "NO_LEAD_VERIFIED"
    };
    fingerprint = fingerprint.replace(
        "external runner verification: NOT_RUN",
        &format!("external runner verification: {top_level}"),
    );
    fs::write(&fingerprint_path, fingerprint).with_context(|| {
        format!(
            "updating candidate fingerprint {}",
            fingerprint_path.display()
        )
    })
}

fn normalize_id(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}
