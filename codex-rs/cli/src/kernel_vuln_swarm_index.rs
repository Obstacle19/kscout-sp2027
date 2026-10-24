//! Structured lead state and evidence graph serialization for swarm runs.

use anyhow::Context;
use anyhow::Result;
use std::fs;
use std::path::Path;

use super::kernel_vuln_swarm_consensus::ArchivedFinding;
use super::kernel_vuln_swarm_consensus::SecurityImpactClass;
use super::kernel_vuln_swarm_consensus::triage_leads;
use super::kernel_vuln_swarm_norms::SwarmEvent;
use super::kernel_vuln_swarm_planner::LeadHistory;
use super::kernel_vuln_swarm_runner::VerificationRecord;

pub(super) fn write_swarm_index(
    candidate_dir: &Path,
    findings: &[ArchivedFinding],
    history: &LeadHistory,
    board_version: usize,
    events: &[SwarmEvent],
    norm_version: u32,
    verification_records: &[VerificationRecord],
) -> Result<()> {
    let leads = triage_leads(findings)
        .into_iter()
        .map(|lead| {
            let state = history.get(&lead.key);
            let rejection_count = state.map_or(0, |state| state.rejected_agents.len());
            let scheduling_status = if rejection_count >= 2 {
                "REJECTED"
            } else if state.is_some_and(|state| state.suspended) {
                "SUSPENDED"
            } else if lead.reproduced_participant_count >= 2
                && lead.security_impact != SecurityImpactClass::Unresolved
            {
                "RESOLVED_FOR_SCHEDULING"
            } else {
                "ACTIVE"
            };
            let evidence_status = match lead.reproduced_participant_count {
                0 => "CANDIDATE",
                1 => "AGENT_REPRODUCED",
                _ => "CROSS_REPRODUCED",
            };
            let verification = verification_records
                .iter()
                .find(|record| normalize_lead_id(&record.lead_id) == normalize_lead_id(&lead.lead_id));
            let lead_events = events
                .iter()
                .filter(|event| {
                    event
                        .lead_id
                        .as_deref()
                        .is_some_and(|lead_id| normalize_lead_id(lead_id) == normalize_lead_id(&lead.lead_id))
                })
                .take(256)
                .collect::<Vec<_>>();
            let claim_events = lead_events
                .iter()
                .filter(|event| {
                    event.action == "FINDING_SUBMITTED"
                        || event.source == "agent_reported" && event.action == "CLAIM"
                })
                .map(|event| event.sequence)
                .collect::<Vec<_>>();
            let challenge_edges = lead_events
                .iter()
                .filter(|event| event.action == "CHALLENGE")
                .map(|event| {
                    serde_json::json!({
                        "event_sequence": event.sequence,
                        "participant": event.participant,
                        "target_claim": event.target_claim,
                        "objection": event.objection,
                        "proposed_test": event.proposed_test,
                        "outcome": event.outcome,
                        "evidence_refs": event.evidence_refs,
                        "source": event.source
                    })
                })
                .collect::<Vec<_>>();
            let evidence_events = lead_events
                .iter()
                .filter(|event| !event.evidence_refs.is_empty())
                .map(|event| {
                    serde_json::json!({
                        "event_sequence": event.sequence,
                        "participant": event.participant,
                        "action": event.action,
                        "evidence_refs": event.evidence_refs,
                        "evidence_state": event.evidence_state,
                        "source": event.source
                    })
                })
                .collect::<Vec<_>>();
            let evidence_refs = lead
                .evidence_paths
                .iter()
                .map(|path| {
                    path.strip_prefix(candidate_dir)
                        .unwrap_or(path)
                        .display()
                        .to_string()
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "lead_id": lead.lead_id,
                "group_key": lead.key,
                "title": lead.title,
                "evidence_status": evidence_status,
                "scheduling_status": scheduling_status,
                "security_impact": lead.security_impact.label(),
                "participant_count": lead.participant_count,
                "reported_local_executions": lead.reproduced_participant_count,
                "archived_submissions_with_independent_analysis_before_shared_evidence": lead.independent_analysis_count,
                "followup_attempts": state.map_or(0, |state| state.attempts),
                "consecutive_no_progress_rounds": state.map_or(0, |state| state.no_progress_rounds),
                "evidence_backed_rejections": rejection_count,
                "evidence_refs": evidence_refs,
                "interaction_graph": {
                    "claim_event_sequences": claim_events,
                    "challenge_edges": challenge_edges,
                    "evidence_events": evidence_events
                },
                "external_runner_verification": verification.map_or("NOT_RUN", |record| record.status.as_str()),
                "runner_verification": verification,
                "reportability_review": "NOT_ASSESSED",
                "security_confirmation": "NOT_ASSESSED"
            })
        })
        .collect::<Vec<_>>();
    let non_positive_events = events
        .iter()
        .filter(|event| {
            event.action == "NON_POSITIVE_OUTCOME"
                || event.action == "LEAD_SUSPENDED"
                || (event.action == "CHALLENGE"
                    && matches!(event.outcome.as_deref(), Some("rejected" | "unresolved")))
        })
        .collect::<Vec<_>>();
    let index = serde_json::json!({
        "schema_version": 1,
        "candidate": candidate_dir.file_name().and_then(|name| name.to_str()).unwrap_or("candidate"),
        "board_version": board_version,
        "norm_version": norm_version,
        "event_log": "SWARM_EVENTS.jsonl",
        "leads": leads,
        "negative_inconclusive_and_suspended_events": non_positive_events,
        "external_runner_verification": if verification_records.iter().any(|record| record.status == "RUNNER_VERIFIED") { "PARTIAL_OR_FULL_RUNNER_VERIFICATION" } else if verification_records.iter().all(|record| record.status == "NOT_RUN") { "NOT_RUN" } else { "NO_LEAD_VERIFIED" }
    });
    fs::write(
        candidate_dir.join("SWARM_INDEX.json"),
        serde_json::to_vec_pretty(&index).context("serializing structured swarm index")?,
    )
    .with_context(|| {
        format!(
            "writing structured swarm index in {}",
            candidate_dir.display()
        )
    })
}

fn normalize_lead_id(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}
