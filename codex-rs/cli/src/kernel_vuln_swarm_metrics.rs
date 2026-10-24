//! Runtime feedback metrics for a frozen swarm norm version.

use super::kernel_vuln_swarm_norms::SwarmEvent;
use super::kernel_vuln_swarm_policy::SwarmNormSet;
use anyhow::Context;
use anyhow::Result;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub(super) fn write_norm_review(
    path: &Path,
    events: &[SwarmEvent],
    norm_set: &SwarmNormSet,
) -> Result<()> {
    let mut actions = BTreeMap::<String, usize>::new();
    let mut agent_actions = BTreeMap::<String, usize>::new();
    let mut no_gain_challenges = 0;
    let mut evidence_progress_challenges = 0;
    let mut challenge_count = 0;
    let mut suspended_leads = 0;
    let mut total_tokens = 0_i64;
    let mut reported_token_sessions = 0;
    let mut elapsed_seconds = 0.0_f64;
    let mut vm_queue_seconds = 0.0_f64;
    let mut vm_execution_seconds = 0.0_f64;
    let mut assigned_discovery = 0;
    let mut assigned_challenges = 0;
    let mut followup_discovery = 0;
    let mut followup_assignments = 0;
    let mut coverage_seen = BTreeSet::new();
    let mut repeated_area_mentions = 0;
    let mut area_mentions = 0;
    let mut first_round_areas = BTreeSet::new();
    let mut first_round_participants = BTreeSet::new();
    for event in events {
        *actions.entry(event.action.clone()).or_default() += 1;
        if event.action == "TASK_ASSIGNED" {
            match event.task.as_deref() {
                Some("explore") => {
                    assigned_discovery += 1;
                    if event.round > 1 {
                        followup_discovery += 1;
                        followup_assignments += 1;
                    }
                }
                Some("challenge") => {
                    assigned_challenges += 1;
                    if event.round > 1 {
                        followup_assignments += 1;
                    }
                }
                _ => {}
            }
        }
        if event.source == "agent_reported" {
            *agent_actions.entry(event.action.clone()).or_default() += 1;
        }
        if event.action == "CHALLENGE" {
            challenge_count += 1;
            match event.information_gain {
                Some(true) => evidence_progress_challenges += 1,
                Some(false) => no_gain_challenges += 1,
                None => {}
            }
        }
        if event.action == "LEAD_SUSPENDED" {
            suspended_leads += 1;
        }
        if event.action == "COVERAGE_RECORDED" {
            for area in &event.code_areas {
                area_mentions += 1;
                if !coverage_seen.insert(area.to_ascii_lowercase()) {
                    repeated_area_mentions += 1;
                }
                if event.round == 1 {
                    first_round_areas.insert(area.to_ascii_lowercase());
                    if let Some(participant) = &event.participant {
                        first_round_participants.insert(participant.clone());
                    }
                }
            }
        }
        if event.action == "SESSION_COMPLETED" {
            if let Some(tokens) = event.total_tokens {
                total_tokens = total_tokens.saturating_add(tokens);
                reported_token_sessions += 1;
            }
            elapsed_seconds += event.elapsed_seconds.unwrap_or_default();
        }
        if let Some(seconds) = event
            .vm_queue_seconds
            .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
        {
            vm_queue_seconds += seconds;
        }
        if let Some(seconds) = event
            .vm_execution_seconds
            .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
        {
            vm_execution_seconds += seconds;
        }
    }
    let discovery_percent = if followup_assignments == 0 {
        0.0
    } else {
        followup_discovery as f64 * 100.0 / followup_assignments as f64
    };
    let new_evidence_per_million_tokens = if total_tokens <= 0 {
        0.0
    } else {
        evidence_progress_challenges as f64 * 1_000_000.0 / total_tokens as f64
    };
    let no_gain_percent = if challenge_count == 0 {
        0.0
    } else {
        no_gain_challenges as f64 * 100.0 / challenge_count as f64
    };
    let repeated_area_percent = if area_mentions == 0 {
        0.0
    } else {
        repeated_area_mentions as f64 * 100.0 / area_mentions as f64
    };
    let mut report = format!(
        "# Swarm norm review\n\n- Norm set version: {}\n- Events recorded: {}\n- Fresh exploration assignments in follow-up rounds: {followup_discovery}/{followup_assignments} ({discovery_percent:.1}%)\n- Fresh exploration assignments across all rounds: {assigned_discovery}\n- Lead challenge assignments: {assigned_challenges}\n- Challenges reporting no information gain: {no_gain_challenges}/{challenge_count} ({no_gain_percent:.1}%)\n- New-evidence challenge events per million participant tokens: {new_evidence_per_million_tokens:.2}\n- Repeated declared source-area mentions: {repeated_area_mentions}/{area_mentions} ({repeated_area_percent:.1}%)\n- First-round declared source-area diversity: {} distinct areas across {} participants\n- Reported participant wall time (sum): {elapsed_seconds:.3} seconds\n- Reported participant tokens: {total_tokens} across {reported_token_sessions} session(s) with token data\n- External VM queue time: {vm_queue_seconds:.3} seconds\n- External VM execution time: {vm_execution_seconds:.3} seconds\n- Norm changes during this run: none (the runtime set stays frozen for reproducible evaluation).\n- External runner verification events: {}\n- Interaction-token share is unavailable from current telemetry. Coverage and information gain are participant-reported and require blind evaluation before use as outcome labels.\n\n",
        norm_set.version,
        events.len(),
        first_round_areas.len(),
        first_round_participants.len(),
        events
            .iter()
            .filter(|event| {
                event.source == "coordinator"
                    && event.evidence_state.as_deref() == Some("RUNNER_VERIFIED")
            })
            .count(),
    );
    report.push_str("## Runtime trace counts\n\n");
    if actions.is_empty() {
        report.push_str("No interaction events were recorded.\n");
    } else {
        for (action, count) in actions {
            report.push_str(&format!("- `{action}`: {count}\n"));
        }
    }
    report.push_str(&format!(
        "\n## Norm feedback for the next version\n\n- Agent-reported action types: {}\n- Lead challenges reporting new information: {evidence_progress_challenges}\n- Lead challenges reporting no information gain: {no_gain_challenges}\n- Leads suspended after repeated no-progress follow-ups: {suspended_leads}\n- Suggested review: compare these counts with independently evaluated finding outcomes and token/time costs before changing N3, N4, N7, or N8. Counts alone do not establish that a norm caused an outcome.\n",
        if agent_actions.is_empty() {
            "none".to_string()
        } else {
            agent_actions
                .into_iter()
                .map(|(action, count)| format!("{action}={count}"))
                .collect::<Vec<_>>()
                .join(", ")
        },
    ));
    fs::write(path, report).with_context(|| format!("writing swarm norm review {}", path.display()))
}
