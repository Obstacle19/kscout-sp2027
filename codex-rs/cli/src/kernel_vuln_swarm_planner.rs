//! Evidence-gap scheduling for role-free argument rounds in the kernel audit swarm.

use super::kernel_vuln_swarm_consensus::ArchivedFinding;
use super::kernel_vuln_swarm_consensus::LeadTriage;
use super::kernel_vuln_swarm_consensus::SecurityImpactClass;
use super::kernel_vuln_swarm_consensus::triage_leads;
use super::kernel_vuln_swarm_policy::SwarmNormSet;
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

const MAX_CONTEXT_LEADS: usize = 40;
const MAX_CONTEXT_TITLE_CHARS: usize = 120;

#[derive(Default)]
pub(super) struct LeadFollowupState {
    pub(super) rejected_agents: BTreeSet<String>,
    pub(super) evidence_refs: BTreeSet<String>,
    pub(super) attempts: usize,
    pub(super) no_progress_rounds: usize,
    pub(super) total_tokens: i64,
    pub(super) total_elapsed_seconds: f64,
    pub(super) new_evidence_count: usize,
    pub(super) suspended: bool,
    pub(super) blind_challenge_completed: bool,
    pub(super) suggested_task: Option<String>,
}

pub(super) type LeadHistory = BTreeMap<String, LeadFollowupState>;

pub(super) struct FollowupUpdate<'a> {
    pub(super) participant: &'a str,
    pub(super) disposition: Option<&'a str>,
    pub(super) evidence_refs: &'a [String],
    pub(super) information_gain: Option<bool>,
    pub(super) independent_analysis: bool,
    pub(super) suggested_task: Option<&'a str>,
    pub(super) evidence_tokens: i64,
    pub(super) elapsed_seconds: f64,
    pub(super) suspend_after_no_progress: usize,
}

pub(super) struct PeerAssignment {
    pub(super) agent_name: String,
    pub(super) task: PeerTask,
    pub(super) context: String,
}

pub(super) enum PeerTask {
    Discovery,
    Followup {
        lead: LeadTriage,
        blind_challenge: bool,
    },
}

pub(super) fn initial_round(agent_count: usize) -> Vec<PeerAssignment> {
    (1..=agent_count)
        .map(|participant| PeerAssignment {
            agent_name: format!("agent-{participant:02}"),
            task: PeerTask::Discovery,
            context: "Round 1 begins without prior swarm claims. Select and analyze an audit direction independently.".to_string(),
        })
        .collect()
}

pub(super) fn argument_round(
    findings: &[ArchivedFinding],
    history: &LeadHistory,
    prior_outcomes: &[String],
    covered_areas: &[String],
    agent_limit: usize,
    first_participant: usize,
    norm_set: &SwarmNormSet,
) -> Vec<PeerAssignment> {
    let all_leads = triage_leads(findings);
    let mut leads = all_leads
        .iter()
        .filter(|lead| needs_independent_followup(lead, history))
        .cloned()
        .collect::<Vec<_>>();
    leads.sort_by_key(|lead| {
        (
            Reverse(followup_value(lead, history, norm_set)),
            lead.key.clone(),
        )
    });

    let exploration_share = if leads.is_empty() {
        1.0
    } else {
        let scarcity = 1.0 - (leads.len() as f64 / agent_limit.max(1) as f64).min(1.0);
        let stagnation = leads
            .iter()
            .map(|lead| {
                history.get(&lead.key).map_or(0.0, |state| {
                    state.no_progress_rounds as f64
                        / norm_set.resource_policy.suspend_after_no_progress as f64
                })
            })
            .sum::<f64>()
            / leads.len() as f64;
        let adjustment = scarcity.max(stagnation.min(1.0));
        let policy = &norm_set.resource_policy;
        (policy.exploration_min_percent as f64
            + (policy.exploration_max_percent - policy.exploration_min_percent) as f64 * adjustment)
            / 100.0
    };
    let discovery_floor = ((agent_limit as f64 * exploration_share).ceil() as usize).max(1);
    let followup_budget = agent_limit.saturating_sub(discovery_floor);
    let followup_count = followup_budget.min(leads.len());
    let mut assignments = Vec::with_capacity(agent_limit);
    for (offset, lead) in leads.into_iter().take(followup_count).enumerate() {
        let state = history.get(&lead.key);
        let blind_challenge = !state.is_some_and(|state| state.blind_challenge_completed);
        let suggestion = state.and_then(|state| state.suggested_task.as_deref());
        assignments.push(PeerAssignment {
            agent_name: format!("agent-{:02}", first_participant + offset),
            context: followup_context(&lead, blind_challenge, suggestion),
            task: PeerTask::Followup {
                lead,
                blind_challenge,
            },
        });
    }

    let discovery_context = discovery_context(&all_leads, history, prior_outcomes, covered_areas);
    while assignments.len() < agent_limit {
        let participant = first_participant + assignments.len();
        assignments.push(PeerAssignment {
            agent_name: format!("agent-{participant:02}"),
            task: PeerTask::Discovery,
            context: discovery_context.clone(),
        });
    }
    assignments
}

pub(super) fn has_actionable_leads(findings: &[ArchivedFinding], history: &LeadHistory) -> bool {
    triage_leads(findings)
        .iter()
        .any(|lead| needs_independent_followup(lead, history))
}

pub(super) fn update_followup_state(
    history: &mut LeadHistory,
    lead: &LeadTriage,
    update: FollowupUpdate<'_>,
) -> (usize, bool) {
    let state = history.entry(lead.key.clone()).or_default();
    state.attempts += 1;
    if update.independent_analysis {
        state.blind_challenge_completed = true;
    }
    if let Some(suggested_task) = update.suggested_task {
        state.suggested_task = Some(suggested_task.to_string());
    }
    state.total_tokens = state
        .total_tokens
        .saturating_add(update.evidence_tokens.max(0));
    state.total_elapsed_seconds += update.elapsed_seconds.max(0.0);
    let has_new_evidence_ref = update
        .evidence_refs
        .iter()
        .any(|reference| !state.evidence_refs.contains(reference));
    state
        .evidence_refs
        .extend(update.evidence_refs.iter().cloned());
    if update
        .disposition
        .is_some_and(|value| value.eq_ignore_ascii_case("rejected"))
        && !update.evidence_refs.is_empty()
    {
        state.rejected_agents.insert(update.participant.to_string());
    }
    let made_progress = has_new_evidence_ref
        && (update.information_gain == Some(true)
            || update.disposition.is_some_and(|value| {
                value.eq_ignore_ascii_case("upheld") || value.eq_ignore_ascii_case("rejected")
            }));
    if made_progress {
        state.no_progress_rounds = 0;
        state.suspended = false;
        state.new_evidence_count = state.new_evidence_count.saturating_add(1);
    } else {
        state.no_progress_rounds += 1;
        if state.no_progress_rounds >= update.suspend_after_no_progress {
            state.suspended = true;
        }
    }
    (state.no_progress_rounds, state.suspended)
}

fn needs_independent_followup(lead: &LeadTriage, history: &LeadHistory) -> bool {
    let state = history.get(&lead.key);
    if state.is_some_and(|state| state.rejected_agents.len() >= 2 || state.suspended) {
        return false;
    }
    lead.reproduced_participant_count < 2 || lead.security_impact == SecurityImpactClass::Unresolved
}

fn followup_value(lead: &LeadTriage, history: &LeadHistory, norm_set: &SwarmNormSet) -> usize {
    let state = history.get(&lead.key);
    let reproduced_gap = 2usize
        .saturating_sub(lead.reproduced_participant_count)
        .min(2);
    let impact_gap = (lead.security_impact == SecurityImpactClass::Unresolved) as usize;
    let policy = &norm_set.resource_policy;
    let information_value = state.map_or(0, |state| state.new_evidence_count.min(3));
    let benefit = usize::from(lead.security_impact.priority())
        * policy.security_gap_weight as usize
        + reproduced_gap * policy.reproduction_gap_weight as usize
        + impact_gap * policy.security_gap_weight as usize
        + information_value * policy.new_evidence_weight as usize;
    let estimated_cost = state.map_or(1.0, |state| {
        let average_tokens = state.total_tokens as f64 / state.attempts.max(1) as f64;
        let average_elapsed = state.total_elapsed_seconds / state.attempts.max(1) as f64;
        1.0 + (average_tokens / 10_000.0) * policy.token_cost_weight as f64
            + (average_elapsed / 300.0) * policy.elapsed_cost_weight as f64
            + state.no_progress_rounds as f64
    });
    (benefit as f64 * 1000.0 / estimated_cost) as usize
}

fn followup_context(
    lead: &LeadTriage,
    blind_challenge: bool,
    suggested_task: Option<&str>,
) -> String {
    let title = lead
        .title
        .chars()
        .take(MAX_CONTEXT_TITLE_CHARS)
        .collect::<String>();
    if blind_challenge {
        return format!(
            "# Blind lead challenge\n\nLead ID: `{}`\nReported issue title: {title}\n\nIndependently derive the root cause and a falsifiable check from the source before reading the full board or archived peer reports. Save that independent analysis in `blind-analysis.md`, then inspect the existing evidence and update your conclusion. The title is a search hint, not evidence. {}\n",
            lead.lead_id,
            suggested_task.map_or(String::new(), |task| format!(
                "Prior peer task suggestion: {task}"
            )),
        );
    }
    let evidence_paths = lead
        .evidence_paths
        .iter()
        .take(4)
        .map(|path| format!("- `{}`", path.display()))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "# Focused lead context\n\n- Lead ID: `{}`\n- Reported title: {title}\n- Existing participants: {}\n- Independent local reproductions reported: {}\n- Security assessment: {}\n- Relevant evidence archives:\n{}\n\n{}Use these references only for this lead. Preserve disagreements and report any new evidence explicitly.\n",
        lead.lead_id,
        lead.participant_count,
        lead.reproduced_participant_count,
        lead.security_impact.label(),
        if evidence_paths.is_empty() {
            "- No archived evidence path is available yet.".to_string()
        } else {
            evidence_paths
        },
        suggested_task.map_or(String::new(), |task| format!(
            "- Prior peer task suggestion: {task}\n\n"
        )),
    )
}

fn discovery_context(
    leads: &[LeadTriage],
    history: &LeadHistory,
    prior_outcomes: &[String],
    covered_areas: &[String],
) -> String {
    let mut context = String::from(
        "# Compact swarm memory\n\nUse this index to avoid repeating covered root causes. It contains only lead identifiers, short titles, and evidence state; open full evidence only when your source path overlaps a listed lead. A majority opinion is never a reason to discard counterevidence.\n\n",
    );
    for lead in leads.iter().take(MAX_CONTEXT_LEADS) {
        let title = lead
            .title
            .chars()
            .take(MAX_CONTEXT_TITLE_CHARS)
            .collect::<String>();
        let evidence_state = match lead.reproduced_participant_count {
            0 => "candidate",
            1 => "agent-reproduced",
            _ => "cross-reproduced",
        };
        let state = history.get(&lead.key);
        let scheduling_state = state.map_or("active".to_string(), |state| {
            if state.suspended {
                "suspended; unresolved, with evidence retained".to_string()
            } else if state.rejected_agents.len() >= 2 {
                "rejected by two evidence-backed challenges".to_string()
            } else {
                format!(
                    "active; {} evidence-backed rejection(s), {} no-progress follow-up(s)",
                    state.rejected_agents.len(),
                    state.no_progress_rounds
                )
            }
        });
        context.push_str(&format!(
            "- `{}` — {title}; evidence: {evidence_state}; follow-up: {scheduling_state}.\n",
            lead.lead_id
        ));
    }
    if leads.len() > MAX_CONTEXT_LEADS {
        context.push_str(&format!(
            "- {} additional lead(s) are in `SWARM_INDEX.json`.\n",
            leads.len() - MAX_CONTEXT_LEADS
        ));
    }
    if !prior_outcomes.is_empty() {
        context.push_str("\n## Prior negative and inconclusive work\n\n");
        for outcome in prior_outcomes.iter().take(20) {
            context.push_str(&format!("- {outcome}\n"));
        }
        if prior_outcomes.len() > 20 {
            context.push_str(&format!(
                "- {} additional outcome(s) are retained in `SWARM_EVENTS.jsonl`.\n",
                prior_outcomes.len() - 20
            ));
        }
    }
    if !covered_areas.is_empty() {
        context.push_str("\n## Previously explored source areas\n\n");
        for area in covered_areas.iter().rev().take(40) {
            context.push_str(&format!(
                "- `{area}` — choose a different area unless you have a concrete new evidence path.\n"
            ));
        }
    }
    if leads.is_empty() {
        context.push_str("No positive or plausible leads have been archived yet. Explore an unexamined source area.\n");
    }
    context
}
