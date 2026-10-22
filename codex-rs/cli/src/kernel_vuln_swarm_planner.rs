//! Evidence-guided staffing for argument rounds in the kernel audit swarm.

use super::kernel_vuln_swarm_consensus::ArchivedFinding;
use super::kernel_vuln_swarm_consensus::LeadTriage;
use super::kernel_vuln_swarm_consensus::SecurityImpactClass;
use super::kernel_vuln_swarm_consensus::triage_leads;
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

pub(super) type LeadRejections = BTreeMap<String, BTreeSet<String>>;

pub(super) struct PeerAssignment {
    pub(super) agent_name: String,
    pub(super) task: PeerTask,
}

pub(super) enum PeerTask {
    Discovery,
    Followup(LeadTriage),
}

pub(super) fn initial_round(agent_count: usize) -> Vec<PeerAssignment> {
    (1..=agent_count)
        .map(|participant| PeerAssignment {
            agent_name: format!("agent-{participant:02}"),
            task: PeerTask::Discovery,
        })
        .collect()
}

pub(super) fn argument_round(
    findings: &[ArchivedFinding],
    rejections: &LeadRejections,
    agent_limit: usize,
    first_participant: usize,
) -> Vec<PeerAssignment> {
    let mut leads = triage_leads(findings)
        .into_iter()
        .filter(|lead| needs_independent_followup(lead, rejections))
        .collect::<Vec<_>>();
    leads.sort_by_key(|lead| {
        (
            Reverse(lead.security_impact.priority()),
            Reverse(lead.reproduced_participant_count),
            Reverse(lead.participant_count),
            lead.key.clone(),
        )
    });

    // Keep one slot for a fresh source search. The remaining slots independently
    // challenge the highest-priority unresolved leads, one peer per lead.
    let lead_slots = agent_limit.saturating_sub(1).min(leads.len());
    let mut assignments = leads
        .into_iter()
        .take(lead_slots)
        .enumerate()
        .map(|(offset, lead)| PeerAssignment {
            agent_name: format!("agent-{:02}", first_participant + offset),
            task: PeerTask::Followup(lead),
        })
        .collect::<Vec<_>>();
    assignments.push(PeerAssignment {
        agent_name: format!("agent-{:02}", first_participant + lead_slots),
        task: PeerTask::Discovery,
    });
    assignments
}

pub(super) fn has_actionable_leads(
    findings: &[ArchivedFinding],
    rejections: &LeadRejections,
) -> bool {
    triage_leads(findings)
        .iter()
        .any(|lead| needs_independent_followup(lead, rejections))
}

fn needs_independent_followup(lead: &LeadTriage, rejections: &LeadRejections) -> bool {
    if rejections.get(&lead.key).map_or(0, BTreeSet::len) >= 2 {
        return false;
    }
    lead.reproduced_participant_count < 2 || lead.security_impact == SecurityImpactClass::Unresolved
}
