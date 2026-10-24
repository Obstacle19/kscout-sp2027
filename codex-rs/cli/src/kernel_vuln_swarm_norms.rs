//! Versioned collaboration norms and an auditable event stream for kernel swarms.

use super::kernel_vuln_swarm_policy::SwarmNormSet;
use super::kernel_vuln_swarm_protocol::validate_evidence_refs;
use anyhow::Context;
use anyhow::Result;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use std::fs;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::path::Path;

pub(super) const EVENT_SCHEMA_VERSION: u32 = 1;
const MAX_AGENT_EVENTS_PER_SESSION: usize = 256;
const MAX_AGENT_EVENT_LINES_PER_SESSION: usize = 512;
const MAX_AGENT_EVENT_LINE_BYTES: usize = 8 * 1024;
const MAX_EVIDENCE_REFS_PER_EVENT: usize = 32;

#[derive(Clone, Debug, Serialize)]
pub(super) struct SwarmEvent {
    pub(super) schema_version: u32,
    pub(super) sequence: u64,
    pub(super) recorded_at: String,
    pub(super) source: String,
    pub(super) round: usize,
    pub(super) participant: Option<String>,
    pub(super) board_version_seen: usize,
    pub(super) action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) task: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) lead_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) claim_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) target_claim: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) objection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) proposed_test: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) evidence_refs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) code_areas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) evidence_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) independent_execution: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) independent_analysis: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) information_gain: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) elapsed_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) vm_queue_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) vm_execution_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) total_tokens: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) detail: Option<String>,
}

#[derive(Default)]
pub(super) struct EventDraft {
    pub(super) round: usize,
    pub(super) participant: Option<String>,
    pub(super) board_version_seen: usize,
    pub(super) action: String,
    pub(super) task: Option<String>,
    pub(super) lead_id: Option<String>,
    pub(super) claim_id: Option<String>,
    pub(super) target_claim: Option<String>,
    pub(super) objection: Option<String>,
    pub(super) proposed_test: Option<String>,
    pub(super) evidence_refs: Vec<String>,
    pub(super) code_areas: Vec<String>,
    pub(super) outcome: Option<String>,
    pub(super) evidence_state: Option<String>,
    pub(super) independent_execution: Option<bool>,
    pub(super) independent_analysis: Option<bool>,
    pub(super) information_gain: Option<bool>,
    pub(super) elapsed_seconds: Option<f64>,
    pub(super) vm_queue_seconds: Option<f64>,
    pub(super) vm_execution_seconds: Option<f64>,
    pub(super) total_tokens: Option<i64>,
    pub(super) detail: Option<String>,
}

impl EventDraft {
    pub(super) fn new(
        round: usize,
        participant: Option<&str>,
        board_version_seen: usize,
        action: &str,
    ) -> Self {
        Self {
            round,
            participant: participant.map(str::to_string),
            board_version_seen,
            action: action.to_string(),
            ..Self::default()
        }
    }
}

pub(super) struct SwarmEventLog {
    path: std::path::PathBuf,
    next_sequence: u64,
    events: Vec<SwarmEvent>,
}

#[derive(Deserialize)]
struct AgentEventInput {
    schema_version: Option<u32>,
    action: Option<String>,
    board_version_seen: Option<usize>,
    task: Option<String>,
    lead_id: Option<String>,
    claim_id: Option<String>,
    target_claim: Option<String>,
    objection: Option<String>,
    proposed_test: Option<String>,
    evidence_refs: Option<Vec<String>>,
    code_areas: Option<Vec<String>>,
    outcome: Option<String>,
    evidence_state: Option<String>,
    independent_execution: Option<bool>,
    independent_analysis: Option<bool>,
    information_gain: Option<bool>,
    detail: Option<String>,
}

impl SwarmEventLog {
    pub(super) fn create(path: &Path) -> Result<Self> {
        fs::write(path, "")
            .with_context(|| format!("creating swarm event log {}", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            next_sequence: 1,
            events: Vec::new(),
        })
    }

    pub(super) fn append_coordinator(&mut self, draft: EventDraft) -> Result<()> {
        self.append(draft, "coordinator")
    }

    pub(super) fn import_agent_events(
        &mut self,
        path: &Path,
        round: usize,
        participant: &str,
        maximum_board_version: usize,
        assigned_lead_id: Option<&str>,
    ) -> Result<usize> {
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("opening agent event log {}", path.display()));
            }
        };
        let reader = BufReader::new(file);
        let mut imported = 0;
        for (line_number, line) in reader.lines().enumerate() {
            if imported >= MAX_AGENT_EVENTS_PER_SESSION
                || line_number >= MAX_AGENT_EVENT_LINES_PER_SESSION
            {
                break;
            }
            let line =
                line.with_context(|| format!("reading agent event log {}", path.display()))?;
            if line.len() > MAX_AGENT_EVENT_LINE_BYTES {
                continue;
            }
            let Ok(input) = serde_json::from_str::<AgentEventInput>(&line) else {
                continue;
            };
            if input.schema_version != Some(EVENT_SCHEMA_VERSION) {
                continue;
            }
            let Some(action) = input.action.as_deref().and_then(normalize_agent_action) else {
                continue;
            };
            let reported_refs = input
                .evidence_refs
                .unwrap_or_default()
                .into_iter()
                .filter(|reference| !reference.trim().is_empty())
                .take(MAX_EVIDENCE_REFS_PER_EVENT)
                .collect::<Vec<_>>();
            let (evidence_refs, invalid_refs) = validate_evidence_refs(
                path.parent().unwrap_or_else(|| Path::new(".")),
                &reported_refs,
            );
            let mut draft = EventDraft::new(
                round,
                Some(participant),
                input
                    .board_version_seen
                    .unwrap_or(maximum_board_version)
                    .min(maximum_board_version),
                action,
            );
            draft.task = input.task;
            draft.lead_id = input
                .lead_id
                .or_else(|| assigned_lead_id.map(str::to_string));
            draft.claim_id = bounded_text(input.claim_id);
            draft.target_claim = bounded_text(input.target_claim);
            draft.objection = bounded_text(input.objection);
            draft.proposed_test = bounded_text(input.proposed_test);
            draft.evidence_refs = evidence_refs;
            draft.code_areas = input
                .code_areas
                .unwrap_or_default()
                .into_iter()
                .filter_map(normalize_code_area)
                .take(32)
                .collect();
            draft.outcome = input.outcome;
            draft.evidence_state = input.evidence_state.filter(|state| {
                matches!(
                    state.as_str(),
                    "CANDIDATE" | "AGENT_REPRODUCED" | "CROSS_REPRODUCED"
                )
            });
            draft.independent_execution = input.independent_execution;
            draft.independent_analysis = input.independent_analysis;
            draft.information_gain = input.information_gain;
            draft.detail = Some(if invalid_refs.is_empty() {
                input.detail.unwrap_or_else(|| {
                    format!("Imported from {} line {}", path.display(), line_number + 1)
                })
            } else {
                format!(
                    "{}; dropped {} invalid or unavailable evidence reference(s)",
                    input.detail.unwrap_or_else(|| {
                        format!("Imported from {} line {}", path.display(), line_number + 1)
                    }),
                    invalid_refs.len()
                )
            });
            self.append(draft, "agent_reported")?;
            imported += 1;
        }
        Ok(imported)
    }

    pub(super) fn events(&self) -> &[SwarmEvent] {
        &self.events
    }

    fn append(&mut self, draft: EventDraft, source: &str) -> Result<()> {
        let event = SwarmEvent {
            schema_version: EVENT_SCHEMA_VERSION,
            sequence: self.next_sequence,
            recorded_at: Utc::now().to_rfc3339(),
            source: source.to_string(),
            round: draft.round,
            participant: draft.participant,
            board_version_seen: draft.board_version_seen,
            action: draft.action,
            task: draft.task,
            lead_id: draft.lead_id,
            claim_id: draft.claim_id,
            target_claim: draft.target_claim,
            objection: draft.objection,
            proposed_test: draft.proposed_test,
            evidence_refs: draft.evidence_refs,
            code_areas: draft.code_areas,
            outcome: draft.outcome,
            evidence_state: draft.evidence_state,
            independent_execution: draft.independent_execution,
            independent_analysis: draft.independent_analysis,
            information_gain: draft.information_gain,
            elapsed_seconds: draft.elapsed_seconds,
            vm_queue_seconds: draft.vm_queue_seconds,
            vm_execution_seconds: draft.vm_execution_seconds,
            total_tokens: draft.total_tokens,
            detail: draft.detail,
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("opening swarm event log {}", self.path.display()))?;
        serde_json::to_writer(&mut file, &event).context("serializing swarm interaction event")?;
        file.write_all(b"\n")
            .with_context(|| format!("appending swarm event log {}", self.path.display()))?;
        self.next_sequence += 1;
        self.events.push(event);
        Ok(())
    }
}

pub(super) fn write_norm_manifest(path: &Path, norm_set: &SwarmNormSet) -> Result<()> {
    let manifest = serde_json::json!({
        "schema_version": norm_set.schema_version,
        "version": norm_set.version,
        "norm_set": "norm_guided_adaptive_swarm",
        "status": "frozen_runtime_policy",
        "adaptation_policy": "Use blind independent evaluation feedback with --adapt-swarm-norms to write a new version. Never update a version during a measured run.",
        "resource_policy": {
            "exploration_min_percent": norm_set.resource_policy.exploration_min_percent,
            "exploration_max_percent": norm_set.resource_policy.exploration_max_percent,
            "suspend_after_no_progress": norm_set.resource_policy.suspend_after_no_progress,
            "reproduction_gap_weight": norm_set.resource_policy.reproduction_gap_weight,
            "security_gap_weight": norm_set.resource_policy.security_gap_weight,
            "new_evidence_weight": norm_set.resource_policy.new_evidence_weight,
            "token_cost_weight": norm_set.resource_policy.token_cost_weight,
            "elapsed_cost_weight": norm_set.resource_policy.elapsed_cost_weight
        },
        "update_record": norm_set.update_record,
        "rules": [
            {"id": "N1_AUTONOMOUS_CONTRIBUTION", "category": "behavioral", "enforcement": "soft", "trigger": "all tasks", "rule": "Peers may discover, challenge, verify, revise, retract, branch, or pause without a permanent role."},
            {"id": "N2_EVIDENCE_PRIORITY", "category": "behavioral", "enforcement": "hard", "trigger": "evidence classification", "rule": "A peer count cannot establish local reproduction or security impact."},
            {"id": "N3_PRODUCTIVE_CHALLENGE", "category": "behavioral", "enforcement": "soft", "trigger": "lead challenge", "rule": "Name the disputed claim and a falsifiable check."},
            {"id": "N4_INCREMENTAL_CONTRIBUTION", "category": "behavioral", "enforcement": "soft", "trigger": "repeated lead work", "rule": "Report new evidence, a counterexample, or a changed analysis path."},
            {"id": "N5_DISSENT_PRESERVATION", "category": "coordination", "enforcement": "hard", "trigger": "unresolved counterevidence", "rule": "Do not dismiss a lead by majority vote; retain positive and negative evidence."},
            {"id": "N6_INDEPENDENT_VALIDATION", "category": "behavioral", "enforcement": "hard", "trigger": "cross-reproduction", "rule": "Count distinct participant executions separately from independent analysis; external runner verification remains NOT_RUN unless an external runner actually checks it."},
            {"id": "N7_REUSE_NEGATIVE_MEMORY", "category": "coordination", "enforcement": "soft", "trigger": "new task assignment", "rule": "Consult the compact lead and outcome index before repeating covered work."},
            {"id": "N8_ADAPTIVE_SUSPENSION", "category": "resource", "enforcement": "hard", "trigger": format!("{} consecutive follow-ups without evidence progress", norm_set.resource_policy.suspend_after_no_progress), "rule": "Suspend further scheduling while preserving the unresolved lead and its evidence; new archived evidence resets the no-progress streak."}
        ]
    });
    fs::write(
        path,
        serde_json::to_vec_pretty(&manifest).context("serializing swarm norm manifest")?,
    )
    .with_context(|| format!("writing swarm norm manifest {}", path.display()))
}

fn normalize_agent_action(action: &str) -> Option<&'static str> {
    match action.trim().to_ascii_uppercase().as_str() {
        "CLAIM" | "NEW_CLAIM" => Some("CLAIM"),
        "CHALLENGE" => Some("CHALLENGE"),
        "TEST" | "VERIFY" => Some("TEST"),
        "REVISE" => Some("REVISE"),
        "RETRACT" => Some("RETRACT"),
        "EXPLORE" | "BRANCH" => Some("EXPLORE"),
        _ => None,
    }
}

fn normalize_code_area(value: String) -> Option<String> {
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

fn bounded_text(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.chars().take(1_000).collect::<String>())
        .filter(|value| !value.trim().is_empty())
}
