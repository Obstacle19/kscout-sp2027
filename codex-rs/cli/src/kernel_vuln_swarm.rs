//! Round-based peer swarm for autonomous Linux kernel vulnerability research.
//!
//! Every participant starts as an equal researcher. The first round is blind;
//! later rounds receive a shared argument board and may challenge,
//! reproduce, reject, or branch from any earlier lead. There is no finding
//! count limit. Agent count and rounds are bounded by the CLI to control cost.

use super::FINDING_INDEX_FILE_NAME;
use super::RunOptions;
use super::kernel_vuln_cleanup::cleanup_scratch_directory;
use super::kernel_vuln_rule_prompt::render_rule_review_prompt;
use super::kernel_vuln_rules::RuleReview;
use super::kernel_vuln_support::append_log;
use super::kernel_vuln_support::build_child_args;
use super::kernel_vuln_support::format_command_for_file;
use super::kernel_vuln_support::render_prompt;
use super::kernel_vuln_support::run_agent;
use super::kernel_vuln_support::sandbox_name;
use super::kernel_vuln_swarm_consensus::ArchivedFinding;
use super::kernel_vuln_swarm_consensus::SecurityImpactClass;
use super::kernel_vuln_swarm_consensus::archived_finding;
use super::kernel_vuln_swarm_consensus::archived_followup_reproduction;
use super::kernel_vuln_swarm_consensus::classify_peer_evidence;
use super::kernel_vuln_swarm_consensus::group_findings;
use super::kernel_vuln_swarm_consensus::triage_leads;
use super::kernel_vuln_swarm_evaluation::write_evaluation_template;
use super::kernel_vuln_swarm_index::write_swarm_index;
use super::kernel_vuln_swarm_metrics::write_norm_review;
use super::kernel_vuln_swarm_norms::EventDraft;
use super::kernel_vuln_swarm_norms::SwarmEventLog;
use super::kernel_vuln_swarm_norms::write_norm_manifest;
use super::kernel_vuln_swarm_planner::FollowupUpdate;
use super::kernel_vuln_swarm_planner::LeadHistory;
use super::kernel_vuln_swarm_planner::PeerAssignment;
use super::kernel_vuln_swarm_planner::PeerTask;
use super::kernel_vuln_swarm_planner::argument_round;
use super::kernel_vuln_swarm_planner::has_actionable_leads;
use super::kernel_vuln_swarm_planner::initial_round;
use super::kernel_vuln_swarm_planner::update_followup_state;
use super::kernel_vuln_swarm_policy::SwarmNormSet;
use super::kernel_vuln_swarm_protocol::normalize_swarm_field;
use super::kernel_vuln_swarm_protocol::read_challenge_update;
use super::kernel_vuln_swarm_protocol::validate_evidence_refs;
use super::kernel_vuln_swarm_runner::VerifyLeadsRequest;
use super::kernel_vuln_swarm_runner::verify_leads;
use super::kernel_vuln_swarm_runner_report::add_verification_to_reports;
use super::kernel_vuln_usage::CandidateUsageRecord;
use super::kernel_vuln_usage::TokenUsageSummary;
use super::kernel_vuln_usage::aggregate_token_usage;
use super::kernel_vuln_usage::persist_nested_candidate_usage;
use super::kernel_vuln_usage::read_finding_outcome;
use super::kernel_vuln_usage::read_token_usage;
use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use chrono::DateTime;
use chrono::Utc;
use codex_utils_cli::CliConfigOverrides;
use futures::future::join_all;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::time::Instant;

const MAX_BOARD_BYTES: usize = 256 * 1024;
const ROTATING_RESEARCH_LENSES: [&str; 4] = [
    "Trace state, ownership, object lifetime, locking, and cleanup paths.",
    "Trace attacker-controlled input, parser boundaries, arithmetic, and API contracts.",
    "Look for unexpected state transitions, error paths, and interactions across subsystems.",
    "Try to falsify prior claims and independently derive a distinct lead from source and history.",
];

const SWARM_CONTRACT: &str = r#"

## Peer swarm assignment

You are one equal participant in a cooperative kernel audit swarm. There is no
permanent reviewer, no designated lead, and no limit on the number of distinct
findings. Every participant may discover leads, dispute another participant's
reasoning, independently reproduce it, reject it with evidence, or branch into
a new lead. Do not treat consensus as proof; source-level reasoning and a
repeatable userland oracle with a close negative control are required.

Round: {round}/{round_count}. Participant: {agent_name}. Your rotating audit
lens is: {lens}
Task context: `{context_path}`
Frozen norm policy: `{workspace}/SWARM_NORMS.json` (version {norm_version}). Follow the hard rules and report soft-rule omissions in the structured update.
Trace-induced guidance from the frozen version: {induced_guidance}

Shared prior context: {shared_context_hint}. Read your bounded, task-specific
`SWARM_CONTEXT.md` first; open only relevant evidence when your task requires
it. In round 1, work independently before seeing any other participant's
claims. A blind challenge must save a source-based independent analysis in
`blind-analysis.md` before opening the board or archived reports.
You may reject a lead, reproduce it through a clean setup, revise it, or start
a new branch. Record each challenge and its evidence in `peer-arguments.md`.
Do not edit another participant's files or the shared board.

The coordinator assigns later-round sessions from the unresolved leads. If you
receive an assigned Lead ID, investigate that exact lead first: independently
reproduce or falsify it, verify realistic attacker preconditions and the
security boundary involved, and state what evidence would change your view.
Do not assume a reproducible behavior is a security vulnerability. If your task
is fresh discovery, choose an unexamined code area and avoid repeating the
assigned leads.

Your persistent artifact workspace is `{workspace}`. Use your dedicated
temporary scratch directory `{scratch_dir}` for source copies, build trees,
object files, intermediate kernels, VM disks and snapshots, temporary root
filesystems/initramfs images, downloads, and caches. Put complete reports,
finding fingerprints, logs, PoC source, reproduction instructions, and raw
positive/control evidence in the persistent workspace or finding folders.
Your process working directory is scratch; relative temporary outputs go there.
Use the absolute persistent workspace path for reports and evidence.
Keep only final binaries needed to reproduce a finding. Copy and verify every
required artifact outside scratch before finishing; do not leave the only copy
there. Keep report text, logs, and evidence complete; do not shorten or discard
them to save disk space. Do not write the final candidate summary at
`{candidate_dir}`; the coordinator composes that summary.
For every distinct issue you want preserved, create
`findings/<stable-lead-id>/candidate-report.md` and
`findings/<stable-lead-id>/finding-fingerprint.md`, plus its PoC, reproduction
steps, controls, and raw evidence. There is no finding-count cap. Keep separate
root causes in separate folders, and reuse the same stable lead ID when
discussing the same root cause in a later round. Start each finding fingerprint
with machine-readable `Outcome: confirmed|plausible|negative|duplicate` and
`Lead ID: <stable-id>` fields. In the candidate report, label `Local
reproduction:` and `Security impact:` separately. Also include
`Security impact class: security-relevant | correctness-only | unresolved`.
Choose exactly one class value. Use `security-relevant` only when you identify a concrete attacker capability
and security boundary or protected asset; otherwise use `correctness-only` or
`unresolved`. Include the exact lead ID, status, commands, clean setup, oracle,
and control in `peer-arguments.md`.

In each finding fingerprint, `Outcome: confirmed` means this participant has
locally reproduced the behavior with a deterministic positive, a close
negative control, and a clean repeat. Use `plausible` when the behavior itself
has not been reproduced. Do not downgrade a locally reproduced finding merely
because no peer has checked it yet; the coordinator records swarm consensus
separately after grouping participants by stable Lead ID. In the report, assess
security impact separately from reproduction status: a reproducible API or
correctness defect is not automatically a security vulnerability. A participant
may disagree; record the disagreement and leave the security impact unresolved
when the evidence does not resolve it.

At the end, write `SWARM_UPDATE.md` with the exact lead IDs discovered,
challenged, independently confirmed, rejected, unresolved, and any concrete
follow-up task another participant should take. State `Round status: quiescent`
only if no actionable lead or evidence task remains. Do not hide failed
experiments, incomplete work, or uncertainty.
Include `Audit outcome: positive | negative | inconclusive | duplicate` so
negative and incomplete work remains searchable in the event index.

Write one JSON object per line for each meaningful interaction in
`SWARM_EVENTS.jsonl`. Use schema_version 1 and the fields `action` (CLAIM,
CHALLENGE, TEST, REVISE, RETRACT, or EXPLORE), `board_version_seen`, optional
`task`, `lead_id`, `evidence_refs` (workspace-relative artifact paths),
`outcome`, `evidence_state`, `independent_execution`,
`independent_analysis`, `information_gain` (boolean), and `detail`. Events are
your reported actions; the coordinator records them as agent-reported evidence
and preserves the original file. Do not invent evidence references.
Include `code_areas` as relative Linux source paths or named subsystems when the
event concerns a specific area. Use `claim_id` and `target_claim` to connect
claims and challenges; include `objection` and `proposed_test` for challenges.

For a coordinator-assigned challenge, also include these machine-readable lines
in `SWARM_UPDATE.md`:
- `Assigned Lead ID: <stable-id>`
- `Claim ID: <stable-id for this challenge claim>`
- `Target claim ID: <claim being challenged, or none>`
- `Lead challenge disposition: upheld | rejected | unresolved`
- `Independent reproduction: confirmed | failed | not-run`
- `Independent analysis: completed | not-run`
- `Evidence progress: new | none`
- `Evidence refs: <comma-separated artifact paths or none>`
- `Disputed claim: <specific claim or none>`
- `Falsifiable check: <test or source check that could disprove it>`
- `Explored areas: <comma-separated Linux source paths or subsystems>`
- `Suggested follow-up task: <concrete evidence gap for a future peer, or none>`
Use `rejected` only when source tracing or a
controlled experiment falsifies the lead's central claim; otherwise use
`unresolved`. Include an evidence reference for `upheld`, `rejected`, or
`Evidence progress: new`. A failed local reproduction caused by an environment
or setup problem is `unresolved`, not `rejected`. Two distinct peers with
evidence-backed rejections stop challenge scheduling; repeated follow-ups with
no new evidence may suspend a lead without rejecting it.
"#;

pub(super) struct CandidateRunOutcome {
    pub(super) status: Option<ExitStatus>,
    pub(super) error: Option<String>,
    pub(super) child_result: String,
    pub(super) exit_code: Option<i32>,
    pub(super) token_usage: TokenUsageSummary,
}

impl CandidateRunOutcome {
    pub(super) fn from_single_agent(status: ExitStatus, token_usage: TokenUsageSummary) -> Self {
        let child_result = if status.success() {
            "success"
        } else {
            "failure"
        };
        Self {
            exit_code: status.code(),
            status: Some(status),
            error: None,
            child_result: child_result.to_string(),
            token_usage,
        }
    }

    pub(super) fn failed_to_start(error: impl std::fmt::Display) -> Self {
        Self {
            status: None,
            error: Some(format!("{error:#}")),
            child_result: "failed_to_start".to_string(),
            exit_code: None,
            token_usage: unavailable_usage(),
        }
    }
}

struct PreparedSession {
    name: String,
    agent_name: String,
    round: usize,
    board_version_seen: usize,
    blind_challenge: bool,
    workspace: PathBuf,
    scratch_dir: PathBuf,
    prompt: String,
    args: Vec<std::ffi::OsString>,
}

struct SessionResult {
    status: Option<ExitStatus>,
    error: Option<String>,
    usage: CandidateUsageRecord,
}

struct TimedSessionResult {
    result: Result<ExitStatus>,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    elapsed_seconds: f64,
}

pub(super) struct SwarmRunRequest<'a, 'b> {
    pub(super) root_config_overrides: &'a CliConfigOverrides,
    pub(super) run_options: &'a RunOptions<'b>,
    pub(super) candidate_index: u32,
    pub(super) candidate_dir: &'a Path,
    pub(super) executable: &'a Path,
    pub(super) api_key: Option<&'a OsStr>,
    pub(super) run_started_at: &'a str,
    pub(super) focus: Option<&'a str>,
    pub(super) commit: Option<&'a str>,
    pub(super) extra_prompt: Option<&'a str>,
    pub(super) dry_run: bool,
    pub(super) rule_review: Option<&'a RuleReview>,
    pub(super) agent_count: usize,
    pub(super) round_count: usize,
    pub(super) keep_workspace: bool,
    pub(super) norm_set: &'a SwarmNormSet,
    pub(super) verifier: Option<&'a Path>,
}

pub(super) async fn run_candidate(request: SwarmRunRequest<'_, '_>) -> Result<CandidateRunOutcome> {
    if !(2..=16).contains(&request.agent_count) {
        bail!("swarm agent count must be between 2 and 16");
    }
    if !(1..=4).contains(&request.round_count) {
        bail!("swarm round count must be between 1 and 4");
    }

    let candidate_dir = request.candidate_dir;
    let agents_dir = candidate_dir.join("agents");
    fs::create_dir_all(&agents_dir)
        .with_context(|| format!("creating swarm workspace root {}", agents_dir.display()))?;
    fs::write(
        agents_dir.join("README.md"),
        "# Swarm workspaces\n\nEvery agent is a peer. Round 1 starts independently; later rounds receive a bounded, task-specific `SWARM_CONTEXT.md` and are dynamically assigned to evidence gaps or fresh discovery. No reviewer role is assigned. Follow-up sessions use new participant IDs. Each round has isolated persistent artifact workspaces and event/usage logs. A dedicated `scratch/` directory holds temporary builds and images; it is removed after that round's findings are archived unless `--keep-workspace` is set. Reports, logs, PoCs, and reproduction evidence stay in the persistent workspaces.\n",
    )
    .with_context(|| format!("writing swarm guide in {}", agents_dir.display()))?;

    let board_path = candidate_dir.join("SWARM_BOARD.md");
    fs::write(
        &board_path,
        format!(
            "# Swarm argument board\n\nCandidate: candidate-{:03}\n\nRound 1 starts blind and independent. Later round summaries are appended below. Findings are not capped; a claim is not confirmed by consensus alone.\n",
            request.candidate_index
        ),
    )
    .with_context(|| format!("creating swarm board {}", board_path.display()))?;
    write_norm_manifest(&candidate_dir.join("SWARM_NORMS.json"), request.norm_set)?;

    fs::write(
        candidate_dir.join("prompt.md"),
        format!(
            "# Peer swarm audit\n\n`--count 1` schedules one swarm group with up to {} parallel peers per round and up to {} shared-board rounds. The first round discovers independently; later rounds adapt the fresh-exploration share between {}% and {}% based on the actionable lead queue, then allocate remaining sessions by evidence gap. There is no finding count limit, and actual session count may be lower than the maximum. Individual prompts and evidence are in `agents/`.\n\nShared board: {}\nNorm set: SWARM_NORMS.json (version {})\n",
            request.agent_count,
            request.round_count,
            request.norm_set.resource_policy.exploration_min_percent,
            request.norm_set.resource_policy.exploration_max_percent,
            board_path.display(),
            request.norm_set.version
        ),
    )
    .with_context(|| format!("writing swarm prompt in {}", candidate_dir.display()))?;
    fs::write(
        candidate_dir.join("command.txt"),
        "Peer swarm coordinator; commands and exact prompts are recorded per session under agents/round-NN/agent-NN/.\n",
    )
    .with_context(|| format!("writing swarm command manifest in {}", candidate_dir.display()))?;
    let process_log = request.run_options.output_dir.join("PROCESS_LOG.md");
    let maximum_session_count = request.agent_count.saturating_mul(request.round_count);
    if request.dry_run {
        let mut next_participant = 1;
        for round in 1..=request.round_count {
            for _ in 0..request.agent_count {
                let assignment = PeerAssignment {
                    agent_name: format!("agent-{next_participant:02}"),
                    task: PeerTask::Discovery,
                    context: "Dry-run preview. At execution time, runtime evidence determines the task-specific context.".to_string(),
                };
                next_participant += 1;
                let agent_name = &assignment.agent_name;
                let session_name = format!("round-{round:02}-{agent_name}");
                let workspace = agents_dir
                    .join(format!("round-{round:02}"))
                    .join(agent_name);
                prepare_session(
                    &request,
                    &session_name,
                    &assignment,
                    round,
                    &workspace,
                    &board_path,
                )?;
            }
        }
        append_log(
            &process_log,
            &format!(
                "\n#### candidate-{:03} peer swarm dry-run\n\n- Prepared the maximum layout of {maximum_session_count} session prompts and commands, with up to {} parallel peers across {} rounds. Lead-specific follow-ups are selected from runtime evidence; this dry run shows discovery-template prompts for those slots. No child was started.\n",
                request.candidate_index, request.agent_count, request.round_count
            ),
        )?;
        return Ok(CandidateRunOutcome {
            status: None,
            error: None,
            child_result: "dry_run".to_string(),
            exit_code: None,
            token_usage: unavailable_usage(),
        });
    }

    append_log(
        &process_log,
        &format!(
            "\n#### candidate-{:03} peer swarm\n\n- Maximum parallel peers per round: {}\n- Maximum shared-board rounds: {}\n- Maximum possible child sessions: {maximum_session_count}; follow-up rounds are dynamically staffed and may stop early.\n- Fresh-exploration share adapts between {}% and {}% of follow-up sessions using the frozen norm policy.\n- Norm set version: {}; the run uses a frozen policy.\n- Keep per-agent scratch workspaces: {}\n- No permanent reviewer; every participant may discover, argue, reproduce, reject, and branch.\n- Shared argument board: {}\n- Structured interaction log: {}\n",
            request.candidate_index,
            request.agent_count,
            request.round_count,
            request.norm_set.resource_policy.exploration_min_percent,
            request.norm_set.resource_policy.exploration_max_percent,
            request.norm_set.version,
            request.keep_workspace,
            board_path.display(),
            candidate_dir.join("SWARM_EVENTS.jsonl").display()
        ),
    )?;

    let mut all_sessions = Vec::with_capacity(maximum_session_count);
    let findings_dir = candidate_dir.join("findings");
    fs::create_dir_all(&findings_dir)
        .with_context(|| format!("creating finding archive {}", findings_dir.display()))?;
    let mut findings = Vec::new();
    let mut records = Vec::with_capacity(maximum_session_count);
    let mut all_sessions_succeeded = true;
    let mut last_status = None;
    let mut failing_status = None;
    let mut any_spawn_failure = false;
    let mut errors = Vec::new();
    let mut lead_history = LeadHistory::new();
    let mut interaction_log = SwarmEventLog::create(&candidate_dir.join("SWARM_EVENTS.jsonl"))?;
    let mut next_participant = 1;
    let mut completed_round_count = 0;

    for round in 1..=request.round_count {
        let assignments = if round == 1 {
            initial_round(request.agent_count)
        } else {
            let prior_outcomes = interaction_log
                .events()
                .iter()
                .filter(|event| {
                    event.action == "NON_POSITIVE_OUTCOME"
                        || (event.action == "CHALLENGE"
                            && matches!(event.outcome.as_deref(), Some("rejected" | "unresolved")))
                })
                .take(21)
                .map(|event| {
                    format!(
                        "{} {:?} (lead: {}); evidence: {}",
                        event.outcome.as_deref().unwrap_or("unresolved"),
                        event.task.as_deref().unwrap_or("task"),
                        event.lead_id.as_deref().unwrap_or("none"),
                        if event.evidence_refs.is_empty() {
                            "SWARM_UPDATE.md".to_string()
                        } else {
                            event.evidence_refs.join(", ")
                        }
                    )
                })
                .collect::<Vec<_>>();
            let mut covered_area_set = BTreeSet::new();
            let covered_areas = interaction_log
                .events()
                .iter()
                .filter(|event| event.action == "COVERAGE_RECORDED")
                .flat_map(|event| event.code_areas.iter())
                .filter(|area| covered_area_set.insert(area.to_ascii_lowercase()))
                .cloned()
                .collect::<Vec<_>>();
            argument_round(
                &findings,
                &lead_history,
                &prior_outcomes,
                &covered_areas,
                request.agent_count,
                next_participant,
                request.norm_set,
            )
        };
        let sessions = assignments
            .iter()
            .map(|assignment| {
                let agent_name = &assignment.agent_name;
                let session_name = format!("round-{round:02}-{agent_name}");
                let workspace = agents_dir
                    .join(format!("round-{round:02}"))
                    .join(agent_name);
                prepare_session(
                    &request,
                    &session_name,
                    assignment,
                    round,
                    &workspace,
                    &board_path,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        next_participant += assignments.len();
        for (assignment, session) in assignments.iter().zip(&sessions) {
            let (task, lead_id, detail) = match &assignment.task {
                PeerTask::Discovery => ("explore", None, "fresh source discovery".to_string()),
                PeerTask::Followup {
                    lead,
                    blind_challenge,
                } => (
                    "challenge",
                    Some(lead.lead_id.clone()),
                    if *blind_challenge {
                        "blind source-based challenge".to_string()
                    } else {
                        "focused evidence-gap challenge".to_string()
                    },
                ),
            };
            let mut event = EventDraft::new(
                round,
                Some(&assignment.agent_name),
                session.board_version_seen,
                "TASK_ASSIGNED",
            );
            event.task = Some(task.to_string());
            event.lead_id = lead_id;
            event.detail = Some(detail);
            interaction_log.append_coordinator(event)?;
        }
        let task_summary = assignments
            .iter()
            .map(|assignment| match &assignment.task {
                PeerTask::Discovery => format!("{}: fresh discovery", assignment.agent_name),
                PeerTask::Followup {
                    lead,
                    blind_challenge,
                } => {
                    format!(
                        "{}: {} Lead ID {}",
                        assignment.agent_name,
                        if *blind_challenge {
                            "blind challenge"
                        } else {
                            "challenge"
                        },
                        lead.lead_id,
                    )
                }
            })
            .collect::<Vec<_>>()
            .join("; ");

        println!(
            "[kernel-vuln] candidate {:03}: swarm round {round}/{} starting {} peer agents in parallel",
            request.candidate_index,
            request.round_count,
            sessions.len()
        );
        append_log(
            &process_log,
            &format!(
                "\n- Round {round}/{} started; {} agents running in parallel. Tasks: {task_summary}.\n",
                request.round_count,
                sessions.len()
            ),
        )?;

        let round_timer = Instant::now();
        let timed_results = join_all(
            sessions
                .iter()
                .map(|session| run_prepared_session_timed(&request, session)),
        )
        .await;
        let mut round_results = Vec::with_capacity(sessions.len());
        for (session, timed) in sessions.iter().zip(timed_results) {
            let result = complete_session(
                &request,
                session,
                timed.result,
                timed.started_at,
                timed.finished_at,
                timed.elapsed_seconds,
            )?;
            if result.usage.child_result != "success" {
                all_sessions_succeeded = false;
                if result.usage.child_result == "failed_to_start" {
                    any_spawn_failure = true;
                }
                let detail = result.error.clone().unwrap_or_else(|| {
                    format!(
                        "child exited with status {}",
                        result
                            .status
                            .as_ref()
                            .copied()
                            .map(status_label)
                            .unwrap_or_else(|| "unavailable".to_string())
                    )
                });
                errors.push(format!("{}: {detail}", session.name));
            }
            if let Some(status) = result.status {
                if !status.success() && failing_status.is_none() {
                    failing_status = Some(status);
                }
                last_status = Some(status);
            }
            round_results.push(result);
        }
        for (assignment, session) in assignments.iter().zip(&sessions) {
            let assigned_lead_id = match &assignment.task {
                PeerTask::Discovery => None,
                PeerTask::Followup { lead, .. } => Some(lead.lead_id.as_str()),
            };
            interaction_log.import_agent_events(
                &session.workspace.join("SWARM_EVENTS.jsonl"),
                round,
                &session.agent_name,
                session.board_version_seen,
                assigned_lead_id,
            )?;
            let update = read_challenge_update(&session.workspace.join("SWARM_UPDATE.md"));
            if !update.explored_areas.is_empty() {
                let mut event = EventDraft::new(
                    round,
                    Some(&session.agent_name),
                    session.board_version_seen,
                    "COVERAGE_RECORDED",
                );
                event.task = Some(match &assignment.task {
                    PeerTask::Discovery => "explore".to_string(),
                    PeerTask::Followup { .. } => "challenge".to_string(),
                });
                event.lead_id = assigned_lead_id.map(str::to_string);
                event.code_areas = update.explored_areas;
                event.detail = Some(
                    "Source coverage declared in the session update; used as a redundancy hint."
                        .to_string(),
                );
                interaction_log.append_coordinator(event)?;
            }
        }
        for ((assignment, session), result) in assignments.iter().zip(&sessions).zip(&round_results)
        {
            let mut event = EventDraft::new(
                round,
                Some(&session.agent_name),
                session.board_version_seen,
                "SESSION_COMPLETED",
            );
            event.outcome = result
                .usage
                .finding_outcome
                .clone()
                .or_else(|| {
                    read_challenge_update(&session.workspace.join("SWARM_UPDATE.md")).audit_outcome
                })
                .or_else(|| Some("unreported".to_string()));
            event.task = Some(match &assignment.task {
                PeerTask::Discovery => "explore".to_string(),
                PeerTask::Followup { .. } => "challenge".to_string(),
            });
            event.elapsed_seconds = Some(result.usage.elapsed_seconds);
            event.total_tokens = result.usage.token_usage.total_tokens;
            event.evidence_refs = vec!["SWARM_UPDATE.md".to_string()];
            if event.outcome.as_deref().is_some_and(|outcome| {
                matches!(
                    outcome.to_ascii_lowercase().as_str(),
                    "negative" | "inconclusive" | "duplicate"
                )
            }) {
                let mut non_positive = EventDraft::new(
                    round,
                    Some(&session.agent_name),
                    session.board_version_seen,
                    "NON_POSITIVE_OUTCOME",
                );
                non_positive.task = event.task.clone();
                non_positive.outcome = event.outcome.clone();
                non_positive.evidence_refs = event.evidence_refs.clone();
                interaction_log.append_coordinator(non_positive)?;
            }
            interaction_log.append_coordinator(event)?;
        }
        append_board_round(&board_path, round, &sessions)?;
        append_log(
            &process_log,
            &format!(
                "- Round {round} finished in {:.3} seconds; argument board updated.\n",
                round_timer.elapsed().as_secs_f64()
            ),
        )?;
        let previous_lead_evidence_counts = triage_leads(&findings)
            .into_iter()
            .map(|lead| (lead.key, lead.evidence_paths.len()))
            .collect::<BTreeMap<_, _>>();
        let round_findings = archive_findings(&sessions, &findings_dir, request.keep_workspace)?;
        for finding in &round_findings {
            let session = sessions
                .iter()
                .find(|session| session.agent_name == finding.agent_name)
                .context("archived finding does not match a swarm session")?;
            let mut event = EventDraft::new(
                round,
                Some(&finding.agent_name),
                session.board_version_seen,
                "FINDING_SUBMITTED",
            );
            event.lead_id = finding.lead_ids.iter().next().cloned();
            event.claim_id = event.lead_id.clone();
            event.evidence_refs = vec![
                finding
                    .path
                    .strip_prefix(candidate_dir)
                    .unwrap_or(&finding.path)
                    .display()
                    .to_string(),
            ];
            event.evidence_state = Some(if finding.locally_reproduced {
                "AGENT_REPRODUCED".to_string()
            } else {
                "CANDIDATE".to_string()
            });
            event.independent_execution = Some(finding.locally_reproduced);
            event.independent_analysis = Some(finding.independent_analysis);
            interaction_log.append_coordinator(event)?;
        }
        findings.extend(round_findings);
        for lead in triage_leads(&findings) {
            let previous_count = previous_lead_evidence_counts
                .get(&lead.key)
                .copied()
                .unwrap_or_default();
            if lead.evidence_paths.len() <= previous_count {
                continue;
            }
            let Some(state) = lead_history.get_mut(&lead.key) else {
                continue;
            };
            let was_suspended = state.suspended;
            state.suspended = false;
            state.no_progress_rounds = 0;
            if !was_suspended {
                continue;
            }
            let mut event = EventDraft::new(round, None, round, "LEAD_REACTIVATED");
            event.lead_id = Some(lead.lead_id.clone());
            event.evidence_refs = lead
                .evidence_paths
                .iter()
                .skip(previous_count)
                .map(|path| {
                    path.strip_prefix(candidate_dir)
                        .unwrap_or(path)
                        .display()
                        .to_string()
                })
                .collect();
            event.detail = Some(
                "New archived finding evidence reopened a previously suspended lead for scheduling."
                    .to_string(),
            );
            interaction_log.append_coordinator(event)?;
            append_log(
                &process_log,
                &format!(
                    "- Lead ID {} reactivated after new archived evidence; it is eligible for follow-up scheduling.\n",
                    lead.lead_id
                ),
            )?;
        }
        for session in &sessions {
            record_session_scratch_cleanup(session, request.keep_workspace, &process_log)?;
        }
        let mut followup_reproductions = Vec::new();
        for ((assignment, session), result) in assignments.iter().zip(&sessions).zip(&round_results)
        {
            let PeerTask::Followup {
                lead,
                blind_challenge,
            } = &assignment.task
            else {
                continue;
            };
            let update = read_challenge_update(&session.workspace.join("SWARM_UPDATE.md"));
            let assigned_lead_matches = update.assigned_lead_id.as_deref().is_some_and(|lead_id| {
                normalize_swarm_field(lead_id) == normalize_swarm_field(&lead.lead_id)
            });
            let (evidence_refs, invalid_refs) = if assigned_lead_matches {
                validate_evidence_refs(&session.workspace, &update.evidence_refs)
            } else {
                (Vec::new(), Vec::new())
            };
            if !invalid_refs.is_empty() {
                let mut event = EventDraft::new(
                    round,
                    Some(&assignment.agent_name),
                    session.board_version_seen,
                    "INVALID_EVIDENCE_REFS",
                );
                event.lead_id = Some(lead.lead_id.clone());
                event.evidence_refs = invalid_refs;
                event.detail = Some(
                    "Rejected evidence references that were absent, absolute, or outside the participant workspace."
                        .to_string(),
                );
                interaction_log.append_coordinator(event)?;
            }
            let disposition = assigned_lead_matches
                .then_some(update.disposition.as_deref())
                .flatten();
            let information_gain = assigned_lead_matches
                .then_some(update.information_gain)
                .flatten();
            let independent_analysis = *blind_challenge
                && assigned_lead_matches
                && update.independent_analysis
                && session.workspace.join("blind-analysis.md").is_file();
            let independent_reproduction = assigned_lead_matches
                && update.independent_reproduction.as_deref() == Some("confirmed")
                && !evidence_refs.is_empty();
            if assigned_lead_matches
                && (update.disputed_claim.is_none() || update.falsifiable_check.is_none())
            {
                let mut event = EventDraft::new(
                    round,
                    Some(&assignment.agent_name),
                    session.board_version_seen,
                    "NORM_SOFT_VIOLATION",
                );
                event.lead_id = Some(lead.lead_id.clone());
                event.outcome = Some("N3_PRODUCTIVE_CHALLENGE".to_string());
                event.detail = Some(
                    "Challenge omitted a machine-readable disputed claim or falsifiable check."
                        .to_string(),
                );
                interaction_log.append_coordinator(event)?;
            }
            if independent_reproduction && let Some(reference) = evidence_refs.first() {
                followup_reproductions.push(archived_followup_reproduction(
                    &assignment.agent_name,
                    lead,
                    independent_analysis,
                    session.workspace.join(reference),
                ));
            }
            let (no_progress_rounds, suspended) = update_followup_state(
                &mut lead_history,
                lead,
                FollowupUpdate {
                    participant: &assignment.agent_name,
                    disposition,
                    evidence_refs: &evidence_refs,
                    information_gain,
                    independent_analysis,
                    suggested_task: assigned_lead_matches
                        .then_some(update.suggested_task.as_deref())
                        .flatten(),
                    evidence_tokens: result.usage.token_usage.total_tokens.unwrap_or_default(),
                    elapsed_seconds: result.usage.elapsed_seconds,
                    suspend_after_no_progress: request
                        .norm_set
                        .resource_policy
                        .suspend_after_no_progress,
                },
            );
            let mut event = EventDraft::new(
                round,
                Some(&assignment.agent_name),
                session.board_version_seen,
                "CHALLENGE",
            );
            event.task = Some(if *blind_challenge {
                "blind challenge".to_string()
            } else {
                "focused challenge".to_string()
            });
            event.lead_id = Some(lead.lead_id.clone());
            event.claim_id = update
                .claim_id
                .clone()
                .or_else(|| Some(format!("{}:{}", lead.lead_id, assignment.agent_name)));
            event.target_claim = update.target_claim_id.clone();
            event.objection = update.disputed_claim.clone();
            event.proposed_test = update.falsifiable_check.clone();
            event.evidence_refs = evidence_refs;
            let challenge_evidence_refs = event.evidence_refs.clone();
            event.outcome = disposition.map(str::to_string);
            event.independent_execution = Some(independent_reproduction);
            event.independent_analysis = Some(independent_analysis);
            event.information_gain = information_gain;
            event.detail = Some(format!(
                "{no_progress_rounds} consecutive no-progress follow-up(s)"
            ));
            interaction_log.append_coordinator(event)?;
            if disposition.is_some_and(|value| value.eq_ignore_ascii_case("rejected"))
                && !challenge_evidence_refs.is_empty()
            {
                let rejection_count = lead_history
                    .get(&lead.key)
                    .map_or(0, |state| state.rejected_agents.len());
                append_log(
                    &process_log,
                    &format!(
                        "- {} rejected assigned Lead ID {} with evidence; {} independent peer rejection(s) recorded.\n",
                        assignment.agent_name, lead.lead_id, rejection_count
                    ),
                )?;
            }
            if suspended {
                let mut event = EventDraft::new(
                    round,
                    Some(&assignment.agent_name),
                    session.board_version_seen,
                    "LEAD_SUSPENDED",
                );
                event.lead_id = Some(lead.lead_id.clone());
                event.evidence_refs = challenge_evidence_refs.clone();
                event.detail = Some(format!(
                    "{} consecutive follow-ups reported no evidence progress; the lead remains unresolved and indexed.",
                    request.norm_set.resource_policy.suspend_after_no_progress
                ));
                interaction_log.append_coordinator(event)?;
                append_log(
                    &process_log,
                    &format!(
                        "- Lead ID {} suspended after {} follow-ups without evidence progress; it remains unresolved in SWARM_INDEX.json.\n",
                        lead.lead_id, request.norm_set.resource_policy.suspend_after_no_progress
                    ),
                )?;
            }
        }
        findings.extend(followup_reproductions);
        let quiescent = sessions.iter().all(session_declares_quiescence);
        records.extend(round_results.into_iter().map(|result| result.usage));
        all_sessions.extend(sessions);
        completed_round_count = round;
        let pending_leads = has_actionable_leads(&findings, &lead_history);
        if quiescent && !pending_leads && round < request.round_count {
            println!(
                "[kernel-vuln] candidate {:03}: swarm reached quiescence after round {round}; stopping early",
                request.candidate_index
            );
            append_log(
                &process_log,
                &format!(
                    "- All peers declared round {round} quiescent and no lead needs an independent reproduction or security-impact assessment; later rounds skipped.\n"
                ),
            )?;
            break;
        }
    }

    classify_peer_evidence(&mut findings)?;
    for lead in triage_leads(&findings) {
        let evidence_state = match lead.reproduced_participant_count {
            0 => "CANDIDATE",
            1 => "AGENT_REPRODUCED",
            _ => "CROSS_REPRODUCED",
        };
        let mut event = EventDraft::new(
            completed_round_count,
            None,
            completed_round_count,
            "EVIDENCE_CLASSIFIED",
        );
        event.lead_id = Some(lead.lead_id.clone());
        event.evidence_refs = lead
            .evidence_paths
            .iter()
            .map(|path| {
                path.strip_prefix(candidate_dir)
                    .unwrap_or(path)
                    .display()
                    .to_string()
            })
            .collect();
        event.evidence_state = Some(evidence_state.to_string());
        event.independent_execution = Some(lead.reproduced_participant_count > 0);
        event.independent_analysis = Some(lead.independent_analysis_count > 0);
        event.detail = Some(format!(
            "{} distinct local executions; {} archived submissions with independent analysis before shared evidence",
            lead.reproduced_participant_count, lead.independent_analysis_count
        ));
        interaction_log.append_coordinator(event)?;
    }
    let verifier_scratch = candidate_dir.join("scratch");
    let candidate_leads = triage_leads(&findings);
    let verification_records = verify_leads(VerifyLeadsRequest {
        runner: request.verifier,
        candidate_dir,
        scratch_root: &verifier_scratch,
        linux_source: request.run_options.linux_path,
        requested_revision: request.commit,
        norm_version: request.norm_set.version,
        leads: &candidate_leads,
        keep_scratch: request.keep_workspace,
    })
    .await?;
    for verification in &verification_records {
        let mut event = EventDraft::new(
            completed_round_count,
            None,
            completed_round_count,
            "RUNNER_VERIFICATION",
        );
        event.lead_id = Some(verification.lead_id.clone());
        event.outcome = Some(verification.status.clone());
        event.evidence_state = Some(verification.status.clone());
        event.evidence_refs = verification.evidence_refs.clone();
        event.vm_queue_seconds = verification
            .vm_queue_seconds
            .filter(|seconds| seconds.is_finite() && *seconds >= 0.0);
        event.vm_execution_seconds = verification
            .vm_execution_seconds
            .filter(|seconds| seconds.is_finite() && *seconds >= 0.0);
        event.detail = Some(verification.detail.clone());
        interaction_log.append_coordinator(event)?;
    }
    let actual_session_count = all_sessions.len();
    let all_sessions_negative = records.iter().all(|record| {
        record
            .finding_outcome
            .as_deref()
            .is_some_and(|outcome| outcome.eq_ignore_ascii_case("negative"))
    });
    let all_sessions_duplicate = records.iter().all(|record| {
        record
            .finding_outcome
            .as_deref()
            .is_some_and(|outcome| outcome.eq_ignore_ascii_case("duplicate"))
    });
    write_candidate_summary(
        candidate_dir,
        &findings,
        CandidateSummaryContext {
            all_sessions_succeeded,
            all_sessions_negative,
            all_sessions_duplicate,
            max_parallel_agents: request.agent_count,
            participant_count: actual_session_count,
            round_count: completed_round_count,
            lead_history: &lead_history,
        },
    )?;
    add_verification_to_reports(candidate_dir, &findings, &verification_records)?;
    write_swarm_index(
        candidate_dir,
        &findings,
        &lead_history,
        completed_round_count,
        interaction_log.events(),
        request.norm_set.version,
        &verification_records,
    )?;
    write_norm_review(
        &candidate_dir.join("SWARM_NORM_REVIEW.md"),
        interaction_log.events(),
        request.norm_set,
    )?;
    write_evaluation_template(
        &candidate_dir.join("SWARM_NORM_FEEDBACK_TEMPLATE.json"),
        request.norm_set,
    )?;

    let token_usage = aggregate_token_usage(
        &records
            .iter()
            .map(|record| record.token_usage.clone())
            .collect::<Vec<_>>(),
    );
    for record in &records {
        append_log(&process_log, &format!("\n{}", record.markdown_summary()))?;
    }
    let group_succeeded = all_sessions_succeeded && has_complete_outputs(candidate_dir);
    let child_result = if group_succeeded {
        "success"
    } else {
        "failure"
    };
    append_log(
        &process_log,
        &format!(
            "\n- Swarm finished; overall group result: {child_result}; actual child sessions: {actual_session_count}; archived finding submissions: {}; logical findings after Lead-ID/root-cause grouping: {}.{}\n",
            findings.len(),
            group_findings(&findings).len(),
            if errors.is_empty() {
                String::new()
            } else {
                format!(" Session issues: {}.", errors.join("; "))
            }
        ),
    )?;

    let aggregate_status = if any_spawn_failure {
        None
    } else {
        failing_status.or(last_status)
    };
    Ok(CandidateRunOutcome {
        exit_code: aggregate_status.as_ref().and_then(ExitStatus::code),
        status: aggregate_status,
        error: (!group_succeeded).then(|| {
            if errors.is_empty() {
                "swarm did not produce a complete aggregate report and fingerprint".to_string()
            } else {
                errors.join("; ")
            }
        }),
        child_result: child_result.to_string(),
        token_usage,
    })
}

fn status_label(status: ExitStatus) -> String {
    status
        .code()
        .map(|code| format!("exit code {code}"))
        .unwrap_or_else(|| "terminated by signal".to_string())
}

fn prepare_session(
    request: &SwarmRunRequest<'_, '_>,
    session_name: &str,
    assignment: &PeerAssignment,
    round: usize,
    workspace: &Path,
    board_path: &Path,
) -> Result<PreparedSession> {
    let agent_name = assignment.agent_name.as_str();
    fs::create_dir_all(workspace)
        .with_context(|| format!("creating agent workspace {}", workspace.display()))?;
    fs::copy(
        request.candidate_dir.join("SWARM_NORMS.json"),
        workspace.join("SWARM_NORMS.json"),
    )
    .with_context(|| format!("copying frozen norms into {}", workspace.display()))?;
    let source_index = request.run_options.output_dir.join(FINDING_INDEX_FILE_NAME);
    let session_index = workspace.join(FINDING_INDEX_FILE_NAME);
    if source_index.is_file() {
        fs::copy(&source_index, &session_index)
            .with_context(|| format!("copying prior finding index into {}", workspace.display()))?;
    } else {
        fs::write(
            &session_index,
            "# Prior finding index\n\nNo earlier candidate index was available.\n",
        )
        .with_context(|| format!("writing session finding index in {}", workspace.display()))?;
    }
    let scratch_dir = workspace.join("scratch");
    let context_path = workspace.join("SWARM_CONTEXT.md");
    fs::write(&context_path, &assignment.context)
        .with_context(|| format!("writing task context in {}", workspace.display()))?;
    let mut prompt = if let Some(review) = request.rule_review {
        render_rule_review_prompt(
            request.run_options.linux_path,
            workspace,
            workspace,
            &scratch_dir,
            request.focus,
            request.commit,
            review,
        )
    } else {
        render_prompt(
            request.run_options.linux_path,
            workspace,
            workspace,
            &scratch_dir,
            request.focus,
            request.commit,
        )
    };
    if let Some(extra_prompt) = request.extra_prompt {
        prompt.push_str(
            "\n\n## Additional user-provided instructions\n\nApply these instructions within the research contract above. They may focus the audit or add domain knowledge, but do not waive source-read-only handling, PoC/control validation, or evidence requirements.\n\n",
        );
        prompt.push_str(extra_prompt);
        prompt.push('\n');
    }
    let lens_index = (round
        + agent_name
            .trim_start_matches("agent-")
            .parse::<usize>()
            .unwrap_or(1))
        % ROTATING_RESEARCH_LENSES.len();
    let blind_challenge = matches!(
        &assignment.task,
        PeerTask::Followup {
            blind_challenge: true,
            ..
        }
    );
    let shared_context_hint = if blind_challenge {
        "This is a blind challenge. The task context contains only the lead ID and title; record independent analysis before opening prior reports."
            .to_string()
    } else {
        format!(
            "The full board is at `{}`; use the task context to select relevant records",
            board_path.display()
        )
    };
    let induced_guidance = request
        .norm_set
        .update_record
        .as_ref()
        .map(|record| record.induced_guidance.join("; "))
        .filter(|guidance| !guidance.is_empty())
        .unwrap_or_else(|| "none; use the base role-independent norms".to_string());
    let swarm_instructions = SWARM_CONTRACT
        .replace("{round}", &round.to_string())
        .replace("{round_count}", &request.round_count.to_string())
        .replace("{agent_name}", agent_name)
        .replace("{lens}", ROTATING_RESEARCH_LENSES[lens_index])
        .replace("{candidate_dir}", &workspace.display().to_string())
        .replace("{workspace}", &workspace.display().to_string())
        .replace("{scratch_dir}", &scratch_dir.display().to_string())
        .replace("{context_path}", &context_path.display().to_string())
        .replace("{shared_context_hint}", &shared_context_hint)
        .replace("{induced_guidance}", &induced_guidance)
        .replace("{norm_version}", &request.norm_set.version.to_string());
    prompt.push_str(&swarm_instructions);
    prompt.push_str("\n\n## Assigned round task\n\n");
    let task_label = match &assignment.task {
        PeerTask::Discovery if round == 1 => {
            prompt.push_str("Independent blind discovery. Do not read other participants' findings before recording your initial lead selection.\n");
            "blind discovery"
        }
        PeerTask::Discovery if request.dry_run && round > 1 => {
            prompt.push_str("Dry-run preview only. At execution time, this slot will either challenge an unresolved lead selected from prior-round evidence or explore an unexamined source area.\n");
            "adaptive follow-up preview"
        }
        PeerTask::Discovery => {
            prompt.push_str("Fresh discovery. Use the compact lead index in SWARM_CONTEXT.md to avoid already-covered root causes. Explore an unexamined code area and open full prior evidence only if your source path overlaps a listed lead.\n");
            "fresh discovery"
        }
        PeerTask::Followup {
            lead,
            blind_challenge,
        } => {
            if *blind_challenge {
                prompt.push_str(&format!(
                    "Blindly challenge Lead ID `{}`. Use only the title and your source analysis in SWARM_CONTEXT.md until `blind-analysis.md` records your independently derived root cause and falsification plan. Then inspect the archived evidence, reproduce or falsify the behavior, and assess security impact.\n",
                    lead.lead_id
                ));
            } else {
                prompt.push_str(&format!(
                    "Challenge Lead ID `{}` using the focused evidence in SWARM_CONTEXT.md. Re-read the source path and trigger assumptions, inspect the PoC, positive oracle, and closest negative control, then report what new evidence or counterexample you add. Assess security impact separately from reproducibility.\n",
                    lead.lead_id
                ));
            }
            "assigned lead challenge"
        }
    };
    let board_version_seen = if blind_challenge {
        0
    } else {
        round.saturating_sub(1)
    };

    let args = build_child_args(
        request.root_config_overrides,
        request.run_options,
        &scratch_dir,
        workspace,
        &[],
    );
    fs::write(workspace.join("prompt.md"), &prompt)
        .with_context(|| format!("writing agent prompt in {}", workspace.display()))?;
    fs::write(
        workspace.join("command.txt"),
        format_command_for_file(request.executable, &args),
    )
    .with_context(|| format!("writing agent command in {}", workspace.display()))?;
    fs::write(
        workspace.join("run-metadata.md"),
        format!(
            "# Swarm session metadata\n\n- role: equal peer researcher\n- task: {task_label}\n- participant: {agent_name}\n- round: {round}/{}\n- board version seen: {}\n- audit group: candidate-{:03}\n- persistent workspace: {}\n- scratch directory: {}\n- keep scratch after run: {}\n- Linux source: {}\n- model: {}\n- API key variable: {} (value redacted)\n- API base URL: {}\n- sandbox: {}\n- prompt: prompt.md\n- task context: SWARM_CONTEXT.md\n- structured interaction events: SWARM_EVENTS.jsonl\n- Codex event log: agent-events.jsonl\n- stderr log: agent-stderr.log\n- usage summary: usage.json\n",
            request.round_count,
            board_version_seen,
            request.candidate_index,
            workspace.display(),
            scratch_dir.display(),
            request.keep_workspace,
            request.run_options.linux_path.display(),
            request.run_options.model.unwrap_or("config/default"),
            request.run_options.api_key_env,
            request
                .run_options
                .api_base_url
                .unwrap_or("default provider"),
            sandbox_name(request.run_options.sandbox),
        ),
    )
    .with_context(|| format!("writing session metadata in {}", workspace.display()))?;

    Ok(PreparedSession {
        name: session_name.to_string(),
        agent_name: agent_name.to_string(),
        round,
        board_version_seen,
        blind_challenge,
        workspace: workspace.to_path_buf(),
        scratch_dir,
        prompt,
        args,
    })
}

async fn run_prepared_session_timed(
    request: &SwarmRunRequest<'_, '_>,
    session: &PreparedSession,
) -> TimedSessionResult {
    let started_at = Utc::now();
    let timer = Instant::now();
    let result = run_agent(
        request.executable,
        &session.args,
        &session.scratch_dir,
        &session.workspace,
        request.api_key,
        &session.prompt,
        request.run_options.show_progress,
    )
    .await;
    TimedSessionResult {
        result,
        started_at,
        finished_at: Utc::now(),
        elapsed_seconds: timer.elapsed().as_secs_f64(),
    }
}

fn record_session_scratch_cleanup(
    session: &PreparedSession,
    keep_workspace: bool,
    process_log: &Path,
) -> Result<()> {
    let cleanup_note = if keep_workspace {
        format!(
            "retained by --keep-workspace: {}",
            session.scratch_dir.display()
        )
    } else {
        match cleanup_scratch_directory(&session.workspace, &session.scratch_dir) {
            Ok(()) => format!("removed {}", session.scratch_dir.display()),
            Err(error) => format!(
                "failed to remove {}: {error:#}",
                session.scratch_dir.display()
            ),
        }
    };
    fs::write(
        session.workspace.join("workspace-cleanup.md"),
        format!("Scratch workspace cleanup: {cleanup_note}\n"),
    )
    .with_context(|| format!("writing cleanup record in {}", session.workspace.display()))?;
    append_log(
        process_log,
        &format!("- {} scratch cleanup: {cleanup_note}\n", session.name),
    )
}

fn complete_session(
    request: &SwarmRunRequest<'_, '_>,
    session: &PreparedSession,
    result: Result<ExitStatus>,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    elapsed_seconds: f64,
) -> Result<SessionResult> {
    let final_path = session.workspace.join("agent-final.md");
    let has_final = fs::read_to_string(&final_path).is_ok_and(|message| !message.trim().is_empty());
    let (status, error, child_result, exit_code) = match result {
        Ok(status) if status.success() && has_final => {
            (Some(status), None, "success", status.code())
        }
        Ok(status) if status.success() => (
            Some(status),
            Some(format!("{} is missing or empty", final_path.display())),
            "failure",
            status.code(),
        ),
        Ok(status) => (Some(status), None, "failure", status.code()),
        Err(error) => (None, Some(format!("{error:#}")), "failed_to_start", None),
    };
    let token_usage = read_token_usage(&session.workspace.join("agent-events.jsonl"))?;
    let finding_outcome = read_finding_outcome(&session.workspace.join("finding-fingerprint.md"))
        .or_else(|| {
            read_challenge_update(&session.workspace.join("SWARM_UPDATE.md")).audit_outcome
        });
    let usage = CandidateUsageRecord {
        run_started_at: request.run_started_at.to_string(),
        candidate: format!(
            "candidate-{:03}/round-{}/{}",
            request.candidate_index, session.round, session.agent_name
        ),
        model: request
            .run_options
            .model
            .unwrap_or("config/default")
            .to_string(),
        child_result: child_result.to_string(),
        exit_code,
        started_at: started_at.to_rfc3339(),
        finished_at: finished_at.to_rfc3339(),
        elapsed_seconds,
        finding_outcome,
        token_usage,
    };
    persist_nested_candidate_usage(&usage, &session.workspace)?;
    if let Some(error) = &error {
        append_log(
            &request.run_options.output_dir.join("PROCESS_LOG.md"),
            &format!("- {} failed: {error}\n", session.name),
        )?;
    }
    Ok(SessionResult {
        status,
        error,
        usage,
    })
}

fn append_board_round(board_path: &Path, round: usize, sessions: &[PreparedSession]) -> Result<()> {
    let mut board = fs::read_to_string(board_path)
        .with_context(|| format!("reading swarm board {}", board_path.display()))?;
    board.push_str(&format!("\n\n## Round {round} contributions\n"));
    for session in sessions {
        board.push_str(&format!("\n### {}\n\n", session.agent_name));
        let update = read_bounded_file(&session.workspace.join("SWARM_UPDATE.md"), 2_500);
        let fingerprint =
            read_bounded_file(&session.workspace.join("finding-fingerprint.md"), 1_800);
        let arguments = read_bounded_file(&session.workspace.join("peer-arguments.md"), 2_500);
        let final_message = read_bounded_file(&session.workspace.join("agent-final.md"), 2_000);
        for (label, content) in [
            ("SWARM_UPDATE.md", update),
            ("finding-fingerprint.md", fingerprint),
            ("peer-arguments.md", arguments),
            ("agent-final.md", final_message),
        ] {
            if !content.trim().is_empty() {
                board.push_str(&format!("#### {label}\n\n{content}\n\n"));
            }
        }
    }
    if board.len() > MAX_BOARD_BYTES {
        let keep_from = board.len() - MAX_BOARD_BYTES + 160;
        let boundary = board
            .char_indices()
            .find_map(|(index, _)| (index >= keep_from).then_some(index))
            .unwrap_or(board.len());
        board = format!(
            "# Swarm argument board (older entries trimmed to keep prompts bounded)\n\n{}",
            &board[boundary..]
        );
    }
    fs::write(board_path, board)
        .with_context(|| format!("updating swarm board {}", board_path.display()))
}

fn session_declares_quiescence(session: &PreparedSession) -> bool {
    fs::read_to_string(session.workspace.join("SWARM_UPDATE.md")).is_ok_and(|update| {
        update
            .lines()
            .any(|line| line.trim().eq_ignore_ascii_case("Round status: quiescent"))
    })
}

fn read_bounded_file(path: &Path, max_chars: usize) -> String {
    let Ok(contents) = fs::read_to_string(path) else {
        return String::new();
    };
    let mut chars = contents.chars();
    let excerpt = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{excerpt}\n[excerpt truncated]")
    } else {
        excerpt
    }
}

fn archive_findings(
    sessions: &[PreparedSession],
    findings_dir: &Path,
    keep_workspace: bool,
) -> Result<Vec<ArchivedFinding>> {
    let mut archived = Vec::new();
    for session in sessions {
        let agent_findings_dir = session.workspace.join("findings");
        if let Ok(entries) = fs::read_dir(&agent_findings_dir) {
            let mut entries = entries
                .filter_map(std::result::Result::ok)
                .filter(|entry| entry.file_type().is_ok_and(|ty| ty.is_dir()))
                .collect::<Vec<_>>();
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                let source = entry.path();
                archive_finding_folder(
                    session,
                    &source,
                    findings_dir,
                    keep_workspace,
                    &mut archived,
                )?;
            }
        }

        let root_fingerprint = session.workspace.join("finding-fingerprint.md");
        let root_report = session.workspace.join("candidate-report.md");
        let outcome = read_finding_outcome(&root_fingerprint).unwrap_or_default();
        if root_report.is_file()
            && root_fingerprint.is_file()
            && matches!(
                outcome.to_ascii_lowercase().as_str(),
                "confirmed" | "plausible"
            )
        {
            let source = session.workspace.clone();
            let dest = unique_finding_path(
                findings_dir,
                &format!("root-r{:02}-{}", session.round, session.agent_name),
            );
            fs::create_dir_all(&dest)
                .with_context(|| format!("creating finding archive {}", dest.display()))?;
            fs::copy(&root_report, dest.join("candidate-report.md"))
                .with_context(|| format!("copying {}", root_report.display()))?;
            fs::copy(&root_fingerprint, dest.join("finding-fingerprint.md"))
                .with_context(|| format!("copying {}", root_fingerprint.display()))?;
            write_evidence_pointer(&dest, &source, keep_workspace)?;
            archived.push(archived_finding(
                &session.agent_name,
                session_has_independent_analysis(session),
                dest,
                &root_fingerprint,
                &root_report,
            )?);
        }
    }
    Ok(archived)
}

fn archive_finding_folder(
    session: &PreparedSession,
    source: &Path,
    findings_dir: &Path,
    keep_workspace: bool,
    archived: &mut Vec<ArchivedFinding>,
) -> Result<()> {
    let fingerprint = source.join("finding-fingerprint.md");
    let report = source.join("candidate-report.md");
    let outcome = read_finding_outcome(&fingerprint).unwrap_or_default();
    if !fingerprint.is_file()
        || !report.is_file()
        || !matches!(
            outcome.to_ascii_lowercase().as_str(),
            "confirmed" | "plausible"
        )
    {
        return Ok(());
    }
    let folder = source
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("lead");
    let dest = unique_finding_path(
        findings_dir,
        &format!("{}-r{:02}-{}", folder, session.round, session.agent_name),
    );
    copy_tree(source, &dest)?;
    write_evidence_pointer(&dest, &session.workspace, keep_workspace)?;
    archived.push(archived_finding(
        &session.agent_name,
        session_has_independent_analysis(session),
        dest,
        &fingerprint,
        &report,
    )?);
    Ok(())
}

fn session_has_independent_analysis(session: &PreparedSession) -> bool {
    session.round == 1
        || (session.blind_challenge
            && read_challenge_update(&session.workspace.join("SWARM_UPDATE.md"))
                .independent_analysis
            && session.workspace.join("blind-analysis.md").is_file())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)
        .with_context(|| format!("creating finding archive {}", destination.display()))?;
    for entry in fs::read_dir(source).with_context(|| format!("reading {}", source.display()))? {
        let entry = entry.with_context(|| format!("reading entries in {}", source.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("reading file type for {}", entry.path().display()))?;
        let target = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), &target).with_context(|| {
                format!("copying {} to {}", entry.path().display(), target.display())
            })?;
        }
    }
    Ok(())
}

fn write_evidence_pointer(destination: &Path, source: &Path, keep_workspace: bool) -> Result<()> {
    fs::write(
        destination.join("SWARM_EVIDENCE_SOURCE.md"),
        format!(
            "This finding was submitted by a swarm participant. Its persistent workspace and event logs remain at `{}`. Scratch is {}. Required reports and evidence must be stored outside scratch; finding files copied into this archive remain available here.\n",
            source.display(),
            if keep_workspace {
                format!("retained at `{}`", source.join("scratch").display())
            } else {
                "removed after this round's finding archive was created".to_string()
            },
        ),
    )
    .with_context(|| format!("writing evidence pointer in {}", destination.display()))
}

struct CandidateSummaryContext<'a> {
    all_sessions_succeeded: bool,
    all_sessions_negative: bool,
    all_sessions_duplicate: bool,
    max_parallel_agents: usize,
    participant_count: usize,
    round_count: usize,
    lead_history: &'a LeadHistory,
}

fn write_candidate_summary(
    candidate_dir: &Path,
    findings: &[ArchivedFinding],
    context: CandidateSummaryContext<'_>,
) -> Result<()> {
    let CandidateSummaryContext {
        all_sessions_succeeded,
        all_sessions_negative,
        all_sessions_duplicate,
        max_parallel_agents,
        participant_count,
        round_count,
        lead_history,
    } = context;
    let groups = group_findings(findings);
    let lead_triage = triage_leads(findings);
    let mut report = String::from(
        "# Swarm candidate report\n\nThis report summarizes the peer swarm. Each participant's full prompt, source audit, experiments, event stream, stderr, and usage are preserved under `agents/`. Every positive or plausible submission is archived under `findings/`; submissions with the same stable Lead ID are grouped here, with normalized title and root-cause matching as a legacy fallback. Their separate evidence remains available. No finding count limit is applied.\n\n",
    );
    if groups.is_empty() {
        report.push_str("No participant submitted a complete positive or plausible finding folder. Read the round board and agent workspaces for coverage and rejected leads.\n");
    } else {
        report.push_str("## Findings\n\n");
        for (index, (group, lead)) in groups.iter().zip(&lead_triage).enumerate() {
            let finding = group[0];
            let evidence_state = if group.iter().any(|finding| {
                finding
                    .swarm_outcome
                    .eq_ignore_ascii_case("cross_reproduced")
            }) {
                "CROSS_REPRODUCED"
            } else if group.iter().any(|finding| {
                finding
                    .swarm_outcome
                    .eq_ignore_ascii_case("agent_reproduced")
            }) {
                "AGENT_REPRODUCED"
            } else {
                "CANDIDATE"
            };
            let legacy_outcome = if evidence_state == "CROSS_REPRODUCED" {
                "confirmed"
            } else {
                "plausible"
            };
            let agents = group
                .iter()
                .map(|finding| finding.agent_name.as_str())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ");
            let evidence_paths = group
                .iter()
                .map(|finding| {
                    finding
                        .path
                        .strip_prefix(candidate_dir)
                        .unwrap_or(&finding.path)
                        .display()
                        .to_string()
                })
                .collect::<Vec<_>>()
                .join("`, `");
            let security_classes = group
                .iter()
                .map(|finding| finding.security_impact)
                .collect::<BTreeSet<_>>();
            let security_impact = if security_classes.len() == 1 {
                security_classes
                    .iter()
                    .next()
                    .copied()
                    .unwrap_or(SecurityImpactClass::Unresolved)
            } else {
                SecurityImpactClass::Unresolved
            };
            let state = lead_history.get(&lead.key);
            let rejection_count = state.map_or(0, |state| state.rejected_agents.len());
            let scheduling_state = if state.is_some_and(|state| state.suspended) {
                "SUSPENDED"
            } else if rejection_count >= 2 {
                "REJECTED_BY_TWO_EVIDENCE_BACKED_CHALLENGES"
            } else if lead.reproduced_participant_count >= 2
                && lead.security_impact != SecurityImpactClass::Unresolved
            {
                "RESOLVED_FOR_SCHEDULING"
            } else {
                "ACTIVE"
            };
            report.push_str(&format!(
                "{}. **{}** (`Lead ID: {}`) — legacy outcome: `{legacy_outcome}`; evidence status: `{evidence_state}`; distinct participants reporting local execution: {}; archived submissions with independent analysis before shared evidence: {}; external runner verification: `NOT_RUN`; reportability review: `NOT_ASSESSED`; security assessment: {}; lead scheduling state: `{scheduling_state}` ({rejection_count} evidence-backed rejection(s)); submitted by `{agents}`; evidence archives: `{evidence_paths}`.\n",
                index + 1,
                if finding.title.trim().is_empty() {
                    "Untitled finding"
                } else {
                    finding.title.as_str()
                },
                lead.lead_id,
                lead.reproduced_participant_count,
                lead.independent_analysis_count,
                security_impact.label(),
            ));
        }
        report.push_str("\n`CROSS_REPRODUCED` means two distinct participants reported local executions for the same Lead ID; it does not establish independent root-cause analysis or security impact. `RUNNER_VERIFIED`, `REPORTABLE`, and `SECURITY_CONFIRMED` are separate states and remain unset until their own checks occur. Positive, rejected, inconclusive, and suspended evidence is indexed in `SWARM_EVENTS.jsonl` and `SWARM_INDEX.json`.\n");
    }
    fs::write(candidate_dir.join("candidate-report.md"), &report)
        .with_context(|| format!("writing swarm report in {}", candidate_dir.display()))?;

    let outcome = if findings.iter().any(|finding| {
        finding
            .swarm_outcome
            .eq_ignore_ascii_case("cross_reproduced")
    }) {
        "confirmed"
    } else if !findings.is_empty() {
        "plausible"
    } else if all_sessions_succeeded && all_sessions_negative {
        "negative"
    } else if all_sessions_succeeded && all_sessions_duplicate {
        "duplicate"
    } else {
        "inconclusive"
    };
    let mut fingerprint = format!(
        "Outcome: {outcome}\nTitle: {}\nSubsystem: multiple or not established\nAffected files/functions: see individual finding folders under findings/\nRoot cause/invariant: see individual finding folders under findings/\nUser-controlled trigger: see individual finding folders under findings/\nObservable oracle: see individual finding folders under findings/\nAffected revision: see source-status-before.txt\nDuplicate-of: none\n\nSwarm coverage: {participant_count} distinct peer participants, up to {max_parallel_agents} concurrent peers per round, {round_count} completed rounds; {} archived finding folders.\nEvidence status: {}; external runner verification: NOT_RUN; reportability review: NOT_ASSESSED; security confirmation: NOT_ASSESSED.\n",
        if groups.is_empty() {
            "No validated finding"
        } else {
            "Peer swarm findings; see per-finding fingerprints"
        },
        groups.len(),
        if outcome == "confirmed" {
            "CROSS_REPRODUCED"
        } else if outcome == "plausible" {
            "CANDIDATE_OR_AGENT_REPRODUCED"
        } else {
            "NO_POSITIVE_FINDING"
        },
    );
    if !all_sessions_succeeded {
        fingerprint.push_str("\nSome child sessions failed or omitted their final message; treat a no-finding result as inconclusive.\n");
    }
    fs::write(candidate_dir.join("finding-fingerprint.md"), fingerprint)
        .with_context(|| format!("writing swarm fingerprint in {}", candidate_dir.display()))?;
    Ok(())
}

fn has_complete_outputs(candidate_dir: &Path) -> bool {
    let report = candidate_dir.join("candidate-report.md");
    let fingerprint = candidate_dir.join("finding-fingerprint.md");
    let report_ok = fs::read_to_string(report).is_ok_and(|contents| !contents.trim().is_empty());
    let outcome_ok = read_finding_outcome(&fingerprint).is_some_and(|outcome| {
        matches!(
            outcome.to_ascii_lowercase().as_str(),
            "confirmed" | "plausible" | "negative" | "inconclusive" | "duplicate"
        )
    });
    report_ok && outcome_ok
}

fn unique_finding_path(findings_dir: &Path, wanted: &str) -> PathBuf {
    let base = sanitize_id(wanted);
    let mut path = findings_dir.join(&base);
    let mut suffix = 1_u32;
    while path.exists() {
        path = findings_dir.join(format!("{base}-{suffix:02}"));
        suffix += 1;
    }
    path
}

fn sanitize_id(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    let trimmed = sanitized.trim_matches('-');
    if trimmed.is_empty() {
        "finding".to_string()
    } else {
        trimmed.chars().take(96).collect()
    }
}

fn unavailable_usage() -> TokenUsageSummary {
    TokenUsageSummary {
        status: super::kernel_vuln_usage::UsageStatus::Unavailable,
        completed_turns: 0,
        usage_turns: 0,
        input_tokens: None,
        cached_input_tokens: None,
        cache_write_input_tokens: None,
        output_tokens: None,
        reasoning_output_tokens: None,
        total_tokens: None,
    }
}
