//! Round-based peer swarm for autonomous Linux kernel vulnerability research.
//!
//! Every participant starts as an equal researcher. The first round is blind;
//! later rounds receive a shared argument board and may challenge,
//! reproduce, reject, or branch from any earlier lead. There is no finding
//! count limit. Agent count and rounds are bounded by the CLI to control cost.

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

All files from earlier rounds are available below `{candidate_dir}/agents/`.
The current shared argument board is `{board_path}`. In round 1, work
independently before seeing any other participant's claims. In later rounds,
read the board and the relevant original evidence, then explicitly argue for or
against each unresolved lead. You may reject a lead, confirm it through an
independent clean setup, or start a new branch. Record each challenge and its
evidence in `peer-arguments.md` in your workspace. Do not edit another
participant's files or the shared board.

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
discussing the same root cause in a later round. Include the exact lead ID,
status, commands, clean setup, oracle, and control in `peer-arguments.md`.

For a finding marked `confirmed`, include the deterministic positive result,
the close negative control, and a clean repeat. To raise a finding from
`plausible` to swarm-level `confirmed`, another distinct participant must
independently reproduce the same root cause and oracle. A participant may
disagree; record the disagreement and leave the result plausible or
inconclusive when the evidence does not resolve it.

At the end, write `SWARM_UPDATE.md` with the exact lead IDs discovered,
challenged, independently confirmed, rejected, unresolved, and any concrete
follow-up task another participant should take. State `Round status: quiescent`
only if no actionable lead or evidence task remains. Do not hide failed
experiments, incomplete work, or uncertainty.
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

struct ArchivedFinding {
    agent_name: String,
    path: PathBuf,
    outcome: String,
    title: String,
    root_cause: String,
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
}

pub(super) async fn run_candidate(request: SwarmRunRequest<'_, '_>) -> Result<CandidateRunOutcome> {
    if !(2..=8).contains(&request.agent_count) {
        bail!("swarm agent count must be between 2 and 8");
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
        "# Swarm workspaces\n\nEvery agent is a peer. Round 1 starts independently; later rounds receive `SWARM_BOARD.md` and may challenge, reproduce, reject, or branch from earlier leads. No reviewer role is assigned. Each round has isolated persistent artifact workspaces and event/usage logs. A dedicated `scratch/` directory holds temporary builds and images; it is removed after that round's findings are archived unless `--keep-workspace` is set. Reports, logs, PoCs, and reproduction evidence stay in the persistent workspaces.\n",
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

    fs::write(
        candidate_dir.join("prompt.md"),
        format!(
            "# Peer swarm audit\n\n`--count 1` schedules one swarm group with {} peer agents and up to {} shared-board rounds. The first round discovers independently; later rounds argue, reproduce, reject, or branch. There is no finding count limit. Individual prompts and evidence are in `agents/`.\n\nShared board: {}\n",
            request.agent_count,
            request.round_count,
            board_path.display()
        ),
    )
    .with_context(|| format!("writing swarm prompt in {}", candidate_dir.display()))?;
    fs::write(
        candidate_dir.join("command.txt"),
        "Peer swarm coordinator; commands and exact prompts are recorded per session under agents/round-NN/agent-NN/.\n",
    )
    .with_context(|| format!("writing swarm command manifest in {}", candidate_dir.display()))?;
    let process_log = request.run_options.output_dir.join("PROCESS_LOG.md");
    let session_count = request.agent_count.saturating_mul(request.round_count);
    if request.dry_run {
        for round in 1..=request.round_count {
            for agent_number in 1..=request.agent_count {
                let agent_name = format!("agent-{agent_number:02}");
                let session_name = format!("round-{round:02}-{agent_name}");
                let workspace = agents_dir
                    .join(format!("round-{round:02}"))
                    .join(&agent_name);
                prepare_session(
                    &request,
                    &session_name,
                    &agent_name,
                    round,
                    &workspace,
                    &board_path,
                )?;
            }
        }
        append_log(
            &process_log,
            &format!(
                "\n#### candidate-{:03} peer swarm dry-run\n\n- Prepared {session_count} session prompts and commands for {} agents across up to {} rounds; no child was started.\n",
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
            "\n#### candidate-{:03} peer swarm\n\n- Peer agents per round: {}\n- Maximum shared-board rounds: {}\n- Scheduled child sessions: {session_count}\n- Keep per-agent scratch workspaces: {}\n- No permanent reviewer; every participant may discover, argue, reproduce, reject, and branch.\n- Shared argument board: {}\n",
            request.candidate_index,
            request.agent_count,
            request.round_count,
            request.keep_workspace,
            board_path.display()
        ),
    )?;

    let mut all_sessions = Vec::with_capacity(session_count);
    let findings_dir = candidate_dir.join("findings");
    fs::create_dir_all(&findings_dir)
        .with_context(|| format!("creating finding archive {}", findings_dir.display()))?;
    let mut findings = Vec::new();
    let mut records = Vec::with_capacity(session_count);
    let mut all_sessions_succeeded = true;
    let mut last_status = None;
    let mut failing_status = None;
    let mut any_spawn_failure = false;
    let mut errors = Vec::new();

    for round in 1..=request.round_count {
        let sessions = (1..=request.agent_count)
            .map(|agent_number| {
                let agent_name = format!("agent-{agent_number:02}");
                let session_name = format!("round-{round:02}-{agent_name}");
                let workspace = agents_dir
                    .join(format!("round-{round:02}"))
                    .join(&agent_name);
                prepare_session(
                    &request,
                    &session_name,
                    &agent_name,
                    round,
                    &workspace,
                    &board_path,
                )
            })
            .collect::<Result<Vec<_>>>()?;

        println!(
            "[kernel-vuln] candidate {:03}: swarm round {round}/{} starting {} peer agents in parallel",
            request.candidate_index, request.round_count, request.agent_count
        );
        append_log(
            &process_log,
            &format!(
                "\n- Round {round}/{} started; {} agents running in parallel.\n",
                request.round_count, request.agent_count
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
        append_board_round(&board_path, round, &sessions)?;
        append_log(
            &process_log,
            &format!(
                "- Round {round} finished in {:.3} seconds; argument board updated.\n",
                round_timer.elapsed().as_secs_f64()
            ),
        )?;
        findings.extend(archive_findings(
            &sessions,
            &findings_dir,
            request.keep_workspace,
        )?);
        for session in &sessions {
            record_session_scratch_cleanup(session, request.keep_workspace, &process_log)?;
        }
        let quiescent = sessions.iter().all(session_declares_quiescence);
        records.extend(round_results.into_iter().map(|result| result.usage));
        all_sessions.extend(sessions);
        if quiescent && round < request.round_count {
            println!(
                "[kernel-vuln] candidate {:03}: swarm reached quiescence after round {round}; stopping early",
                request.candidate_index
            );
            append_log(
                &process_log,
                &format!("- All peers declared round {round} quiescent; later rounds skipped.\n"),
            )?;
            break;
        }
    }

    apply_peer_confirmation_gate(&mut findings)?;
    let actual_round_count = all_sessions.len() / request.agent_count;
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
        all_sessions_succeeded,
        all_sessions_negative,
        all_sessions_duplicate,
        request.agent_count,
        actual_round_count,
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
            "\n- Swarm finished; overall group result: {child_result}; archived finding submissions: {}; logical findings after title/root-cause grouping: {}.{}\n",
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

fn status_label(status: &ExitStatus) -> String {
    status
        .code()
        .map(|code| format!("exit code {code}"))
        .unwrap_or_else(|| "terminated by signal".to_string())
}

fn prepare_session(
    request: &SwarmRunRequest<'_, '_>,
    session_name: &str,
    agent_name: &str,
    round: usize,
    workspace: &Path,
    board_path: &Path,
) -> Result<PreparedSession> {
    fs::create_dir_all(workspace)
        .with_context(|| format!("creating agent workspace {}", workspace.display()))?;
    let scratch_dir = workspace.join("scratch");
    let mut prompt = if let Some(review) = request.rule_review {
        render_rule_review_prompt(
            request.run_options.linux_path,
            request.run_options.output_dir,
            workspace,
            &scratch_dir,
            request.focus,
            request.commit,
            review,
        )
    } else {
        render_prompt(
            request.run_options.linux_path,
            request.run_options.output_dir,
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
    let swarm_instructions = SWARM_CONTRACT
        .replace("{round}", &round.to_string())
        .replace("{round_count}", &request.round_count.to_string())
        .replace("{agent_name}", agent_name)
        .replace("{lens}", ROTATING_RESEARCH_LENSES[lens_index])
        .replace(
            "{candidate_dir}",
            &request.candidate_dir.display().to_string(),
        )
        .replace("{workspace}", &workspace.display().to_string())
        .replace("{scratch_dir}", &scratch_dir.display().to_string())
        .replace("{board_path}", &board_path.display().to_string());
    prompt.push_str(&swarm_instructions);

    let args = build_child_args(
        request.root_config_overrides,
        request.run_options,
        &scratch_dir,
        workspace,
        &[request.candidate_dir, request.run_options.output_dir],
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
            "# Swarm session metadata\n\n- role: equal peer researcher\n- participant: {agent_name}\n- round: {round}/{}\n- audit group: candidate-{:03}\n- persistent workspace: {}\n- scratch directory: {}\n- keep scratch after run: {}\n- Linux source: {}\n- model: {}\n- API key variable: {} (value redacted)\n- API base URL: {}\n- sandbox: {}\n- prompt: prompt.md\n- command: command.txt\n- event log: agent-events.jsonl\n- stderr log: agent-stderr.log\n- usage summary: usage.json\n",
            request.round_count,
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
    let finding_outcome = read_finding_outcome(&session.workspace.join("finding-fingerprint.md"));
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
                dest,
                &root_fingerprint,
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
    archived.push(archived_finding(&session.agent_name, dest, &fingerprint)?);
    Ok(())
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

fn archived_finding(
    agent_name: &str,
    path: PathBuf,
    fingerprint: &Path,
) -> Result<ArchivedFinding> {
    let contents = fs::read_to_string(fingerprint)
        .with_context(|| format!("reading finding fingerprint {}", fingerprint.display()))?;
    Ok(ArchivedFinding {
        agent_name: agent_name.to_string(),
        path,
        outcome: read_finding_outcome(fingerprint).unwrap_or_default(),
        title: fingerprint_field(&contents, "Title"),
        root_cause: fingerprint_field(&contents, "Root cause/invariant"),
    })
}

fn apply_peer_confirmation_gate(findings: &mut [ArchivedFinding]) -> Result<()> {
    let mut confirming_agents: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for finding in findings
        .iter()
        .filter(|finding| finding.outcome.eq_ignore_ascii_case("confirmed"))
    {
        let key = claim_key(&finding.title, &finding.root_cause);
        if !key.is_empty() {
            confirming_agents
                .entry(key)
                .or_default()
                .insert(finding.agent_name.clone());
        }
    }
    for finding in findings.iter_mut() {
        if !finding.outcome.eq_ignore_ascii_case("confirmed") {
            continue;
        }
        let key = claim_key(&finding.title, &finding.root_cause);
        let peers = confirming_agents.get(&key).map_or(0, BTreeSet::len);
        if peers >= 2 {
            continue;
        }
        let fingerprint_path = finding.path.join("finding-fingerprint.md");
        let mut fingerprint = fs::read_to_string(&fingerprint_path)
            .with_context(|| format!("reading {}", fingerprint_path.display()))?;
        fingerprint = replace_first_outcome(&fingerprint, "plausible");
        fingerprint.push_str(
            "\nSwarm confirmation gate: downgraded to plausible because no second distinct participant independently reported the same title and root cause as confirmed. Review the original workspace and peer arguments before treating this as confirmed.\n",
        );
        fs::write(&fingerprint_path, fingerprint)
            .with_context(|| format!("updating {}", fingerprint_path.display()))?;
        finding.outcome = "plausible".to_string();
    }
    Ok(())
}

fn claim_key(title: &str, root_cause: &str) -> String {
    let normalize = |value: &str| {
        value
            .chars()
            .filter(|character| character.is_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect::<String>()
    };
    let title = normalize(title);
    let root_cause = normalize(root_cause);
    if title.is_empty() || root_cause.is_empty() {
        String::new()
    } else {
        format!("{title}:{root_cause}")
    }
}

fn group_findings(findings: &[ArchivedFinding]) -> Vec<Vec<&ArchivedFinding>> {
    let mut groups: BTreeMap<String, Vec<&ArchivedFinding>> = BTreeMap::new();
    for finding in findings {
        let key = claim_key(&finding.title, &finding.root_cause);
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
            key.trim()
                .trim_matches('*')
                .eq_ignore_ascii_case(wanted)
                .then(|| value.trim().to_string())
        })
        .unwrap_or_default()
}

fn replace_first_outcome(fingerprint: &str, outcome: &str) -> String {
    let mut replaced = false;
    fingerprint
        .lines()
        .map(|line| {
            if !replaced
                && let Some((key, _)) = line.split_once(':')
                && key
                    .trim()
                    .trim_start_matches(['-', '*'])
                    .trim()
                    .eq_ignore_ascii_case("Outcome")
            {
                replaced = true;
                return format!("Outcome: {outcome}");
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn write_candidate_summary(
    candidate_dir: &Path,
    findings: &[ArchivedFinding],
    all_sessions_succeeded: bool,
    all_sessions_negative: bool,
    all_sessions_duplicate: bool,
    agent_count: usize,
    round_count: usize,
) -> Result<()> {
    let groups = group_findings(findings);
    let mut report = String::from(
        "# Swarm candidate report\n\nThis report summarizes the peer swarm. Each participant's full prompt, source audit, experiments, event stream, stderr, and usage are preserved under `agents/`. Every positive or plausible submission is archived under `findings/`; repeated submissions with matching titles and root causes are grouped here while their separate evidence remains available. No finding count limit is applied.\n\n",
    );
    if groups.is_empty() {
        report.push_str("No participant submitted a complete positive or plausible finding folder. Read the round board and agent workspaces for coverage and rejected leads.\n");
    } else {
        report.push_str("## Findings\n\n");
        for (index, group) in groups.iter().enumerate() {
            let finding = group[0];
            let outcome = if group
                .iter()
                .any(|finding| finding.outcome.eq_ignore_ascii_case("confirmed"))
            {
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
            report.push_str(&format!(
                "{}. **{}** — `{}`; submitted by `{agents}`; evidence archives: `{evidence_paths}`.\n",
                index + 1,
                if finding.title.trim().is_empty() {
                    "Untitled finding"
                } else {
                    finding.title.as_str()
                },
                outcome,
            ));
        }
        report.push_str("\nA `confirmed` status requires two distinct participants to report matching titles and root causes as confirmed. Otherwise the coordinator downgrades that archive to `plausible`; inspect original evidence and disagreements before relying on any claim.\n");
    }
    fs::write(candidate_dir.join("candidate-report.md"), &report)
        .with_context(|| format!("writing swarm report in {}", candidate_dir.display()))?;

    let outcome = if findings
        .iter()
        .any(|finding| finding.outcome.eq_ignore_ascii_case("confirmed"))
    {
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
        "Outcome: {outcome}\nTitle: {}\nSubsystem: multiple or not established\nAffected files/functions: see individual finding folders under findings/\nRoot cause/invariant: see individual finding folders under findings/\nUser-controlled trigger: see individual finding folders under findings/\nObservable oracle: see individual finding folders under findings/\nAffected revision: see source-status-before.txt\nDuplicate-of: none\n\nSwarm coverage: {agent_count} peer agents, {round_count} shared-board rounds; {} archived finding folders.\n",
        if groups.is_empty() {
            "No validated finding"
        } else {
            "Peer swarm findings; see per-finding fingerprints"
        },
        groups.len(),
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
