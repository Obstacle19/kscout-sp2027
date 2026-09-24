//! Autonomous, deterministic Linux kernel vulnerability research workflow.
//!
//! This command deliberately orchestrates isolated Codex exec child processes
//! instead of embedding another agent loop in the top-level CLI. Each child
//! gets one candidate directory, a fixed research contract, and an
//! environment-only API key mapping.

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use chrono::Utc;
use clap::Parser;
use codex_arg0::Arg0DispatchPaths;
use codex_utils_cli::CliConfigOverrides;
use codex_utils_cli::SandboxModeCliArg;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

#[path = "kernel_vuln_dedup.rs"]
mod kernel_vuln_dedup;
#[path = "kernel_vuln_support.rs"]
mod kernel_vuln_support;

use self::kernel_vuln_dedup::refresh_finding_index;
use self::kernel_vuln_support::allocate_candidate_directory;
use self::kernel_vuln_support::append_log;
use self::kernel_vuln_support::build_child_args;
use self::kernel_vuln_support::canonicalize_directory;
use self::kernel_vuln_support::format_command_for_file;
use self::kernel_vuln_support::initialize_output_files;
use self::kernel_vuln_support::prepare_output_directory;
use self::kernel_vuln_support::render_prompt;
use self::kernel_vuln_support::resolve_api_key;
use self::kernel_vuln_support::run_agent;
use self::kernel_vuln_support::sandbox_name;
use self::kernel_vuln_support::source_snapshot;
use self::kernel_vuln_support::status_string;
use self::kernel_vuln_support::validate_api_base_url;
use self::kernel_vuln_support::validate_environment_variable_name;

const CUSTOM_PROVIDER_ID: &str = "linux_vuln_provider";
const DEFAULT_LINUX_PATH: &str = "/root/workspace/linux";
const DEFAULT_OUTPUT_DIR: &str = "./linux-vuln-set";
const DEFAULT_API_KEY_ENV: &str = "OPENAI_API_KEY";
const FINDING_INDEX_FILE_NAME: &str = "FINDING_INDEX.md";

const PROMPT_TEMPLATE: &str = r#"# Linux kernel vulnerability research contract

You are running one independent candidate pass of a Linux kernel vulnerability
research workflow. The user supplied the Linux source tree and the output
directory at runtime. Read the source tree directly, do not invent results,
and stop with a negative result if no candidate meets the contract.

Required constraints:

1. Find a deterministic vulnerability with a clear user-observable oracle.
   Reject hardware-dependent issues, timing-only issues, flaky races, and
   findings that are only a KASAN report without a stable userland oracle.
2. Do not use syzkaller, fuzzers, corpus mutation, or generic fuzzing.
   Perform an autonomous source audit and targeted deterministic validation.
3. You may use upstream history and commits as the audit unit, but do not
   present an already fixed vulnerability, a known public PoC, or a copied
   reproduction as a discovery.
4. The result must include a complete userland PoC and exact reproduction
   commands.
5. The PoC may use ordinary userland programs and syscalls only. Never call
   kernel functions directly, inject kernel code, or treat an in-kernel helper
   as a PoC.
6. Assess realistic deployment and attacker preconditions, reproducibility,
   impact, and limitations. Do not claim privilege escalation unless it is
   actually demonstrated.
7. Preserve evidence: source locations, the reasoning chain, control cases,
   command output, and the exact source revision.
8. Do not modify the supplied Linux source tree. Use out-of-tree build
   directories, temporary images, QEMU snapshots, and the candidate directory.
9. Save a detailed PROCESS_LOG.md describing the audit and every important
   command or decision.

Discovery discipline:

- Start from code and commit history in the supplied tree.
- Before selecting a lead, read the tool-managed FINDING_INDEX.md at the
  overall output directory. Use its prior candidate summaries only to exclude
  duplicate root causes; do not use them as discovery evidence or copy their
  PoCs. If a lead matches a prior finding's root cause, invariant, trigger,
  affected code, and oracle, reject it and continue with a different issue.
- Do not mine unrelated pre-existing research directories, prior PoCs, review
  records, or external finding databases for a candidate. If such artifacts are
  visible in the environment, treat them as contaminated leads that may only be
  used to exclude a result, never as discovery evidence or a reproduction.
- Prefer bugs in ordinary local or virtualized configurations and filesystem,
  syscall, namespace, IPC, or network paths that can be exercised without
  special hardware.
- Establish the invariant before writing a PoC.
- Validate the positive result, a close negative control, and a clean rerun.
- If a candidate is already repaired in the current tree, exclude it rather
  than presenting it as newly found.
- If the mechanism or PoC exists only in a pre-existing artifact outside the
  candidate directory, report it as excluded and continue auditing the supplied
  source; do not copy or adapt it into the result.

Deliverables in the candidate directory:

- a candidate report with root cause and source references;
- a concise finding-fingerprint.md with outcome, title, subsystem,
  affected files/functions, root cause/invariant, user-controlled trigger,
  observable oracle, affected revision, and duplicate-of (or none). For a
  negative or inconclusive pass, state that outcome and the scope checked;
- a userland-only PoC source and built artifact when practical;
- an exact reproduction and operation guide;
- raw command output and relevant kernel or userspace logs;
- PROCESS_LOG.md with the complete audit trail.

The final response must identify the exact oracle, the commands used, the
observed result, the controls, and the real-world assessment. Do not hide an
inconclusive result behind a vulnerability claim.
"#;

#[derive(Debug, Parser)]
pub(crate) struct KernelVulnCommand {
    /// Path to the Linux kernel source tree to audit.
    #[arg(long = "linux-path", value_name = "PATH", default_value = DEFAULT_LINUX_PATH)]
    linux_path: PathBuf,

    /// Directory where all run artifacts and candidate folders are stored.
    #[arg(long = "output-dir", value_name = "DIR", default_value = DEFAULT_OUTPUT_DIR)]
    output_dir: PathBuf,

    /// Number of independent candidate passes to run.
    #[arg(long, short = 'n', default_value_t = 1)]
    count: u32,

    /// Environment variable containing the external API key.
    ///
    /// The value is never placed in argv or written to the process log. It is
    /// mapped to CODEX_API_KEY only inside each child process.
    #[arg(long = "api-key-env", value_name = "ENV_VAR", default_value = DEFAULT_API_KEY_ENV)]
    api_key_env: String,

    /// Optional OpenAI-compatible Responses API base URL.
    ///
    /// When set, a temporary model provider is supplied through config overrides.
    #[arg(long = "api-base-url", value_name = "URL")]
    api_base_url: Option<String>,

    /// Model name forwarded to each non-interactive child session.
    #[arg(long, short = 'm', value_name = "MODEL")]
    model: Option<String>,

    /// Optional subsystem, directory, or topic to prioritize during auditing.
    #[arg(long, value_name = "FOCUS")]
    focus: Option<String>,

    /// Optional commit or revision to audit first.
    #[arg(long = "commit", value_name = "REVISION")]
    commit: Option<String>,

    /// Sandbox mode for the child agent. The default permits evidence writes
    /// below the candidate/output roots while keeping the Linux source tree
    /// outside the writable roots.
    #[arg(long, value_enum, default_value = "workspace-write")]
    sandbox: SandboxModeCliArg,

    /// Allow the child agent to run without approvals and without sandboxing.
    ///
    /// Use only inside an isolated research VM or equivalent lab.
    #[arg(long = "dangerously-bypass-approvals-and-sandbox")]
    dangerously_bypass_approvals_and_sandbox: bool,

    /// Permit stored Codex authentication when the selected API-key variable
    /// is absent.
    #[arg(long = "allow-stored-auth")]
    allow_stored_auth: bool,

    /// Stop remaining candidates after a child exits unsuccessfully.
    #[arg(long = "stop-on-error")]
    stop_on_error: bool,

    /// Stream Codex-style child progress, tool calls, command output, and
    /// agent messages to the terminal while preserving the raw event logs.
    #[arg(long = "show-progress", visible_alias = "verbose")]
    show_progress: bool,

    /// Generate prompts and command files without contacting the model.
    #[arg(long)]
    dry_run: bool,
}

struct RunOptions<'a> {
    linux_path: &'a Path,
    output_dir: &'a Path,
    count: u32,
    api_key_env: &'a str,
    api_base_url: Option<&'a str>,
    model: Option<&'a str>,
    sandbox: SandboxModeCliArg,
    dangerous_bypass: bool,
    show_progress: bool,
}

pub(crate) async fn run(
    command: KernelVulnCommand,
    root_config_overrides: &CliConfigOverrides,
    arg0_paths: Arg0DispatchPaths,
) -> Result<()> {
    let KernelVulnCommand {
        linux_path,
        output_dir,
        count,
        api_key_env,
        api_base_url,
        model,
        focus,
        commit,
        sandbox,
        dangerously_bypass_approvals_and_sandbox,
        allow_stored_auth,
        stop_on_error,
        show_progress,
        dry_run,
    } = command;

    ensure!(
        (1..=100).contains(&count),
        "--count must be between 1 and 100"
    );
    ensure!(
        dangerously_bypass_approvals_and_sandbox || !matches!(sandbox, SandboxModeCliArg::ReadOnly),
        "kernel-vuln must be able to save candidate evidence; use --sandbox workspace-write (the default) or --dangerously-bypass-approvals-and-sandbox"
    );
    validate_environment_variable_name(&api_key_env)?;
    validate_api_base_url(api_base_url.as_deref())?;

    let linux_path = canonicalize_directory(&linux_path, "Linux source")?;
    let output_dir = prepare_output_directory(&output_dir, &linux_path)?;

    let candidates_dir = output_dir.join("candidates");
    fs::create_dir_all(&candidates_dir)
        .with_context(|| format!("creating {}", candidates_dir.display()))?;
    let finding_index = output_dir.join(FINDING_INDEX_FILE_NAME);

    let executable = arg0_paths
        .codex_self_exe
        .or_else(|| std::env::current_exe().ok())
        .context("cannot locate the Codex executable for child sessions")?;

    let api_key = if dry_run {
        None
    } else {
        let key = resolve_api_key(&api_key_env);
        if key.is_none() && !allow_stored_auth {
            bail!(
                "no API key found in {api_key_env} or CODEX_API_KEY; set the variable, \
                 use --api-key-env, or explicitly pass --allow-stored-auth"
            );
        }
        key
    };

    let process_log = output_dir.join("PROCESS_LOG.md");
    let run_options = RunOptions {
        linux_path: &linux_path,
        output_dir: &output_dir,
        count,
        api_key_env: &api_key_env,
        api_base_url: api_base_url.as_deref(),
        model: model.as_deref(),
        sandbox,
        dangerous_bypass: dangerously_bypass_approvals_and_sandbox,
        show_progress,
    };
    initialize_output_files(&run_options, &process_log)?;
    refresh_finding_index(&candidates_dir, &finding_index)?;

    let started_at = Utc::now().to_rfc3339();
    append_log(
        &process_log,
        &format!(
            "\n## Run started: {started_at}\n\n\
             - Linux source: {}\n\
             - Output directory: {}\n\
             - Candidate count: {count}\n\
             - API key variable: {api_key_env} (value redacted)\n\
             - API base URL: {}\n\
             - Model: {}\n\
             - Focus: {}\n\
             - Commit scope: {}\n\
             - Duplicate exclusion index: {}\n\
             - Sandbox: {}\n\
             - Dangerous bypass: {dangerously_bypass_approvals_and_sandbox}\n\
             - Live progress: {show_progress}\n\
             - Dry run: {dry_run}\n",
            linux_path.display(),
            output_dir.display(),
            api_base_url.as_deref().unwrap_or("default provider"),
            model.as_deref().unwrap_or("config/default"),
            focus.as_deref().unwrap_or("none"),
            commit.as_deref().unwrap_or("current tree/history"),
            finding_index.display(),
            sandbox_name(sandbox),
        ),
    )?;

    fs::write(
        output_dir.join("source-status-before.txt"),
        source_snapshot(&linux_path),
    )
    .with_context(|| format!("writing source status in {}", output_dir.display()))?;

    let mut next_candidate_index = 1_u32;
    let mut failures = Vec::new();

    for ordinal in 0..count {
        let (candidate_index, candidate_dir) =
            allocate_candidate_directory(&candidates_dir, next_candidate_index)?;
        next_candidate_index = candidate_index.saturating_add(1);

        let prompt = render_prompt(
            &linux_path,
            &output_dir,
            &candidate_dir,
            focus.as_deref(),
            commit.as_deref(),
        );
        let args = build_child_args(root_config_overrides, &run_options, &candidate_dir);

        fs::create_dir_all(&candidate_dir)
            .with_context(|| format!("creating {}", candidate_dir.display()))?;
        fs::write(candidate_dir.join("prompt.md"), &prompt)
            .with_context(|| format!("writing prompt in {}", candidate_dir.display()))?;
        fs::write(
            candidate_dir.join("command.txt"),
            format_command_for_file(&executable, &args),
        )
        .with_context(|| format!("writing command in {}", candidate_dir.display()))?;
        fs::write(
            candidate_dir.join("run-metadata.md"),
            format!(
                "# Candidate run metadata\n\n\
                 - ordinal: {}\n\
                 - candidate directory: {}\n\
                 - Linux source: {}\n\
                 - API key variable: {} (value redacted)\n\
                 - API base URL: {}\n\
                 - model: {}\n\
                 - sandbox: {}\n\
                 - dangerous bypass: {}\n\
                 - live progress: {}\n\
                 - prompt: prompt.md\n\
                 - event log: agent-events.jsonl\n\
                 - stderr log: agent-stderr.log\n",
                ordinal + 1,
                candidate_dir.display(),
                linux_path.display(),
                api_key_env,
                api_base_url.as_deref().unwrap_or("default provider"),
                model.as_deref().unwrap_or("config/default"),
                sandbox_name(sandbox),
                dangerously_bypass_approvals_and_sandbox,
                show_progress,
            ),
        )
        .with_context(|| format!("writing metadata in {}", candidate_dir.display()))?;

        append_log(
            &process_log,
            &format!(
                "\n### Candidate {candidate_index:03} started\n\n\
                 - Directory: {}\n\
                 - Prompt: {}/prompt.md\n\
                 - Invocation: {}/command.txt\n",
                candidate_dir.display(),
                candidate_dir.display(),
                candidate_dir.display(),
            ),
        )?;

        if dry_run {
            println!(
                "[kernel-vuln] dry-run candidate {candidate_index:03}: {}",
                candidate_dir.display()
            );
            append_log(&process_log, "- Result: dry-run, child not started\n")?;
            continue;
        }

        println!(
            "[kernel-vuln] starting candidate {candidate_index:03} ({}/{count})",
            ordinal + 1
        );
        let result = run_agent(
            &executable,
            &args,
            &candidate_dir,
            &candidate_dir,
            api_key.as_deref(),
            &prompt,
            show_progress,
        )
        .await;
        refresh_finding_index(&candidates_dir, &finding_index)?;

        match result {
            Ok(status) if status.success() => {
                println!("[kernel-vuln] candidate {candidate_index:03} finished successfully");
                append_log(
                    &process_log,
                    &format!("- Result: success, exit status {}\n", status_string(status)),
                )?;
            }
            Ok(status) => {
                let message = format!(
                    "candidate {candidate_index:03} exited with {}",
                    status_string(status)
                );
                eprintln!("[kernel-vuln] {message}");
                append_log(&process_log, &format!("- Result: failure, {message}\n"))?;
                failures.push(message);
                if stop_on_error {
                    append_log(
                        &process_log,
                        "- Stop-on-error: remaining candidates were not started\n",
                    )?;
                    break;
                }
            }
            Err(error) => {
                let message = format!("candidate {candidate_index:03} failed to start: {error:#}");
                eprintln!("[kernel-vuln] {message}");
                append_log(&process_log, &format!("- Result: failure, {message}\n"))?;
                failures.push(message);
                if stop_on_error {
                    append_log(
                        &process_log,
                        "- Stop-on-error: remaining candidates were not started\n",
                    )?;
                    break;
                }
            }
        }
    }

    fs::write(
        output_dir.join("source-status-after.txt"),
        source_snapshot(&linux_path),
    )
    .with_context(|| format!("writing final source status in {}", output_dir.display()))?;
    append_log(
        &process_log,
        &format!(
            "\n## Run finished: {}\n\n- Source status snapshots: source-status-before.txt and source-status-after.txt\n",
            Utc::now().to_rfc3339()
        ),
    )?;

    if failures.is_empty() {
        println!(
            "[kernel-vuln] completed; artifacts are under {}",
            output_dir.display()
        );
        Ok(())
    } else {
        bail!(
            "{} candidate run(s) failed; inspect {}",
            failures.len(),
            process_log.display()
        );
    }
}

#[cfg(test)]
#[path = "kernel_vuln_tests.rs"]
mod tests;
