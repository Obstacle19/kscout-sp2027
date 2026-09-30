use super::CUSTOM_PROVIDER_ID;
use super::PROMPT_TEMPLATE;
use super::RunOptions;
use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use codex_utils_cli::CliConfigOverrides;
use codex_utils_cli::SandboxModeCliArg;
use serde_json::Value;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command as StdCommand;
use std::process::ExitStatus;
use std::process::Stdio;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncRead;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::process::Command;

pub(super) fn initialize_output_files(
    run_options: &RunOptions<'_>,
    process_log: &Path,
) -> Result<()> {
    let output_dir = run_options.output_dir;
    write_if_missing(
        &output_dir.join("README.md"),
        &format!(
            "# Linux kernel vulnerability hunt output\n\n\
             This directory is managed by codex kernel-vuln.\n\n\
             - Linux source: {}\n\
             - Requested autonomous passes per run: {}\n\
             - API key variable: {} (value is never stored here)\n\
             - API base URL: {}\n\
             - Model: {}\n\
             - Sandbox: {}\n\
             - Dangerous bypass: {}\n\
             - Live progress: {}\n\n\
             ## Layout\n\n\
             - PROCESS_LOG.md: orchestrator-level timeline and statuses.\n\
             - FINDING_INDEX.md: prior candidate fingerprints used to exclude duplicate findings.\n\
             - USAGE.jsonl: cumulative per-candidate elapsed time and token usage summaries.\n\
             - rule-scan-*.md: optional deterministic CVE-derived candidate enumeration and filter report.\n\
             - PROMPT_TEMPLATE.md: fixed research contract.\n\
             - source-status-before.txt and source-status-after.txt: source-tree checks.\n\
             - candidates/candidate-NNN/: one isolated agent pass and its evidence.\n",
            run_options.linux_path.display(),
            run_options.count,
            run_options.api_key_env,
            run_options.api_base_url.unwrap_or("default provider"),
            run_options.model.unwrap_or("config/default"),
            sandbox_name(run_options.sandbox),
            run_options.dangerous_bypass,
            run_options.show_progress,
        ),
    )?;
    write_if_missing(&output_dir.join("PROMPT_TEMPLATE.md"), PROMPT_TEMPLATE)?;
    write_if_missing(
        process_log,
        "# Linux kernel vulnerability hunt process log\n\n\
         API key values are intentionally excluded from this file.\n",
    )?;
    Ok(())
}

pub(super) fn write_if_missing(path: &Path, contents: &str) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

pub(super) fn prepare_output_directory(path: &Path, protected_root: &Path) -> Result<PathBuf> {
    let resolved = canonicalize_path_before_create(path)?;
    ensure!(
        !resolved.starts_with(protected_root) && !protected_root.starts_with(&resolved),
        "--linux-path and --output-dir must be separate directories; source={} output={}",
        protected_root.display(),
        resolved.display()
    );
    fs::create_dir_all(&resolved).with_context(|| format!("creating {}", resolved.display()))?;
    fs::canonicalize(&resolved).with_context(|| format!("resolving {}", resolved.display()))
}

fn canonicalize_path_before_create(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolving the current directory for --output-dir")?
            .join(path)
    };
    let mut existing = absolute.clone();
    while !existing.exists() {
        existing = existing
            .parent()
            .context("--output-dir has no existing parent directory")?
            .to_path_buf();
    }

    let mut resolved = fs::canonicalize(&existing)
        .with_context(|| format!("resolving output parent {}", existing.display()))?;
    let missing = absolute
        .strip_prefix(&existing)
        .context("resolving the output path components")?;
    for component in missing.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(component) => resolved.push(component),
            Component::Prefix(_) | Component::RootDir => {}
        }
    }
    Ok(resolved)
}

pub(super) fn canonicalize_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let resolved =
        fs::canonicalize(path).with_context(|| format!("resolving {label} {}", path.display()))?;
    ensure!(
        resolved.is_dir(),
        "{label} is not a directory: {}",
        resolved.display()
    );
    Ok(resolved)
}

pub(super) fn validate_environment_variable_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && !name.contains('=') && !name.contains('\0'),
        "invalid API key environment variable name: {name:?}"
    );
    Ok(())
}

pub(super) fn validate_api_base_url(base_url: Option<&str>) -> Result<()> {
    let Some(base_url) = base_url else {
        return Ok(());
    };
    ensure!(
        !base_url.trim().is_empty(),
        "--api-base-url cannot be empty"
    );
    let parsed = url::Url::parse(base_url)
        .with_context(|| format!("invalid --api-base-url {base_url:?}"))?;
    ensure!(
        matches!(parsed.scheme(), "http" | "https"),
        "--api-base-url must use http or https"
    );
    Ok(())
}

pub(super) fn resolve_api_key(primary_env: &str) -> Option<OsString> {
    non_empty_env(primary_env).or_else(|| non_empty_env("CODEX_API_KEY"))
}

fn non_empty_env(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|value| !value.to_string_lossy().trim().is_empty())
}

pub(super) fn allocate_candidate_directory(root: &Path, start: u32) -> Result<(u32, PathBuf)> {
    for index in start..=100_000 {
        let candidate = root.join(format!("candidate-{index:03}"));
        if !candidate.exists() {
            return Ok((index, candidate));
        }
    }
    bail!(
        "could not allocate a candidate directory below {}",
        root.display()
    )
}

pub(super) fn render_prompt(
    linux_path: &Path,
    output_dir: &Path,
    candidate_dir: &Path,
    focus: Option<&str>,
    commit: Option<&str>,
) -> String {
    let focus = focus.unwrap_or("no extra focus; choose the strongest candidate autonomously");
    let commit = commit.unwrap_or("current HEAD and relevant local upstream history");
    let finding_index = output_dir.join("FINDING_INDEX.md");
    format!(
        "{PROMPT_TEMPLATE}\n\n\
         Runtime paths for this pass:\n\n\
         - Linux source: {linux_path}\n\
         - Overall output directory: {output_dir}\n\
         - Candidate directory: {candidate_dir}\n\
         - Duplicate exclusion index: {finding_index}\n\
         - Audit focus: {focus}\n\
         - First commit or revision to inspect: {commit}\n\n\
         Execution rules for this pass:\n\n\
         - Work on exactly one candidate. Do not pad the report with unrelated findings.\n\
         - Keep all generated files, builds, images, logs, and PoCs below the candidate directory.\n\
         - The source tree is read-only for this pass; use out-of-tree builds and temporary copies.\n\
         - Start by recording the exact git revision and source status.\n\
         - Before claiming success, run the PoC twice from a fresh setup and run at least one close control.\n\
         - Report a negative or inconclusive result honestly when the oracle is not stable.\n",
        linux_path = linux_path.display(),
        output_dir = output_dir.display(),
        candidate_dir = candidate_dir.display(),
        finding_index = finding_index.display(),
    )
}

pub(super) fn build_child_args(
    root_config_overrides: &CliConfigOverrides,
    run_options: &RunOptions<'_>,
    candidate_dir: &Path,
) -> Vec<OsString> {
    let mut args = Vec::new();
    for override_value in &root_config_overrides.raw_overrides {
        push_config_override(&mut args, override_value);
    }
    if let Some(base_url) = run_options.api_base_url {
        push_config_override(&mut args, &format!("model_provider={CUSTOM_PROVIDER_ID}"));
        push_config_override(
            &mut args,
            &format!(
                "model_providers.{CUSTOM_PROVIDER_ID}.name={}",
                toml_quote("Linux vulnerability research provider")
            ),
        );
        push_config_override(
            &mut args,
            &format!(
                "model_providers.{CUSTOM_PROVIDER_ID}.base_url={}",
                toml_quote(base_url)
            ),
        );
        push_config_override(
            &mut args,
            &format!("model_providers.{CUSTOM_PROVIDER_ID}.env_key=CODEX_API_KEY"),
        );
        push_config_override(
            &mut args,
            &format!("model_providers.{CUSTOM_PROVIDER_ID}.requires_openai_auth=false"),
        );
    }

    args.push(OsString::from("exec"));
    args.push(OsString::from("--skip-git-repo-check"));
    args.push(OsString::from("--ephemeral"));
    args.push(OsString::from("--json"));
    // Keep the agent's writable workspace rooted at the candidate directory.
    // The Linux source tree is intentionally only an explicit read target in
    // the prompt, so workspace-write cannot modify it accidentally.
    args.push(OsString::from("--cd"));
    args.push(candidate_dir.as_os_str().to_os_string());
    args.push(OsString::from("--add-dir"));
    args.push(run_options.output_dir.as_os_str().to_os_string());
    args.push(OsString::from("--add-dir"));
    args.push(candidate_dir.as_os_str().to_os_string());
    if let Some(model) = run_options.model {
        args.push(OsString::from("--model"));
        args.push(OsString::from(model));
    }
    if run_options.dangerous_bypass {
        args.push(OsString::from("--dangerously-bypass-approvals-and-sandbox"));
    } else {
        args.push(OsString::from("--sandbox"));
        args.push(OsString::from(sandbox_name(run_options.sandbox)));
    }
    args.push(OsString::from("--output-last-message"));
    args.push(candidate_dir.join("agent-final.md").into_os_string());
    args.push(OsString::from("-"));
    args
}

fn push_config_override(args: &mut Vec<OsString>, value: &str) {
    args.push(OsString::from("--config"));
    args.push(OsString::from(value));
}

fn toml_quote(value: &str) -> String {
    serde_json::Value::String(value.to_owned()).to_string()
}

pub(super) async fn run_agent(
    executable: &Path,
    args: &[OsString],
    working_dir: &Path,
    candidate_dir: &Path,
    api_key: Option<&OsStr>,
    prompt: &str,
    show_progress: bool,
) -> Result<ExitStatus> {
    let mut command = Command::new(executable);
    command
        .args(args)
        .current_dir(working_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(api_key) = api_key {
        command.env("CODEX_API_KEY", api_key);
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("spawning {}", executable.display()))?;

    let mut stdin = child.stdin.take().context("child stdin was not piped")?;
    stdin
        .write_all(prompt.as_bytes())
        .await
        .context("writing the research prompt to the child")?;
    drop(stdin);

    let stdout = child.stdout.take().context("child stdout was not piped")?;
    let stderr = child.stderr.take().context("child stderr was not piped")?;
    let stdout_task = collect_child_stream(stdout, show_progress, false);
    let stderr_task = collect_child_stream(stderr, show_progress, true);
    let (stdout, stderr, status) = tokio::join!(stdout_task, stderr_task, child.wait());
    let stdout = stdout.context("reading child Codex events")?;
    let stderr = stderr.context("reading child Codex stderr")?;
    let status = status.context("waiting for the child Codex session")?;

    fs::write(candidate_dir.join("agent-events.jsonl"), stdout)
        .with_context(|| format!("writing events in {}", candidate_dir.display()))?;
    fs::write(candidate_dir.join("agent-stderr.log"), stderr)
        .with_context(|| format!("writing stderr in {}", candidate_dir.display()))?;
    Ok(status)
}

async fn collect_child_stream<R>(stream: R, show_progress: bool, is_stderr: bool) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut reader = BufReader::new(stream);
    let mut collected = Vec::new();
    let mut line = Vec::new();
    let mut renderer = LiveProgressRenderer::default();

    loop {
        line.clear();
        let bytes_read = reader
            .read_until(b'\n', &mut line)
            .await
            .context("reading a child output line")?;
        if bytes_read == 0 {
            break;
        }
        collected.extend_from_slice(&line);
        if show_progress {
            if is_stderr {
                render_child_stderr(&line);
            } else {
                renderer.render_json_line(&line);
            }
        }
    }

    Ok(collected)
}

#[derive(Default)]
pub(super) struct LiveProgressRenderer {
    pub(super) command_output: HashMap<String, String>,
}

impl LiveProgressRenderer {
    pub(super) fn render_json_line(&mut self, line: &[u8]) {
        let Ok(event) = serde_json::from_slice::<Value>(line) else {
            let text = String::from_utf8_lossy(line);
            print_live(&format!("[codex] {}", text.trim_end()));
            return;
        };

        match event.get("type").and_then(Value::as_str) {
            Some("thread.started") => {
                if let Some(thread_id) = event.get("thread_id").and_then(Value::as_str) {
                    print_live(&format!("• thread started: {thread_id}"));
                }
            }
            Some("turn.started") => print_live("• turn started; agent is working"),
            Some("item.started") => {
                if let Some(item) = event.get("item") {
                    self.render_item_started(item);
                }
            }
            Some("item.updated") => {
                if let Some(item) = event.get("item") {
                    self.render_item_updated(item);
                }
            }
            Some("item.completed") => {
                if let Some(item) = event.get("item") {
                    self.render_item_completed(item);
                }
            }
            Some("turn.completed") => {
                let usage = event.get("usage");
                let input = usage
                    .and_then(|value| value.get("input_tokens"))
                    .and_then(Value::as_i64)
                    .unwrap_or_default();
                let output = usage
                    .and_then(|value| value.get("output_tokens"))
                    .and_then(Value::as_i64)
                    .unwrap_or_default();
                print_live(&format!(
                    "• turn completed (input: {input}, output: {output})"
                ));
            }
            Some("turn.failed") => {
                let message = event
                    .get("error")
                    .and_then(|error| error.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown turn failure");
                print_live(&format!("✗ turn failed: {message}"));
            }
            Some("error") => {
                let message = event
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown Codex error");
                print_live(&format!("✗ codex error: {message}"));
            }
            Some(event_type) => print_live(&format!("• codex event: {event_type}")),
            None => print_live("• codex event without a type"),
        }
    }

    fn render_item_started(&mut self, item: &Value) {
        match item.get("type").and_then(Value::as_str) {
            Some("command_execution") => {
                let command = item
                    .get("command")
                    .and_then(Value::as_str)
                    .unwrap_or("<command>");
                print_live(&format!("\nexec\n{command}"));
            }
            Some("mcp_tool_call") => {
                let server = item.get("server").and_then(Value::as_str).unwrap_or("?");
                let tool = item.get("tool").and_then(Value::as_str).unwrap_or("?");
                print_live(&format!("mcp: {server}/{tool} started"));
            }
            Some("web_search") => {
                let query = item.get("query").and_then(Value::as_str).unwrap_or("?");
                print_live(&format!("web search: {query}"));
            }
            Some("file_change") => print_live("apply patch"),
            Some("todo_list") => print_live("plan started"),
            Some(item_type) => print_live(&format!("item started: {item_type}")),
            None => {}
        }
    }

    fn render_item_updated(&mut self, item: &Value) {
        if item.get("type").and_then(Value::as_str) == Some("command_execution") {
            self.render_command_output(item);
        }
    }

    fn render_item_completed(&mut self, item: &Value) {
        match item.get("type").and_then(Value::as_str) {
            Some("agent_message") => {
                if let Some(text) = item.get("text").and_then(Value::as_str) {
                    print_live(&format!("\ncodex\n{text}"));
                }
            }
            Some("reasoning") => {
                if let Some(text) = item.get("text").and_then(Value::as_str)
                    && !text.trim().is_empty()
                {
                    print_live(text);
                }
            }
            Some("command_execution") => {
                let status = item
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("completed");
                let suffix = item
                    .get("exit_code")
                    .and_then(Value::as_i64)
                    .map(|code| format!(" (exit {code})"))
                    .unwrap_or_default();
                print_live(&format!("{status}{suffix}:"));
                self.render_command_output(item);
            }
            Some("file_change") => {
                let status = item
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("completed");
                print_live(&format!("patch: {status}"));
                if let Some(changes) = item.get("changes").and_then(Value::as_array) {
                    for change in changes {
                        if let Some(path) = change.get("path").and_then(Value::as_str) {
                            print_live(path);
                        }
                    }
                }
            }
            Some("mcp_tool_call") => {
                let server = item.get("server").and_then(Value::as_str).unwrap_or("?");
                let tool = item.get("tool").and_then(Value::as_str).unwrap_or("?");
                let status = item
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("completed");
                print_live(&format!("mcp: {server}/{tool} ({status})"));
                if let Some(error) = item
                    .get("error")
                    .and_then(|value| value.get("message"))
                    .and_then(Value::as_str)
                {
                    print_live(&format!("[mcp error] {error}"));
                }
            }
            Some("todo_list") => print_live("plan updated"),
            Some("error") => {
                if let Some(message) = item.get("message").and_then(Value::as_str) {
                    print_live(&format!("✗ {message}"));
                }
            }
            Some(item_type) => print_live(&format!("item completed: {item_type}")),
            None => {}
        }
    }

    fn render_command_output(&mut self, item: &Value) {
        let Some(item_id) = item.get("id").and_then(Value::as_str) else {
            return;
        };
        let output = item
            .get("aggregated_output")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let previous = self
            .command_output
            .insert(item_id.to_string(), output.to_string())
            .unwrap_or_default();
        let delta = output.strip_prefix(&previous).unwrap_or(output).trim_end();
        if !delta.is_empty() {
            print_live(delta);
        }
    }
}

fn render_child_stderr(line: &[u8]) {
    let text = String::from_utf8_lossy(line).trim_end().to_string();
    if !text.is_empty() {
        print_live(&format!("[codex] {text}"));
    }
}

fn print_live(text: &str) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{text}");
    let _ = stderr.flush();
}

pub(super) fn format_command_for_file(executable: &Path, args: &[OsString]) -> String {
    let mut lines = vec![shell_quote(&executable.to_string_lossy())];
    let mut redact_next_config = false;
    for arg in args {
        let value = arg.to_string_lossy();
        if value == "--config" || value == "-c" {
            lines.push(value.into_owned());
            redact_next_config = true;
            continue;
        }
        if redact_next_config {
            lines.push(redact_config_override(&value));
            redact_next_config = false;
        } else {
            lines.push(shell_quote(&value));
        }
    }
    lines.join(" ")
}

fn redact_config_override(value: &str) -> String {
    let Some((key, _)) = value.split_once('=') else {
        return shell_quote(value);
    };
    let lower_key = key.to_ascii_lowercase();
    let sensitive = lower_key.ends_with("api_key")
        || lower_key.contains("token")
        || lower_key.contains("secret")
        || lower_key.contains("password")
        || lower_key.contains("bearer");
    if sensitive {
        return format!("{key}=<redacted>");
    }
    shell_quote(value)
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "-_./:=,".contains(character))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub(super) fn append_log(path: &Path, contents: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("appending {}", path.display()))?;
    Ok(())
}

pub(super) fn source_snapshot(path: &Path) -> String {
    let head = git_output(path, &["rev-parse", "HEAD"]);
    let status = git_output(path, &["status", "--short"]);
    format!(
        "path: {}\nhead: {}\nstatus:\n{}\n",
        path.display(),
        head.trim(),
        if status.trim().is_empty() {
            "(clean or not a git worktree)"
        } else {
            status.trim()
        }
    )
}

fn git_output(path: &Path, args: &[&str]) -> String {
    let Ok(output) = StdCommand::new("git").args(args).current_dir(path).output() else {
        return "git command unavailable".to_string();
    };
    if output.status.success() {
        return String::from_utf8_lossy(&output.stdout).into_owned();
    }
    "not a git worktree or command failed".to_string()
}

pub(super) fn sandbox_name(sandbox: SandboxModeCliArg) -> &'static str {
    match sandbox {
        SandboxModeCliArg::ReadOnly => "read-only",
        SandboxModeCliArg::WorkspaceWrite => "workspace-write",
        SandboxModeCliArg::DangerFullAccess => "danger-full-access",
    }
}

pub(super) fn status_string(status: ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("code {code}"),
        None => "terminated by signal".to_string(),
    }
}
