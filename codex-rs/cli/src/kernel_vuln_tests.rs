use super::kernel_vuln_support::LiveProgressRenderer;
use super::*;
use codex_utils_cli::CliConfigOverrides;
use pretty_assertions::assert_eq;
use std::ffi::OsString;
use tempfile::tempdir;

#[test]
fn candidate_directory_allocation_skips_existing_data() {
    let temp = tempdir().expect("temporary directory");
    let root = temp.path().join("candidates");
    std::fs::create_dir_all(root.join("candidate-001")).expect("existing candidate");

    let (index, path) = allocate_candidate_directory(&root, 1).expect("allocate candidate");

    assert_eq!(index, 2);
    assert_eq!(path, root.join("candidate-002"));
}

#[test]
fn finding_index_includes_each_archived_swarm_finding() {
    let temp = tempdir().expect("temporary directory");
    let candidates = temp.path().join("candidates");
    let finding = candidates.join("candidate-001/findings/lead-one");
    std::fs::create_dir_all(&finding).expect("create finding archive");
    std::fs::write(
        candidates.join("candidate-001/finding-fingerprint.md"),
        "Outcome: plausible\nTitle: Aggregate swarm result\n",
    )
    .expect("write aggregate fingerprint");
    std::fs::write(
        finding.join("finding-fingerprint.md"),
        "Outcome: confirmed\nTitle: Individual issue one\nRoot cause/invariant: invariant one\n",
    )
    .expect("write finding fingerprint");
    let index = temp.path().join("FINDING_INDEX.md");

    super::kernel_vuln_dedup::refresh_finding_index(&candidates, &index)
        .expect("refresh finding index");

    let contents = std::fs::read_to_string(index).expect("read finding index");
    assert!(!contents.contains("Aggregate swarm result"));
    assert!(contents.contains("Individual issue one"));
}

#[test]
fn child_command_keeps_api_key_out_of_argv() {
    let run_options = RunOptions {
        linux_path: Path::new("/tmp/linux"),
        output_dir: Path::new("/tmp/output"),
        count: 1,
        swarm: false,
        swarm_agents: 3,
        swarm_rounds: 2,
        api_key_env: "OPENAI_API_KEY",
        api_base_url: Some("https://api.example.test/v1"),
        model: Some("research-model"),
        sandbox: SandboxModeCliArg::ReadOnly,
        dangerous_bypass: false,
        show_progress: true,
    };
    let args = build_child_args(
        &CliConfigOverrides::default(),
        &run_options,
        Path::new("/tmp/output/candidates/candidate-001"),
        &[Path::new("/tmp/output")],
    );

    let rendered = format_command_for_file(Path::new("/tmp/codex"), &args);

    assert!(!rendered.contains("sk-secret"));
    assert!(rendered.contains("exec"));
    assert!(rendered.contains("--cd /tmp/output/candidates/candidate-001"));
    assert!(rendered.contains("--add-dir /tmp/output"));
    assert!(rendered.contains("--sandbox read-only"));
    assert!(rendered.ends_with(" -"));
}

#[test]
fn live_progress_renderer_tracks_incremental_command_output() {
    let mut renderer = LiveProgressRenderer::default();

    renderer.render_json_line(
        br#"{"type":"item.started","item":{"id":"cmd-1","type":"command_execution","command":"git status","status":"in_progress"}}"#,
    );
    renderer.render_json_line(
        br#"{"type":"item.updated","item":{"id":"cmd-1","type":"command_execution","aggregated_output":"clean\n","status":"in_progress"}}"#,
    );
    renderer.render_json_line(
        br#"{"type":"item.completed","item":{"id":"msg-1","type":"agent_message","text":"candidate checked"}}"#,
    );

    assert_eq!(
        renderer.command_output.get("cmd-1").map(String::as_str),
        Some("clean\n")
    );
}

#[test]
fn sensitive_config_values_are_redacted_in_saved_command() {
    let args = vec![
        OsString::from("--config"),
        OsString::from("provider.experimental_bearer_token=sk-secret"),
    ];

    let rendered = format_command_for_file(Path::new("/tmp/codex"), &args);

    assert_eq!(
        rendered,
        "/tmp/codex --config provider.experimental_bearer_token=<redacted>"
    );
}

#[test]
fn prompt_contains_each_runtime_output_path() {
    let prompt = render_prompt(
        Path::new("/tmp/linux"),
        Path::new("/tmp/output"),
        Path::new("/tmp/output/candidates/candidate-001"),
        Some("fs/ntfs3"),
        Some("deadbeef"),
    );

    assert!(prompt.contains("/tmp/linux"));
    assert!(prompt.contains("/tmp/output"));
    assert!(prompt.contains("fs/ntfs3"));
    assert!(prompt.contains("deadbeef"));
}

#[test]
fn cve_rules_are_disabled_by_default_and_enabled_only_by_flag() {
    let default_command = KernelVulnCommand::try_parse_from(["kernel-vuln"])
        .expect("default kernel-vuln command should parse");
    assert!(!default_command.use_cve_rules);
    assert!(!default_command.swarm);
    assert_eq!(default_command.swarm_agents, 3);
    assert_eq!(default_command.swarm_rounds, 2);
    assert!(!default_command.rule_mode_enabled());

    let swarm_command = KernelVulnCommand::try_parse_from([
        "kernel-vuln",
        "--swarm",
        "--swarm-agents",
        "5",
        "--swarm-rounds",
        "3",
    ])
    .expect("swarm options should parse");
    assert!(swarm_command.swarm);
    assert_eq!(swarm_command.swarm_agents, 5);
    assert_eq!(swarm_command.swarm_rounds, 3);

    let legacy_command = KernelVulnCommand::try_parse_from(["kernel-vuln", "--multi-agent"])
        .expect("legacy multi-agent alias should parse");
    assert!(legacy_command.swarm);

    assert!(KernelVulnCommand::try_parse_from(["kernel-vuln", "--swarm-agents", "9"]).is_err());
    assert!(KernelVulnCommand::try_parse_from(["kernel-vuln", "--swarm-rounds", "0"]).is_err());

    let rule_command = KernelVulnCommand::try_parse_from(["kernel-vuln", "--use-cve-rules"])
        .expect("CVE-rule option should parse");
    assert!(rule_command.use_cve_rules);
    assert!(rule_command.rule_mode_enabled());

    let selected_rules = KernelVulnCommand::try_parse_from([
        "kernel-vuln",
        "--cve-rule",
        "CVE-2025-38193",
        "--cve-rule",
        "CVE-2023-52640",
    ])
    .expect("repeated CVE-rule selectors should parse");
    assert!(!selected_rules.use_cve_rules);
    assert!(selected_rules.rule_mode_enabled());
    assert_eq!(
        selected_rules.cve_rules,
        ["CVE-2025-38193".to_string(), "CVE-2023-52640".to_string()]
    );
}

#[test]
fn cve_rule_mode_uses_the_count_as_a_total_review_budget() {
    assert_eq!(scheduled_pass_counts(3, 7, true), (3, 3));
    assert_eq!(scheduled_pass_counts(3, 1, true), (1, 1));
    assert_eq!(scheduled_pass_counts(3, 0, true), (0, 0));
    assert_eq!(scheduled_pass_counts(3, 7, false), (3, 0));
}

#[cfg(unix)]
#[tokio::test]
async fn swarm_runs_peer_rounds_archives_all_findings_and_gates_confirmation() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().expect("temporary directory");
    let linux = temp.path().join("linux");
    let output = temp.path().join("output");
    let candidate = output.join("candidates/candidate-001");
    std::fs::create_dir_all(&linux).expect("create linux source fixture");
    std::fs::create_dir_all(&candidate).expect("create candidate fixture");
    std::fs::write(output.join("PROCESS_LOG.md"), "# process log\n").expect("process log");

    let mock_codex = temp.path().join("mock-codex");
    std::fs::write(
        &mock_codex,
        r##"#!/bin/sh
final_path=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output-last-message" ]; then
    shift
    final_path="$1"
    break
  fi
  shift
done
cat >/dev/null
printf 'Mock participant completed.\n' > "$final_path"
printf '%s\n' '{"type":"turn.completed","usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}'
agent=$(basename "$PWD")
cat > "$PWD/candidate-report.md" <<'EOF'
Mock report with reproducible evidence.
EOF
cat > "$PWD/finding-fingerprint.md" <<'EOF'
Outcome: confirmed
Title: Shared mock issue
Subsystem: test
Affected files/functions: fixture
Root cause/invariant: stable mock invariant
User-controlled trigger: test input
Observable oracle: deterministic mock oracle
Affected revision: fixture
Duplicate-of: none
EOF
for number in 01 02 03; do
  lead="lead-"$agent"-"$number
  mkdir -p "$PWD/findings/$lead"
  cat > "$PWD/findings/$lead/candidate-report.md" <<EOF
Distinct mock report for $lead.
EOF
  cat > "$PWD/findings/$lead/finding-fingerprint.md" <<EOF
Outcome: confirmed
Title: Distinct issue $lead
Subsystem: test
Affected files/functions: fixture
Root cause/invariant: invariant for $lead
User-controlled trigger: test input
Observable oracle: deterministic mock oracle
Affected revision: fixture
Duplicate-of: none
EOF
done
cat > "$PWD/SWARM_UPDATE.md" <<'EOF'
Round status: active
No mock follow-up required.
EOF
case "$PWD" in
  */round-02/*)
    if grep -q '## Round 1 contributions' "$PWD/../../../SWARM_BOARD.md"; then
      printf 'Round 1 board read successfully.\n' > "$PWD/SWARM_BOARD_SEEN.md"
    fi
    ;;
esac
"##,
    )
    .expect("write mock Codex executable");
    let mut permissions = std::fs::metadata(&mock_codex)
        .expect("read mock executable metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&mock_codex, permissions).expect("make mock executable");

    let run_options = RunOptions {
        linux_path: &linux,
        output_dir: &output,
        count: 1,
        swarm: true,
        swarm_agents: 2,
        swarm_rounds: 2,
        api_key_env: "OPENAI_API_KEY",
        api_base_url: None,
        model: Some("mock-model"),
        sandbox: SandboxModeCliArg::WorkspaceWrite,
        dangerous_bypass: false,
        show_progress: false,
    };
    let root_config_overrides = CliConfigOverrides::default();
    let run_started_at = chrono::Utc::now().to_rfc3339();
    let outcome =
        super::kernel_vuln_swarm::run_candidate(super::kernel_vuln_swarm::SwarmRunRequest {
            root_config_overrides: &root_config_overrides,
            run_options: &run_options,
            candidate_index: 1,
            candidate_dir: &candidate,
            executable: &mock_codex,
            api_key: None,
            run_started_at: &run_started_at,
            focus: None,
            commit: None,
            extra_prompt: None,
            dry_run: false,
            rule_review: None,
            agent_count: 2,
            round_count: 2,
        })
        .await
        .expect("run mock swarm");

    assert_eq!(outcome.child_result, "success");
    assert_eq!(outcome.token_usage.total_tokens, Some(16));
    let root_fingerprint = std::fs::read_to_string(candidate.join("finding-fingerprint.md"))
        .expect("read aggregate fingerprint");
    assert!(root_fingerprint.starts_with("Outcome: confirmed\n"));
    let findings = std::fs::read_dir(candidate.join("findings"))
        .expect("read archived findings")
        .count();
    assert_eq!(
        findings, 16,
        "all four participant sessions' findings archive"
    );
    let report = std::fs::read_to_string(candidate.join("candidate-report.md"))
        .expect("read grouped candidate report");
    assert!(
        report.contains("7. **"),
        "repeat claims group into 7 logical findings"
    );
    assert!(candidate.join("SWARM_BOARD.md").is_file());
    assert!(
        candidate
            .join("agents/round-02/agent-01/SWARM_BOARD_SEEN.md")
            .is_file()
    );
    assert!(
        candidate
            .join("agents/round-02/agent-02/SWARM_BOARD_SEEN.md")
            .is_file()
    );
    for round in ["round-01", "round-02"] {
        for agent in ["agent-01", "agent-02"] {
            assert!(
                candidate
                    .join(format!("agents/{round}/{agent}/usage.json"))
                    .is_file()
            );
        }
    }

    let isolated_finding = std::fs::read_dir(candidate.join("findings"))
        .expect("read finding archive")
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            std::fs::read_to_string(path.join("finding-fingerprint.md"))
                .is_ok_and(|fingerprint| fingerprint.contains("Distinct issue"))
        })
        .expect("find independently unsupported mock finding");
    let isolated_fingerprint =
        std::fs::read_to_string(isolated_finding.join("finding-fingerprint.md"))
            .expect("read isolated fingerprint");
    assert!(isolated_fingerprint.starts_with("Outcome: plausible\n"));
}
