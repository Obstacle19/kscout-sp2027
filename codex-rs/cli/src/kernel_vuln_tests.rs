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
fn child_command_keeps_api_key_out_of_argv() {
    let run_options = RunOptions {
        linux_path: Path::new("/tmp/linux"),
        output_dir: Path::new("/tmp/output"),
        count: 1,
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
    );

    let rendered = format_command_for_file(Path::new("/tmp/codex"), &args);

    assert!(!rendered.contains("sk-secret"));
    assert!(rendered.contains("exec"));
    assert!(rendered.contains("--cd /tmp/output/candidates/candidate-001"));
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
