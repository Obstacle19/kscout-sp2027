//! External, independently configured verification runner protocol.

use anyhow::Context;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use std::fs;
use std::path::Component;
use std::path::Path;
use std::process::Command as StdCommand;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

use super::kernel_vuln_swarm_consensus::LeadTriage;

const RUNNER_SCHEMA_VERSION: u32 = 1;
const RUNNER_TIMEOUT: Duration = Duration::from_secs(30 * 60);

pub(super) struct VerifyLeadsRequest<'a> {
    pub(super) runner: Option<&'a Path>,
    pub(super) candidate_dir: &'a Path,
    pub(super) scratch_root: &'a Path,
    pub(super) linux_source: &'a Path,
    pub(super) requested_revision: Option<&'a str>,
    pub(super) norm_version: u32,
    pub(super) leads: &'a [LeadTriage],
    pub(super) keep_scratch: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct VerificationRecord {
    pub(super) lead_id: String,
    pub(super) status: String,
    pub(super) verifier: Option<String>,
    pub(super) isolation: Option<String>,
    pub(super) clean_setup: Option<bool>,
    pub(super) positive_repetitions: Option<u32>,
    pub(super) negative_controls: Option<u32>,
    pub(super) vm_queue_seconds: Option<f64>,
    pub(super) vm_execution_seconds: Option<f64>,
    pub(super) kernel_revision: Option<String>,
    pub(super) kernel_config_sha256: Option<String>,
    pub(super) evidence_refs: Vec<String>,
    pub(super) detail: String,
}

#[derive(Serialize)]
struct VerificationRequest<'a> {
    schema_version: u32,
    candidate: String,
    lead_id: &'a str,
    title: &'a str,
    linux_source: &'a str,
    requested_revision: Option<&'a str>,
    expected_source_revision: Option<String>,
    evidence_refs: Vec<String>,
    reported_local_executions: usize,
    independent_analysis_reports: usize,
    required_checks: [&'static str; 7],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnerOutput {
    schema_version: u32,
    lead_id: String,
    verifier: String,
    status: String,
    isolation: String,
    clean_setup: bool,
    positive_repetitions: u32,
    negative_controls: u32,
    vm_queue_seconds: f64,
    vm_execution_seconds: f64,
    kernel_revision: String,
    kernel_config_sha256: String,
    evidence_refs: Vec<String>,
    summary: String,
}

pub(super) async fn verify_leads(
    request: VerifyLeadsRequest<'_>,
) -> Result<Vec<VerificationRecord>> {
    let VerifyLeadsRequest {
        runner,
        candidate_dir,
        scratch_root,
        linux_source,
        requested_revision,
        norm_version,
        leads,
        keep_scratch,
    } = request;
    let verification_dir = candidate_dir.join("verification");
    let request_dir = verification_dir.join("requests");
    let result_dir = verification_dir.join("results");
    fs::create_dir_all(&request_dir)
        .with_context(|| format!("creating verifier requests in {}", request_dir.display()))?;
    fs::create_dir_all(&result_dir)
        .with_context(|| format!("creating verifier results in {}", result_dir.display()))?;
    let candidate = candidate_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("candidate")
        .to_string();
    let expected_source_revision = resolve_source_revision(linux_source);
    let mut records = Vec::with_capacity(leads.len());
    for (lead_index, lead) in leads.iter().enumerate() {
        let id = format!("{}-{lead_index:03}", safe_component(&lead.lead_id));
        let request_path = request_dir.join(format!("{id}.json"));
        let result_path = result_dir.join(format!("{id}.json"));
        let linux_source_path = linux_source.display().to_string();
        let request = VerificationRequest {
            schema_version: RUNNER_SCHEMA_VERSION,
            candidate: candidate.clone(),
            lead_id: &lead.lead_id,
            title: &lead.title,
            linux_source: &linux_source_path,
            requested_revision,
            expected_source_revision: expected_source_revision.clone(),
            evidence_refs: lead
                .evidence_paths
                .iter()
                .map(|path| {
                    path.strip_prefix(candidate_dir)
                        .unwrap_or(path)
                        .display()
                        .to_string()
                })
                .collect(),
            reported_local_executions: lead.reproduced_participant_count,
            independent_analysis_reports: lead.independent_analysis_count,
            required_checks: [
                "run the positive case at least twice from a clean setup",
                "run at least one close negative control",
                "record the exact kernel revision and configuration",
                "record the SHA-256 digest of the exact kernel .config used",
                "perform all execution inside an isolated virtual machine",
                "record VM queue time in seconds",
                "record VM execution time in seconds",
            ],
        };
        fs::write(
            &request_path,
            serde_json::to_vec_pretty(&request).context("serializing verification request")?,
        )
        .with_context(|| format!("writing verification request {}", request_path.display()))?;

        let Some(runner) = runner else {
            records.push(VerificationRecord {
                lead_id: lead.lead_id.clone(),
                status: "NOT_RUN".to_string(),
                verifier: None,
                isolation: None,
                clean_setup: None,
                positive_repetitions: None,
                negative_controls: None,
                vm_queue_seconds: None,
                vm_execution_seconds: None,
                kernel_revision: None,
                kernel_config_sha256: None,
                evidence_refs: Vec::new(),
                detail: "No external verification runner was configured.".to_string(),
            });
            continue;
        };

        let work_dir = scratch_root.join("runner").join(&id);
        fs::create_dir_all(&work_dir)
            .with_context(|| format!("creating verifier scratch in {}", work_dir.display()))?;
        let path = std::env::var_os("PATH").unwrap_or_default();
        let output = timeout(
            RUNNER_TIMEOUT,
            Command::new(runner)
                .arg("--request")
                .arg(&request_path)
                .arg("--result")
                .arg(&result_path)
                .current_dir(&work_dir)
                .env_clear()
                .env("PATH", path)
                .env("TMPDIR", &work_dir)
                .env("TEMP", &work_dir)
                .env("HOME", &work_dir)
                .kill_on_drop(true)
                .output(),
        )
        .await;
        match output {
            Err(_) => records.push(VerificationRecord {
                lead_id: lead.lead_id.clone(),
                status: "RUNNER_INCONCLUSIVE".to_string(),
                verifier: Some(runner.display().to_string()),
                isolation: None,
                clean_setup: None,
                positive_repetitions: None,
                negative_controls: None,
                vm_queue_seconds: None,
                vm_execution_seconds: None,
                kernel_revision: None,
                kernel_config_sha256: None,
                evidence_refs: Vec::new(),
                detail: format!(
                    "Verifier exceeded the {} second timeout.",
                    RUNNER_TIMEOUT.as_secs()
                ),
            }),
            Ok(Err(error)) => records.push(VerificationRecord {
                lead_id: lead.lead_id.clone(),
                status: "RUNNER_INCONCLUSIVE".to_string(),
                verifier: Some(runner.display().to_string()),
                isolation: None,
                clean_setup: None,
                positive_repetitions: None,
                negative_controls: None,
                vm_queue_seconds: None,
                vm_execution_seconds: None,
                kernel_revision: None,
                kernel_config_sha256: None,
                evidence_refs: Vec::new(),
                detail: format!("Could not start the configured verifier: {error}"),
            }),
            Ok(Ok(output)) => {
                fs::write(result_dir.join(format!("{id}.stdout")), &output.stdout)
                    .with_context(|| format!("saving verifier stdout for lead {}", lead.lead_id))?;
                fs::write(result_dir.join(format!("{id}.stderr")), &output.stderr)
                    .with_context(|| format!("saving verifier stderr for lead {}", lead.lead_id))?;
                let record = parse_runner_result(
                    &result_path,
                    output.status.success(),
                    runner,
                    candidate_dir,
                    &lead.lead_id,
                    expected_source_revision.as_deref(),
                )?;
                records.push(record);
            }
        }
        if !keep_scratch {
            let _ = fs::remove_dir_all(&work_dir);
        }
    }
    let manifest = serde_json::json!({
        "schema_version": RUNNER_SCHEMA_VERSION,
        "norm_version": norm_version,
        "runner_configured": runner.is_some(),
        "runner_protocol": "<runner> --request REQUEST.json --result RESULT.json",
        "results": records
    });
    fs::write(
        verification_dir.join("SWARM_VERIFICATION.json"),
        serde_json::to_vec_pretty(&manifest).context("serializing verification manifest")?,
    )
    .with_context(|| {
        format!(
            "writing verification manifest in {}",
            verification_dir.display()
        )
    })?;
    Ok(records)
}

fn parse_runner_result(
    result_path: &Path,
    process_succeeded: bool,
    runner: &Path,
    candidate_dir: &Path,
    assigned_lead_id: &str,
    expected_source_revision: Option<&str>,
) -> Result<VerificationRecord> {
    let output = fs::read_to_string(result_path).ok();
    let parsed = output
        .as_deref()
        .and_then(|text| serde_json::from_str::<RunnerOutput>(text).ok());
    let Some(parsed) = parsed else {
        return Ok(VerificationRecord {
            lead_id: assigned_lead_id.to_string(),
            status: "RUNNER_INCONCLUSIVE".to_string(),
            verifier: Some(runner.display().to_string()),
            isolation: None,
            clean_setup: None,
            positive_repetitions: None,
            negative_controls: None,
            vm_queue_seconds: None,
            vm_execution_seconds: None,
            kernel_revision: None,
            kernel_config_sha256: None,
            evidence_refs: Vec::new(),
            detail: "Verifier did not produce a valid schema-version 1 result file.".to_string(),
        });
    };
    let (evidence_refs, invalid_refs) = validate_runner_refs(candidate_dir, &parsed.evidence_refs);
    let common_checks_pass = process_succeeded
        && parsed.schema_version == RUNNER_SCHEMA_VERSION
        && normalize_id(&parsed.lead_id) == normalize_id(assigned_lead_id)
        && parsed.isolation == "isolated_vm"
        && parsed.clean_setup
        && parsed.vm_queue_seconds.is_finite()
        && parsed.vm_queue_seconds >= 0.0
        && parsed.vm_execution_seconds.is_finite()
        && parsed.vm_execution_seconds >= 0.0
        && !parsed.kernel_revision.trim().is_empty()
        && expected_source_revision
            .is_some_and(|revision| parsed.kernel_revision.eq_ignore_ascii_case(revision))
        && is_sha256_hex(&parsed.kernel_config_sha256)
        && !evidence_refs.is_empty()
        && invalid_refs.is_empty();
    let checks_pass = common_checks_pass
        && parsed.status.eq_ignore_ascii_case("verified")
        && parsed.positive_repetitions >= 2
        && parsed.negative_controls >= 1;
    let status = if checks_pass {
        "RUNNER_VERIFIED"
    } else if common_checks_pass
        && parsed.status.eq_ignore_ascii_case("rejected")
        && parsed.negative_controls >= 1
    {
        "RUNNER_REJECTED"
    } else {
        "RUNNER_INCONCLUSIVE"
    };
    let detail = if checks_pass {
        parsed.summary
    } else {
        format!(
            "{}; required isolated VM, clean setup, two positive repetitions, one negative control, finite nonnegative VM queue/execution timings, exact source HEAD match, SHA-256 kernel config, matching lead ID, and in-candidate evidence references. Expected source HEAD: {}. Invalid references: {}",
            parsed.summary,
            expected_source_revision.unwrap_or("unavailable; verification cannot be confirmed"),
            if invalid_refs.is_empty() {
                "none".to_string()
            } else {
                invalid_refs.join(", ")
            }
        )
    };
    Ok(VerificationRecord {
        lead_id: assigned_lead_id.to_string(),
        status: status.to_string(),
        verifier: Some(parsed.verifier),
        isolation: Some(parsed.isolation),
        clean_setup: Some(parsed.clean_setup),
        positive_repetitions: Some(parsed.positive_repetitions),
        negative_controls: Some(parsed.negative_controls),
        vm_queue_seconds: Some(parsed.vm_queue_seconds),
        vm_execution_seconds: Some(parsed.vm_execution_seconds),
        kernel_revision: Some(parsed.kernel_revision),
        kernel_config_sha256: Some(parsed.kernel_config_sha256),
        evidence_refs,
        detail,
    })
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn resolve_source_revision(linux_source: &Path) -> Option<String> {
    let output = StdCommand::new("git")
        .arg("-C")
        .arg(linux_source)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let revision = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if revision.len() < 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(revision.to_ascii_lowercase())
}

fn validate_runner_refs(candidate_dir: &Path, references: &[String]) -> (Vec<String>, Vec<String>) {
    let Ok(candidate_root) = fs::canonicalize(candidate_dir) else {
        return (Vec::new(), references.to_vec());
    };
    let mut valid = Vec::new();
    let mut invalid = Vec::new();
    for reference in references {
        let relative = Path::new(reference);
        if relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            invalid.push(reference.clone());
            continue;
        }
        let Ok(path) = fs::canonicalize(candidate_root.join(relative)) else {
            invalid.push(reference.clone());
            continue;
        };
        if !path.starts_with(&candidate_root) || !path.is_file() {
            invalid.push(reference.clone());
            continue;
        }
        valid.push(
            path.strip_prefix(&candidate_root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned(),
        );
    }
    (valid, invalid)
}

fn safe_component(value: &str) -> String {
    let safe = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '-')
        .take(80)
        .collect::<String>();
    if safe.is_empty() {
        "lead".to_string()
    } else {
        safe
    }
}

fn normalize_id(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}
