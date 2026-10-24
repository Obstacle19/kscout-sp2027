//! Blind-review metric template emitted for each swarm candidate.

use super::kernel_vuln_swarm_policy::SwarmNormSet;
use anyhow::Context;
use anyhow::Result;
use std::fs;
use std::path::Path;

pub(super) fn write_evaluation_template(path: &Path, norm_set: &SwarmNormSet) -> Result<()> {
    let metrics = || {
        serde_json::json!({
            "valid_findings": 0,
            "total_tokens": 0,
            "total_tool_seconds": 0.0,
            "total_wall_clock_hours": 0.0,
            "completed_passes": 0,
            "candidate_count": 0,
            "first_valid_finding_seconds": null,
            "confirmed_findings": 0,
            "false_confirmations": 0,
            "redundant_explorations": 0,
            "explorations": 0,
            "no_gain_challenges": 0,
            "challenges": 0,
            "effective_evidence_items": 0,
            "interaction_tokens": 0,
            "evidence_resolved_disputes": 0,
            "key_disputes": 0,
            "unique_first_round_source_areas": 0,
            "first_round_participants": 0,
            "valid_leads_recovered_after_suspension": 0
        })
    };
    let conditions = || {
        serde_json::json!({
            "source_revision": "",
            "model": "",
            "agent_count": 0,
            "focus": "",
            "extra_prompt_sha256": "",
            "kernel_config_sha256": "",
            "evaluation_task_set_sha256": "",
            "environment_id": ""
        })
    };
    let template = serde_json::json!({
        "schema_version": 1,
        "source_norm_version": norm_set.version,
        "split": "train",
        "audit_tasks": 0,
        "repeated_runs": 0,
        "budget_regime": "fixed_total_budget",
        "total_token_budget": 0,
        "total_tool_seconds_budget": 0.0,
        "independently_evaluated": false,
        "reviewer_blinded_to_architecture": false,
        "baseline_conditions": conditions(),
        "norm_guided_conditions": conditions(),
        "baseline_trace_files": [],
        "norm_guided_trace_files": [],
        "baseline": metrics(),
        "norm_guided": metrics()
    });
    fs::write(
        path,
        serde_json::to_vec_pretty(&template).context("serializing evaluator feedback template")?,
    )
    .with_context(|| format!("writing evaluator feedback template {}", path.display()))
}
