//! Trace-induced norm updates gated by independent, controlled evaluation.

use super::kernel_vuln_swarm_policy::EvaluationMetrics;
use super::kernel_vuln_swarm_policy::NormUpdateRecord;
use super::kernel_vuln_swarm_policy::SwarmNormSet;
use super::kernel_vuln_swarm_trace::challenge_specificity_rate;
use super::kernel_vuln_swarm_trace::no_gain_rate;
use super::kernel_vuln_swarm_trace::repeated_area_rate;
use super::kernel_vuln_swarm_trace::summarize_trace_comparison;
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluatorFeedback {
    schema_version: u32,
    source_norm_version: u32,
    split: String,
    audit_tasks: u32,
    repeated_runs: u32,
    budget_regime: String,
    total_token_budget: u64,
    total_tool_seconds_budget: f64,
    independently_evaluated: bool,
    reviewer_blinded_to_architecture: bool,
    baseline_conditions: ExperimentConditions,
    norm_guided_conditions: ExperimentConditions,
    baseline_trace_files: Vec<String>,
    norm_guided_trace_files: Vec<String>,
    baseline: EvaluationMetrics,
    norm_guided: EvaluationMetrics,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ExperimentConditions {
    source_revision: String,
    model: String,
    agent_count: u8,
    focus: String,
    extra_prompt_sha256: String,
    kernel_config_sha256: String,
    evaluation_task_set_sha256: String,
    environment_id: String,
}

pub(super) fn adapt_norm_set(
    feedback_path: &Path,
    source_norms_path: Option<&Path>,
    output_path: &Path,
) -> Result<SwarmNormSet> {
    let output_identity = canonical_target_path(output_path)?;
    ensure!(
        canonical_target_path(feedback_path)? != output_identity,
        "norm feedback and output paths must be different"
    );
    if let Some(source_norms_path) = source_norms_path {
        ensure!(
            canonical_target_path(source_norms_path)? != output_identity,
            "the new norm version must use a different path from its parent version"
        );
    }
    let contents = fs::read_to_string(feedback_path)
        .with_context(|| format!("reading norm feedback {}", feedback_path.display()))?;
    let feedback: EvaluatorFeedback = serde_json::from_str(&contents)
        .with_context(|| format!("parsing norm feedback {}", feedback_path.display()))?;
    ensure!(
        feedback.schema_version == 1,
        "unsupported norm feedback schema version"
    );
    ensure!(
        feedback.independently_evaluated && feedback.reviewer_blinded_to_architecture,
        "norm updates require independent evaluation blinded to architecture"
    );
    ensure!(
        matches!(feedback.split.as_str(), "train" | "validation"),
        "norm updates accept train or validation feedback; test feedback must remain frozen"
    );
    ensure!(
        feedback.audit_tasks >= 3,
        "norm updates require at least three independent audit tasks"
    );
    ensure!(
        feedback.repeated_runs >= 3,
        "norm updates require at least three repeated runs"
    );
    ensure!(
        feedback.budget_regime == "fixed_total_budget",
        "norm updates require a fixed-total-budget comparison"
    );
    ensure!(
        feedback.baseline_conditions == feedback.norm_guided_conditions,
        "baseline and norm-guided conditions must match in source, model, agent count, focus, prompts, kernel configuration, task set, and environment"
    );
    validate_experiment_conditions(&feedback.baseline_conditions)?;
    let mut norms = SwarmNormSet::load(source_norms_path)?;
    ensure!(
        feedback.source_norm_version == norms.version,
        "feedback references norm version {}, but the source norm set is version {}",
        feedback.source_norm_version,
        norms.version
    );
    validate_metrics(&feedback.baseline)?;
    validate_metrics(&feedback.norm_guided)?;
    ensure!(
        feedback.total_token_budget > 0
            && feedback.baseline.total_tokens <= feedback.total_token_budget
            && feedback.norm_guided.total_tokens <= feedback.total_token_budget,
        "both architectures must stay within the shared positive total-token budget"
    );
    ensure!(
        feedback.total_tool_seconds_budget.is_finite()
            && feedback.total_tool_seconds_budget > 0.0
            && feedback.baseline.total_tool_seconds <= feedback.total_tool_seconds_budget
            && feedback.norm_guided.total_tool_seconds <= feedback.total_tool_seconds_budget,
        "both architectures must stay within the shared positive tool-time budget"
    );
    let (baseline_trace_observation, norm_guided_trace_observation) = summarize_trace_comparison(
        feedback_path,
        &feedback.baseline_trace_files,
        &feedback.norm_guided_trace_files,
    )?;
    let mut decisions = Vec::new();
    let mut induced_guidance = Vec::new();

    let baseline_false_rate = rate(
        feedback.baseline.false_confirmations,
        feedback.baseline.confirmed_findings,
    );
    let guided_false_rate = rate(
        feedback.norm_guided.false_confirmations,
        feedback.norm_guided.confirmed_findings,
    );
    ensure!(
        guided_false_rate <= baseline_false_rate,
        "norm-guided feedback has a higher false-confirmation rate; no new norm version was written"
    );

    let baseline_efficiency = efficiency(
        feedback.baseline.valid_findings,
        feedback.baseline.total_tokens,
    );
    let guided_efficiency = efficiency(
        feedback.norm_guided.valid_findings,
        feedback.norm_guided.total_tokens,
    );
    let guided_wall_clock_efficiency = wall_clock_efficiency(&feedback.norm_guided);
    let baseline_wall_clock_efficiency = wall_clock_efficiency(&feedback.baseline);
    let baseline_redundancy = rate(
        feedback.baseline.redundant_explorations,
        feedback.baseline.explorations,
    );
    let guided_redundancy = rate(
        feedback.norm_guided.redundant_explorations,
        feedback.norm_guided.explorations,
    );
    let baseline_no_gain = rate(
        feedback.baseline.no_gain_challenges,
        feedback.baseline.challenges,
    );
    let guided_no_gain = rate(
        feedback.norm_guided.no_gain_challenges,
        feedback.norm_guided.challenges,
    );

    let trace_redundancy_regressed = repeated_area_rate(&norm_guided_trace_observation)
        > repeated_area_rate(&baseline_trace_observation) + 0.05;
    let diversity_regressed = first_round_diversity(&feedback.norm_guided) + 0.1
        < first_round_diversity(&feedback.baseline);
    if guided_redundancy > baseline_redundancy + 0.05
        || trace_redundancy_regressed
        || diversity_regressed
    {
        norms.resource_policy.exploration_min_percent =
            (norms.resource_policy.exploration_min_percent + 5).min(60);
        norms.resource_policy.exploration_max_percent =
            (norms.resource_policy.exploration_max_percent + 5).min(70);
        decisions.push(
            "Raised the exploration share by five points because evaluator redundancy or trace-measured source-area repetition increased by more than five percentage points.".to_string(),
        );
    } else if guided_efficiency < baseline_efficiency * 0.95
        || pass_efficiency(&feedback.norm_guided) < pass_efficiency(&feedback.baseline) * 0.95
        || guided_wall_clock_efficiency < baseline_wall_clock_efficiency * 0.95
    {
        norms.resource_policy.exploration_max_percent =
            (norms.resource_policy.exploration_max_percent + 5).min(70);
        decisions.push(
            "Raised the maximum exploration share by five points because valid findings per token fell by more than five percent.".to_string(),
        );
    } else {
        decisions.push(
            "Kept exploration shares because valid-finding efficiency and redundancy did not trigger a bounded adjustment.".to_string(),
        );
    }

    if feedback.norm_guided.valid_leads_recovered_after_suspension
        > feedback.baseline.valid_leads_recovered_after_suspension
    {
        norms.resource_policy.suspend_after_no_progress =
            (norms.resource_policy.suspend_after_no_progress + 1).min(4);
        decisions.push(
            "Delayed suspension by one follow-up because the evaluator found more valid leads recovered after suspension.".to_string(),
        );
    } else if guided_no_gain > baseline_no_gain + 0.1
        && no_gain_rate(&norm_guided_trace_observation)
            > no_gain_rate(&baseline_trace_observation) + 0.1
    {
        norms.resource_policy.suspend_after_no_progress = norms
            .resource_policy
            .suspend_after_no_progress
            .saturating_sub(1)
            .max(2);
        decisions.push(
            "Reduced the suspension threshold where allowed because evaluator and trace-measured no-gain challenges both increased by more than ten percentage points.".to_string(),
        );
    } else {
        decisions.push(
            "Kept the suspension threshold because feedback did not show a clear recovery or no-gain regression.".to_string(),
        );
    }

    if challenge_specificity_rate(&norm_guided_trace_observation) < 0.8 {
        induced_guidance.push(
            "N3 trace induction: name the exact disputed claim and a falsifiable source check or experiment in every challenge.".to_string(),
        );
    }
    if candidate_precision(&feedback.norm_guided) + 0.1 < candidate_precision(&feedback.baseline) {
        induced_guidance.push(
            "N3 trace induction: separate observed behavior from the vulnerability claim, and attach a falsifiable check to every claim.".to_string(),
        );
    }
    if repeated_area_rate(&norm_guided_trace_observation) > 0.2 {
        induced_guidance.push(
            "N7 trace induction: inspect the coverage and negative-outcome index before entering a previously reported source area; explain what new path is being tested.".to_string(),
        );
    }
    if no_gain_rate(&norm_guided_trace_observation) > 0.35 {
        induced_guidance.push(
            "N4 trace induction: after a no-gain challenge, change the evidence path or submit a concrete follow-up task instead of repeating the same analysis.".to_string(),
        );
    }
    if interaction_token_share(&feedback.norm_guided)
        > interaction_token_share(&feedback.baseline) + 0.05
        || evidence_per_interaction_token(&feedback.norm_guided)
            < evidence_per_interaction_token(&feedback.baseline) * 0.9
    {
        induced_guidance.push(
            "N4 trace induction: share only the evidence and context needed for the assigned lead, and make follow-up reports incremental.".to_string(),
        );
    }
    if dispute_resolution_rate(&feedback.norm_guided)
        < dispute_resolution_rate(&feedback.baseline) - 0.1
    {
        induced_guidance.push(
            "N5 trace induction: keep unresolved counterevidence visible and state which evidence would resolve each key dispute; do not settle it by vote.".to_string(),
        );
    }

    ensure!(norms.version < u32::MAX, "swarm norm version exhausted");
    norms.version += 1;
    norms.update_record = Some(NormUpdateRecord {
        split: feedback.split,
        feedback_file: feedback_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("evaluation-feedback.json")
            .to_string(),
        audit_tasks: feedback.audit_tasks,
        repeated_runs: feedback.repeated_runs,
        budget_regime: feedback.budget_regime,
        decisions,
        baseline_metrics: Some(feedback.baseline),
        norm_guided_metrics: Some(feedback.norm_guided),
        baseline_trace_observation,
        norm_guided_trace_observation,
        induced_guidance,
    });
    norms.write(output_path)?;
    Ok(norms)
}

fn validate_metrics(metrics: &EvaluationMetrics) -> Result<()> {
    ensure!(
        metrics.false_confirmations <= metrics.confirmed_findings,
        "false_confirmations cannot exceed confirmed_findings"
    );
    ensure!(
        metrics.redundant_explorations <= metrics.explorations,
        "redundant_explorations cannot exceed explorations"
    );
    ensure!(
        metrics.no_gain_challenges <= metrics.challenges,
        "no_gain_challenges cannot exceed challenges"
    );
    ensure!(
        metrics.valid_findings <= metrics.candidate_count,
        "valid_findings cannot exceed candidate_count"
    );
    ensure!(
        metrics.confirmed_findings <= metrics.candidate_count,
        "confirmed_findings cannot exceed candidate_count"
    );
    ensure!(
        metrics.evidence_resolved_disputes <= metrics.key_disputes,
        "evidence_resolved_disputes cannot exceed key_disputes"
    );
    ensure!(
        metrics.completed_passes > 0,
        "completed_passes must be positive"
    );
    ensure!(
        metrics.total_wall_clock_hours.is_finite() && metrics.total_wall_clock_hours > 0.0,
        "total_wall_clock_hours must be finite and positive"
    );
    ensure!(
        metrics.first_round_participants > 0,
        "first_round_participants must be positive"
    );
    ensure!(
        metrics.total_tokens > 0,
        "evaluation total_tokens must be positive"
    );
    ensure!(
        metrics.total_tool_seconds.is_finite() && metrics.total_tool_seconds > 0.0,
        "total_tool_seconds must be finite and positive"
    );
    ensure!(
        metrics.interaction_tokens <= metrics.total_tokens,
        "interaction_tokens cannot exceed total_tokens"
    );
    if metrics.valid_findings > 0 {
        ensure!(
            metrics.first_valid_finding_seconds.is_some(),
            "first_valid_finding_seconds is required when a valid finding exists"
        );
    } else {
        ensure!(
            metrics.first_valid_finding_seconds.is_none(),
            "first_valid_finding_seconds must be null when there are no valid findings"
        );
    }
    if let Some(seconds) = metrics.first_valid_finding_seconds {
        ensure!(
            metrics.valid_findings > 0
                && seconds.is_finite()
                && seconds >= 0.0
                && seconds <= metrics.total_wall_clock_hours * 3600.0,
            "first_valid_finding_seconds must be a valid time within the measured run"
        );
    }
    Ok(())
}

fn validate_experiment_conditions(conditions: &ExperimentConditions) -> Result<()> {
    ensure!(
        (2..=16).contains(&conditions.agent_count),
        "norm adaptation requires matching swarm sizes from 2 through 16 agents"
    );
    for (name, value) in [
        ("model", conditions.model.as_str()),
        ("focus", conditions.focus.as_str()),
        ("environment_id", conditions.environment_id.as_str()),
    ] {
        ensure!(
            !value.trim().is_empty(),
            "experiment {name} must not be empty"
        );
    }
    ensure!(
        (40..=64).contains(&conditions.source_revision.len())
            && conditions
                .source_revision
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "source_revision must be a Git SHA"
    );
    for (name, value) in [
        (
            "extra_prompt_sha256",
            conditions.extra_prompt_sha256.as_str(),
        ),
        (
            "kernel_config_sha256",
            conditions.kernel_config_sha256.as_str(),
        ),
        (
            "evaluation_task_set_sha256",
            conditions.evaluation_task_set_sha256.as_str(),
        ),
    ] {
        ensure!(
            is_sha256_hex(value),
            "experiment {name} must be a lowercase SHA-256"
        );
    }
    Ok(())
}

fn rate(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn efficiency(valid_findings: u64, total_tokens: u64) -> f64 {
    valid_findings as f64 / total_tokens as f64
}

fn pass_efficiency(metrics: &EvaluationMetrics) -> f64 {
    metrics.valid_findings as f64 / metrics.completed_passes as f64
}

fn wall_clock_efficiency(metrics: &EvaluationMetrics) -> f64 {
    metrics.valid_findings as f64 / metrics.total_wall_clock_hours
}

fn candidate_precision(metrics: &EvaluationMetrics) -> f64 {
    rate(metrics.valid_findings, metrics.candidate_count)
}

fn first_round_diversity(metrics: &EvaluationMetrics) -> f64 {
    if metrics.first_round_participants == 0 {
        0.0
    } else {
        metrics.unique_first_round_source_areas as f64 / metrics.first_round_participants as f64
    }
}

fn interaction_token_share(metrics: &EvaluationMetrics) -> f64 {
    rate(metrics.interaction_tokens, metrics.total_tokens)
}

fn evidence_per_interaction_token(metrics: &EvaluationMetrics) -> f64 {
    rate(metrics.effective_evidence_items, metrics.interaction_tokens)
}

fn dispute_resolution_rate(metrics: &EvaluationMetrics) -> f64 {
    rate(metrics.evidence_resolved_disputes, metrics.key_disputes)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn canonical_target_path(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return fs::canonicalize(path)
            .with_context(|| format!("resolving output path {}", path.display()));
    }
    let file_name = path.file_name().context("output path must name a file")?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(fs::canonicalize(parent)
        .with_context(|| format!("resolving output directory {}", parent.display()))?
        .join(file_name))
}
