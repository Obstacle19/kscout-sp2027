//! Versioned runtime policy and evaluator-gated norm updates for kernel swarms.

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use serde::Deserialize;
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct SwarmNormSet {
    pub(super) schema_version: u32,
    pub(super) version: u32,
    pub(super) resource_policy: ResourcePolicy,
    #[serde(default)]
    pub(super) update_record: Option<NormUpdateRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResourcePolicy {
    pub(super) exploration_min_percent: u8,
    pub(super) exploration_max_percent: u8,
    pub(super) suspend_after_no_progress: usize,
    pub(super) reproduction_gap_weight: u32,
    pub(super) security_gap_weight: u32,
    pub(super) new_evidence_weight: u32,
    pub(super) token_cost_weight: u32,
    pub(super) elapsed_cost_weight: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct NormUpdateRecord {
    pub(super) split: String,
    pub(super) feedback_file: String,
    pub(super) audit_tasks: u32,
    pub(super) repeated_runs: u32,
    pub(super) budget_regime: String,
    pub(super) decisions: Vec<String>,
    #[serde(default)]
    pub(super) baseline_metrics: Option<EvaluationMetrics>,
    #[serde(default)]
    pub(super) norm_guided_metrics: Option<EvaluationMetrics>,
    #[serde(default)]
    pub(super) baseline_trace_observation: NormTraceObservation,
    #[serde(default)]
    pub(super) norm_guided_trace_observation: NormTraceObservation,
    #[serde(default)]
    pub(super) induced_guidance: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(super) struct NormTraceObservation {
    pub(super) trace_files: usize,
    pub(super) events: usize,
    pub(super) challenges: usize,
    pub(super) classified_challenges: usize,
    pub(super) no_gain_challenges: usize,
    pub(super) specific_challenges: usize,
    pub(super) evidence_backed_events: usize,
    pub(super) source_area_mentions: usize,
    pub(super) unique_source_areas: usize,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EvaluationMetrics {
    pub(super) valid_findings: u64,
    pub(super) total_tokens: u64,
    pub(super) total_tool_seconds: f64,
    pub(super) total_wall_clock_hours: f64,
    pub(super) completed_passes: u64,
    pub(super) candidate_count: u64,
    #[serde(default)]
    pub(super) first_valid_finding_seconds: Option<f64>,
    pub(super) confirmed_findings: u64,
    pub(super) false_confirmations: u64,
    pub(super) redundant_explorations: u64,
    pub(super) explorations: u64,
    pub(super) no_gain_challenges: u64,
    pub(super) challenges: u64,
    pub(super) effective_evidence_items: u64,
    pub(super) interaction_tokens: u64,
    pub(super) evidence_resolved_disputes: u64,
    pub(super) key_disputes: u64,
    pub(super) unique_first_round_source_areas: u64,
    pub(super) first_round_participants: u64,
    pub(super) valid_leads_recovered_after_suspension: u64,
}

impl Default for SwarmNormSet {
    fn default() -> Self {
        Self {
            schema_version: 1,
            version: 1,
            resource_policy: ResourcePolicy {
                exploration_min_percent: 25,
                exploration_max_percent: 40,
                suspend_after_no_progress: 2,
                reproduction_gap_weight: 6,
                security_gap_weight: 5,
                new_evidence_weight: 4,
                token_cost_weight: 1,
                elapsed_cost_weight: 1,
            },
            update_record: None,
        }
    }
}

impl SwarmNormSet {
    pub(super) fn load(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let contents = fs::read_to_string(path)
            .with_context(|| format!("reading swarm norm set {}", path.display()))?;
        let norms: Self = serde_json::from_str(&contents)
            .with_context(|| format!("parsing swarm norm set {}", path.display()))?;
        norms.validate()?;
        Ok(norms)
    }

    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported swarm norm schema version"
        );
        ensure!(self.version > 0, "swarm norm version must be positive");
        let policy = &self.resource_policy;
        ensure!(
            (25..=60).contains(&policy.exploration_min_percent),
            "exploration_min_percent must be between 25 and 60"
        );
        ensure!(
            policy.exploration_min_percent <= policy.exploration_max_percent,
            "exploration_min_percent must not exceed exploration_max_percent"
        );
        ensure!(
            (40..=70).contains(&policy.exploration_max_percent),
            "exploration_max_percent must be between 40 and 70"
        );
        ensure!(
            (2..=4).contains(&policy.suspend_after_no_progress),
            "suspend_after_no_progress must be between 2 and 4"
        );
        ensure!(
            policy.reproduction_gap_weight > 0
                && policy.security_gap_weight > 0
                && policy.new_evidence_weight > 0
                && policy.token_cost_weight > 0
                && policy.elapsed_cost_weight > 0,
            "all scheduling weights must be positive"
        );
        Ok(())
    }

    pub(super) fn write(&self, path: &Path) -> Result<()> {
        self.validate()?;
        fs::write(
            path,
            serde_json::to_vec_pretty(self).context("serializing swarm norm set")?,
        )
        .with_context(|| format!("writing swarm norm set {}", path.display()))
    }
}
