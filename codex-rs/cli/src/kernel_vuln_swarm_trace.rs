//! Bounded parsing and summaries for versioned swarm interaction traces.

use super::kernel_vuln_swarm_policy::NormTraceObservation;
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;
use std::path::PathBuf;

#[derive(Deserialize)]
struct TraceEvent {
    schema_version: u32,
    action: String,
    #[serde(default)]
    information_gain: Option<bool>,
    #[serde(default)]
    target_claim: Option<String>,
    #[serde(default)]
    proposed_test: Option<String>,
    #[serde(default)]
    evidence_refs: Vec<String>,
    #[serde(default)]
    code_areas: Vec<String>,
}

pub(super) fn summarize_trace_comparison(
    feedback_path: &Path,
    baseline_trace_files: &[String],
    norm_guided_trace_files: &[String],
) -> Result<(NormTraceObservation, NormTraceObservation)> {
    let mut trace_paths = BTreeSet::new();
    let baseline = summarize_traces(feedback_path, baseline_trace_files, &mut trace_paths)?;
    let norm_guided = summarize_traces(feedback_path, norm_guided_trace_files, &mut trace_paths)?;
    Ok((baseline, norm_guided))
}

fn summarize_traces(
    feedback_path: &Path,
    trace_files: &[String],
    used_paths: &mut BTreeSet<PathBuf>,
) -> Result<NormTraceObservation> {
    ensure!(
        trace_files.len() >= 3,
        "norm induction requires at least three trace files per architecture"
    );
    let base_dir = feedback_path.parent().unwrap_or_else(|| Path::new("."));
    let mut observation = NormTraceObservation {
        trace_files: trace_files.len(),
        ..NormTraceObservation::default()
    };
    let mut source_areas = BTreeSet::new();
    for trace_file in trace_files {
        let path = Path::new(trace_file);
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            base_dir.join(path)
        };
        let path = fs::canonicalize(&path)
            .with_context(|| format!("resolving swarm trace {}", path.display()))?;
        ensure!(
            used_paths.insert(path.clone()),
            "baseline and norm-guided trace files must be distinct"
        );
        ensure!(
            path.is_file(),
            "swarm trace is not a file: {}",
            path.display()
        );
        let metadata = fs::metadata(&path)
            .with_context(|| format!("reading swarm trace metadata {}", path.display()))?;
        ensure!(
            metadata.len() <= 64 * 1024 * 1024,
            "swarm trace exceeds the 64 MiB limit: {}",
            path.display()
        );
        let file = fs::File::open(&path)
            .with_context(|| format!("opening swarm trace {}", path.display()))?;
        for (line_number, line) in BufReader::new(file).lines().enumerate() {
            let line = line.with_context(|| format!("reading swarm trace {}", path.display()))?;
            if line.trim().is_empty() {
                continue;
            }
            ensure!(
                line.len() <= 64 * 1024,
                "oversized event in {} at line {}",
                path.display(),
                line_number + 1
            );
            let event: TraceEvent = serde_json::from_str(&line).with_context(|| {
                format!(
                    "parsing swarm trace {} at line {}",
                    path.display(),
                    line_number + 1
                )
            })?;
            ensure!(
                event.schema_version == 1,
                "unsupported event schema in {} at line {}",
                path.display(),
                line_number + 1
            );
            observation.events += 1;
            if event.action.eq_ignore_ascii_case("CHALLENGE") {
                observation.challenges += 1;
                if let Some(information_gain) = event.information_gain {
                    observation.classified_challenges += 1;
                    if !information_gain {
                        observation.no_gain_challenges += 1;
                    }
                }
                if event
                    .target_claim
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
                    && event
                        .proposed_test
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty())
                {
                    observation.specific_challenges += 1;
                }
            }
            if !event.evidence_refs.is_empty() {
                observation.evidence_backed_events += 1;
            }
            if event.action.eq_ignore_ascii_case("COVERAGE_RECORDED") {
                for area in event.code_areas {
                    let normalized = area.trim().to_ascii_lowercase();
                    if !normalized.is_empty() {
                        observation.source_area_mentions += 1;
                        source_areas.insert(normalized);
                    }
                }
            }
        }
    }
    ensure!(
        observation.events > 0,
        "swarm trace files contained no valid events"
    );
    observation.unique_source_areas = source_areas.len();
    Ok(observation)
}

pub(super) fn repeated_area_rate(observation: &NormTraceObservation) -> f64 {
    if observation.source_area_mentions == 0 {
        return 0.0;
    }
    observation
        .source_area_mentions
        .saturating_sub(observation.unique_source_areas) as f64
        / observation.source_area_mentions as f64
}

pub(super) fn challenge_specificity_rate(observation: &NormTraceObservation) -> f64 {
    if observation.challenges == 0 {
        return 1.0;
    }
    observation.specific_challenges as f64 / observation.challenges as f64
}

pub(super) fn no_gain_rate(observation: &NormTraceObservation) -> f64 {
    if observation.classified_challenges == 0 {
        return 0.0;
    }
    observation.no_gain_challenges as f64 / observation.classified_challenges as f64
}
