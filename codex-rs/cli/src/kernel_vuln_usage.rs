//! Per-candidate wall-clock and token usage summaries for kernel-vulnerability runs.

use anyhow::Context;
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum UsageStatus {
    Complete,
    Partial,
    Unavailable,
}

impl UsageStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct TokenUsageSummary {
    #[serde(rename = "usage_status")]
    pub(super) status: UsageStatus,
    pub(super) completed_turns: u64,
    pub(super) usage_turns: u64,
    pub(super) input_tokens: Option<i64>,
    pub(super) cached_input_tokens: Option<i64>,
    pub(super) cache_write_input_tokens: Option<i64>,
    pub(super) output_tokens: Option<i64>,
    pub(super) reasoning_output_tokens: Option<i64>,
    pub(super) total_tokens: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct CandidateUsageRecord {
    pub(super) run_started_at: String,
    pub(super) candidate: String,
    pub(super) model: String,
    pub(super) child_result: String,
    pub(super) exit_code: Option<i32>,
    pub(super) started_at: String,
    pub(super) finished_at: String,
    pub(super) elapsed_seconds: f64,
    pub(super) finding_outcome: Option<String>,
    #[serde(flatten)]
    pub(super) token_usage: TokenUsageSummary,
}

#[derive(Default)]
struct UsageAccumulator {
    completed_turns: u64,
    usage_turns: u64,
    failed_turns: u64,
    latest_reported_usage: Option<ReportedTokenUsage>,
}

#[derive(Default)]
struct ReportedTokenUsage {
    input_tokens: Option<i64>,
    cached_input_tokens: Option<i64>,
    cache_write_input_tokens: Option<i64>,
    output_tokens: Option<i64>,
    reasoning_output_tokens: Option<i64>,
    total_tokens: Option<i64>,
}

impl ReportedTokenUsage {
    fn from_event(usage: &Value) -> Self {
        let input_tokens = integer(usage.get("input_tokens"));
        let output_tokens = integer(usage.get("output_tokens"));
        Self {
            input_tokens,
            cached_input_tokens: integer(usage.get("cached_input_tokens"))
                .or_else(|| integer(usage.pointer("/input_tokens_details/cached_tokens"))),
            cache_write_input_tokens: integer(usage.get("cache_write_input_tokens")),
            output_tokens,
            reasoning_output_tokens: integer(usage.get("reasoning_output_tokens"))
                .or_else(|| integer(usage.pointer("/output_tokens_details/reasoning_tokens"))),
            total_tokens: integer(usage.get("total_tokens")),
        }
    }

    fn was_reported(&self, usage_event: &Value) -> bool {
        match usage_event.get("usage_reported").and_then(Value::as_bool) {
            Some(reported) => reported,
            None => [
                self.input_tokens,
                self.cached_input_tokens,
                self.cache_write_input_tokens,
                self.output_tokens,
                self.reasoning_output_tokens,
                self.total_tokens,
            ]
            .into_iter()
            .flatten()
            .any(|count| count > 0),
        }
    }
}

pub(super) fn read_token_usage(events_path: &Path) -> Result<TokenUsageSummary> {
    let events = match fs::read(events_path) {
        Ok(events) => events,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(UsageAccumulator::default().finish());
        }
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", events_path.display()));
        }
    };

    let mut usage = UsageAccumulator::default();
    for line in events.split(|byte| *byte == b'\n') {
        let Ok(event) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        match event.get("type").and_then(Value::as_str) {
            Some("turn.completed") => {
                usage.completed_turns += 1;
                let Some(turn_usage) = event.get("usage").filter(|value| value.is_object()) else {
                    continue;
                };
                let reported_usage = ReportedTokenUsage::from_event(turn_usage);
                if reported_usage.was_reported(turn_usage) {
                    usage.usage_turns += 1;
                    // The exec JSONL event carries cumulative thread usage. Keep the
                    // latest reported snapshot instead of adding each turn together.
                    usage.latest_reported_usage = Some(reported_usage);
                }
            }
            Some("turn.failed") => usage.failed_turns += 1,
            _ => {}
        }
    }

    Ok(usage.finish())
}

impl UsageAccumulator {
    fn finish(self) -> TokenUsageSummary {
        let Some(latest_usage) = self.latest_reported_usage else {
            return TokenUsageSummary {
                status: UsageStatus::Unavailable,
                completed_turns: self.completed_turns,
                usage_turns: self.usage_turns,
                input_tokens: None,
                cached_input_tokens: None,
                cache_write_input_tokens: None,
                output_tokens: None,
                reasoning_output_tokens: None,
                total_tokens: None,
            };
        };

        let status = if self.usage_turns != self.completed_turns
            || self.failed_turns > 0
            || latest_usage.input_tokens.is_none()
            || latest_usage.output_tokens.is_none()
            || latest_usage.total_tokens.is_none()
        {
            UsageStatus::Partial
        } else {
            UsageStatus::Complete
        };

        TokenUsageSummary {
            status,
            completed_turns: self.completed_turns,
            usage_turns: self.usage_turns,
            input_tokens: latest_usage.input_tokens,
            cached_input_tokens: latest_usage.cached_input_tokens,
            cache_write_input_tokens: latest_usage.cache_write_input_tokens,
            output_tokens: latest_usage.output_tokens,
            reasoning_output_tokens: latest_usage.reasoning_output_tokens,
            total_tokens: latest_usage.total_tokens,
        }
    }
}

fn integer(value: Option<&Value>) -> Option<i64> {
    value.and_then(Value::as_i64)
}

pub(super) fn read_finding_outcome(fingerprint_path: &Path) -> Option<String> {
    let fingerprint = fs::read_to_string(fingerprint_path).ok()?;
    fingerprint.lines().find_map(|line| {
        let line = line.trim().trim_start_matches(['-', '*', ' ']).trim();
        let (key, value) = line.split_once(':')?;
        if !key.trim().trim_matches('*').eq_ignore_ascii_case("outcome") {
            return None;
        }
        let value = value.trim().trim_matches('*');
        (!value.is_empty()).then(|| value.to_string())
    })
}

impl CandidateUsageRecord {
    pub(super) fn markdown_summary(&self) -> String {
        format!(
            "\n\n## Execution and usage\n\n\
             - Model: {}\n\
             - Child result: {}\n\
             - Finding outcome: {}\n\
             - Started at (UTC): {}\n\
             - Finished at (UTC): {}\n\
             - Candidate wall-clock time: {:.3} seconds\n\
             - Usage status: {} ({}/{} completed turns reported usage)\n\
             - Input tokens (reported total): {}\n\
             - Cached input tokens (reported total): {}\n\
             - Cache-write input tokens (reported total): {}\n\
             - Output tokens (reported total): {}\n\
             - Reasoning output tokens (reported total): {}\n\
             - Total tokens (reported total): {}\n",
            self.model,
            self.child_result,
            self.finding_outcome.as_deref().unwrap_or("not reported"),
            self.started_at,
            self.finished_at,
            self.elapsed_seconds,
            self.token_usage.status.as_str(),
            self.token_usage.usage_turns,
            self.token_usage.completed_turns,
            render_count(self.token_usage.input_tokens),
            render_count(self.token_usage.cached_input_tokens),
            render_count(self.token_usage.cache_write_input_tokens),
            render_count(self.token_usage.output_tokens),
            render_count(self.token_usage.reasoning_output_tokens),
            render_count(self.token_usage.total_tokens),
        )
    }
}

fn render_count(count: Option<i64>) -> String {
    count
        .map(|count| count.to_string())
        .unwrap_or_else(|| "not reported".to_string())
}

pub(super) fn persist_candidate_usage(
    record: &CandidateUsageRecord,
    candidate_dir: &Path,
    output_dir: &Path,
) -> Result<()> {
    let candidate_usage_path = candidate_dir.join("usage.json");
    let usage_json = serde_json::to_vec_pretty(record).context("serializing candidate usage")?;
    fs::write(&candidate_usage_path, usage_json)
        .with_context(|| format!("writing {}", candidate_usage_path.display()))?;

    let usage_jsonl_path = output_dir.join("USAGE.jsonl");
    let mut usage_jsonl = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&usage_jsonl_path)
        .with_context(|| format!("opening {}", usage_jsonl_path.display()))?;
    let line = serde_json::to_string(record).context("serializing candidate usage record")?;
    writeln!(usage_jsonl, "{line}")
        .with_context(|| format!("appending {}", usage_jsonl_path.display()))?;

    let metadata_path = candidate_dir.join("run-metadata.md");
    let mut metadata = OpenOptions::new()
        .append(true)
        .open(&metadata_path)
        .with_context(|| format!("opening {}", metadata_path.display()))?;
    metadata
        .write_all(record.markdown_summary().as_bytes())
        .with_context(|| format!("appending {}", metadata_path.display()))?;
    Ok(())
}

pub(super) fn render_run_usage_summary(
    records: &[CandidateUsageRecord],
    elapsed_seconds: f64,
) -> String {
    let candidate_elapsed_seconds = records
        .iter()
        .map(|record| record.elapsed_seconds)
        .sum::<f64>();
    let successful_candidates = records
        .iter()
        .filter(|record| record.child_result == "success")
        .count();
    let failed_candidates = records
        .iter()
        .filter(|record| record.child_result == "failure")
        .count();
    let failed_to_start = records
        .iter()
        .filter(|record| record.child_result == "failed_to_start")
        .count();
    format!(
        "\n## Run usage summary\n\n\
         - Run wall-clock time: {elapsed_seconds:.3} seconds\n\
         - Candidate wall-clock time total: {candidate_elapsed_seconds:.3} seconds\n\
         - Candidates with usage records: {}\n\
         - Child results: {successful_candidates} successful, {failed_candidates} failed, {failed_to_start} failed to start\n\
         - Input tokens (reported sum): {}\n\
         - Cached input tokens (reported sum): {}\n\
         - Cache-write input tokens (reported sum): {}\n\
         - Output tokens (reported sum): {}\n\
         - Reasoning output tokens (reported sum): {}\n\
         - Total tokens (reported sum): {}\n",
        records.len(),
        aggregate_metric(records, |record| record.token_usage.input_tokens),
        aggregate_metric(records, |record| record.token_usage.cached_input_tokens),
        aggregate_metric(records, |record| record
            .token_usage
            .cache_write_input_tokens),
        aggregate_metric(records, |record| record.token_usage.output_tokens),
        aggregate_metric(records, |record| record.token_usage.reasoning_output_tokens),
        aggregate_metric(records, |record| record.token_usage.total_tokens),
    )
}

fn aggregate_metric(
    records: &[CandidateUsageRecord],
    value: impl Fn(&CandidateUsageRecord) -> Option<i64>,
) -> String {
    if records.is_empty() {
        return "not reported (no model calls)".to_string();
    }

    let (sum, reported, incomplete_usage) = records.iter().fold(
        (0_i64, 0_usize, 0_usize),
        |(sum, reported, incomplete_usage), record| {
            let (sum, reported) = match value(record) {
                Some(value) => (sum + value, reported + 1),
                None => (sum, reported),
            };
            let incomplete_usage = if matches!(record.token_usage.status, UsageStatus::Complete) {
                incomplete_usage
            } else {
                incomplete_usage + 1
            };
            (sum, reported, incomplete_usage)
        },
    );
    if reported == 0 {
        "not reported for any candidate".to_string()
    } else if reported == records.len() && incomplete_usage == 0 {
        sum.to_string()
    } else if incomplete_usage > 0 {
        format!(
            "{sum} reported for {reported}/{} candidates; usage partial or unavailable for {incomplete_usage}/{}",
            records.len(),
            records.len()
        )
    } else {
        format!(
            "{sum} reported for {reported}/{} candidates; metric unavailable for {}/{}",
            records.len(),
            records.len() - reported,
            records.len()
        )
    }
}
