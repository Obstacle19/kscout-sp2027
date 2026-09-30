use super::kernel_vuln_rules::ObservationStatus;
use super::kernel_vuln_rules::RuleScanResult;

pub(super) fn render_rule_scan_report(
    scan: &RuleScanResult,
    source_snapshot: &str,
    candidate_limit: u32,
) -> String {
    let review_groups = scan.review_groups();
    let selected_count = review_groups.len().min(candidate_limit as usize);
    let mut scopes: Vec<_> = scan.rules.iter().map(|rule| rule.scope).collect();
    scopes.sort_unstable();
    scopes.dedup();
    let mut report = format!(
        "# CVE-derived rule scan\n\n\
         Source snapshot: `{}`\n\n\
         - Rule set: {} manually reviewed rules\n\
         - Scanned scopes: {}\n\
         - C source files found / parsed: {} / {}\n\
         - Rule-pattern locations: {}\n\
         - Filtered by exact recognized safe shape: {}\n\
         - Locations retained for semantic review: {}\n\
         - Distinct rule-family review bundles: {}\n\
         - Rule-family bundles selected by the total `--count` budget: {} (limit: {})\n\
         - Rules without a matching location: {}\n\
         - Parser/read coverage gaps: {}\n\n\
         The scanner searches every parsed C function in the selected rule scopes using deterministic lexical patterns derived from verified fixes. Related locations for one rule are grouped into one model review so the shared cause and validation route are traced once. Historical function names below are provenance, not scan anchors. A lexical hit is only a candidate hypothesis, not proof. Parser failures are reported as coverage gaps, not as safe code. Rule mode schedules only these focused bundles; it does not start open-ended autonomous-search passes.\n\n\
         ## Reviewed rules\n",
        source_snapshot.trim(),
        scan.rules.len(),
        scopes.join(", "),
        scan.source_file_count,
        scan.parsed_file_count,
        scan.raw_match_count(),
        scan.filtered_safe_count(),
        scan.candidates.len(),
        review_groups.len(),
        selected_count,
        candidate_limit,
        scan.unmatched_rule_count(),
        scan.parse_errors.len(),
    );

    for rule in &scan.rules {
        report.push_str(&format!(
            "\n### {} — {}\n\n\
             - CVE: [{}]({})\n\
             - Primary CWE: `{}`\n\
             - Scan scope: `{}`\n\
             - Verified fix: [`{}`]({})\n\
             - Original fix site: `{}` in `{}`\n\
             - Vulnerability condition: {}\n\
             - Reusable dangerous pattern: {}\n\
             - Safety invariant: {}\n\
             - Agent verification contract: {}\n\
             - Knowledge verified against: `{}`\n\
             - Reusable verified facts:\n{}\
             - Known-safe cases:\n{}\
             - Unresolved hypotheses (not confirmed findings):\n{}\
             - Focused review checks:\n{}\n",
            rule.id,
            rule.title,
            rule.cve,
            rule.advisory_url,
            rule.cwe,
            rule.scope,
            rule.fix_commit,
            rule.fix_url,
            rule.source_function,
            rule.source_file,
            rule.condition,
            rule.dangerous_pattern,
            rule.safety_invariant,
            rule.verification_contract,
            rule.knowledge.verified_revision,
            format_bullets(rule.knowledge.verified_facts),
            format_bullets(rule.knowledge.known_safe_cases),
            format_bullets(rule.knowledge.unresolved_hypotheses),
            format_bullets(rule.knowledge.focused_checks),
        ));
    }

    report.push_str("\n## Enumerated locations\n");
    if scan.observations.is_empty() {
        report.push_str("\n- No locations matched the current rule patterns.\n");
    }
    for observation in &scan.observations {
        let (status, reason) = match observation.status {
            ObservationStatus::Candidate => ("candidate", ""),
            ObservationStatus::FilteredSafe(reason) => ("filtered_safe", reason),
        };
        report.push_str(&format!(
            "\n- `{}` `{}` `{}` at line {}: **{}** ({}) — {}",
            observation.candidate.rule.id,
            observation.candidate.relative_file,
            observation.candidate.function,
            observation.candidate.line,
            status,
            observation.candidate.match_strength.label(),
            if reason.is_empty() {
                observation.candidate.match_evidence
            } else {
                reason
            },
        ));
        if !reason.is_empty() {
            report.push_str(&format!(
                " (pattern: {})",
                observation.candidate.match_evidence
            ));
        }
    }

    if !scan.unmatched_rules.is_empty() {
        report.push_str("\n\n## Rules with no matching location\n");
        for rule_id in &scan.unmatched_rules {
            report.push_str(&format!(
                "\n- `{rule_id}`: no matching function among successfully parsed files; review parser coverage gaps above."
            ));
        }
    }
    if !scan.parse_errors.is_empty() {
        report.push_str("\n\n## Parser and source-read coverage gaps\n");
        for error in &scan.parse_errors {
            report.push_str(&format!("\n- `{error}`"));
        }
    }

    report.push_str("\n\n## Selected focused rule reviews\n");
    if selected_count == 0 {
        report.push_str(
            "\n- None; no rule-family bundle remains after conservative filtering, so this rules-only run starts no model review.\n",
        );
    } else {
        for review in review_groups.iter().take(selected_count) {
            report.push_str(&format!(
                "\n- `{}` — {} related source location(s):",
                review.rule.id,
                review.locations.len(),
            ));
            for candidate in &review.locations {
                report.push_str(&format!(
                    "\n  - `{}` `{}` at line {} ({})",
                    candidate.relative_file,
                    candidate.function,
                    candidate.line,
                    candidate.match_strength.label(),
                ));
            }
        }
        report.push('\n');
    }

    if review_groups.len() > selected_count {
        report.push_str(&format!(
            "\n\n{} distinct rule-family review bundle(s) were left unscheduled by the per-run `--count` limit.",
            review_groups.len() - selected_count,
        ));
    }
    report.push('\n');
    report
}

fn format_bullets(items: &[&str]) -> String {
    if items.is_empty() {
        return "  - None\n".to_string();
    }
    let mut rendered = String::new();
    for item in items {
        rendered.push_str(&format!("  - {item}\n"));
    }
    rendered
}
