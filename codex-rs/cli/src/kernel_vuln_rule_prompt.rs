//! Compact prompt for one knowledge-base-guided rule-family review.

use std::path::Path;

use super::kernel_vuln_rules::RuleReview;

pub(super) fn render_rule_review_prompt(
    linux_path: &Path,
    output_dir: &Path,
    candidate_dir: &Path,
    scratch_dir: &Path,
    focus: Option<&str>,
    commit: Option<&str>,
    review: &RuleReview,
) -> String {
    let rule = review.rule;
    let knowledge = rule.knowledge;
    let finding_index = output_dir.join("FINDING_INDEX.md");
    let mut prompt = format!(
        "# Focused CVE-derived Linux kernel review\n\n\
         Review one shared security-condition family from the curated knowledge base. This is a bounded, rule-guided audit; do not run an open-ended subsystem search or repeat independent reasoning for every listed function.\n\n\
         ## Runtime paths\n\n\
         - Linux source: {}\n\
         - Overall output directory: {}\n\
         - Candidate directory: {}\n\
         - Temporary scratch directory: {}\n\
         - The child process working directory is scratch; relative temporary outputs go there. Use the absolute candidate directory for persistent reports and evidence.\n\
         - Duplicate exclusion index: {}\n\
         - Requested focus: {}\n\
         - Requested revision/commit: {}\n\n\
         ## Rule record\n\n\
         - Rule: `{}` — {}\n\
         - Source CVE: [{}]({})\n\
         - Primary CWE: `{}`\n\
         - Scan scope: `{}`\n\
         - Verified fix: [`{}`]({})\n\
         - Original fix location: `{}` in `{}`\n\
         - Vulnerability condition: {}\n\
         - Dangerous pattern: {}\n\
         - Required invariant: {}\n\
         - Knowledge verified against revision: `{}`\n\n\
         ## Reusable knowledge\n\n\
         Treat these entries according to their stated status. Verified facts can replace re-deriving the same source trace when the current revision and route are unchanged. Safe cases are controls, not bug triggers. Unresolved hypotheses are not confirmed findings and must not be presented as new discoveries.\n\n\
         ### Verified facts\n",
        linux_path.display(),
        output_dir.display(),
        candidate_dir.display(),
        scratch_dir.display(),
        finding_index.display(),
        focus.unwrap_or("all active rule scopes"),
        commit.unwrap_or("current HEAD"),
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
        knowledge.verified_revision,
    );
    append_bullets(&mut prompt, knowledge.verified_facts);
    prompt.push_str("\n### Known-safe cases\n");
    append_bullets(&mut prompt, knowledge.known_safe_cases);
    prompt.push_str("\n### Unresolved hypotheses\n");
    if knowledge.unresolved_hypotheses.is_empty() {
        prompt.push_str("- None recorded.\n");
    } else {
        append_bullets(&mut prompt, knowledge.unresolved_hypotheses);
    }
    prompt.push_str("\n### Focused checks\n");
    append_bullets(&mut prompt, knowledge.focused_checks);
    prompt.push_str("\n## Matched source locations (one review bundle)\n");
    for location in &review.locations {
        prompt.push_str(&format!(
            "\n- `{}` `{}` at line {} ({}) — {}",
            location.relative_file,
            location.function,
            location.line,
            location.match_strength.label(),
            location.match_evidence,
        ));
    }
    prompt.push_str(
        "\n\n## Work contract\n\n\
         1. Record the exact source revision and worktree status. Compare it with the knowledge revision; if different, re-check only the rule's fix gate and affected route before reusing revision-specific facts.\n\
         2. Read FINDING_INDEX only to exclude duplicate root causes. Compare the candidate route with the recorded validation gate and sinks. If revision, guard, and route are unchanged, reuse the recorded trace and controls without reconstructing them; if they changed or a candidate bypasses them, trace only that delta or bypass once. Do not turn each location into a separate candidate.\n\
         3. If the verified guard covers the reachable class and no distinct residual condition remains, report negative or duplicate with the source/control evidence and stop. Do not search for unrelated vulnerabilities in this pass.\n\
         4. For a distinct reachable violation, establish its invariant and user-controlled trigger. Build one userland PoC for the root cause, run it twice from fresh setups, and run a close negative control. Never trigger a kernel bug or potentially destabilizing input on the host kernel; use a disposable VM with a snapshot and an out-of-tree kernel build. If no isolated target is available, do not run the trigger and report the runtime result as inconclusive. Never modify the supplied Linux tree.\n\
         5. Use the temporary scratch directory for source copies, build trees, object files, intermediate kernels, VM disks and snapshots, temporary root filesystems/initramfs images, downloads, and caches. Keep full reports, logs, PoC source, exact commands, reproduction instructions, fingerprints, revision/configuration details, and positive/control output in the persistent candidate directory. Preserve final binaries only when needed to reproduce the finding. Never leave the only copy of a required artifact in scratch; copy and verify it before finishing. Do not keep build trees or temporary development environments in the persistent candidate directory. Do not shorten or discard text reports, logs, or evidence to save disk space.\n\
         6. Record exact commands, raw output, source references, impact, and limitations in PROCESS_LOG.md and candidate-report.md. Write finding-fingerprint.md with first line `Outcome: confirmed`, `plausible`, `negative`, `inconclusive`, or `duplicate`. Never promote an unresolved knowledge-base hypothesis without new evidence.\n",
    );
    prompt
}

fn append_bullets(prompt: &mut String, items: &[&str]) {
    if items.is_empty() {
        prompt.push_str("- None.\n");
        return;
    }
    for item in items {
        prompt.push_str(&format!("- {item}\n"));
    }
}
