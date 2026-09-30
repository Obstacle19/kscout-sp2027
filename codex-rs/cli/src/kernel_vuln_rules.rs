//! CVE-derived rules that enumerate similar security-condition candidates
//! throughout each rule's declared Linux subsystem.

use anyhow::Context;
use anyhow::Result;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

#[path = "kernel_vuln_c.rs"]
mod kernel_vuln_c;

use self::kernel_vuln_c::FunctionBody;
use self::kernel_vuln_c::attribute_alloc_size_is_bounded;
use self::kernel_vuln_c::cve_specific_filter_reason;
use self::kernel_vuln_c::cve_specific_rule_match;
use self::kernel_vuln_c::ea_name_length_is_bounded;
use self::kernel_vuln_c::extract_all_function_bodies;
use self::kernel_vuln_c::lex_c;
use self::kernel_vuln_c::perturb_period_conversion_is_bounded;
use self::kernel_vuln_c::perturb_period_tick_conversion_sites;
use super::kernel_vuln_rule_knowledge::ATTRIBUTE_ALLOC_SIZE;
use super::kernel_vuln_rule_knowledge::EA_NAME_LENGTH;
use super::kernel_vuln_rule_knowledge::SFQ_PERTURB_PERIOD;
#[path = "kernel_vuln_rule_catalog.rs"]
mod catalog;
use self::catalog::ADDITIONAL_CVE_RULES;

#[derive(Clone, Copy, Debug)]
pub(super) enum CandidatePattern {
    EaNameLength,
    AttributeAllocSize,
    PerturbPeriodTicks,
    EbtSnatWritable,
    OverlayfsIdMapping,
    PacketHeaderLenSnapshot,
    NftVerdictOwnership,
    Xen9pTeardown,
    IoUringTimeoutList,
    NftStatefulExpression,
    IoUringFixedFilePut,
    NftAnonymousSetLifetime,
    MirredSkbOwnership,
    KsmbdTconRefcount,
    FuseSyncSubmountRelease,
    UdpGsoSocketOwnership,
    PipeBufferFlags,
    NftVlanCopyArithmetic,
    TlsSpliceCursor,
    Ipv4FragGapLength,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum SafeFilter {
    EaNameLength,
    AttributeAllocSize,
    PerturbPeriodTicks,
    CveSpecific,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct KernelCveRule {
    pub(super) id: &'static str,
    pub(super) title: &'static str,
    pub(super) cve: &'static str,
    pub(super) cwe: &'static str,
    pub(super) scope: &'static str,
    pub(super) source_file: &'static str,
    pub(super) source_function: &'static str,
    pub(super) condition: &'static str,
    pub(super) dangerous_pattern: &'static str,
    pub(super) safety_invariant: &'static str,
    pub(super) verification_contract: &'static str,
    pub(super) fix_commit: &'static str,
    pub(super) fix_url: &'static str,
    pub(super) advisory_url: &'static str,
    pub(super) knowledge: &'static super::kernel_vuln_rule_knowledge::RuleKnowledge,
    candidate_pattern: CandidatePattern,
    safe_filter: SafeFilter,
}

/// Rules are manually derived from verified Linux fixes. Historical file and
/// function names are provenance only; the scanner does not use them as
/// candidate-location constraints.
pub(super) const CVE_RULES: &[KernelCveRule] = &[
    KernelCveRule {
        id: "ntfs3-ea-name-length",
        title: "EA name length must fit its enclosing entry",
        cve: "CVE-2023-52640",
        cwe: "CWE-125",
        scope: "fs/ntfs3",
        source_file: "fs/ntfs3/xattr.c",
        source_function: "ntfs_list_ea",
        condition: "An on-disk EA name length is used for output sizing or a memory read without first proving it fits in the enclosing EA entry.",
        dangerous_pattern: "Decode an EA entry extent with unpacked_ea_size(), then use the entry's name_len for a name copy or output-size calculation.",
        safety_invariant: "Before any name read or output-size update, prove name_len <= the decoded enclosing-entry size on every path that reaches the use.",
        verification_contract: "Trace the entry extent and name length from their disk-backed fields to every read, copy, and size update. Check branches, loops, aliases, and exits. Do not infer safety from an unrelated name limit or from a bounds check on another extent.",
        fix_commit: "731ab1f9828800df871c5a7ab9ffe965317d3f15",
        fix_url: "https://git.kernel.org/stable/c/731ab1f9828800df871c5a7ab9ffe965317d3f15",
        advisory_url: "https://lists.openwall.net/linux-cve-announce/2024/04/03/50",
        knowledge: &EA_NAME_LENGTH,
        candidate_pattern: CandidatePattern::EaNameLength,
        safe_filter: SafeFilter::EaNameLength,
    },
    KernelCveRule {
        id: "ntfs3-attribute-alloc-size",
        title: "Nonresident attribute allocation size must fit the volume",
        cve: "CVE-2024-50246",
        cwe: "CWE-1284",
        scope: "fs/ntfs3",
        source_file: "fs/ntfs3/record.c",
        source_function: "mi_enum_attr",
        condition: "An on-disk nonresident attribute's alloc_size is accepted or used for accounting without a valid upper bound, allowing later cluster or metadata accounting to trust an impossible extent.",
        dangerous_pattern: "Decode an ATTRIB nres.alloc_size field and use the resulting size in an acceptance, extent, allocation, or accounting path.",
        safety_invariant: "Before accepting or accounting for the parsed extent, establish a bound valid for the attribute type and all relevant sparse/compressed cases; a check of data_size, evcn, or another extent is not equivalent.",
        verification_contract: "Trace nres.alloc_size from endian decoding through each accepted return and size/cluster accounting path. Check the exact conditions under which the size is bounded by volume.size, including sparse/compressed cases, aliases, and goto/return paths. Do not treat a check of data_size, evcn, or a different extent as equivalent.",
        fix_commit: "c4a8ba334262e9a5c158d618a4820e1b9c12495c",
        fix_url: "https://git.kernel.org/stable/c/c4a8ba334262e9a5c158d618a4820e1b9c12495c",
        advisory_url: "https://lists.openwall.net/linux-cve-announce/2024/11/09/28",
        knowledge: &ATTRIBUTE_ALLOC_SIZE,
        candidate_pattern: CandidatePattern::AttributeAllocSize,
        safe_filter: SafeFilter::AttributeAllocSize,
    },
    KernelCveRule {
        id: "net-sched-perturb-period",
        title: "Perturb periods must fit their timer tick representation",
        cve: "CVE-2025-38193",
        cwe: "CWE-190",
        scope: "net/sched",
        source_file: "net/sched/sch_sfq.c",
        source_function: "sfq_change",
        condition: "A user-controlled perturb period is multiplied by HZ without proving the configured value is non-negative and the result fits the timer's integer representation.",
        dangerous_pattern: "Assign a perturb_period from a value multiplied by HZ, then store or schedule it as a timer period without a dominating range check.",
        safety_invariant: "Before converting to ticks, reject negative values and values above INT_MAX / HZ; preserve zero as the valid disabled-period value.",
        verification_contract: "Trace each configuration source through signedness, integer promotions, multiplication by HZ, storage, and timer scheduling. Check every create and update path and any indirect policy bounds. A check of nonzero, a bound on an unrelated field, or a check after multiplication is not sufficient. Preserve zero as the disabled timer setting. For analogous paths, establish whether wraparound changes timer behavior and whether that behavior is security-relevant before reporting a finding.",
        fix_commit: "e0936ff56be4e08ad5b60ec26971eae0c40af305",
        fix_url: "https://git.kernel.org/stable/c/e0936ff56be4e08ad5b60ec26971eae0c40af305",
        advisory_url: "https://nvd.nist.gov/vuln/detail/CVE-2025-38193",
        knowledge: &SFQ_PERTURB_PERIOD,
        candidate_pattern: CandidatePattern::PerturbPeriodTicks,
        safe_filter: SafeFilter::PerturbPeriodTicks,
    },
];

fn all_cve_rules() -> impl Iterator<Item = &'static KernelCveRule> {
    CVE_RULES.iter().chain(ADDITIONAL_CVE_RULES.iter())
}

#[derive(Clone, Debug)]
pub(super) struct RuleCandidate {
    pub(super) rule: &'static KernelCveRule,
    pub(super) relative_file: String,
    pub(super) function: String,
    pub(super) line: usize,
    pub(super) match_strength: MatchStrength,
    pub(super) match_evidence: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MatchStrength {
    RelatedExtentUse,
    DirectAttributeAcceptance,
    PerturbPeriodConversion,
    CveDerivedInvariant,
}

impl MatchStrength {
    fn rank(self) -> u8 {
        match self {
            Self::RelatedExtentUse => 1,
            Self::DirectAttributeAcceptance => 2,
            Self::PerturbPeriodConversion => 2,
            Self::CveDerivedInvariant => 2,
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::RelatedExtentUse => "related extent use",
            Self::DirectAttributeAcceptance => "direct parsed-attribute acceptance",
            Self::PerturbPeriodConversion => "period-to-ticks conversion",
            Self::CveDerivedInvariant => "CVE-derived invariant pattern",
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct RuleReview {
    pub(super) rule: &'static KernelCveRule,
    pub(super) locations: Vec<RuleCandidate>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct RuleMatch {
    pub(super) strength: MatchStrength,
    pub(super) evidence: &'static str,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ObservationStatus {
    Candidate,
    FilteredSafe(&'static str),
}

#[derive(Clone, Debug)]
pub(super) struct RuleObservation {
    pub(super) candidate: RuleCandidate,
    pub(super) status: ObservationStatus,
}

#[derive(Clone, Debug)]
pub(super) struct RuleScanResult {
    pub(super) rules: Vec<&'static KernelCveRule>,
    pub(super) source_file_count: usize,
    pub(super) parsed_file_count: usize,
    pub(super) parse_errors: Vec<String>,
    pub(super) unmatched_rules: Vec<&'static str>,
    pub(super) observations: Vec<RuleObservation>,
    pub(super) candidates: Vec<RuleCandidate>,
}

impl RuleScanResult {
    pub(super) fn raw_match_count(&self) -> usize {
        self.observations.len()
    }

    pub(super) fn filtered_safe_count(&self) -> usize {
        self.observations
            .iter()
            .filter(|observation| matches!(observation.status, ObservationStatus::FilteredSafe(_)))
            .count()
    }

    pub(super) fn unmatched_rule_count(&self) -> usize {
        self.unmatched_rules.len()
    }

    pub(super) fn review_groups(&self) -> Vec<RuleReview> {
        let mut groups: Vec<RuleReview> = Vec::new();
        for candidate in &self.candidates {
            if let Some(group) = groups
                .iter_mut()
                .find(|group| group.rule.id == candidate.rule.id)
            {
                group.locations.push(candidate.clone());
            } else {
                groups.push(RuleReview {
                    rule: candidate.rule,
                    locations: vec![candidate.clone()],
                });
            }
        }
        groups
    }
}

/// Applies each reviewed pattern to C sources and headers in its declared
/// scope. Historical function names are provenance only and do not restrict
/// candidate locations. Parser failures remain visible coverage gaps.
pub(super) fn scan_cve_rules(
    linux_path: &Path,
    focus: Option<&str>,
    cve_rule_ids: &[String],
) -> Result<RuleScanResult> {
    let requested_cves: Vec<String> = cve_rule_ids
        .iter()
        .map(|cve| cve.trim().to_ascii_uppercase())
        .collect();
    let all_rules: Vec<_> = all_cve_rules().collect();
    anyhow::ensure!(
        cve_rule_focus_is_supported(focus),
        "--focus {focus:?} does not include any active CVE-derived rule scope"
    );
    for requested_cve in &requested_cves {
        let matching_rules: Vec<_> = all_rules
            .iter()
            .copied()
            .filter(|rule| rule.cve.eq_ignore_ascii_case(requested_cve))
            .collect();
        anyhow::ensure!(
            !matching_rules.is_empty(),
            "--cve-rule {requested_cve} does not match an active CVE-derived rule (the ID may be unknown or reference-only)"
        );
        if let Some(focus) = focus {
            let matching_scopes: Vec<_> = matching_rules
                .iter()
                .filter(|rule| focus_matches_scope(Some(focus), rule.scope))
                .map(|rule| rule.scope)
                .collect();
            anyhow::ensure!(
                !matching_scopes.is_empty(),
                "--cve-rule {requested_cve} belongs to scope(s) {}, which do not match --focus {focus}",
                matching_rules
                    .iter()
                    .map(|rule| rule.scope)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    let rules: Vec<_> = all_rules
        .into_iter()
        .filter(|rule| {
            focus_matches_scope(focus, rule.scope)
                && (requested_cves.is_empty()
                    || requested_cves
                        .iter()
                        .any(|cve| rule.cve.eq_ignore_ascii_case(cve)))
        })
        .collect();
    let mut scopes: Vec<_> = rules.iter().map(|rule| rule.scope).collect();
    scopes.sort_unstable();
    scopes.dedup();

    let mut source_files = Vec::new();
    for scope in &scopes {
        collect_c_files(&linux_path.join(scope), &mut source_files)?;
    }
    source_files.sort();
    source_files.dedup();

    let mut observations = Vec::new();
    let mut candidates = Vec::new();
    let mut parse_errors = Vec::new();
    let mut parsed_file_count = 0;
    let mut matched_rule_ids = HashSet::new();

    for source_path in &source_files {
        let source = match fs::read_to_string(source_path) {
            Ok(source) => source,
            Err(error) => {
                parse_errors.push(format!("{}: {error}", source_path.display()));
                continue;
            }
        };
        let tokens = match lex_c(&source) {
            Ok(tokens) => tokens,
            Err(error) => {
                parse_errors.push(format!("{}: {error:#}", source_path.display()));
                continue;
            }
        };
        let functions = match extract_all_function_bodies(&tokens) {
            Ok(functions) => functions,
            Err(error) => {
                parse_errors.push(format!("{}: {error:#}", source_path.display()));
                continue;
            }
        };
        parsed_file_count += 1;
        let relative_file = source_path
            .strip_prefix(linux_path)
            .unwrap_or(source_path)
            .to_string_lossy()
            .replace('\\', "/");

        for function in functions {
            for rule in &rules {
                if !relative_file.starts_with(&format!("{}/", rule.scope)) {
                    continue;
                }
                let Some(rule_match) = rule_matches(rule, &function.body) else {
                    continue;
                };
                matched_rule_ids.insert(rule.id);
                let candidate = RuleCandidate {
                    rule,
                    relative_file: relative_file.clone(),
                    function: function.name.clone(),
                    line: function.body.line,
                    match_strength: rule_match.strength,
                    match_evidence: rule_match.evidence,
                };
                let safe_reason = if function.body.conditional_depth == 0 {
                    safe_filter_reason(rule, &function.body)
                } else {
                    None
                };
                if let Some(reason) = safe_reason {
                    observations.push(RuleObservation {
                        candidate,
                        status: ObservationStatus::FilteredSafe(reason),
                    });
                } else {
                    candidates.push(candidate.clone());
                    observations.push(RuleObservation {
                        candidate,
                        status: ObservationStatus::Candidate,
                    });
                }
            }
        }
    }

    let unmatched_rules = rules
        .iter()
        .filter(|rule| !matched_rule_ids.contains(rule.id))
        .map(|rule| rule.id)
        .collect();

    candidates.sort_by(|left, right| {
        right
            .match_strength
            .rank()
            .cmp(&left.match_strength.rank())
            .then_with(|| left.relative_file.cmp(&right.relative_file))
            .then_with(|| left.line.cmp(&right.line))
            .then_with(|| left.function.cmp(&right.function))
            .then_with(|| left.rule.id.cmp(right.rule.id))
    });
    candidates.dedup_by(|left, right| {
        left.relative_file == right.relative_file
            && left.function == right.function
            && left.rule.id == right.rule.id
    });

    Ok(RuleScanResult {
        rules,
        source_file_count: source_files.len(),
        parsed_file_count,
        parse_errors,
        unmatched_rules,
        observations,
        candidates,
    })
}

fn focus_matches_scope(focus: Option<&str>, scope: &str) -> bool {
    let Some(focus) = focus else {
        return true;
    };
    let focus = if focus == "ntfs3" { "fs/ntfs3" } else { focus };
    scope == focus
        || scope
            .strip_prefix(focus)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

pub(super) fn cve_rule_focus_is_supported(focus: Option<&str>) -> bool {
    focus.is_none() || all_cve_rules().any(|rule| focus_matches_scope(focus, rule.scope))
}

fn collect_c_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    if !directory.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(directory)
        .with_context(|| format!("listing CVE-rule scope {}", directory.display()))?
    {
        let entry = entry.with_context(|| format!("reading entry in {}", directory.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("reading file type for {}", path.display()))?;
        if file_type.is_dir() {
            collect_c_files(&path, files)?;
        } else if file_type.is_file()
            && path.extension().is_some_and(|ext| ext == "c" || ext == "h")
        {
            files.push(path);
        }
    }
    Ok(())
}

fn rule_matches(rule: &KernelCveRule, function: &FunctionBody) -> Option<RuleMatch> {
    match rule.candidate_pattern {
        CandidatePattern::EaNameLength => {
            let tokens = &function.tokens;
            let extent_entry_variables =
                simple_call_identifier_arguments(tokens, "unpacked_ea_size");
            let matched = extent_entry_variables.into_iter().any(|entry| {
                let has_disk_name_length = has_member_access(tokens, entry, "name_len");
                let has_disk_name = has_member_access(tokens, entry, "name");
                let has_name_copy = tokens
                    .iter()
                    .any(|token| matches!(token.text.as_str(), "memcpy" | "memmove"));
                let has_output_size_update = tokens.iter().any(|token| token.text == "+=")
                    && tokens.iter().any(|token| token.text == "ret");
                has_disk_name_length && has_disk_name && (has_name_copy || has_output_size_update)
            });
            matched.then_some(RuleMatch {
                strength: MatchStrength::RelatedExtentUse,
                evidence: "Same-function entry-extent decode, disk-backed EA name length, and name-copy/output-size use.",
            })
        }
        CandidatePattern::AttributeAllocSize => {
            let tokens = &function.tokens;
            let has_disk_extent_decode = tokens.windows(8).any(|window| {
                window[0].text == "le64_to_cpu"
                    && window[1].text == "("
                    && window[3].text == "->"
                    && window[4].text == "nres"
                    && window[5].text == "."
                    && window[6].text == "alloc_size"
                    && window[7].text == ")"
            });
            let has_extent_use = has_sequence(tokens, &["return", "attr"])
                || has_sequence(tokens, &["bytes_to_cluster"])
                || has_sequence(tokens, &["inode_set_bytes"])
                || has_sequence(tokens, &["alloc_size", ">"])
                || has_sequence(tokens, &["alloc_size", "<"])
                || has_sequence(tokens, &[">", "alloc_size"])
                || has_sequence(tokens, &["<", "alloc_size"])
                || has_sequence(tokens, &["alloc_size", "+"])
                || has_sequence(tokens, &["alloc_size", ">", ">"]);
            if !has_disk_extent_decode || !has_extent_use {
                return None;
            }
            if has_sequence(tokens, &["return", "attr", ";"]) {
                Some(RuleMatch {
                    strength: MatchStrength::DirectAttributeAcceptance,
                    evidence: "Same-function disk-backed nres.alloc_size decode and direct return of the parsed attribute.",
                })
            } else {
                Some(RuleMatch {
                    strength: MatchStrength::RelatedExtentUse,
                    evidence: "Same-function endian decode of an on-disk nres.alloc_size field and a related extent/accounting use.",
                })
            }
        }
        CandidatePattern::PerturbPeriodTicks => {
            (!perturb_period_tick_conversion_sites(&function.tokens).is_empty()).then_some(
                RuleMatch {
                    strength: MatchStrength::PerturbPeriodConversion,
                    evidence: "A perturb_period assignment multiplies a configured value by HZ; inspect its bounds and the resulting timer use.",
                },
            )
        }
        _ => cve_specific_rule_match(rule.candidate_pattern, function),
    }
}

fn safe_filter_reason(rule: &KernelCveRule, function: &FunctionBody) -> Option<&'static str> {
    match rule.safe_filter {
        SafeFilter::EaNameLength => ea_name_length_is_bounded(&function.tokens),
        SafeFilter::AttributeAllocSize => attribute_alloc_size_is_bounded(&function.tokens),
        SafeFilter::PerturbPeriodTicks => perturb_period_conversion_is_bounded(&function.tokens),
        SafeFilter::CveSpecific => {
            cve_specific_filter_reason(rule.candidate_pattern, &function.tokens)
        }
    }
}

fn has_sequence(tokens: &[kernel_vuln_c::CToken], sequence: &[&str]) -> bool {
    tokens.windows(sequence.len()).any(|window| {
        window
            .iter()
            .map(|token| token.text.as_str())
            .eq(sequence.iter().copied())
    })
}

fn simple_call_identifier_arguments<'a>(
    tokens: &'a [kernel_vuln_c::CToken],
    call: &'a str,
) -> impl Iterator<Item = &'a str> + 'a {
    tokens.windows(4).filter_map(move |window| {
        (window[0].text == call
            && window[1].text == "("
            && is_identifier(&window[2].text)
            && window[3].text == ")")
            .then_some(window[2].text.as_str())
    })
}

fn has_member_access(tokens: &[kernel_vuln_c::CToken], receiver: &str, member: &str) -> bool {
    tokens.windows(3).any(|window| {
        window[0].text == receiver && window[1].text == "->" && window[2].text == member
    })
}

fn is_identifier(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
#[path = "kernel_vuln_rules_tests.rs"]
mod tests;
