//! Additional CVE-specific lexical patterns and narrow fixed-shape filters.

use super::super::CandidatePattern;
use super::super::MatchStrength;
use super::super::RuleMatch;
use super::CToken;
use super::FunctionBody;

pub fn cve_specific_rule_match(
    pattern: CandidatePattern,
    function: &FunctionBody,
) -> Option<RuleMatch> {
    let tokens = &function.tokens;
    let matched = match pattern {
        CandidatePattern::EbtSnatWritable => {
            has(tokens, &["skb_header_pointer"])
                && has(tokens, &["skb_store_bits"])
                && has(tokens, &["ETH_ALEN"])
        }
        CandidatePattern::OverlayfsIdMapping => {
            has(tokens, &["ctx", ".", "stat", ".", "uid"])
                && has(tokens, &["ctx", ".", "stat", ".", "gid"])
                && has(tokens, &["ovl_need_meta_copy_up"])
        }
        CandidatePattern::PacketHeaderLenSnapshot => {
            count(tokens, &["dev", "->", "hard_header_len"]) >= 2
                && (has(tokens, &["sock_wmalloc"]) || has(tokens, &["packet_alloc_skb"]))
                && has(tokens, &["skb_reserve"])
        }
        CandidatePattern::NftVerdictOwnership => {
            has(tokens, &["NFTA_VERDICT_CODE"])
                && has(tokens, &["NF_VERDICT_MASK"])
                && has(tokens, &["NF_DROP"])
                && has(tokens, &["NF_QUEUE"])
        }
        CandidatePattern::Xen9pTeardown => {
            has(tokens, &["dev_get_drvdata"])
                && has(tokens, &["xen_9pfs_front_free"])
                && has(tokens, &["dev_set_drvdata"])
        }
        CandidatePattern::IoUringTimeoutList => {
            has(
                tokens,
                &[
                    "while",
                    "(",
                    "!",
                    "list_empty",
                    "(",
                    "&",
                    "ctx",
                    "->",
                    "timeout_list",
                ],
            ) && has(tokens, &["io_kill_timeout"])
        }
        CandidatePattern::NftStatefulExpression => {
            has(tokens, &["nf_tables_expr_parse"])
                && has(
                    tokens,
                    &["kzalloc", "(", "expr_info", ".", "ops", "->", "size"],
                )
                && has(tokens, &["nf_tables_newexpr"])
        }
        CandidatePattern::IoUringFixedFilePut => {
            has(tokens, &["io_put_file", "(", "req", "->", "file", ")"])
                && has(tokens, &["req", "->", "file", "=", "NULL"])
        }
        CandidatePattern::NftAnonymousSetLifetime => {
            has(tokens, &["->", "set", "->", "use", "++"])
                || has(tokens, &["set", "->", "use", "++"])
        }
        CandidatePattern::MirredSkbOwnership => {
            has(tokens, &["tcf_mirred_forward"])
                && has(tokens, &["if", "(", "err", ")", "{"])
                && has(tokens, &["is_redirect"])
                && has(tokens, &["retval", "=", "TC_ACT_SHOT"])
        }
        CandidatePattern::KsmbdTconRefcount => {
            has(tokens, &["wait_event"])
                && has(tokens, &["refcount"])
                && has(tokens, &["atomic_read"])
                && has(tokens, &["kfree"])
        }
        CandidatePattern::FuseSyncSubmountRelease => has(
            tokens,
            &["fuse_file_put", "(", "ff", ",", "false", ",", "isdir", ")"],
        ),
        CandidatePattern::UdpGsoSocketOwnership => {
            has(tokens, &["gso_skb", "->", "destructor", "=", "NULL"])
                && has(tokens, &["sock_wfree"])
                && has(tokens, &["skb_segment"])
        }
        CandidatePattern::PipeBufferFlags => {
            has(tokens, &["struct", "pipe_buffer"])
                && has(tokens, &["->", "ops"])
                && has(tokens, &["->", "page"])
        }
        CandidatePattern::NftVlanCopyArithmetic => has(
            tokens,
            &[
                "ethlen",
                "-=",
                "offset",
                "+",
                "len",
                "-",
                "VLAN_ETH_HLEN",
                "+",
                "vlan_hlen",
            ],
        ),
        CandidatePattern::TlsSpliceCursor => {
            has(tokens, &["sk_msg_page_add", "(", "msg_pl"])
                && has(tokens, &["sk_mem_charge", "(", "sk"])
        }
        CandidatePattern::Ipv4FragGapLength => {
            has(
                tokens,
                &["alloclen", "=", "fragheaderlen", "+", "transhdrlen", ";"],
            ) && has(
                tokens,
                &["pagedlen", "=", "datalen", "-", "transhdrlen", ";"],
            )
        }
        CandidatePattern::EaNameLength
        | CandidatePattern::AttributeAllocSize
        | CandidatePattern::PerturbPeriodTicks => return None,
    };

    matched.then_some(RuleMatch {
        strength: MatchStrength::CveDerivedInvariant,
        evidence: "A CVE-derived source pattern matched; trace its input, ownership or bounds invariant, and downstream effects.",
    })
}

pub fn cve_specific_filter_reason(
    pattern: CandidatePattern,
    tokens: &[CToken],
) -> Option<&'static str> {
    match pattern {
        CandidatePattern::EbtSnatWritable
            if guard_precedes_uses(
                tokens,
                &[
                    "if",
                    "(",
                    "skb_ensure_writable",
                    "(",
                    "skb",
                    ",",
                    "sizeof",
                    "(",
                    "_ah",
                    ")",
                    "+",
                    "ETH_ALEN",
                    ")",
                    ")",
                    "return",
                    "EBT_DROP",
                    ";",
                ],
                &["skb_header_pointer"],
            ) && positions(tokens, &["skb_store_bits"])
                .iter()
                .any(|store_position| {
                    positions(tokens, &["skb_header_pointer"])
                        .iter()
                        .any(|header_position| {
                            *header_position < *store_position
                                && is_same_brace_scope(tokens, *header_position, *store_position)
                        })
                }) =>
        {
            Some(
                "The exact full-range writable guard is a direct statement in the same ARP branch before the header access and write.",
            )
        }
        CandidatePattern::OverlayfsIdMapping
            if guard_precedes_uses(
                tokens,
                &[
                    "if",
                    "(",
                    "!",
                    "kuid_has_mapping",
                    "(",
                    "current_user_ns",
                    "(",
                    ")",
                    ",",
                    "ctx",
                    ".",
                    "stat",
                    ".",
                    "uid",
                    ")",
                    "||",
                    "!",
                    "kgid_has_mapping",
                    "(",
                    "current_user_ns",
                    "(",
                    ")",
                    ",",
                    "ctx",
                    ".",
                    "stat",
                    ".",
                    "gid",
                    ")",
                    ")",
                    "return",
                    "-",
                    "EOVERFLOW",
                    ";",
                ],
                &["ovl_need_meta_copy_up"],
            ) =>
        {
            Some(
                "The exact paired uid/gid mapping guard directly rejects copy-up before metadata handling.",
            )
        }
        CandidatePattern::Xen9pTeardown if xen_teardown_is_serialized(tokens) => Some(
            "The exact remove path reads and clears drvdata under the write lock, exits if already removed, and frees only after unlocking.",
        ),
        CandidatePattern::NftStatefulExpression
            if nft_stateful_guard_precedes_allocation(tokens) =>
        {
            Some(
                "The exact non-stateful rejection jumps to error cleanup before expression allocation.",
            )
        }
        CandidatePattern::IoUringFixedFilePut
            if guard_precedes_uses(
                tokens,
                &[
                    "if",
                    "(",
                    "!",
                    "(",
                    "req",
                    "->",
                    "flags",
                    "&",
                    "REQ_F_FIXED_FILE",
                    ")",
                    ")",
                    "io_put_file",
                    "(",
                    "req",
                    "->",
                    "file",
                    ")",
                    ";",
                ],
                &["req", "->", "file", "=", "NULL"],
            ) =>
        {
            Some(
                "The exact fixed-file guard controls the transient put before request-field clearing.",
            )
        }
        CandidatePattern::UdpGsoSocketOwnership if udp_gso_ownership_is_paired(tokens) => Some(
            "The exact segmentation path clears socket and destructor together and restores both on error.",
        ),
        CandidatePattern::PipeBufferFlags if pipe_flags_initialized(tokens) => Some(
            "This construction path initializes flags before publication or assigns the exact locked-write flag alternatives.",
        ),
        CandidatePattern::TlsSpliceCursor if tls_splice_cursor_is_advanced(tokens) => Some(
            "The exact splice path resets copybreak and advances curr to end before charging and reusing the scatterlist.",
        ),
        CandidatePattern::PacketHeaderLenSnapshot
        | CandidatePattern::NftVerdictOwnership
        | CandidatePattern::IoUringTimeoutList
        | CandidatePattern::NftAnonymousSetLifetime
        | CandidatePattern::MirredSkbOwnership
        | CandidatePattern::KsmbdTconRefcount
        | CandidatePattern::FuseSyncSubmountRelease
        | CandidatePattern::NftVlanCopyArithmetic
        | CandidatePattern::Ipv4FragGapLength
        | CandidatePattern::EaNameLength
        | CandidatePattern::AttributeAllocSize
        | CandidatePattern::PerturbPeriodTicks
        | CandidatePattern::EbtSnatWritable
        | CandidatePattern::OverlayfsIdMapping
        | CandidatePattern::Xen9pTeardown
        | CandidatePattern::NftStatefulExpression
        | CandidatePattern::IoUringFixedFilePut
        | CandidatePattern::UdpGsoSocketOwnership
        | CandidatePattern::PipeBufferFlags
        | CandidatePattern::TlsSpliceCursor => None,
    }
}

fn pipe_flags_initialized(tokens: &[CToken]) -> bool {
    let ops = [
        &["buf", "->", "ops", "=", "&", "page_cache_pipe_buf_ops", ";"][..],
        &["buf", "->", "ops", "=", "&", "default_pipe_buf_ops", ";"][..],
    ];
    let zero_flags = ["buf", "->", "flags", "=", "0", ";"];
    let page_assignment = ["buf", "->", "page", "=", "page", ";"];
    let head_publication = ["pipe", "->", "head", "="];
    let packetized_flags = [
        "if",
        "(",
        "is_packetized",
        "(",
        "filp",
        ")",
        ")",
        "buf",
        "->",
        "flags",
        "=",
        "PIPE_BUF_FLAG_PACKET",
        ";",
        "else",
        "buf",
        "->",
        "flags",
        "=",
        "PIPE_BUF_FLAG_CAN_MERGE",
        ";",
    ];
    if ops.iter().any(|sequence| {
        direct_sequence_precedes(tokens, sequence, &zero_flags)
            && direct_sequence_precedes(tokens, &zero_flags, &page_assignment)
    }) || direct_sequence_precedes(tokens, &zero_flags, &head_publication)
    {
        return true;
    }

    anon_pipe_write_flags_are_protected(tokens, &packetized_flags)
}

fn anon_pipe_write_flags_are_protected(tokens: &[CToken], flag_branch: &[&str]) -> bool {
    let lock_helper = [
        "anon_pipe_prefill_and_lock",
        "(",
        "pipe",
        ",",
        "total_len",
        ")",
        ";",
    ];
    let head_publication = ["pipe", "->", "head", "=", "head", "+", "1", ";"];
    let page_assignment = ["buf", "->", "page", "=", "page", ";"];
    let ops_assignment = ["buf", "->", "ops", "=", "&", "anon_pipe_buf_ops", ";"];
    let mutex_unlock = ["mutex_unlock", "(", "&", "pipe", "->", "mutex", ")", ";"];
    let wait = [
        "wait_event_interruptible_exclusive",
        "(",
        "pipe",
        "->",
        "wr_wait",
    ];
    let mutex_lock = ["mutex_lock", "(", "&", "pipe", "->", "mutex", ")", ";"];
    let unlock_helper = ["anon_pipe_trim_and_unlock", "(", "pipe", ")", ";"];
    let flag_assignments = positions(tokens, &["buf", "->", "flags", "="]);
    let lock_positions = positions(tokens, &lock_helper);
    let branch_positions = positions(tokens, flag_branch);
    let unlock_positions = positions(tokens, &unlock_helper);
    let Some(lock_position) = lock_positions.first().copied() else {
        return false;
    };

    if flag_assignments.len() != 2
        || branch_positions.len() != 1
        || positions(tokens, &["struct", "pipe_buffer"]).len() != 1
        || positions(tokens, &page_assignment).len() != 1
        || positions(tokens, &ops_assignment).len() != 1
        || positions(tokens, &head_publication).len() != 1
    {
        return false;
    }

    branch_positions.iter().any(|branch_position| {
        let Some(unlock_position) = unlock_positions
            .iter()
            .copied()
            .find(|position| *branch_position < *position)
        else {
            return false;
        };
        let Some(publication_position) = positions(tokens, &head_publication)
            .into_iter()
            .find(|position| lock_position < *position && *position < *branch_position)
        else {
            return false;
        };
        let Some(page_position) = positions(tokens, &page_assignment)
            .into_iter()
            .find(|position| publication_position < *position && *position < *branch_position)
        else {
            return false;
        };
        let Some(ops_position) = positions(tokens, &ops_assignment)
            .into_iter()
            .find(|position| page_position < *position && *position < *branch_position)
        else {
            return false;
        };
        let Some(unlock_position_in_loop) = positions(tokens, &mutex_unlock)
            .into_iter()
            .find(|position| *branch_position < *position && *position < unlock_position)
        else {
            return false;
        };
        let Some(wait_position) = positions(tokens, &wait)
            .into_iter()
            .find(|position| unlock_position_in_loop < *position && *position < unlock_position)
        else {
            return false;
        };
        let Some(relock_position) = positions(tokens, &mutex_lock)
            .into_iter()
            .find(|position| wait_position < *position && *position < unlock_position)
        else {
            return false;
        };
        lock_position < publication_position
            && ops_position < *branch_position
            && relock_position < unlock_position
            && has(tokens, &["goto", "out", ";"])
            && has(tokens, &["out", ":"])
            && positions(tokens, &["out", ":"])
                .iter()
                .any(|label_position| {
                    *branch_position < *label_position && *label_position < unlock_position
                })
            && !has_control_transfer_or_label(
                &tokens[ops_position + ops_assignment.len()..*branch_position],
            )
    })
}

fn guard_precedes_uses(tokens: &[CToken], guard: &[&str], use_site: &[&str]) -> bool {
    positions(tokens, guard).iter().any(|guard_position| {
        if !is_direct_statement(tokens, *guard_position) {
            return false;
        }
        let guard_end = *guard_position + guard.len();
        if tokens
            .get(guard_end)
            .is_some_and(|token| token.text == "else")
        {
            return false;
        }
        positions(tokens, use_site).iter().any(|use_position| {
            guard_end <= *use_position
                && is_same_brace_scope(tokens, *guard_position, *use_position)
                && !has_control_transfer_or_label(&tokens[guard_end..*use_position])
                && tokens[*guard_position].conditional_depth == 0
                && tokens[*use_position].conditional_depth == 0
        })
    })
}

fn direct_sequence_precedes(tokens: &[CToken], first: &[&str], second: &[&str]) -> bool {
    positions(tokens, first).iter().any(|first_position| {
        is_direct_statement(tokens, *first_position)
            && positions(tokens, second).iter().any(|second_position| {
                *first_position + first.len() <= *second_position
                    && is_direct_statement(tokens, *second_position)
                    && is_same_brace_scope(tokens, *first_position, *second_position)
                    && !has_control_transfer_or_label(
                        &tokens[*first_position + first.len()..*second_position],
                    )
            })
    })
}

fn sequence_precedes_same_scope(tokens: &[CToken], first: &[&str], second: &[&str]) -> bool {
    positions(tokens, first).iter().any(|first_position| {
        positions(tokens, second).iter().any(|second_position| {
            *first_position + first.len() <= *second_position
                && is_direct_statement(tokens, *first_position)
                && is_same_brace_scope(tokens, *first_position, *second_position)
                && !has_control_transfer_or_label(
                    &tokens[*first_position + first.len()..*second_position],
                )
        })
    })
}

fn xen_teardown_is_serialized(tokens: &[CToken]) -> bool {
    let null_guard = [
        "if",
        "(",
        "priv",
        "==",
        "NULL",
        ")",
        "{",
        "write_unlock",
        "(",
        "&",
        "xen_9pfs_lock",
        ")",
        ";",
        "return",
        ";",
        "}",
    ];
    let drvdata_read = ["dev_get_drvdata", "(", "&", "dev", "->", "dev", ")"];
    let drvdata_clear = [
        "dev_set_drvdata",
        "(",
        "&",
        "dev",
        "->",
        "dev",
        ",",
        "NULL",
        ")",
        ";",
    ];
    let write_lock = ["write_lock", "(", "&", "xen_9pfs_lock", ")", ";"];
    let write_unlock = ["write_unlock", "(", "&", "xen_9pfs_lock", ")", ";"];
    let free = ["xen_9pfs_front_free", "(", "priv", ")", ";"];
    positions(tokens, &null_guard).iter().any(|guard_position| {
        let guard_end = *guard_position + null_guard.len();
        let Some(read_position) = positions(tokens, &drvdata_read)
            .into_iter()
            .find(|position| *position < *guard_position)
        else {
            return false;
        };
        let Some(clear_position) = positions(tokens, &drvdata_clear)
            .into_iter()
            .find(|position| guard_end <= *position)
        else {
            return false;
        };
        let Some(free_position) = positions(tokens, &free)
            .into_iter()
            .find(|position| clear_position + drvdata_clear.len() <= *position)
        else {
            return false;
        };
        is_direct_statement(tokens, *guard_position)
            && is_same_brace_scope(tokens, read_position, *guard_position)
            && is_same_brace_scope(tokens, *guard_position, clear_position)
            && is_same_brace_scope(tokens, clear_position, free_position)
            && sequence_precedes_same_scope(tokens, &write_lock, &drvdata_read)
            && direct_sequence_precedes(tokens, &drvdata_clear, &write_unlock)
            && direct_sequence_precedes(tokens, &write_unlock, &free)
            && !has_control_transfer_or_label(&tokens[read_position..free_position])
    })
}

fn nft_stateful_guard_precedes_allocation(tokens: &[CToken]) -> bool {
    let guard = [
        "if",
        "(",
        "!",
        "(",
        "expr_info",
        ".",
        "ops",
        "->",
        "type",
        "->",
        "flags",
        "&",
        "NFT_EXPR_STATEFUL",
        ")",
        ")",
        "goto",
        "err_expr_stateful",
        ";",
    ];
    let allocation = ["kzalloc", "(", "expr_info", ".", "ops", "->", "size"];
    let label = ["err_expr_stateful", ":"];
    let error_return = ["return", "ERR_PTR", "(", "err", ")", ";"];
    positions(tokens, &guard).iter().any(|guard_position| {
        let guard_end = *guard_position + guard.len();
        is_direct_statement(tokens, *guard_position)
            && positions(tokens, &allocation)
                .iter()
                .any(|allocation_position| {
                    guard_end <= *allocation_position
                        && is_same_brace_scope(tokens, *guard_position, *allocation_position)
                        && !has_control_transfer_or_label(&tokens[guard_end..*allocation_position])
                        && positions(tokens, &label).iter().any(|label_position| {
                            *allocation_position < *label_position
                                && positions(tokens, &error_return)
                                    .iter()
                                    .any(|return_position| *label_position < *return_position)
                        })
                })
    })
}

fn udp_gso_ownership_is_paired(tokens: &[CToken]) -> bool {
    let clear = [
        "if",
        "(",
        "copy_dtor",
        ")",
        "{",
        "gso_skb",
        "->",
        "destructor",
        "=",
        "NULL",
        ";",
        "gso_skb",
        "->",
        "sk",
        "=",
        "NULL",
        ";",
        "}",
    ];
    let segment = ["skb_segment", "(", "gso_skb"];
    let restore = [
        "if",
        "(",
        "IS_ERR_OR_NULL",
        "(",
        "segs",
        ")",
        ")",
        "{",
        "if",
        "(",
        "copy_dtor",
        ")",
        "{",
        "gso_skb",
        "->",
        "destructor",
        "=",
        "sock_wfree",
        ";",
        "gso_skb",
        "->",
        "sk",
        "=",
        "sk",
        ";",
        "}",
        "return",
        "segs",
        ";",
        "}",
    ];
    positions(tokens, &clear).iter().any(|clear_position| {
        let clear_end = *clear_position + clear.len();
        positions(tokens, &segment).iter().any(|segment_position| {
            clear_end <= *segment_position
                && is_direct_statement(tokens, *clear_position)
                && is_same_brace_scope(tokens, *clear_position, *segment_position)
                && positions(tokens, &restore).iter().any(|restore_position| {
                    *segment_position < *restore_position
                        && is_same_brace_scope(tokens, *segment_position, *restore_position)
                        && !has_control_transfer_or_label(&tokens[clear_end..*restore_position])
                })
        })
    })
}

fn tls_splice_cursor_is_advanced(tokens: &[CToken]) -> bool {
    let add = ["sk_msg_page_add", "(", "msg_pl"];
    let copybreak = ["msg_pl", "->", "sg", ".", "copybreak", "=", "0", ";"];
    let curr = [
        "msg_pl", "->", "sg", ".", "curr", "=", "msg_pl", "->", "sg", ".", "end", ";",
    ];
    let charge = ["sk_mem_charge", "(", "sk"];
    positions(tokens, &add).iter().any(|add_position| {
        positions(tokens, &copybreak)
            .iter()
            .any(|copybreak_position| {
                positions(tokens, &curr).iter().any(|curr_position| {
                    positions(tokens, &charge).iter().any(|charge_position| {
                        *add_position < *copybreak_position
                            && *copybreak_position < *curr_position
                            && *curr_position < *charge_position
                            && [
                                *add_position,
                                *copybreak_position,
                                *curr_position,
                                *charge_position,
                            ]
                            .windows(2)
                            .all(|pair| is_same_brace_scope(tokens, pair[0], pair[1]))
                            && is_direct_statement(tokens, *copybreak_position)
                            && is_direct_statement(tokens, *curr_position)
                            && !has_control_transfer_or_label(
                                &tokens[*add_position..*charge_position],
                            )
                    })
                })
            })
    })
}

fn is_direct_statement(tokens: &[CToken], position: usize) -> bool {
    position == 0
        || tokens
            .get(position.wrapping_sub(1))
            .is_some_and(|token| matches!(token.text.as_str(), ";" | "{" | "}" | ":"))
}

fn is_same_brace_scope(tokens: &[CToken], first: usize, second: usize) -> bool {
    fn scope(tokens: &[CToken], position: usize) -> Option<usize> {
        let mut stack = Vec::new();
        for (index, token) in tokens.iter().enumerate().take(position) {
            match token.text.as_str() {
                "{" => stack.push(index),
                "}" => {
                    stack.pop();
                }
                _ => {}
            }
        }
        stack.last().copied()
    }
    scope(tokens, first) == scope(tokens, second)
}

fn has_control_transfer_or_label(tokens: &[CToken]) -> bool {
    tokens.windows(2).any(|pair| {
        matches!(pair[0].text.as_str(), "goto" | "case" | "default")
            || (is_identifier(&pair[0].text) && pair[1].text == ":")
    })
}

fn is_identifier(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn count(tokens: &[CToken], sequence: &[&str]) -> usize {
    positions(tokens, sequence).len()
}

fn has(tokens: &[CToken], sequence: &[&str]) -> bool {
    !positions(tokens, sequence).is_empty()
}

fn positions(tokens: &[CToken], sequence: &[&str]) -> Vec<usize> {
    if sequence.is_empty() {
        return Vec::new();
    }
    tokens
        .windows(sequence.len())
        .enumerate()
        .filter_map(|(index, window)| {
            window
                .iter()
                .map(|token| token.text.as_str())
                .eq(sequence.iter().copied())
                .then_some(index)
        })
        .collect()
}
