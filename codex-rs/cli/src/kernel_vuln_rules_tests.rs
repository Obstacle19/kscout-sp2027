use super::kernel_vuln_c::FunctionBody;
use super::kernel_vuln_c::extract_all_function_bodies;
use super::kernel_vuln_c::extract_function_bodies;
use super::kernel_vuln_c::perturb_period_conversion_is_bounded;
use super::*;
use pretty_assertions::assert_eq;
use std::fs;
use tempfile::tempdir;

const EA_BEFORE_FIX: &str = r#"
static ssize_t ntfs_list_ea(void)
{
    int ea_size;
    for (;;) {
        ea_size = unpacked_ea_size(ea);
        if (!ea->name_len)
            break;
        if (buffer)
            memcpy(buffer + ret, ea->name, ea->name_len);
        ret += ea->name_len + 1;
    }
    return ret;
}
"#;

const EA_AFTER_FIX: &str = r#"
static ssize_t ntfs_list_ea(void)
{
    int ea_size;
    for (;;) {
        ea_size = unpacked_ea_size(ea);
        if (!ea->name_len)
            break;
        if (ea->name_len > ea_size)
            break;
        if (buffer)
            memcpy(buffer + ret, ea->name, ea->name_len);
        ret += ea->name_len + 1;
    }
    return ret;
}
"#;

const EA_AFTER_FIX_CURRENT: &str = r#"
static ssize_t ntfs_list_ea(void)
{
    for (;;) {
        int ea_size = unpacked_ea_size(ea);
        u8 name_len = ea->name_len;
        if (!name_len)
            break;
        if (name_len > ea_size) {
            ntfs_set_state(ni->mi.sbi, NTFS_DIRTY_ERROR);
            err = -EINVAL;
            break;
        }
        if (buffer)
            memcpy(buffer + ret, ea->name, name_len);
        ret += name_len + 1;
    }
    return ret;
}
"#;

const ATTR_BEFORE_FIX: &str = r#"
struct ATTRIB *mi_enum_attr(void)
{
    alloc_size = le64_to_cpu(attr->nres.alloc_size);
    if (data_size > alloc_size)
        goto out;
    return attr;
out:
    return NULL;
}
"#;

const ATTR_AFTER_FIX_DIRECT: &str = r#"
struct ATTRIB *mi_enum_attr(void)
{
    alloc_size = le64_to_cpu(attr->nres.alloc_size);
    if (alloc_size > mi->sbi->volume.size)
        return NULL;
    return attr;
out:
    return NULL;
}
"#;

const ATTR_AFTER_FIX_GOTO: &str = r#"
struct ATTRIB *mi_enum_attr(void)
{
    alloc_size = le64_to_cpu(attr->nres.alloc_size);
    if (alloc_size > mi->sbi->volume.size)
        goto out;
    return attr;
out:
    _ntfs_bad_inode();
    return NULL;
}
"#;

const SFQ_BEFORE_FIX: &str = r#"
static int sfq_change(void)
{
    int perturb_period;
    perturb_period = ctl->perturb_period * HZ;
    if (perturb_period)
        mod_timer(&q->perturb_timer, jiffies + perturb_period);
    return 0;
}
"#;

const SFQ_AFTER_FIX: &str = r#"
static int sfq_change(void)
{
    int perturb_period;
    if (ctl->perturb_period < 0 ||
        ctl->perturb_period > INT_MAX / HZ) {
        NL_SET_ERR_MSG_MOD(extack, "invalid perturb period");
        return -EINVAL;
    }
    perturb_period = ctl->perturb_period * HZ;
    if (perturb_period)
        mod_timer(&q->perturb_timer, jiffies + perturb_period);
    return 0;
}
"#;

const FLOW_UNBOUNDED_CONVERSION: &str = r#"
static int flow_change(void)
{
    unsigned int perturb_period = 0;
    if (tb[TCA_FLOW_PERTURB])
        perturb_period = nla_get_u32(tb[TCA_FLOW_PERTURB]) * HZ;
    fnew->perturb_period = perturb_period;
    if (perturb_period)
        mod_timer(&fnew->perturb_timer, jiffies + perturb_period);
    return 0;
}
"#;

fn function_body(source: &str, name: &str) -> FunctionBody {
    let tokens = lex_c(source).expect("C source should lex");
    let mut functions = extract_function_bodies(&tokens, name).expect("function should parse");
    assert_eq!(functions.len(), 1);
    functions.pop().expect("one function body")
}

fn active_rule(cve: &str) -> &'static KernelCveRule {
    all_cve_rules()
        .find(|rule| rule.cve == cve)
        .unwrap_or_else(|| panic!("missing active rule for {cve}"))
}

#[test]
fn every_additional_rule_replays_its_pre_fix_signature_and_fixed_control() {
    let cases = [
        (
            "CVE-2026-53266",
            r#"int candidate(void) { ap = skb_header_pointer(skb, 0, sizeof(_ah), &_ah); skb_store_bits(skb, sizeof(_ah), info->mac, ETH_ALEN); }"#,
            r#"int candidate(void) { if (skb_ensure_writable(skb, sizeof(_ah) + ETH_ALEN)) return EBT_DROP; ap = skb_header_pointer(skb, 0, sizeof(_ah), &_ah); skb_store_bits(skb, sizeof(_ah), info->mac, ETH_ALEN); }"#,
            true,
        ),
        (
            "CVE-2023-0386",
            r#"int candidate(void) { if (ctx.stat.uid.val) return -EINVAL; if (ctx.stat.gid.val) return -EINVAL; ctx.metacopy = ovl_need_meta_copy_up(dentry, ctx.stat.mode, flags); }"#,
            r#"int candidate(void) { if (!kuid_has_mapping(current_user_ns(), ctx.stat.uid) || !kgid_has_mapping(current_user_ns(), ctx.stat.gid)) return -EOVERFLOW; ctx.metacopy = ovl_need_meta_copy_up(dentry, ctx.stat.mode, flags); }"#,
            true,
        ),
        (
            "CVE-2026-74582",
            r#"int candidate(void) { hlen = dev->hard_header_len; skb_reserve(skb, dev->hard_header_len); return sock_wmalloc(sk, dev->hard_header_len); }"#,
            r#"int candidate(void) { int hard_header_len = READ_ONCE(dev->hard_header_len); skb_reserve(skb, hard_header_len); return sock_wmalloc(sk, hard_header_len); }"#,
            false,
        ),
        (
            "CVE-2024-1086",
            r#"int candidate(void) { if (!tb[NFTA_VERDICT_CODE]) return -EINVAL; verdict = nla_get_be32(tb[NFTA_VERDICT_CODE]) & NF_VERDICT_MASK; if (verdict == NF_DROP || verdict == NF_QUEUE) return 0; }"#,
            r#"int candidate(void) { switch (code) { case NF_ACCEPT: case NF_DROP: case NF_QUEUE: return 0; default: return -EINVAL; } }"#,
            false,
        ),
        (
            "CVE-2026-43249",
            r#"void candidate(void) { priv = dev_get_drvdata(&dev->dev); xen_9pfs_front_free(priv); dev_set_drvdata(&dev->dev, NULL); }"#,
            r#"void candidate(void) { write_lock(&xen_9pfs_lock); priv = dev_get_drvdata(&dev->dev); if (priv == NULL) { write_unlock(&xen_9pfs_lock); return; } dev_set_drvdata(&dev->dev, NULL); write_unlock(&xen_9pfs_lock); xen_9pfs_front_free(priv); }"#,
            true,
        ),
        (
            "CVE-2022-29582",
            r#"void candidate(void) { while (!list_empty(&ctx->timeout_list)) io_kill_timeout(ctx); }"#,
            r#"void candidate(void) { list_for_each_entry_safe(timeout, tmp, &ctx->timeout_list, list) io_kill_timeout(timeout); }"#,
            false,
        ),
        (
            "CVE-2022-32250",
            r#"int candidate(void) { err = nf_tables_expr_parse(ctx, nla, &expr_info); expr = kzalloc(expr_info.ops->size, GFP_KERNEL_ACCOUNT); return nf_tables_newexpr(ctx, &expr_info, expr); }"#,
            r#"int candidate(void) { err = nf_tables_expr_parse(ctx, nla, &expr_info); if (!(expr_info.ops->type->flags & NFT_EXPR_STATEFUL)) goto err_expr_stateful; expr = kzalloc(expr_info.ops->size, GFP_KERNEL_ACCOUNT); return nf_tables_newexpr(ctx, &expr_info, expr); err_expr_stateful: return ERR_PTR(err); }"#,
            true,
        ),
        (
            "CVE-2022-3910",
            r#"void candidate(void) { io_put_file(req->file); req->file = NULL; }"#,
            r#"void candidate(void) { if (!(req->flags & REQ_F_FIXED_FILE)) io_put_file(req->file); req->file = NULL; }"#,
            true,
        ),
        (
            "CVE-2023-32233",
            r#"void candidate(void) { priv->set->use++; nft_trans_commit_update(ctx); }"#,
            r#"void candidate(void) { nf_tables_activate_set(ctx, priv->set); nf_tables_deactivate_set(ctx, priv->set); }"#,
            false,
        ),
        (
            "CVE-2024-26739",
            r#"int candidate(void) { err = tcf_mirred_forward(skb); if (err) { if (is_redirect) retval = TC_ACT_SHOT; } return retval; }"#,
            r#"int candidate(void) { err = tcf_mirred_forward(skb); if (err) { if (is_redirect) return retval; } return retval; }"#,
            false,
        ),
        (
            "CVE-2025-68817",
            r#"void candidate(void) { wait_event(tree_conn->refcount_q, atomic_read(&tree_conn->refcount) == 0); kfree(tree_conn); }"#,
            r#"void candidate(void) { if (refcount_dec_and_test(&tree_conn->refcount)) kfree(tree_conn); }"#,
            false,
        ),
        (
            "CVE-2026-53381",
            r#"void candidate(void) { fuse_file_put(ff, false, isdir); }"#,
            r#"void candidate(void) { fuse_file_put(ff, ff->fm->fc->auto_submounts); }"#,
            false,
        ),
        (
            "CVE-2025-21926",
            r#"void candidate(void) { copy_dtor = gso_skb->destructor == sock_wfree; gso_skb->destructor = NULL; segs = skb_segment(gso_skb, features); }"#,
            r#"void candidate(void) { copy_dtor = gso_skb->destructor == sock_wfree; if (copy_dtor) { gso_skb->destructor = NULL; gso_skb->sk = NULL; } segs = skb_segment(gso_skb, features); if (IS_ERR_OR_NULL(segs)) { if (copy_dtor) { gso_skb->destructor = sock_wfree; gso_skb->sk = sk; } return segs; } }"#,
            true,
        ),
        (
            "CVE-2022-0847",
            r#"void candidate(void) { struct pipe_buffer *buf; buf->ops = &page_cache_pipe_buf_ops; buf->page = page; }"#,
            r#"void candidate(void) { struct pipe_buffer *buf; buf->ops = &page_cache_pipe_buf_ops; buf->flags = 0; buf->page = page; }"#,
            true,
        ),
        (
            "CVE-2023-0179",
            r#"void candidate(void) { ethlen -= offset + len - VLAN_ETH_HLEN + vlan_hlen; }"#,
            r#"void candidate(void) { ethlen -= offset + len - VLAN_ETH_HLEN - vlan_hlen; }"#,
            false,
        ),
        (
            "CVE-2024-0646",
            r#"void candidate(void) { sk_msg_page_add(msg_pl, page, part, off); sk_mem_charge(sk, part); }"#,
            r#"void candidate(void) { sk_msg_page_add(msg_pl, page, part, off); msg_pl->sg.copybreak = 0; msg_pl->sg.curr = msg_pl->sg.end; sk_mem_charge(sk, part); }"#,
            true,
        ),
        (
            "CVE-2026-53366",
            r#"void candidate(void) { alloclen = fragheaderlen + transhdrlen; pagedlen = datalen - transhdrlen; }"#,
            r#"void candidate(void) { alloclen = fragheaderlen + transhdrlen + fraggap; pagedlen = datalen - transhdrlen - fraggap; }"#,
            false,
        ),
    ];

    for (cve, pre_fix, fixed, fixed_is_filtered) in cases {
        let rule = active_rule(cve);
        let before = function_body(pre_fix, "candidate");
        assert!(
            rule_matches(rule, &before).is_some(),
            "{cve} must retain its pre-fix signature"
        );

        let after = function_body(fixed, "candidate");
        if fixed_is_filtered {
            assert!(
                rule_matches(rule, &after).is_some(),
                "{cve} fixed control should exercise its conservative filter"
            );
            assert!(
                safe_filter_reason(rule, &after).is_some(),
                "{cve} exact fixed control should be filtered safe"
            );
        } else {
            assert!(
                rule_matches(rule, &after).is_none(),
                "{cve} fixed control should no longer match the vulnerable signature"
            );
        }
    }
}

#[test]
fn nft_verdict_rule_ignores_internal_verdict_decoders() {
    let rule = active_rule("CVE-2024-1086");
    let internal_decoder = function_body(
        "int candidate(void) { switch (verdict & NF_VERDICT_MASK) { case NF_DROP: case NF_QUEUE: return 0; } }",
        "candidate",
    );

    assert!(rule_matches(rule, &internal_decoder).is_none());
}

#[test]
fn pipe_buffer_filter_requires_initialization_before_publication() {
    let rule = active_rule("CVE-2022-0847");
    let splice_control = function_body(
        "void candidate(void) { struct pipe_buffer *buf; buf->page = page; buf->ops = ops; buf->flags = 0; pipe->head = head; }",
        "candidate",
    );
    let conditional_initialization = function_body(
        "void candidate(void) { struct pipe_buffer *buf; buf->ops = ops; if (condition) { buf->flags = 0; } buf->page = page; }",
        "candidate",
    );
    let locked_explicit_flags = function_body(
        r#"
void candidate(void)
{
    anon_pipe_prefill_and_lock(pipe, total_len);
    if (!pipe->readers)
        goto out;
    for (;;) {
        if (!pipe_full(head, pipe->tail, pipe->max_usage)) {
            struct pipe_buffer *buf;
            pipe->head = head + 1;
            buf->page = page;
            buf->ops = &anon_pipe_buf_ops;
            if (is_packetized(filp))
                buf->flags = PIPE_BUF_FLAG_PACKET;
            else
                buf->flags = PIPE_BUF_FLAG_CAN_MERGE;
            break;
        }
        mutex_unlock(&pipe->mutex);
        wait_event_interruptible_exclusive(pipe->wr_wait, pipe_writable(pipe));
        mutex_lock(&pipe->mutex);
    }
out:
    anon_pipe_trim_and_unlock(pipe);
}
"#,
        "candidate",
    );

    assert!(rule_matches(rule, &splice_control).is_some());
    assert!(safe_filter_reason(rule, &splice_control).is_some());
    assert_eq!(safe_filter_reason(rule, &conditional_initialization), None);
    assert!(rule_matches(rule, &locked_explicit_flags).is_some());
    assert!(safe_filter_reason(rule, &locked_explicit_flags).is_some());
}

#[test]
fn c_lexer_ignores_comments_and_literals_when_finding_anchors() {
    let source = r#"
/* ntfs_list_ea() { this is a comment } */
static const char *example = "ntfs_list_ea() { not a function }";
static ssize_t ntfs_list_ea(void)
{
    /* braces in comments must not affect the body */
    if (ea->name_len) {
        return 1;
    }
    return 0;
}
"#;
    let tokens = lex_c(source).expect("C source should lex");
    let functions =
        extract_function_bodies(&tokens, "ntfs_list_ea").expect("function should parse");

    assert_eq!(functions.len(), 1);
    assert!(functions[0].line > 1);
}

#[test]
fn c_function_enumerator_finds_definitions_and_skips_prototypes_and_calls() {
    let source = r#"
static int declared_only(void);
static int helper(int value)
{
    return value;
}
static int caller(void)
{
    return helper(1);
}
"#;
    let tokens = lex_c(source).expect("C source should lex");
    let functions = extract_all_function_bodies(&tokens).expect("definitions should parse");

    assert_eq!(
        functions
            .iter()
            .map(|function| function.name.as_str())
            .collect::<Vec<_>>(),
        ["helper", "caller"]
    );
}

#[test]
fn ea_filter_keeps_pre_fix_candidate_and_filters_the_verified_guard() {
    assert_eq!(
        ea_name_length_is_bounded(&function_body(EA_BEFORE_FIX, "ntfs_list_ea").tokens),
        None
    );
    assert!(
        ea_name_length_is_bounded(&function_body(EA_AFTER_FIX, "ntfs_list_ea").tokens).is_some()
    );
    assert!(
        ea_name_length_is_bounded(&function_body(EA_AFTER_FIX_CURRENT, "ntfs_list_ea").tokens)
            .is_some()
    );
}

#[test]
fn ea_filter_keeps_near_miss_guards_for_model_review() {
    let guard_after_sink = r#"
static ssize_t ntfs_list_ea(void)
{
    for (;;) {
        memcpy(buffer + ret, ea->name, name_len);
        if (ea->name_len > ea_size) {
            ntfs_set_state(ni->mi->sbi, NTFS_DIRTY_ERROR);
            err = -EINVAL;
            break;
        }
        ret += name_len + 1;
    }
    return ret;
}
"#;
    let wrong_comparison =
        EA_AFTER_FIX.replace("ea->name_len > ea_size", "ea->name_len >= ea_size");
    let nested_switch = EA_AFTER_FIX_CURRENT.replace(
        "        if (name_len > ea_size) {\n            ntfs_set_state(ni->mi.sbi, NTFS_DIRTY_ERROR);\n            err = -EINVAL;\n            break;\n        }",
        "        switch (state) {\n        case 0:\n            if (name_len > ea_size) {\n                ntfs_set_state(ni->mi.sbi, NTFS_DIRTY_ERROR);\n                err = -EINVAL;\n                break;\n            }\n            break;\n        }",
    );
    let nested_guard = EA_AFTER_FIX.replace(
        "        if (ea->name_len > ea_size)\n            break;",
        "        if (validate_name)\n            if (ea->name_len > ea_size)\n                break;",
    );
    let changed_extent = EA_AFTER_FIX.replace(
        "        if (buffer)",
        "        ea_size = 0;\n        if (buffer)",
    );
    let goto_bypasses_guard = EA_AFTER_FIX.replace(
        "        if (ea->name_len > ea_size)\n            break;",
        "        if (skip_check)\n            goto use_name;\n        if (ea->name_len > ea_size)\n            break;",
    ).replace(
        "        if (buffer)",
        "    use_name:\n        if (buffer)",
    );
    let unrelated_alias = EA_AFTER_FIX_CURRENT.replace(
        "u8 name_len = ea->name_len;",
        "u8 name_len = other_name_len;",
    );
    let reassigned_alias =
        EA_AFTER_FIX_CURRENT.replace("if (!name_len)", "name_len += 1;\n        if (!name_len)");

    assert_eq!(
        ea_name_length_is_bounded(&function_body(guard_after_sink, "ntfs_list_ea").tokens),
        None
    );
    assert_eq!(
        ea_name_length_is_bounded(&function_body(&wrong_comparison, "ntfs_list_ea").tokens),
        None
    );
    assert_eq!(
        ea_name_length_is_bounded(&function_body(&nested_switch, "ntfs_list_ea").tokens),
        None
    );
    assert_eq!(
        ea_name_length_is_bounded(&function_body(&nested_guard, "ntfs_list_ea").tokens),
        None
    );
    assert_eq!(
        ea_name_length_is_bounded(&function_body(&unrelated_alias, "ntfs_list_ea").tokens),
        None
    );
    assert_eq!(
        ea_name_length_is_bounded(&function_body(&reassigned_alias, "ntfs_list_ea").tokens),
        None
    );
    assert_eq!(
        ea_name_length_is_bounded(&function_body(&changed_extent, "ntfs_list_ea").tokens),
        None
    );
    assert_eq!(
        ea_name_length_is_bounded(&function_body(&goto_bypasses_guard, "ntfs_list_ea").tokens),
        None
    );
}

#[test]
fn ea_filter_ignores_guard_text_in_comments_and_strings() {
    let source = r#"
static ssize_t ntfs_list_ea(void)
{
    for (;;) {
        const char *text = "if (ea->name_len > ea_size) break";
        /* if (ea->name_len > ea_size) { break; } */
        memcpy(buffer + ret, ea->name, name_len);
        ret += name_len + 1;
    }
    return ret;
}
"#;

    assert_eq!(
        ea_name_length_is_bounded(&function_body(source, "ntfs_list_ea").tokens),
        None
    );
}

#[test]
fn safe_filter_does_not_trust_checks_hidden_in_preprocessor_branches() {
    let conditional_ea = EA_AFTER_FIX_CURRENT
        .replace(
            "if (name_len > ea_size)",
            r#"#if defined(CONFIG_NTFS3_TEST)
        if (ea->name_len > ea_size)"#,
        )
        .replace(
            r#"            break;
        }
        if (buffer)"#,
            r#"            break;
        }
#endif
        if (buffer)"#,
        );
    let conditional_attr = ATTR_AFTER_FIX_DIRECT
        .replace(
            "if (alloc_size > mi->sbi->volume.size)",
            r#"#if defined(CONFIG_NTFS3_TEST)
    if (alloc_size > mi->sbi->volume.size)"#,
        )
        .replace(
            r#"        return NULL;
    return attr;"#,
            r#"        return NULL;
#endif
    return attr;"#,
        );

    assert_eq!(
        ea_name_length_is_bounded(&function_body(&conditional_ea, "ntfs_list_ea").tokens),
        None
    );
    assert_eq!(
        attribute_alloc_size_is_bounded(&function_body(&conditional_attr, "mi_enum_attr").tokens),
        None
    );
}

#[test]
fn attribute_filter_requires_the_exact_volume_bound_and_reject_path() {
    assert_eq!(
        attribute_alloc_size_is_bounded(&function_body(ATTR_BEFORE_FIX, "mi_enum_attr").tokens),
        None
    );
    assert!(
        attribute_alloc_size_is_bounded(
            &function_body(ATTR_AFTER_FIX_DIRECT, "mi_enum_attr").tokens
        )
        .is_some()
    );
    assert!(
        attribute_alloc_size_is_bounded(&function_body(ATTR_AFTER_FIX_GOTO, "mi_enum_attr").tokens)
            .is_some()
    );

    let wrong_bound =
        ATTR_AFTER_FIX_DIRECT.replace("mi->sbi->volume.size", "mi->sbi->used.bitmap.nbits");
    let nested_guard = ATTR_AFTER_FIX_DIRECT.replace(
        "    if (alloc_size > mi->sbi->volume.size)\n        return NULL;",
        "    if (validate_attr)\n        if (alloc_size > mi->sbi->volume.size)\n            return NULL;",
    );
    let check_before_decode = ATTR_AFTER_FIX_DIRECT.replace(
        "    alloc_size = le64_to_cpu(attr->nres.alloc_size);\n    if (alloc_size > mi->sbi->volume.size)\n        return NULL;",
        "    if (alloc_size > mi->sbi->volume.size)\n        return NULL;\n    alloc_size = le64_to_cpu(attr->nres.alloc_size);",
    );
    let reassigned_alloc_size = ATTR_AFTER_FIX_DIRECT.replace(
        "    return attr;",
        "    alloc_size = U64_MAX;\n    return attr;",
    );
    assert_eq!(
        attribute_alloc_size_is_bounded(&function_body(&wrong_bound, "mi_enum_attr").tokens),
        None
    );
    assert_eq!(
        attribute_alloc_size_is_bounded(&function_body(&nested_guard, "mi_enum_attr").tokens),
        None
    );
    assert_eq!(
        attribute_alloc_size_is_bounded(
            &function_body(&check_before_decode, "mi_enum_attr").tokens
        ),
        None
    );
    assert_eq!(
        attribute_alloc_size_is_bounded(
            &function_body(&reassigned_alloc_size, "mi_enum_attr").tokens
        ),
        None
    );
}

#[test]
fn rule_scan_reports_unmatched_rules_instead_of_treating_them_as_safe() {
    let root = tempdir().expect("temporary source tree");

    let scan =
        scan_cve_rules(root.path(), None, &[]).expect("missing subsystem files are reportable");

    assert_eq!(scan.raw_match_count(), 0);
    assert_eq!(scan.filtered_safe_count(), 0);
    assert_eq!(scan.unmatched_rule_count(), all_cve_rules().count());
    assert!(scan.candidates.is_empty());
}

#[test]
fn rule_scan_filters_only_exact_known_safe_shapes_and_retains_vulnerable_shapes() {
    let root = tempdir().expect("temporary source tree");
    let xattr = root.path().join("fs/ntfs3/xattr.c");
    let record = root.path().join("fs/ntfs3/record.c");
    let alternate = root.path().join("fs/ntfs3/alternate.h");
    let alternate_record = root.path().join("fs/ntfs3/alternate_record.c");
    fs::create_dir_all(xattr.parent().expect("xattr parent")).expect("rule directory");
    fs::write(&xattr, EA_AFTER_FIX).expect("write xattr fixture");
    fs::write(&record, ATTR_BEFORE_FIX).expect("write record fixture");
    fs::write(
        &alternate,
        EA_BEFORE_FIX
            .replace("ntfs_list_ea", "inspect_ea_entries")
            .replace("unpacked_ea_size(ea)", "unpacked_ea_size(entry)")
            .replace("ea->", "entry->"),
    )
    .expect("write relocated vulnerable-pattern fixture");
    fs::write(
        &alternate_record,
        ATTR_BEFORE_FIX
            .replace("mi_enum_attr", "parse_nonresident_extent")
            .replace("attr->", "record_attr->")
            .replace("return attr;", "return record_attr;"),
    )
    .expect("write relocated attribute-pattern fixture");

    let scan = scan_cve_rules(root.path(), Some("fs/ntfs3"), &[]).expect("fixtures should scan");

    assert_eq!(scan.raw_match_count(), 4);
    assert_eq!(scan.filtered_safe_count(), 1);
    assert_eq!(scan.unmatched_rule_count(), 0);
    assert_eq!(scan.candidates.len(), 3);
    assert_eq!(scan.review_groups().len(), 2);
    assert_eq!(
        scan.candidates[0].match_strength,
        MatchStrength::DirectAttributeAcceptance
    );
    assert!(scan.candidates.iter().any(|candidate| {
        candidate.rule.id == "ntfs3-ea-name-length"
            && candidate.relative_file == "fs/ntfs3/alternate.h"
            && candidate.function == "inspect_ea_entries"
    }));
    assert!(scan.candidates.iter().any(|candidate| {
        candidate.rule.id == "ntfs3-attribute-alloc-size" && candidate.function == "mi_enum_attr"
    }));
    assert!(scan.candidates.iter().any(|candidate| {
        candidate.rule.id == "ntfs3-attribute-alloc-size"
            && candidate.relative_file == "fs/ntfs3/alternate_record.c"
            && candidate.function == "parse_nonresident_extent"
    }));
}

#[test]
fn rule_catalog_keeps_cve_and_fix_provenance_with_each_rule() {
    let all_rules: Vec<_> = all_cve_rules().collect();
    assert_eq!(all_rules.len(), 20);
    assert_eq!(
        all_rules
            .iter()
            .map(|rule| rule.cve)
            .collect::<std::collections::HashSet<_>>()
            .len(),
        20
    );
    assert_eq!(CVE_RULES[0].cve, "CVE-2023-52640");
    assert_eq!(
        CVE_RULES[0].fix_commit,
        "731ab1f9828800df871c5a7ab9ffe965317d3f15"
    );
    assert_eq!(CVE_RULES[1].cve, "CVE-2024-50246");
    assert_eq!(
        CVE_RULES[1].fix_commit,
        "c4a8ba334262e9a5c158d618a4820e1b9c12495c"
    );
    assert_eq!(CVE_RULES[2].cve, "CVE-2025-38193");
    assert_eq!(CVE_RULES[2].cwe, "CWE-190");
    assert_eq!(CVE_RULES[2].scope, "net/sched");
    assert_eq!(
        CVE_RULES[2].fix_commit,
        "e0936ff56be4e08ad5b60ec26971eae0c40af305"
    );
}

#[test]
fn perturb_period_rule_finds_pre_fix_code_and_filters_the_verified_fix() {
    let pre_fix = function_body(SFQ_BEFORE_FIX, "sfq_change");
    let fixed = function_body(SFQ_AFTER_FIX, "sfq_change");

    assert_eq!(
        perturb_period_tick_conversion_sites(&pre_fix.tokens).len(),
        1
    );
    assert_eq!(perturb_period_conversion_is_bounded(&pre_fix.tokens), None);
    assert_eq!(perturb_period_tick_conversion_sites(&fixed.tokens).len(), 1);
    assert!(perturb_period_conversion_is_bounded(&fixed.tokens).is_some());
}

#[test]
fn perturb_period_filter_retains_near_miss_guards() {
    let missing_upper_bound = SFQ_AFTER_FIX.replace(
        "ctl->perturb_period > INT_MAX / HZ",
        "ctl->perturb_period > INT_MAX",
    );
    let wrong_boolean = SFQ_AFTER_FIX.replace("< 0 ||", "< 0 &&");
    let late_guard = SFQ_AFTER_FIX.replace(
        "    if (ctl->perturb_period < 0 ||\n        ctl->perturb_period > INT_MAX / HZ) {\n        NL_SET_ERR_MSG_MOD(extack, \"invalid perturb period\");\n        return -EINVAL;\n    }\n    perturb_period = ctl->perturb_period * HZ;",
        "    perturb_period = ctl->perturb_period * HZ;\n    if (ctl->perturb_period < 0 ||\n        ctl->perturb_period > INT_MAX / HZ) {\n        NL_SET_ERR_MSG_MOD(extack, \"invalid perturb period\");\n        return -EINVAL;\n    }",
    );
    let nested_guard = SFQ_AFTER_FIX
        .replace(
            "    if (ctl->perturb_period < 0 ||",
            "    if (trusted) {\n        if (ctl->perturb_period < 0 ||",
        )
        .replace(
            "        return -EINVAL;\n    }\n    perturb_period =",
            "        return -EINVAL;\n        }\n    }\n    perturb_period =",
        );

    for source in [missing_upper_bound, wrong_boolean, late_guard, nested_guard] {
        let body = function_body(&source, "sfq_change");
        assert_eq!(perturb_period_conversion_is_bounded(&body.tokens), None);
    }
}

#[test]
fn net_sched_scan_keeps_unbounded_analog_and_filters_fixed_sfq_control() {
    let root = tempdir().expect("temporary source tree");
    let sfq = root.path().join("net/sched/sch_sfq.c");
    let flow = root.path().join("net/sched/cls_flow.c");
    fs::create_dir_all(sfq.parent().expect("net sched parent")).expect("rule directory");
    fs::write(&sfq, SFQ_AFTER_FIX).expect("write fixed SFQ fixture");
    fs::write(&flow, FLOW_UNBOUNDED_CONVERSION).expect("write analogous flow fixture");

    let scan = scan_cve_rules(root.path(), Some("net/sched"), &[]).expect("fixtures should scan");

    assert_eq!(scan.rules.len(), 2);
    assert!(scan.rules.iter().any(|rule| rule.cve == "CVE-2025-38193"));
    assert_eq!(scan.source_file_count, 2);
    assert_eq!(scan.parsed_file_count, 2);
    assert!(scan.parse_errors.is_empty());
    assert_eq!(scan.raw_match_count(), 2);
    assert_eq!(scan.filtered_safe_count(), 1);
    assert_eq!(scan.candidates.len(), 1);
    assert_eq!(scan.review_groups().len(), 1);
    assert_eq!(scan.candidates[0].relative_file, "net/sched/cls_flow.c");
    assert_eq!(scan.candidates[0].function, "flow_change");
}

#[test]
fn cve_rule_selector_scans_only_the_selected_cve_scope() {
    let root = tempdir().expect("temporary source tree");
    let xattr = root.path().join("fs/ntfs3/xattr.c");
    let sfq = root.path().join("net/sched/sch_sfq.c");
    let flow = root.path().join("net/sched/cls_flow.c");
    fs::create_dir_all(xattr.parent().expect("xattr parent")).expect("ntfs3 rule directory");
    fs::create_dir_all(sfq.parent().expect("sfq parent")).expect("net sched rule directory");
    fs::write(&xattr, EA_BEFORE_FIX).expect("write unselected NTFS fixture");
    fs::write(&sfq, SFQ_AFTER_FIX).expect("write selected fixed control");
    fs::write(&flow, FLOW_UNBOUNDED_CONVERSION).expect("write selected candidate");
    let selected_cves = ["cve-2025-38193".to_string()];

    let scan = scan_cve_rules(root.path(), None, &selected_cves)
        .expect("a registered CVE selector should scan");

    assert_eq!(scan.rules.len(), 1);
    assert_eq!(scan.rules[0].cve, "CVE-2025-38193");
    assert_eq!(scan.rules[0].scope, "net/sched");
    assert_eq!(scan.source_file_count, 2);
    assert_eq!(scan.parsed_file_count, 2);
    assert_eq!(scan.filtered_safe_count(), 1);
    assert_eq!(scan.candidates.len(), 1);
    assert_eq!(scan.candidates[0].relative_file, "net/sched/cls_flow.c");
}

#[test]
fn cve_rule_selector_rejects_unknown_ids_and_conflicting_focus() {
    let root = tempdir().expect("temporary source tree");
    let unknown = ["CVE-2099-0001".to_string()];
    let error = scan_cve_rules(root.path(), None, &unknown)
        .expect_err("unknown CVEs do not have active scanners");
    assert!(
        error
            .to_string()
            .contains("does not match an active CVE-derived rule")
    );

    let selected = ["CVE-2025-38193".to_string()];
    let error = scan_cve_rules(root.path(), Some("fs/ntfs3"), &selected)
        .expect_err("a conflicting focus must not silently drop an explicit selector");
    assert!(error.to_string().contains("do not match --focus fs/ntfs3"));
}

#[test]
fn cve_rule_focus_support_tracks_the_registered_scopes() {
    assert!(cve_rule_focus_is_supported(None));
    assert!(cve_rule_focus_is_supported(Some("fs")));
    assert!(cve_rule_focus_is_supported(Some("net/packet")));
    assert!(cve_rule_focus_is_supported(Some("ntfs3")));
    assert!(!cve_rule_focus_is_supported(Some("drivers/example")));
}
