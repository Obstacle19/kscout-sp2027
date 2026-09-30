//! Reviewed context reused by focused CVE-derived kernel reviews.

#[derive(Debug)]
pub(super) struct RuleKnowledge {
    pub(super) verified_revision: &'static str,
    pub(super) verified_facts: &'static [&'static str],
    pub(super) known_safe_cases: &'static [&'static str],
    pub(super) unresolved_hypotheses: &'static [&'static str],
    pub(super) focused_checks: &'static [&'static str],
}

pub(super) const EA_NAME_LENGTH: RuleKnowledge = RuleKnowledge {
    verified_revision: "fe2ec83746e501645709761605c2464a44fd2929",
    verified_facts: &[
        "CVE-2023-52640 fixes the EA name-length check in ntfs_list_ea; the verified source fix is 731ab1f9828800df871c5a7ab9ffe965317d3f15.",
        "On the verified revision, the current guard compares the decoded entry size with name_len and exits the loop before the name copy and output-size update.",
    ],
    known_safe_cases: &[
        "The exact ntfs_list_ea guard described above is safe only when the compared length is the same disk-backed name_len and the failure branch exits before both sinks. The deterministic filter recognizes this narrow shape.",
    ],
    unresolved_hypotheses: &[],
    focused_checks: &[
        "Look only for disk-backed EA name lengths that reach a name read/copy or output-size calculation before a bound against that same enclosing EA entry.",
        "Do not treat unrelated string limits, another entry's size, or a check after the sink as protection.",
    ],
};

pub(super) const ATTRIBUTE_ALLOC_SIZE: RuleKnowledge = RuleKnowledge {
    verified_revision: "fe2ec83746e501645709761605c2464a44fd2929",
    verified_facts: &[
        "CVE-2024-50246 added the alloc_size-versus-volume.size guard in mi_enum_attr; fix c4a8ba334262e9a5c158d618a4820e1b9c12495c is an ancestor of the verified revision.",
        "On the verified revision, ni_find_attr consumers including attr_set_size_ex and attr_data_get_block_locked obtain on-disk attributes through mi_enum_attr. Treat those consumers as one validation/data-flow review, not independent rule instances.",
        "The guard applies to non-sparse attributes and non-first sparse/compressed segments. The first sparse/compressed segment intentionally uses alloc_size for logical VCN space and total_size for physical allocation; alloc_size greater than the volume alone is not a violation.",
    ],
    known_safe_cases: &[
        "A non-sparse allocation size larger than the volume is rejected by mi_enum_attr before the consumers can use it.",
        "A format-consistent sparse first segment with alloc_size=64 GiB, total_size=8 KiB, and its mapping pairs placed after the extended header was accepted and read correctly on the verified revision. Preserve this as a control; do not add a volume-size bound to this case.",
    ],
    unresolved_hypotheses: &[
        "Candidate-005 on the verified revision observed zero-filled reads and ftruncate(1 GiB) returning ENOENT for a sparse first segment with evcn=0xffffffff and alloc_size=2^44 in a CLST=u32 build. It remains plausible, not confirmed: the encoded extent exceeds the driver's own create-size limit, and NTFS-format validity at that boundary was not established. Do not report it as a confirmed CVE or a new finding; if the current revision is relevant, resolve format validity and reproduce it independently before changing its status.",
    ],
    focused_checks: &[
        "Verify whether the current source still has the mi_enum_attr guard and whether the target consumers can bypass that validator; if the guard and route are unchanged, skip repeating the broad non-sparse trace and its negative control.",
        "For the sparse first-segment exception only, check representability against the configured CLST width, evcn+1 and alloc_size-to-cluster conversions, and consistency between total_size, VCN range, and mapping pairs.",
        "Test the largest format-valid range and a close in-range control. Keep the 64 GiB sparse control structurally valid by relocating mapping pairs after total_size.",
        "Group mi_enum_attr, attr_set_size_ex, attr_data_get_block_locked, and other hits under this rule into one shared-invariant review. A second location is not a new candidate unless it has an independent validation bypass or root cause.",
    ],
};

pub(super) const SFQ_PERTURB_PERIOD: RuleKnowledge = RuleKnowledge {
    verified_revision: "fe2ec83746e501645709761605c2464a44fd2929",
    verified_facts: &[
        "CVE-2025-38193 fixes net/sched/sch_sfq.c:sfq_change; the original mainline fix is 7ca52541c05c832d32b112274f81a985101f9ba8 and the stable fix recorded by the CVE catalog is e0936ff56be4e08ad5b60ec26971eae0c40af305.",
        "The fixed SFQ path rejects ctl->perturb_period < 0 and ctl->perturb_period > INT_MAX / HZ before multiplying by HZ. Zero remains valid and disables the perturb timer.",
        "In the verified source snapshot, net/sched/cls_flow.c:flow_change converts TCA_FLOW_PERTURB values obtained through NLA_U32 into perturb_period ticks in both create and update paths, then schedules the timer. The local source has no matching range guard; this is a review lead, not a confirmed vulnerability.",
        "The first model review of cls_flow.c:flow_change ended negative based on the per-filter callback rate. Follow-up QEMU/KVM tests on an i386 build of revision fe2ec83746e501645709761605c2464a44fd2929 measured two 5-second samples with 1,000 filters: perturb=1 used 39/40 host CPU ticks, while perturb=2147484 at HZ=1000 used 249/243 ticks (CLK_TCK=100). A separate-worktree INT_MAX/HZ guard rejected the high value with EINVAL. Treat the candidate as plausible aggregate resource impact, not as a confirmed vulnerability; the result is one isolated VM configuration.",
    ],
    known_safe_cases: &[
        "The exact sfq_change guard described above dominates its perturb_period * HZ conversion and rejects negative or unrepresentable values. The deterministic filter recognizes only this narrow top-level shape.",
        "A zero perturb period is valid and disables periodic perturbation; do not classify zero as invalid merely because the period is used by a timer.",
        "The upstream CVE verification accepts perturb 2000000 and rejects perturb -10 and perturb 1000000000 on the fixed SFQ path.",
    ],
    unresolved_hypotheses: &[
        "The i386 QEMU result shows aggregate CPU amplification in one HZ=1000, one-vCPU configuration, but unprivileged user-namespace reachability, native-host impact, other HZ values, and the 64-bit wrap-to-short-period case remain untested. Keep this as a plausible resource-impact candidate, not a confirmed vulnerability, and do not filter it automatically. Reopen severity after checking the permission model, timer fanout, and runtime evidence on relevant deployments.",
    ],
    focused_checks: &[
        "For each perturb_period assignment multiplied by HZ, trace the input type and origin, promotion width, result type, storage, and mod_timer use. Check both create and update branches.",
        "Test or reason about zero, the greatest representable period, one above the bound, negative values when the input is signed, and values that wrap after multiplication. Preserve the valid zero-disable behavior.",
        "Check whether validation occurs before multiplication and dominates every conversion. A nonzero test or an NLA_U32 type declaration alone is not a range proof.",
        "When reusing the cls_flow candidate review, confirm the u32 input/storage, timer callback body, CAP_NET_ADMIN precondition, relevant word size, filter fanout, and aggregate resource result have not changed. Do not reuse the result as proof of safety or for a different conversion site.",
        "Group multiple conversions in one function and configuration path into one review; treat each source site as a location within that shared invariant rather than an independent finding.",
    ],
};

const REVIEW_REVISION: &str = "fe2ec83746e501645709761605c2464a44fd2929";

pub(super) const EBT_SNAT_WRITABLE: RuleKnowledge = RuleKnowledge {
    verified_revision: REVIEW_REVISION,
    verified_facts: &[
        "The stable fix bf84ad7c7a9ede46e31afaa41a1ba06a159e8c87 calls skb_ensure_writable() for the full ARP header and sender-hardware-address range before obtaining and modifying the header.",
    ],
    known_safe_cases: &[
        "The exact upstream writable-range guard before the header access is the fixed control; only that narrow guard is eligible for automatic filtering.",
    ],
    unresolved_hypotheses: &[
        "A lexical hit does not prove that a packet can reach the ARP rewrite with shared or file-backed fragments. Verify the skb layout and writable-range API semantics.",
    ],
    focused_checks: &[
        "Trace the exact write range through skb_header_pointer(), skb_store_bits(), and any copy-on-write or writable-range checks. A successful linear pull does not prove the fragment is private.",
    ],
};

pub(super) const OVERLAYFS_ID_MAPPING: RuleKnowledge = RuleKnowledge {
    verified_revision: REVIEW_REVISION,
    verified_facts: &[
        "Fix 4f11ada10d0ad3fd53e2bd67806351de63a4f9c3 rejects copy-up when ctx.stat.uid or ctx.stat.gid has no mapping in current_user_ns() before metadata copy-up proceeds.",
    ],
    known_safe_cases: &[
        "The checked uid and gid mapping failures return -EOVERFLOW before ovl_need_meta_copy_up() and copy-up side effects.",
    ],
    unresolved_hypotheses: &[
        "The rule is a metadata-path lead; only an end-to-end mount and capability test can establish whether a candidate crosses the vulnerable ownership and nosuid conditions.",
    ],
    focused_checks: &[
        "Trace the lower inode uid/gid through idmapped mounts, current_user_ns(), capability metadata, and every copy-up side effect. Keep uid and gid mapping checks paired.",
    ],
};

pub(super) const PACKET_HEADER_LEN_SNAPSHOT: RuleKnowledge = RuleKnowledge {
    verified_revision: REVIEW_REVISION,
    verified_facts: &[
        "Stable fix bcd4df60ac9481b1ceffdfe5ec38fe51dcaae812 snapshots hard_header_len once per skb allocation attempt and reuses the value for reserve, allocation sizing, and header construction.",
    ],
    known_safe_cases: &[
        "A single READ_ONCE() snapshot reused throughout one allocation attempt is the fixed control; packet_sendmsg_spkt refreshes it only when retrying without an skb.",
    ],
    unresolved_hypotheses: &[
        "A same-function multiple-read hit does not establish a concurrent device reconfiguration or a resulting out-of-bounds write.",
    ],
    focused_checks: &[
        "Check packet allocation and reserve calculations against the exact header length used by later skb construction, including retry labels and device reconfiguration.",
    ],
};

pub(super) const NFT_VERDICT_OWNERSHIP: RuleKnowledge = RuleKnowledge {
    verified_revision: REVIEW_REVISION,
    verified_facts: &[
        "Fix f342de4e2f33e0e39165d8639387aa6c19dff660 accepts only the exact NF_ACCEPT, NF_DROP, and NF_QUEUE verdict values; masked positive drop-error values are rejected.",
    ],
    known_safe_cases: &[
        "The explicit exact-value switch with a rejecting default is the fixed control. Do not treat verdicts with extra positive bits as equivalent to NF_DROP.",
    ],
    unresolved_hypotheses: &[
        "A verdict parser match alone does not prove that a packet is double-freed; trace the downstream hook ownership and free paths.",
    ],
    focused_checks: &[
        "Trace parsed verdict values through nft_verdict_init(), nf_hook_slow(), and skb ownership. Reject unsupported positive error values before they reach the hook.",
    ],
};

pub(super) const XEN_9P_TEARDOWN: RuleKnowledge = RuleKnowledge {
    verified_revision: REVIEW_REVISION,
    verified_facts: &[
        "Stable fix 59e7707492576bdbfa8c1dbe7d90791df31e4773 serializes xenbus removal under xen_9pfs_lock, clears drvdata, removes the list entry, and returns when drvdata is already NULL before freeing the private state.",
    ],
    known_safe_cases: &[
        "A removal path that atomically observes and clears drvdata under the protecting lock before teardown is the fixed control.",
    ],
    unresolved_hypotheses: &[
        "Lexical evidence cannot prove all xenwatch, probe, and remove interleavings or the lifetime of the device and private state.",
    ],
    focused_checks: &[
        "Trace every caller of xen_9pfs_front_free(), drvdata publication/clearing, list membership, lock coverage, and partially initialized teardown paths.",
    ],
};

pub(super) const IO_URING_TIMEOUT_LIST: RuleKnowledge = RuleKnowledge {
    verified_revision: REVIEW_REVISION,
    verified_facts: &[
        "Fix e677edbcabee849bfdd43f1602bccbecf736a646 initializes each timeout list node and iterates the timeout list with list_for_each_entry_safe() while cancellation can remove entries.",
    ],
    known_safe_cases: &[
        "The safe-iteration loop plus initialized timeout.list node are the relevant controls; a list-empty test alone does not make iteration safe against removal.",
    ],
    unresolved_hypotheses: &[
        "The source pattern does not establish the timing or reachability of a completion/cancellation race.",
    ],
    focused_checks: &[
        "Trace timeout-list insertion, iteration, removal, completion, and request references under timeout_lock and completion_lock. Check list-node initialization on every preparation path.",
    ],
};

pub(super) const NFT_STATEFUL_EXPRESSION: RuleKnowledge = RuleKnowledge {
    verified_revision: REVIEW_REVISION,
    verified_facts: &[
        "Fix 520778042ccca019f3ffa136dd0ca565c486cedd rejects expressions lacking NFT_EXPR_STATEFUL immediately after parsing and before allocation/initialization when they are used in set elements.",
    ],
    known_safe_cases: &[
        "The stateful-type rejection before object allocation and transaction acceptance is the fixed control.",
    ],
    unresolved_hypotheses: &[
        "A missing local stateful check is not sufficient evidence of a use-after-free; establish that the expression enters a set and reaches the affected transaction lifetime.",
    ],
    focused_checks: &[
        "Follow expression type flags from parsing through allocation, set-element acceptance, module references, and release on every error path.",
    ],
};

pub(super) const IO_URING_FIXED_FILE_PUT: RuleKnowledge = RuleKnowledge {
    verified_revision: REVIEW_REVISION,
    verified_facts: &[
        "Fix fc7222c3a9f56271fba02aabbfbae999042f1679 avoids io_put_file() for REQ_F_FIXED_FILE because the registered ring owns that persistent reference.",
    ],
    known_safe_cases: &[
        "A fixed-file guard around the transient io_put_file() call is the fixed control; clearing req->file does not transfer or release the registered-file reference.",
    ],
    unresolved_hypotheses: &[
        "A matching io_put_file() call must be traced to its reference origin and all later file users before classifying a use-after-free.",
    ],
    focused_checks: &[
        "Track fixed versus transient file references through msg-ring completion, request cleanup, and ring registration teardown.",
    ],
};

pub(super) const NFT_ANONYMOUS_SET_LIFETIME: RuleKnowledge = RuleKnowledge {
    verified_revision: REVIEW_REVISION,
    verified_facts: &[
        "Fix c1592a89942e9678f7d9c8030efa777c0d57edab routes anonymous-set activation through nf_tables_activate_set() and deactivates the next-generation set during transaction preparation.",
    ],
    known_safe_cases: &[
        "The activation/deactivation helper pair coordinates anonymous-set visibility and use counts across prepare, abort, and commit phases.",
    ],
    unresolved_hypotheses: &[
        "A raw set use-count operation is only a lead; confirming a use-after-free requires transaction-phase and concurrent reference tracing.",
    ],
    focused_checks: &[
        "Trace anonymous-set activation, deactivation, generation masks, use counts, abort/commit handling, and all expression owners as one transaction lifecycle.",
    ],
};

pub(super) const MIRRED_SKB_OWNERSHIP: RuleKnowledge = RuleKnowledge {
    verified_revision: REVIEW_REVISION,
    verified_facts: &[
        "Fix f4e294bbdca8ac8757db436fc82214f3882fc7e7 confines TC_ACT_SHOT to failures before skb ownership can transfer; errors returned after forwarding no longer cause the core to drop the transferred skb.",
    ],
    known_safe_cases: &[
        "A post-forward error path that updates statistics but preserves the forwarding action is the fixed control.",
    ],
    unresolved_hypotheses: &[
        "A lexical hit does not prove ownership transfer or a subsequent second free; distinguish clone, redirect, mirror, and ingress reinsertion paths.",
    ],
    focused_checks: &[
        "Track skb ownership across clone, redirect, reinsertion, tcf_mirred_forward(), and every error return that can request a core drop.",
    ],
};

pub(super) const KSMBD_TCON_REFCOUNT: RuleKnowledge = RuleKnowledge {
    verified_revision: REVIEW_REVISION,
    verified_facts: &[
        "Fix 446beed646b2e426dd53d27358365f8678e1dd01 makes the final ksmbd_tree_connect_put() reference release free the tcon and removes disconnect's wait-then-free pattern.",
    ],
    known_safe_cases: &[
        "Every concurrent tcon user must hold a reference; disconnect drops its own reference and does not free while other references remain.",
    ],
    unresolved_hypotheses: &[
        "Atomic refcount operations alone do not prove correct ownership; audit every tcon get/put pair and all asynchronous work users.",
    ],
    focused_checks: &[
        "Trace tcon acquisition, work/session ownership, disconnect, final put, and pointer clearing. Check for waiters or frees that race with a continuing user.",
    ],
};

pub(super) const FUSE_SYNC_SUBMOUNT_RELEASE: RuleKnowledge = RuleKnowledge {
    verified_revision: REVIEW_REVISION,
    verified_facts: &[
        "Fix 607a1d4c42f649e6197567c0448fd9ebb316cd42 requests synchronous release for virtio-fs connections with auto_submounts so each submount superblock waits for its release requests before teardown.",
    ],
    known_safe_cases: &[
        "The auto_submounts-dependent synchronous release is the fixed control; the ordinary asynchronous release path remains valid for other configurations.",
    ],
    unresolved_hypotheses: &[
        "A release-path match alone does not prove that a submount superblock can be destroyed before the release callback finishes.",
    ],
    focused_checks: &[
        "Follow release request completion and wait accounting per superblock through submount teardown; do not substitute connection-wide request counts for per-superblock ordering.",
    ],
};

pub(super) const UDP_GSO_SOCKET_OWNERSHIP: RuleKnowledge = RuleKnowledge {
    verified_revision: REVIEW_REVISION,
    verified_facts: &[
        "Fix 9f28205ddb76e86cac418332e952241d85fed0dc clears both the sock_wfree destructor and skb->sk before segmentation, and restores both together on segmentation failure.",
    ],
    known_safe_cases: &[
        "Destructor and socket pointer ownership are cleared and restored as a pair around skb_segment().",
    ],
    unresolved_hypotheses: &[
        "A destructor change is safe only when the matching socket reference is accounted for on both success and error paths.",
    ],
    focused_checks: &[
        "Trace skb->destructor, skb->sk, socket references, and orphaning across segmentation success, failure, and later freeing.",
    ],
};

pub(super) const PIPE_BUFFER_FLAGS: RuleKnowledge = RuleKnowledge {
    verified_revision: REVIEW_REVISION,
    verified_facts: &[
        "Fix 9d2231c5d74e13b2a0546fee6737ee4446017903 initializes pipe_buffer.flags to zero in both copy_page_to_iter_pipe() and push_pipe() before exposing the buffer. The verified current source also initializes splice_to_pipe() flags before advancing pipe->head, and anon_pipe_write() assigns its packet/merge flags while holding the pipe mutex.",
    ],
    known_safe_cases: &[
        "Zeroing flags before advancing pipe->head is a safe control. anon_pipe_write() explicitly assigns PIPE_BUF_FLAG_PACKET or PIPE_BUF_FLAG_CAN_MERGE while holding the pipe mutex; do not treat an explicit, path-complete assignment as stale state.",
    ],
    unresolved_hypotheses: &[
        "An initialization match must cover every constructor and occur before the buffer can be observed or merged.",
    ],
    focused_checks: &[
        "Enumerate every pipe_buffer construction/reuse path and establish that flags are initialized before publication, page insertion, or merge decisions.",
    ],
};

pub(super) const NFT_VLAN_COPY_ARITHMETIC: RuleKnowledge = RuleKnowledge {
    verified_revision: REVIEW_REVISION,
    verified_facts: &[
        "Fix 696e1a48b1a1b01edad542a1ef293665864a4dd0 subtracts vlan_hlen when adjusting ethlen in nft_payload_copy_vlan(), accounting for the VLAN header exactly once.",
    ],
    known_safe_cases: &[
        "The corrected subtraction keeps the computed copy length within the destination scratch buffer for the checked VLAN offsets.",
    ],
    unresolved_hypotheses: &[
        "The arithmetic expression must be traced with the actual u8/u32 promotions and all earlier bounds checks before inferring an out-of-bounds copy.",
    ],
    focused_checks: &[
        "Model offset, requested length, VLAN header length, ethlen, integer promotions, and destination capacity at the memcpy() sink.",
    ],
};

pub(super) const TLS_SPLICE_CURSOR: RuleKnowledge = RuleKnowledge {
    verified_revision: REVIEW_REVISION,
    verified_facts: &[
        "Fix c5a595000e2677e865a39f249c056bc05d6e55fd resets msg_pl->sg.copybreak and advances msg_pl->sg.curr to msg_pl->sg.end after adding splice pages.",
    ],
    known_safe_cases: &[
        "After sk_msg_page_add(), the scatterlist copy cursor and copybreak state must describe the newly appended end before another writer uses the message.",
    ],
    unresolved_hypotheses: &[
        "A stale cursor match does not alone prove a write outside the scatterlist; establish the subsequent append/copy path and capacity.",
    ],
    focused_checks: &[
        "Trace sk_msg_page_add(), curr/end/copybreak updates, later copy or append operations, and scatterlist capacity on splice and non-splice paths.",
    ],
};

pub(super) const IPV4_FRAGGAP_LENGTH: RuleKnowledge = RuleKnowledge {
    verified_revision: REVIEW_REVISION,
    verified_facts: &[
        "Fix 5c6375bced6147ec2e460ee3b653f4860d5ecdc2 adds fraggap to alloclen and subtracts it from pagedlen in the paged allocation path, matching allocation to the bytes copied into the linear area.",
    ],
    known_safe_cases: &[
        "The fixed allocation and paged lengths account for fraggap once each in opposite directions.",
    ],
    unresolved_hypotheses: &[
        "A length-expression match requires tracing the exact skb layout and byte ranges at every copy site.",
    ],
    focused_checks: &[
        "Trace fragheaderlen, transhdrlen, fraggap, datalen, alloclen, pagedlen, and all subsequent copies; account for integer width and each skb region.",
    ],
};
