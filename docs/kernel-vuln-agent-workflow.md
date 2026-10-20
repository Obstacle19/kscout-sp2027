# KScout kernel-vuln agent 工作流：candidate-005

本文记录这次 `codex kernel-vuln --count 1` 实际启动的研究 agent 如何工作，以及 KScout 如何调度、约束和保存它。重点是 agent 的研究过程，不是只复述漏洞结论。原有的 `docs/kernel-vuln-workflow.md` 未修改。

## 证据与复述范围

本记录依据本次候选目录中的实际产物：

- [完整 agent 事件流](/root/workspace/kscout-workdir/candidates/candidate-005/agent-events.jsonl)：1,420 行，从 `thread.started` 到 `turn.completed`；JSONL 中所有 `item.started` 都有对应的 `item.completed`。它记录 agent 的消息、命令及命令输出。
- [agent 生成的研究日志](/root/workspace/kscout-workdir/candidates/candidate-005/PROCESS_LOG.md)：agent 整理的审计过程、假设、实验和结果。
- [实际注入的 prompt](/root/workspace/kscout-workdir/candidates/candidate-005/prompt.md)、[实际 child 命令](/root/workspace/kscout-workdir/candidates/candidate-005/command.txt)和 [run metadata](/root/workspace/kscout-workdir/candidates/candidate-005/run-metadata.md)。
- 复现及证据：`candidate-005/REPRODUCTION.md`、`candidate-report.md`、`finding-fingerprint.md`、`evidence/` 和 `logs/`。

事件流共记录 657 条完成的 shell 命令事件和 93 条 agent 消息；只有一个顶层 Codex child thread，没有记录到嵌套 agent 启动。因这些材料覆盖完整，这次不需要再运行一轮漏洞研究来补写过程。事件序号是 JSONL 行号；下文引用 `events.jsonl:行号` 均指上述事件流。

## 这条命令怎样变成一个 agent 任务

| 阶段 | 实现位置 | 本次实际效果 |
|---|---|---|
| CLI 分发 | [`main.rs:1049-1051`](/root/workspace/kscout/codex-rs/cli/src/main.rs:1049)、[`main.rs:1156-1162`](/root/workspace/kscout/codex-rs/cli/src/main.rs:1156) | `kernel-vuln` 分支调用 `kernel_vuln::run`。通用 `--disable code_mode_host` 被 CLI 折叠成配置 override；实际 child 命令记录为 `features.code_mode_host=false`。 |
| 参数与输入边界 | [`kernel_vuln.rs:140-242`](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln.rs:140)、[`kernel_vuln.rs:285-361`](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln.rs:285) | `--count 1` 只排一个 candidate；run metadata 记载 `rule mode: false`、`additional prompt: none`、模型 `deepseek-flash`、base URL 和 `workspace-write`。没有额外 focus/commit，因此 prompt 指定 agent 自主选最强候选。API key 从指定环境变量读取，值不落盘。 |
| 固定研究合同和路径 | [`kernel_vuln.rs:71-149`](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln.rs:71)、[`kernel_vuln_support.rs:224-255`](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln_support.rs:224) | prompt 要求从源码和提交历史审计、禁止 fuzz/syzkaller、源码树只读、用普通用户态 PoC、运行阳性与 close control、保存 `PROCESS_LOG.md` 和完整证据；并附上 Linux、output、candidate、duplicate index 路径。 |
| 建 candidate 并保存输入 | [`kernel_vuln_support.rs:211-222`](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln_support.rs:211)、[`kernel_vuln.rs:453-559`](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln.rs:453) | 分配首个空闲目录。本次之前 `candidate-001` 至 `candidate-004` 已占位，所以这一个 pass 使用 `candidate-005`；保存 prompt、命令和 metadata 后才启动 child。 |
| 启动 child 并记录事件 | [`kernel_vuln_support.rs:257-319`](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln_support.rs:257)、[`kernel_vuln_support.rs:330-405`](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln_support.rs:330)、[`kernel_vuln_support.rs:413-450`](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln_support.rs:413) | child 以 `codex exec --ephemeral --json --cd candidate-005 --sandbox workspace-write` 运行；output root 和 candidate 被加入可写目录，Linux 源码不在这些可写根中。prompt 通过 stdin 输入，stdout/stderr 分别保存在 `agent-events.jsonl` 与 `agent-stderr.log`；`--show-progress` 同时渲染 live 进度。 |
| 读结果、计 usage、刷新索引 | [`kernel_vuln.rs:586-609`](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln.rs:586)、[`kernel_vuln_usage.rs:111-146`](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln_usage.rs:111)、[`kernel_vuln_usage.rs:194-205`](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln_usage.rs:194)、[`kernel_vuln_usage.rs:249-278`](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln_usage.rs:249)、[`kernel_vuln_dedup.rs:11-74`](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln_dedup.rs:11) | child 退出后从事件流解析 usage，从 fingerprint 读取 outcome，保存 `usage.json`、追加 `USAGE.jsonl` 和 metadata，并刷新候选排重索引。 |
| 完成检查 | [`kernel_vuln_support.rs:665-688`](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln_support.rs:665)、[`kernel_vuln.rs:651-663`](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln.rs:651) | 记录源码树结束时的 HEAD/status 快照和 run summary。agent 也在自己的最终检查中确认 Linux 源码树状态为空。 |

本次 API key 变量名写入 metadata，但其值没有写入该文件；`command.txt` 保存的是 child CLI 参数，密钥值由父进程经环境传递。`agent-events.jsonl` 开头记录了 `deepseek-flash` 未找到本地模型 metadata、改用 fallback metadata 的提示（事件第 2 行）。

## Agent 实际研究时间线

| 步骤 | agent 实际执行与决策 | 过程证据 | 对应代码/产物 |
|---|---|---|---|
| 1. 确认基线和排重边界 | 先记录 Linux HEAD `24a19b953e2a3d0ea5a8c4951a0ab8f32720c907`（7.3-rc7）及干净状态，再读 `FINDING_INDEX.md`。candidate-003 的 vmsplice/GIFT→FUSE 发现用于排查重复项；最终记录认为它与本次候选的根因、触发方式、代码和 oracle 均不同。 | `events.jsonl:4-24`；`PROCESS_LOG.md:6-26,209-218` | prompt 合同；`kernel_vuln.rs:71-149`。 |
| 2. 从提交历史广泛筛选审计面 | 对比 `v6.17..HEAD` 的新文件、提交和系统调用，逐一看安全敏感的新路径。事件里能看到 `failfs/fchroot`、`task_exec_state`/ptrace、TCP Fast Open 与 MPTCP、`listns`/nstree、Landlock 等；之后还检查 nullfs、rseq、NTFS WOF、io_uring `delayed_filename`、`open_tree_attr`。这些路径没有形成满足合同、具稳定用户态 oracle 的候选，于是继续换面。 | 阶段性 agent 消息见 `events.jsonl:49-229`、`329-1119`；关键转向点包括 `574`、`691`、`755`、`800`、`836`、`1045`、`1119`；汇总见 `PROCESS_LOG.md:28-47`。 | 固定 prompt 要求“自主选最强候选”，不是按规则包筛选；本次 `rule mode: false`。 |
| 3. 深入未合入的 page-cache 系列 | agent 找到 `origin/noref-filemap-read-with-llm`，读取全量 diff、patch message 和 cover letter；枚举 `folio_mark_removed_from_cache()` 调用点、page-cache 删除/替换路径、refcount 与 RCU 延迟释放语义，并把 candidate-003 的 FUSE steal 路径作为必须排除的重复项。审计时有几次回到其他新功能继续清查，最终才决定该系列仍值得做实验。 | `events.jsonl:230-328`、`635-718`、`1034-1133`；整理后的调用点/已清除线索见 `PROCESS_LOG.md:28-63`、`:209-218`。 | prompt 中的排重规则；Linux 分支差异与源码摘录保存在 `evidence/series.diff`、`evidence/series-cover-letter.txt`、`evidence/source-snippets.txt`。 |
| 4. 建立可证伪的机制假设 | 先定不变量：移出 `i_pages` 的 folio 必须等 RCU grace period 后才能复用。系列将 refcount 为零的 folio 暂存在 per-CPU 队列；完成释放前它不在 LRU、buddy 或 pcp free list 中，也不进入 allocator 的可用量计数。于是预测：并行 punch-hole 可堆积隐藏页，随后匿名内存压力会让 allocator 提前 OOM。agent 同时读到作者 cover letter 已披露该根因；因此最终不把根因包装成新发现，而是测试带 expedite 改动的 tip 是否仍触发。 | 决策消息 `events.jsonl:1134`；mechanism 见 `PROCESS_LOG.md:49-63`、`:141-162`。 | 受测代码的逐段引用在 `evidence/source-snippets.txt`；候选报告列出 `__free_pages_prepare()`、`rcu_free_defer()`、`should_reclaim_retry()` 和 `zone_reclaimable_pages()`。 |
| 5. 准备对照环境和最小 PoC | 用 `git archive` 在 candidate 目录生成 base、patch-6、series tip 三份源码副本，分别用相同 x86_64 配置及 `O=` 构建；QEMU guest 为 2 GiB、无 swap、TCG（无 `/dev/kvm`）。编写静态用户态 C 程序，以 initramfs PID 1 启动。`punch_once()` 用 `memfd_create`、写入和 `fallocate(PUNCH_HOLE)` 制造 page-cache 释放；并行 hammer 与 anonymous worker 制造压力。 | `events.jsonl:1139-1168`；`PROCESS_LOG.md:65-82`；`poc/lab.c:101-164`。 | prompt 规定源码只读/out-of-tree；`kernel_vuln_support.rs:296-304` 将工作目录定在 candidate。 |
| 6. 逐轮跑实验并淘汰不稳定 oracle | 先用 `observe`/`watch` 对比 base 与 series 的 `pgfree_rcu*`，确认单线程释放很快排空；接着逐步调并发/内存压力。4 CPU 初测未打出差异；8 CPU 的 patch-6 有 2/4 次 OOM，但相同 base 控制通过，agent 将它判为 timing-sensitive，不拿来做主 oracle。提高到 16 vCPU 后对 base/p6/tip 使用同参数；series tip 多次 OOM，而 base 中一次 OOM 的 worker 已达到全部需求且隐藏页为 0，因此归为内存边缘控制结果，而非系列特有现象。 | `events.jsonl:1172-1238`、`:1266-1310`；原始跑法与结果在 `PROCESS_LOG.md:84-139`，逐次日志在 `evidence/logs/`。 | PoC `lab.mode=observe/watch/run`：`poc/lab.c:168-263,343-386`；主测脚本/命令见 `REPRODUCTION.md` 和 `run_qemu.sh`。 |
| 7. 加测量器，再控制观测扰动 | 在 PoC 中读取 `/proc/vmstat` 的 `pgfree_rcu`、`pgfree_rcu_done`、`oom_kill`，以两计数之差表示“已计作释放、但 allocator 尚不可见”的页；同步采样 meminfo。agent 发现控制台输出频率会改 guest 时序，尝试不同打印/采样 cadence，修正 tip 上短暂 `done > rcu` 的下溢，并保留较安静的测量版本。决定性 plain run 中隐藏量峰值约 1,140 MiB；OOM 报告只计入约 818 MiB/2,048 MiB，杀死当时仅驻留约 617 MiB 的 anonymous worker。 | `events.jsonl:1239-1315`；`PROCESS_LOG.md:122-139`；数值核对见 `evidence/decisive-oom-run2.txt`。 | `hidden_mb()` 和 monitor：`poc/lab.c:214-263`；观察扰动及处理见 `PROCESS_LOG.md:130-136`。 |
| 8. 将随机前提变成一次性 gate | 第一次写报告时 outcome 先记作 `plausible`。agent 发现 plain run 的隐藏量时点仍受调度影响，于是新增 `mode_trigger`：worker 先等 `hidden_mb() >= 256` 再开始匿名分配；base 达不到阈值则 timeout 后走同样的分配路径，作为 close control。首个 `gate=30` tip 尝试只达到 6 MiB 就超时，后续 OOM 不计作越过 gate 的阳性；两个 `gate=20` tip 试验分别在 284/335 MiB 开 gate 且都 OOM。两个 base 控制都保持 hidden=0、分配完 1,600 MiB、`oom_kill delta=0`。因此把 claim 收窄为该未合入系列 tip 上的提前 OOM 行为，并将 outcome 改成 `confirmed`，同时披露作者已知根因。 | `events.jsonl:1330-1381`；`PROCESS_LOG.md:141-162`、`:164-207`；日志 `evidence/logs/trig-*.log`。 | 新 PoC 路径 `poc/lab.c:214-341`；报告 outcome 更新发生在事件第 1361 行附近。 |
| 9. 固化交付物并做末尾核对 | 整理 candidate report、fingerprint、复现手册、完整 `PROCESS_LOG.md`，复制 gate 版本源码/二进制/日志到 evidence；再检查报告中 `plausible` 残留、表格和 oracle 描述的一致性，修正文案，核对源码树状态和 PoC 编译产物。最后输出限定范围的 agent summary。 | `events.jsonl:1319-1419`；文件清单见 `PROCESS_LOG.md:220-239`；源码状态及 PoC hash 核验在事件第 1414 行。 | KScout 父进程保存 child 最后一条消息、usage 和 source snapshot：`kernel_vuln.rs:586-609,651-663`；usage 持久化代码见 `kernel_vuln_usage.rs:249-278`。 |

## 通俗解释：这条假设在说什么

可以把 allocator（负责分配空闲物理页的内核部分）想成仓库管理员，把可分配的内存想成库存。page-cache 是文件数据在内存中的缓存；folio 是内核管理缓存时使用的一页或一组页。folio 被打洞移出缓存后，逻辑上已经不再是文件缓存；但为了让已经开始的 RCU 无锁读操作安全地用完旧指针，内存还不能马上交回 allocator。系列先把它们放进每 CPU 的“待归还区”，等这些读操作结束、grace period 结束后再真正归还。

问题在于：仓库账本只统计空闲库存和可回收货架；“待归还区”里的内存没有记进这些数。并行打洞速度超过归还速度时，待归还区会越来越大。新分配来查账，allocator 看到的库存不足，就可能触发 OOM；实际上有一批内存只是还在等待归还。这里的“隐藏量”由 `pgfree_rcu - pgfree_rcu_done` 估算；它是机制测量值。是否真的发生提前 OOM，则由 `oom_kill`、内核日志和 PoC worker 是否被杀等客观 oracle（判断测试结果的信号）确认。

这不是说 RCU 延迟本身不安全，而是说这套延迟释放机制与内存不足判断之间没有把账接起来。对应代码链是：shmem punch-hole → `folio_mark_removed_from_cache()` 标记 → `__free_pages_prepare()` 延迟入队 → `should_reclaim_retry()` 只按 LRU 和空闲页判断是否还有空间。逐段源码在 `evidence/source-snippets.txt`；核心位置见 [shmem.c:3629](/root/workspace/kscout-workdir/candidates/candidate-005/trees/tip-src/mm/shmem.c:3629)、[internal.h:653](/root/workspace/kscout-workdir/candidates/candidate-005/trees/tip-src/mm/internal.h:653)、[page_alloc.c:1486](/root/workspace/kscout-workdir/candidates/candidate-005/trees/tip-src/mm/page_alloc.c:1486) 和 [page_alloc.c:4815](/root/workspace/kscout-workdir/candidates/candidate-005/trees/tip-src/mm/page_alloc.c:4815)。

验证时，agent 让多路 punch-hole 持续制造待归还页，再让 worker 逐步触碰匿名内存。tip 上的 gate 先确认隐藏量达到 256 MiB 才开始分配；base 达不到阈值，就走 timeout 控制路径。两次 tip gate=20 都达到阈值后 OOM；两次 base 控制隐藏量为 0，并完成同样的 1,600 MiB 分配。第一次 tip gate=30 只达到 6 MiB 后就 timeout，所以之后的 OOM 不能算作“达到前提后的 gate 阳性”。这就是为什么要同时记录“前提是否成立”和“最终是否 OOM”。

## 从本次案例提炼的可复用验证方法

下面是一套可复述、可审查的**研究方法**，从 candidate-005 的实际过程归纳而来。它不是 KScout 内置的自动评分算法，也不能自动决定多个候选中哪个最值得研究。

1. **圈定代码变化。** 记录基线版本、候选提交范围和源码状态；明确比较的是现行代码、某个中间版本还是未合入分支。
2. **把怀疑写成不变量。** 用一句话说明代码必须保证什么，例如“对象被无锁读者看到时，在读者退出前不能被复用”。如果说不清要保护的状态，就先别写 PoC。
3. **沿代码链找责任点。** 从普通用户操作往内追：入口如何改变状态、对象何时释放、状态被记在哪、资源不足时哪个函数作决定。每段结论都应能指回函数和代码位置。
4. **提出能被结果推翻的预测。** 事先写清触发条件、主要 oracle、支持机制的测量值，以及反例会是什么。此处的预测是“隐藏页超过阈值后分配会引发 OOM”，反例包括隐藏量为零却出现同样的 OOM。
5. **先做最小用户态 PoC 和同条件对照。** PoC 只负责触发，避免把内核改动带入实验；在基线和候选版本用相同资源、参数、启动方式运行。将“候选也能发生的正常内存耗尽”与候选特有的提前失败区分开。
6. **重复并记录失败结果。** 观察是否每次都满足预测；若结果随并发、采样方式或资源边缘变化，就标记为不稳定，调整实验后重新比较。保留之前的失败/中止日志，不能只报告成功的一次。
7. **把随机前提变成显式 gate。** 如果失败只可能在某个状态成立时出现，让 PoC 先观测该状态，再开始触发；控制组走相同逻辑但因前提不成立而 timeout。没有越过 gate 的运行不算 gate 阳性。
8. **按证据收窄结论。** 报告实际验证的版本、前提、重复次数、oracle、控制和未解决波动；发现根因已被作者或公开材料说明时，应披露来源，不把它包装成新发现。

简写为：**版本差异 → 不变量 → 代码链 → 可证伪预测 → PoC/对照 → 重复测量 → gate 前提 → 有边界的结论**。这套流程能统一“怎么验证一个方向”；“多个方向里先选哪一个”仍需要额外的候选评估标准，不能从这次验证流程本身推出来。

## 对结论边界的说明

- 这是对本地 `origin/noref-filemap-read-with-llm` **未合入分支**上行为的验证；该分支 tip `4c0f3697118eb` 不是输入 Linux HEAD `24a19b953e2a` 的祖先。不能把报告里的 `confirmed` 理解成当前 7.3-rc7 HEAD 已有该缺陷。
- 作者 cover letter 已写明 deferred free 对 allocator 不可见及 patch 1–6 的 OOM 风险。agent 明确披露这一点；它确认的是带 expedite 的系列 tip 在 16 CPU gate 条件下仍有提前 OOM 行为及其量化证据，不声称发现了全新的根因。
- gate=30 首次尝试没有达到 256 MiB 前置条件，虽然之后 OOM，不能和两次 gate-qualified 的阳性混为一谈。plain pressure 中 base 也有一次真实内存边缘 OOM；报告把它与“隐藏内存导致提前 OOM”区分开。
- 事件流只能证明 agent 做过哪些可观察的命令、写入、判断和报告；不能独立证明其未记录的内部推理正确。报告中的技术结论应以可复现日志、源码摘录和控制组共同评估。

## 执行偏差和运行环境限制

- prompt 要求所有临时产物留在 candidate 目录。事件流显示 agent 曾把文件清单写到 `/tmp/newfiles.txt`、把分支文件导出到 `/tmp/branch_khugepaged.c`，末尾还在 `/tmp/poccheck/lab` 重编 PoC；这是相对 prompt 的落盘位置偏差。Linux 输入树最后状态仍为空，检查结果记录在 `evidence/revisions.txt` 和末尾事件中。
- agent 曾尝试执行 `rm -rf src-branch` 后 clone 临时树；工具以“不允许 rm -f style commands”拒绝，命令没有执行。该拒绝记在 `agent-stderr.log` 第 1 行。之后实际测试使用 candidate 目录内的源码副本和 out-of-tree build。
- 启动阶段除了排重索引，agent 还读取了 output root 的 `PROCESS_LOG.md`、`source-status-before.txt`、`USAGE.jsonl` 并列出已有 candidate 目录（`events.jsonl:11-19`）。可见命令流没有显示它打开旧 candidate 的 PoC 或报告作为新发现依据；之后它按合同把 candidate-003 作为重复排除项处理。记录这个边界是为了区分实际访问过的元数据与本次源码审计证据。
- 长任务期间出现了 7 次 thread-context/compaction 提示；agent 多次通过重新检查工作目录和日志继续工作。异步 build/VM 有几次未能跨工具调用保持运行，agent 改为前台重启；这些未成功尝试保留在事件流及 `PROCESS_LOG.md`，最终测试日志单独标识了一个中止的 boot。
