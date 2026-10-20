# Linux `kernel-vuln` 再审计：agent workflow 监督记录

- 日期：2026-10-15
- Linux HEAD：`24a19b953e2a3d0ea5a8c4951a0ab8f32720c907`（`v7.3-rc7`）

## 结论

这次观察到的前半段仍是“记录基线和排重 → 浏览提交历史 → 挑候选子系统 → 读代码”。候选方向仍由模型定性筛选，没有观察到统一的量化评分或排序规则。

但本轮没有走到一个通过新颖性检查的漏洞假设、PoC 或结论：`candidate-006` 遇到已有的 `listns` 分页回归测试后被监督者中止；`candidate-007` 虽被要求先写新颖性筛查记录，却在没有该记录、shell 网络检查失败的情况下继续读实现代码，随后被中止。因此这次不能把它写成“完整复现了 candidate-005 的九步实验流程”，也不能据此声称 HEAD 上存在或不存在新漏洞。

两次都没有运行 PoC、内核自测或针对漏洞的测试；Linux 源码树最后仍是上述 HEAD 且 `git status` 为空。`candidate-006` 的构建尝试失败，见下文。两次中止后都没有 `agent-events.jsonl`、`agent-final.md`、`finding-fingerprint.md` 或候选报告：KScout 在 child 结束后才把缓冲的 JSONL/stderr 写入文件，所以中断会留下不完整记录，详见 [kernel_vuln_support.rs:330-375](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln_support.rs:330)。

## 本次运行

用户给出的旧可执行文件路径 `/root/workspace/codex/codex-rs/target/debug/codex` 不存在；实际运行的是 `/root/workspace/kscout/codex-rs/target/debug/codex`。`DEEPSEEK_API_KEY` 已在环境中设置，值未打印。两次均在 `/root/workspace/kscout` 执行，参数保持 `deepseek-flash`、DeepSeek API、`--disable code_mode_host`、同一 Linux 源码树、同一 output root、`--count 1 --show-progress`，另加一份排除已知问题的补充 prompt。

```sh
/root/workspace/kscout/codex-rs/target/debug/codex kernel-vuln \
  --api-key-env DEEPSEEK_API_KEY \
  --api-base-url https://api.deepseek.com \
  --model deepseek-flash \
  --disable code_mode_host \
  --linux-path /root/workspace/linux \
  --output-dir /root/workspace/kscout-workdir \
  --count 1 \
  --show-progress \
  --extra-prompt-file /root/workspace/kscout-workdir/agent-audit-006-exclusion-gate.md
```

第一次中止后，第二次改用更严格的补充要求：只用提交元数据和路径名组成候选清单；先创建 `NOVELTY_SCREEN.md`；已存在的 bug 回归测试、公开报告、修复提交、披露不明或网络不可用时都不得进入源码分析和测试。第二次实际使用的文件是 [`agent-audit-007-exclusion-gate.md`](/root/workspace/kscout-workdir/agent-audit-007-exclusion-gate.md)。候选目录分别是 [`candidate-006`](/root/workspace/kscout-workdir/candidates/candidate-006) 和 [`candidate-007`](/root/workspace/kscout-workdir/candidates/candidate-007)。

## candidate-006：在已知 `listns` 线索处停止

1. agent 先记录 HEAD/工作树状态，读取 `FINDING_INDEX.md`，再查看分支、近期提交和大范围 diff。它用新增文件、提交差异和简单脚本筛候选；`opflip.py` 没找到操作符替换，`guardremoved.py` 产生了大量候选行，但没有形成可验证问题。这些是启发式筛查，不是候选打分标准。
2. 它先后考虑 NTFS WOF、若干新增 syscall、`failfs`/`fchroot` 等方向。NTFS WOF 因本机提供的配置没有启用 NTFS 而暂时搁置。
3. 为准备 QEMU/selftest 环境，它试图在源码树外构建。初次构建被 Linux 树中已存在的忽略构建文件挡住，Kbuild 报 `The source tree is not clean`；之后 agent 用 `git archive HEAD` 在 candidate 目录建副本。副本构建又在递归 `make` 时以 `Operation not permitted` 失败。agent 曾请求 `rm -rf build`，执行器拒绝了该命令；原目录没有被删除。
4. 随后它看见并打开了 [`listns_pagination_bug.c`](/root/workspace/linux/tools/testing/selftests/namespaces/listns_pagination_bug.c)，再查到提交 `2cc1c01fe97703d9d694fa49b16fb3aab47b70a9` 的说明明确称其为复现 listns 分页 KASAN 越界的最小测试。这个复现已经存在，因此我立即中止；没有运行该测试，也没有继续分析其触发条件。是否同一缺陷仍能在当前 HEAD 触发，本轮没有判定。

这一轮说明模型可能先做通用环境构建，之后才碰到“已有 reproducer”的提示。虽然它没有运行已知测试，但新颖性筛查发生得太晚，不符合本次要求。

## candidate-007：加强 prompt 后仍未通过门槛

1. agent 再次确认相同 HEAD 和干净状态，读取索引与提交元数据；它先查 selftest 文件名和提交信息，没有打开 `tools/testing/selftests` 的测试正文。shell 对 lore 的连接失败，curl 返回代码 7。
2. 提交元数据明确显示若干路径已有修复或报告背景，例如 `binfmt_misc_bpf` 的竞态修复说明。按本轮约束，这些应当只作为排除依据。
3. 但在网络失败、也没有写出 `NOVELTY_SCREEN.md` 的情况下，agent 选中 Live Update Orchestrator（LUO），开始阅读 `kernel/liveupdate` 源码；之后又查看到已有 `luo_file` UAF 修复的本地历史，并转去读 `mm/shmem.c`。`mm/shmem` 属于前一次候选已经涉及的 page-cache 范围。为避免把这些已知历史或旧审计范围延伸成新发现，我在它开始 PoC/构建前中止。
4. 这次没有具体的新 bug 假设，没有 PoC、内核构建或运行测试。由于 novelty gate 被越过，LUO 代码浏览本身也不作为任何新颖性结论的依据。

我在浏览器侧只核对到 LUO 是有公开文档和上游邮件列表提案的子系统；这不等同于核对任何具体缺陷是否已报告，也不能证明某个 LUO 问题新颖。[Linux LUO 文档](https://docs.kernel.org/next/core-api/liveupdate.html)，[原始上游提案](https://lkml.iu.edu/hypermail/linux/kernel/2506.3/04089.html)。

## 与上一份 agent workflow 的关系

candidate-005 记录的完整路径是：广泛选审计面 → 形成机制假设 → 代码链分析 → PoC 和对照 → 重复测量 → 按证据收窄报告。本次只观察到前两段中的“广泛搜历史、定性选方向、进入代码”；已知问题排除、PoC 验证、实验收敛和交付阶段没有完成。详细成功案例仍见 [kernel-vuln-agent-workflow.md](/root/workspace/kscout/docs/kernel-vuln-agent-workflow.md)。原来的 [kernel-vuln-workflow.md](/root/workspace/kscout/docs/kernel-vuln-workflow.md) 未修改。

由本次可见证据，候选选择还是依赖模型当下的定性判断，例如把新文件、近期 syscall 或新子系统称为“interesting/prime target”。这不是纯随机，但也不是统一评判表：本次没有 `candidate score`、固定阈值或按可达性、影响、修复状态、PoC 成本等维度计算的排序。临时 diff 脚本也没有输出分数。

## 可复用的安全筛选门

为了满足“不要挖掘别人已经提出或修复的 bug”，更稳妥的顺序是：

1. **先锁定审计版本与重复边界**：记录 HEAD、工作树状态，读取 finding index；旧候选资料只用于排除，不能用来构造新方向。
2. **先看候选元数据**：列出当前 HEAD 的提交和改动路径；先检查提交正文中的 `Fixes`、`Closes`、`Reported-by`、CVE、邮件列表链接，以及现有回归测试文件名。出现已知报告、已有 reproducer 或修复时，记为排除并停止，不打开 PoC/测试内容。
3. **查公开状态再读实现**：对剩下的候选查权威上游邮件列表、公告和后续修复。如果外部来源不可访问、状态不确定，就不要继续到实现分析或 PoC；明确报告“因新颖性无法确认而排除”。
4. **通过筛查才建立不变量与预测**：明确当前 HEAD 上仍存在的代码路径、保护的不变量、用户可控触发条件、会支持或推翻假设的 oracle。
5. **最后才构建和验证**：只为通过筛查的一个方向建最小环境；正例、同条件 close control 和重复运行共享相同配置。任何已知报告的旧 PoC 都不复制或改造。

这次最重要的观察是：把这些规则写进 `--extra-prompt-file` 不足以保证执行。KScout 会把补充文字追加到 prompt，见 [kernel_vuln.rs:481-489](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln.rs:481)；补充 prompt 只受 8 KiB 的输入检查，见 [kernel_vuln_support.rs:30-65](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln_support.rs:30)。随后 parent 就启动 child；结果索引只在 child 结束后刷新，见 [kernel_vuln.rs:576-609](/root/workspace/kscout/codex-rs/cli/src/kernel_vuln.rs:576)。这些路径没有显示一个要求 `NOVELTY_SCREEN.md` 先通过、才允许后续审计/测试的程序化状态门。`--show-progress` 提供观察窗口，但语义上的阻止仍由监督者完成。

## 证据完整性边界

- 可复核文件：两个 candidate 的 `prompt.md`、`command.txt`、`run-metadata.md`；candidate-006 另有 `logs/build.log`、history 筛查脚本和 `git archive` 源码副本；candidate-007 有 `evidence/source-state.txt`。
- 因 supervisor 在 child 仍运行时中止了上层命令，`run_agent()` 没有完成把累计 stdout/stderr 写入事件日志的步骤。因此本文件是根据 `--show-progress` 实时输出记录的监督摘要，不是完整 agent 事件转录；没有给出虚构的 event 行号。
- Linux 源码 HEAD 始终为 `24a19b953e2a3d0ea5a8c4951a0ab8f32720c907`，最后 `git status --porcelain` 为空。此次未对 `/root/workspace/linux` 写入代码。
- 本文只记录 workflow 和停止原因，不是漏洞报告，也不声称这轮得到了 negative audit 结果。
