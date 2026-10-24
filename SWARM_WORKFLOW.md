# KScout swarm 工作机制

本文介绍当前 `--swarm` 的调度方式、peer 如何协作、finding 如何进入后续轮次，以及最终状态应如何解读。

## 设计目标

Swarm 将一次候选审计交给一组平等的 peer：没有常驻 reviewer，没有单一 agent 决定结论。系统先并行发现线索，再把额外预算分给仍需验证的线索，同时保留新的源码探索。`--count N` 仍表示启动 N 个独立 swarm 组，不表示最多发现 N 个漏洞。

## 运行参数

```shell
./codex-rs/target/debug/codex kernel-vuln \
  --linux-path /path/to/linux \
  --output-dir ./kscout-swarm-run \
  --count 1 \
  --swarm \
  --swarm-agents 3 \
  --swarm-rounds 2 \
  --swarm-norms ./norms-v2.json \
  --swarm-verifier /path/to/isolated-vm-verifier \
  --prior-finding-index /path/to/previous-kscout-run \
  --show-progress
```

- `--swarm-agents` 是每轮的并发上限，范围为 2–16。
- `--swarm-rounds` 是共享论证轮次上限，范围为 1–4。
- `--swarm-norms` 加载冻结的版本化规范与资源策略；不指定时使用默认版本 1。
- `--swarm-verifier` 配置外部验证程序；没有配置时 Runner 状态保持 `NOT_RUN`。
- `--count` 是 swarm 组数。一个组可以发现零个、一个或多个 finding。
- `--prior-finding-index` 可传入先前运行的 `FINDING_INDEX.md`，也可传入包含该文件的输出目录。可重复传入。
- swarm 的最大 session 预算仍按 `count × swarm-agents × swarm-rounds` 计算并受运行上限约束；动态调度与提前停止会让实际 session 数更少。实际 session 数、轮次和 usage 写入 `PROCESS_LOG.md` 与 `USAGE.jsonl`。

## 一轮审计如何推进

### 1. 父进程准备输入和排重索引

父进程读取 Linux 源码路径、输出目录、模型、并发上限、最大轮数和可选 prior index。所有 prior index 合计最多导入 12 条去重后的 finding 摘要；新输出目录中的 `FINDING_INDEX.md` 会合并本轮输出和这些摘要。索引优先按稳定 `Lead ID` 去重，也会用规范化标题与根因识别跨运行重复；缺少这两类字段时使用摘要内容作为回退键。

索引只用于排除重复根因，不是漏洞证据。每个 peer 仍须从提供的源码和历史开始独立分析。

### 2. 第一轮并行独立探索

第一轮启动 `--swarm-agents` 个 peer。它们使用不同的研究视角并行审计，在选择初始 lead 前不读取其他 peer 的结论。每个 peer 都可以提交多个独立 finding，也可以提交负面结果；finding 数量不设上限。

每个 session 使用独立的持久工作目录和 `scratch/`。报告、PoC、复现步骤、原始输出和 usage 分别保存在 session 目录；临时构建环境按既有清理规则处理。

### 3. 归档本轮证据并更新论证板

轮次内的 peer 完成后，协调器把其 `SWARM_UPDATE.md`、fingerprint、peer arguments 和结束消息追加到 `SWARM_BOARD.md`，并将符合归档条件的 finding 复制到 `findings/`。后续 peer 先读取按任务生成的 `SWARM_CONTEXT.md`；只有任务需要时才打开完整论证板或对应归档。

Finding 按稳定 `Lead ID` 聚合。同一根因的不同 agent 提交保留为独立证据，不会因标题不同自动计为不同漏洞。旧 finding 没有 Lead ID 时，才回退到标题与根因匹配。

### 4. 按待办 lead 动态安排后续 peer

每个后续轮次最多使用 `--swarm-agents` 个并发 session：

1. 协调器按证据缺口、影响分类和既往无进展成本估算跟进价值。仍需跟进的情况包括：本地复现少于两个不同 peer，或安全影响分类仍是 `unresolved`。
2. 有待办 lead 时，按队列规模将约 25%～40% session 用于新源码探索，其余 session 按优先级各挑战一个 lead。没有待办 lead 时，所有 session 都用于新探索。
3. 每条 lead 的第一次跟进是盲式挑战：peer 输入只包含 Lead ID、标题和源码路径，不给出共享板或归档报告路径；`SWARM_NORMS.json` 与先前运行排重索引会复制到该 peer 的独立 workspace。peer 先写 `blind-analysis.md`，记录独立源码分析和证伪方案，再查看之前的结论。之后只提供该 lead 的相关证据索引。此为上下文/提示级盲化；Agent 运行时仍可能通过其文件读取能力自行遍历上级目录，当前 sandbox 没有对子目录施加严格的只读隔离。
4. 后续轮次使用新的 participant ID，例如第一轮的 `agent-01` 到 `agent-03` 后，下一轮从 `agent-04` 开始，避免同一 peer 重复提交被算作独立确认。

被分配 challenge 的 peer 还需在 `SWARM_UPDATE.md` 写机器可读的 `Assigned Lead ID`、`Claim ID`、`Target claim ID`、`Lead challenge disposition`、`Independent reproduction`、`Evidence progress`、`Evidence refs`、`Disputed claim`、`Falsifiable check`、`Explored areas` 和 `Suggested follow-up task` 字段。协调器校验证据引用必须存在且位于 peer workspace；只有两个不同 peer 都提供有效证据并明确写 `rejected` 时，调度器才将 lead 标为 rejected。独立复现也必须有有效证据引用，才进入跨 peer 计数。连续达到当前规范配置的无进展阈值时会标为 `SUSPENDED`，暂停当前运行的调度，但保留未解决状态和所有证据；后续若有新的归档证据指向同一根因，会重置无进展计数并重新加入调度。

收到 lead 任务的 peer 必须重新检查源码路径、触发前提、PoC、正向 oracle 和最近的负对照，尝试独立复现或证伪，并判断在现实攻击者权限下是否跨越安全边界。peer 可以反驳前一轮，也可以在完成指定检查后报告新的线索。

### 5. 按证据停止或继续

所有当前 peer 都声明 `Round status: quiescent`，且没有待独立复现或安全影响未定的 lead 时，协调器会提前结束。只要仍有待验证 lead，即使 peer 声明 quiescent，也会继续安排后续轮次，直至任务得到解决或达到 `--swarm-rounds` 上限。

若达到轮数上限后仍未完成独立复现或安全影响判断，最终报告会保留该不确定性，不会把“达到共识”当成安全结论。

## `confirmed` 的含义

Coordinator 区分 `CANDIDATE`、`AGENT_REPRODUCED` 和 `CROSS_REPRODUCED`。最后一个状态表示两个不同 participant 报告了同一 Lead ID 的本地执行；它本身不代表两人独立推导了根因，也不构成外部验证。挑战复现只有在证据引用真实存在且位于该 peer workspace 时才进入计数。`--swarm-verifier` 配置的程序通过独立 JSON 协议验证：必须声明隔离 VM、干净环境、至少两次正例、至少一个负对照、内核版本和候选目录内的证据文件，协调器才设置 `RUNNER_VERIFIED`。请求、结果和原始 stdout/stderr 保存在 `verification/`。`REPORTABLE` 和 `SECURITY_CONFIRMED` 仍需单独审查。Agent 报告的本地 `confirmed` 仍应包含确定性正向结果、接近的负对照和干净重复实验。

每个 finding 的报告还必须单独提供：

- `Local reproduction:`：复现状态和实验条件。
- `Security impact:`：攻击者能力、攻击前提、边界或受保护资产，以及影响范围。
- `Security impact class:`：且只选择 `security-relevant`、`correctness-only`、`unresolved` 之一。

因此，核查结果时需要分别看 swarm 复现状态和安全影响证据。多个 peer 同意或进程成功退出，都不能替代对 PoC、控制组和现实攻击条件的审查。

独立评审可在运行完成后使用 `--apply-swarm-assessment ASSESSMENT.json` 更新已有候选目录。输入要求 `reviewer_id`、独立评审与架构盲审声明，以及每个 Lead 的 `reportability`、根因/复现审查结果、安全影响类别、安全确认状态和候选目录内的证据引用。只有满足交叉复现或 runner 验证、根因与复现已审查并有证据引用的 Lead 才能标为 `REPORTABLE`；`SECURITY_CONFIRMED` 还要求 `security-relevant` 类别、具体边界/受保护资产和证据。输入及历史保存在 `SWARM_REVIEW.json`，索引和候选报告同步更新。该文件记录评审者声明与可定位证据；系统无法从文件本身证明评审者身份或其独立性。

最小输入形状如下，`candidate_dir` 可相对该 JSON 文件：

```json
{
  "schema_version": 1,
  "candidate_dir": "./candidate-001",
  "reviewer_id": "reviewer-01",
  "independently_reviewed": true,
  "reviewer_blinded_to_architecture": true,
  "assessments": [
    {
      "lead_id": "L012",
      "reportability": "REPORTABLE",
      "root_cause_reviewed": true,
      "reproduction_reviewed": true,
      "security_confirmation": "SECURITY_CONFIRMED",
      "security_impact_class": "security-relevant",
      "security_boundary": "unprivileged process crosses the kernel object boundary",
      "evidence_refs": ["findings/L012/reproduction.log"],
      "review_notes": "Root cause, control, and impact independently reviewed."
    }
  ]
}
```

## 规范归纳与更新

运行时规范按三类写入 `SWARM_NORMS.json`：行为规范 N1–N4、N6；协作规范 N5、N7；资源规范 N8 与探索比例/调度权重。硬规范由协调器状态机或证据校验落实；软规范通过 peer prompt 和结构化违规事件提示，不强行阻断有效的独立复查。

每次运行生成 `SWARM_NORM_FEEDBACK_TEMPLATE.json`。独立评估者应在相同总 Token 和工具耗时上限下比较 baseline 与 norm-guided，填写共享的 `total_token_budget`、`total_tool_seconds_budget`，以及每组实际使用量。两组的 `source_revision`、模型、Agent 数、focus、额外 prompt 摘要、内核配置摘要、测试任务集摘要和环境 ID 也必须一致；更新器会拒绝条件不匹配或任一组超出共同上限的反馈。还需填写有效发现、墙钟耗时、完成 Pass、去重候选、首次有效发现时间、误确认、重复探索、无信息挑战、有效证据、交互 Token、证据解决争议和首轮探索多样性。另需提供每种架构至少 3 个互不重复的 `SWARM_EVENTS.jsonl` 路径；这些轨迹会汇总挑战具体性、证据引用、无进展比例和重复代码区域，形成下一版的 trace-induced 软规范建议。

统一使用根因去重后的 `valid_findings` 和 `candidate_count`；候选精确率为 `valid_findings / candidate_count`，Pass 产出率为 `valid_findings / completed_passes`，发现效率同时报告 `valid_findings / total_tokens` 与 `valid_findings / total_wall_clock_hours`。`completed_passes` 包含没有形成候选的已完成 Pass。`first_valid_finding_seconds` 从该组实验启动算到第一个有效缺陷；无有效发现时填 `null`。`total_tool_seconds` 统计双方约定的工具执行口径，包括 VM 排队/执行和失败重试；`interaction_tokens` 应单独统计协调、事件共享和议题上下文，不应把所有模型 Token 都算成通信成本。有效证据项和证据解决争议由盲审者按固定报告标准计数。固定每 Agent 预算实验可另行报告，但不能用它来更新固定总预算规范版本。

更新器要求独立盲审、至少 3 个审计任务和 3 次重复，只接受 `train` 或 `validation` 数据；test split、反馈版本不匹配、缺失/重复轨迹、无效轨迹或误确认率恶化都会阻止生成新版本。更新器根据评估指标和轨迹画像调整探索比例、暂停阈值，并将轨迹支持的 N3/N4/N5/N7 建议写入新版本上下文；硬规范 N2、N5、N6 不会被自动放宽。所有轨迹归纳都写入新版本 `update_record`，这是可审计的启发式更新，不表示已经证明因果效果。

```shell
./codex-rs/target/debug/codex kernel-vuln \
  --adapt-swarm-norms ./blind-evaluation-feedback.json \
  --adapt-swarm-norms-output ./norms-v2.json \
  --swarm-norms ./candidate-001/SWARM_NORMS.json
```

生成的新规范版本可通过后续运行的 `--swarm-norms` 加载。规范在一次测量运行中保持冻结；轨迹统计和自报覆盖信息用于盲审分析，不会单独作为更新效果的证据。

反馈中的 `baseline_trace_files` 和 `norm_guided_trace_files` 是相对反馈 JSON 所在目录的路径，也可使用绝对路径。两组轨迹必须互不重复，且每条轨迹必须是 schema version 1 的 JSONL 事件日志。

外部 verifier 通过 `--swarm-verifier EXECUTABLE` 调用：

```shell
EXECUTABLE --request REQUEST.json --result RESULT.json
```

结果文件必须是 schema version 1 JSON，包含 `lead_id`、`verifier`、`status` (`verified`、`rejected` 或其他)、`isolation` (`isolated_vm`)、`clean_setup`、`positive_repetitions`、`negative_controls`、`vm_queue_seconds`、`vm_execution_seconds`、`kernel_revision`、`kernel_config_sha256`、`evidence_refs` 和 `summary`。要标记 `RUNNER_VERIFIED`，协调器还会检查两次以上正例、至少一个负对照、非负有限耗时、64 位小写 SHA-256、当前 Linux worktree 的精确 HEAD、lead ID，以及候选目录内真实存在的证据文件。Runner 负责建立隔离 VM 并提供这些记录；协调器能校验结构化结果和证据路径，但不能仅凭 JSON 声明证明外部 VM 的实际隔离实现。

## 关键产物

- `PROCESS_LOG.md`：每轮实际启动的 peer 数、分配的 lead、提前停止原因和 scratch 清理记录。
- `FINDING_INDEX.md`：本输出目录和导入 prior index 的排重摘要。
- `candidates/candidate-NNN/SWARM_BOARD.md`：逐轮论证内容。
- `candidates/candidate-NNN/SWARM_EVENTS.jsonl`：带轮次、participant、议题、证据引用和独立性来源的交互事件流。
- `candidates/candidate-NNN/SWARM_INDEX.json`：Lead 状态、负面结果和暂停状态的结构化索引。
- `candidates/candidate-NNN/SWARM_NORMS.json` 与 `SWARM_NORM_REVIEW.md`：冻结的规范版本和本轮轨迹反馈摘要。
- `candidates/candidate-NNN/SWARM_NORM_FEEDBACK_TEMPLATE.json`：盲审评估填写的版本更新输入模板。
- `candidates/candidate-NNN/SWARM_REVIEW.json`：独立评审声明、逐 Lead 状态、理由和证据引用的版本化记录。
- `candidates/candidate-NNN/verification/`：外部 runner 请求、结果和原始进程输出；VM 排队/执行耗时进入事件和评估摘要。
- `candidates/candidate-NNN/agents/round-NN/agent-NN/`：peer prompt、任务分配、事件流、stderr、usage 和完整工作记录。
- `candidates/candidate-NNN/findings/`：按参与者保留的独立 finding 证据副本。
- `candidates/candidate-NNN/candidate-report.md` 与 `finding-fingerprint.md`：协调器汇总结果与总体状态。

模型、源码版本、初始线索和实验环境都会影响结果。动态分配旨在减少没有待办线索时的重复 session，并将跟进预算集中到可检验的 lead；它本身不能保证更低 token 开销、更短耗时或更低误报率。需要比较效果时，应在相同源码 revision、模型、focus、额外 prompt 和总 token/时间预算下做多次对照。
