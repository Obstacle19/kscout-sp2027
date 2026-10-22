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
  --prior-finding-index /path/to/previous-kscout-run \
  --show-progress
```

- `--swarm-agents` 是每轮的并发上限，范围为 2–10。
- `--swarm-rounds` 是共享论证轮次上限，范围为 1–4。
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

轮次内的 peer 完成后，协调器把其 `SWARM_UPDATE.md`、fingerprint、peer arguments 和结束消息追加到 `SWARM_BOARD.md`，并将符合归档条件的 finding 复制到 `findings/`。下轮 peer 可同时读取论证板与归档证据。

Finding 按稳定 `Lead ID` 聚合。同一根因的不同 agent 提交保留为独立证据，不会因标题不同自动计为不同漏洞。旧 finding 没有 Lead ID 时，才回退到标题与根因匹配。

### 4. 按待办 lead 动态安排后续 peer

每个后续轮次最多使用 `--swarm-agents` 个并发 session：

1. 协调器先按优先级选择需要继续验证的 lead。仍需跟进的情况包括：独立本地复现者少于两个，或安全影响分类仍是 `unresolved`。
2. 排序时先看报告给出的安全影响分类：明确声称 `security-relevant` 的 lead 优先，其次是 `unresolved`，最后是 `correctness-only`；同类中再优先考虑独立复现数和报告该 lead 的 peer 数。
3. 最多分配 `N-1` 个 session，每个 session 独立挑战一个 lead。剩余一个 session 用于探索尚未覆盖的源码区域；没有待跟进 lead 时，只启动这一个探索 session。
4. 后续轮次使用新的 participant ID，例如第一轮的 `agent-01` 到 `agent-03` 后，下一轮从 `agent-04` 开始，避免同一 peer 重复提交被算作独立确认。

被分配 challenge 的 peer 还需在 `SWARM_UPDATE.md` 写机器可读的 `Assigned Lead ID`、`Lead challenge disposition` 和 `Independent reproduction` 字段。只有两个不同 peer 都明确写 `rejected` 时，调度器才停止为该 lead 消耗后续 challenge session；两份反对意见仍会在最终候选报告中显示，不能据此抹掉原始正向证据。

收到 lead 任务的 peer 必须重新检查源码路径、触发前提、PoC、正向 oracle 和最近的负对照，尝试独立复现或证伪，并判断在现实攻击者权限下是否跨越安全边界。peer 可以反驳前一轮，也可以在完成指定检查后报告新的线索。

### 5. 按证据停止或继续

所有当前 peer 都声明 `Round status: quiescent`，且没有待独立复现或安全影响未定的 lead 时，协调器会提前结束。只要仍有待验证 lead，即使 peer 声明 quiescent，也会继续安排后续轮次，直至任务得到解决或达到 `--swarm-rounds` 上限。

若达到轮数上限后仍未完成独立复现或安全影响判断，最终报告会保留该不确定性，不会把“达到共识”当成安全结论。

## `confirmed` 的含义

Coordinator 的 swarm 级 `confirmed` 表示至少两个不同 participant 对同一 Lead ID 独立报告了本地复现；每份本地 `confirmed` 还应包含确定性正向结果、接近的负对照和干净重复实验。它确认的是报告的行为可复现，不自动证明该行为构成安全漏洞。

每个 finding 的报告还必须单独提供：

- `Local reproduction:`：复现状态和实验条件。
- `Security impact:`：攻击者能力、攻击前提、边界或受保护资产，以及影响范围。
- `Security impact class:`：且只选择 `security-relevant`、`correctness-only`、`unresolved` 之一。

因此，核查结果时需要分别看 swarm 复现状态和安全影响证据。`confirmed`、进程成功退出或多个 peer 同意，都不能替代对 PoC、控制组和现实攻击条件的审查。

## 关键产物

- `PROCESS_LOG.md`：每轮实际启动的 peer 数、分配的 lead、提前停止原因和 scratch 清理记录。
- `FINDING_INDEX.md`：本输出目录和导入 prior index 的排重摘要。
- `candidates/candidate-NNN/SWARM_BOARD.md`：逐轮论证内容。
- `candidates/candidate-NNN/agents/round-NN/agent-NN/`：peer prompt、任务分配、事件流、stderr、usage 和完整工作记录。
- `candidates/candidate-NNN/findings/`：按参与者保留的独立 finding 证据副本。
- `candidates/candidate-NNN/candidate-report.md` 与 `finding-fingerprint.md`：协调器汇总结果与总体状态。

模型、源码版本、初始线索和实验环境都会影响结果。动态分配旨在减少没有待办线索时的重复 session，并将跟进预算集中到可检验的 lead；它本身不能保证更低 token 开销、更短耗时或更低误报率。需要比较效果时，应在相同源码 revision、模型、focus、额外 prompt 和总 token/时间预算下做多次对照。
