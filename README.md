# KScout：Linux 内核漏洞挖掘平台

KScout 基于 Codex CLI 构建，用于审查 Linux 内核源码和提交历史、验证可疑缺陷，并保存可复核的报告、PoC 和实验记录。它提供单 agent、peer swarm 和可选的 CVE 派生规则审查模式。

KScout 仓库不包含 Linux 源码树。运行时请通过 `--linux-path` 指定本机 Linux checkout；下面的命令面向从仓库根目录启动的使用方式，不依赖某个固定的 clone 路径。

## 快速开始

### 1. 构建 CLI

构建需要 Rust 工具链；实际运行还需要可用的 Codex 模型/API 配置。仓库根目录下运行：

```shell
cd codex-rs
cargo build --locked -p codex-cli --bin codex
cd ..
```

构建出的程序位于 `codex-rs/target/debug/codex`。

### 2. 先生成 dry-run 产物

`--dry-run` 会生成 prompt、命令和目录结构，不会启动模型会话：

```shell
./codex-rs/target/debug/codex kernel-vuln \
  --linux-path /path/to/linux \
  --output-dir ./kscout-workdir \
  --count 1 \
  --dry-run
```

把 `/path/to/linux` 换成本机 Linux 源码目录。建议始终显式传入 `--linux-path`，避免依赖不同机器上的默认路径。

### 3. 运行一次单 agent 审计

默认使用 `OPENAI_API_KEY`。密钥通过环境变量提供，不要把它写进命令参数或报告：

```shell
export OPENAI_API_KEY='your-api-key'

./codex-rs/target/debug/codex kernel-vuln \
  --linux-path /path/to/linux \
  --output-dir ./kscout-workdir \
  --count 1 \
  --show-progress
```

若使用其他兼容 Responses API 的服务，可指定对应环境变量、API 地址和模型：

```shell
export PROVIDER_API_KEY='your-api-key'

./codex-rs/target/debug/codex kernel-vuln \
  --api-key-env PROVIDER_API_KEY \
  --api-base-url https://api.example.com/v1 \
  --model model-name \
  --linux-path /path/to/linux \
  --output-dir ./kscout-workdir \
  --count 1
```

在当前工作区使用 DeepSeek 的命令示例（请先在环境中设置 `DEEPSEEK_API_KEY`）：

```shell
/root/workspace/codex/codex-rs/target/debug/codex kernel-vuln \
  --api-key-env DEEPSEEK_API_KEY \
  --api-base-url https://api.deepseek.com \
  --model deepseek-flash \
  --disable code_mode_host \
  --linux-path /root/workspace/linux \
  --output-dir /root/workspace/kscout-workdir \
  --count 1 \
  --show-progress \
  --stop-on-error
```

这是与当前开发环境对应的示例；其他 clone 路径下请替换可执行文件和 Linux 源码路径。

## 审计模式

### 单 agent

默认模式下，`--count 1` 安排一个独立候选审计任务。增大 `--count` 会顺序安排更多候选任务；它表示任务数，不代表漏洞数或成功保证。结果可能是 `confirmed`、`plausible`、`negative`、`inconclusive`、重复线索或运行失败。

### Peer swarm

`--swarm` 把一个候选任务交给多个平等的 peer。第一轮并行独立挖掘；后续轮次根据已归档证据挑选未完成的 lead，安排新的 peer 独立复现或反驳，同时保留一个名额继续探索新方向。没有固定 reviewer，也不限制发现数量；最终结论仍须由源码路径、PoC、对照实验和日志证据支撑。

```shell
./codex-rs/target/debug/codex kernel-vuln \
  --linux-path /path/to/linux \
  --output-dir ./kscout-swarm-run \
  --count 1 \
  --swarm \
  --swarm-agents 3 \
  --swarm-rounds 2 \
  --show-progress
```

默认第一轮 3 个 peer、最多 2 轮；一轮内并发、轮次之间顺序执行。后续轮按待办 lead 数量，将约 25%～40% 的 session 留给新方向，其余按证据缺口挑战不同 lead；没有待跟进 lead 时所有 session 都探索。首次跟进先进行盲式源码分析，反复没有新增证据的 lead 会暂停调度但保留记录。若 peer 全部报告无后续任务且没有待独立复现或待定安全影响的 lead，会提前结束。因此 `--count 1` 是一个 swarm 组，默认最多可用 6 个 child session，实际数量可能更少；日志会记录实际数量。`--swarm-agents` 设置每轮并发上限（2–16），`--swarm-rounds` 设置最多轮数（1–4）。

跟进 lead 按证据缺口、影响分类、信息增益和历史 Token/时长成本排序。有效证据引用的 challenge 复现会进入跨 peer 计数。两名不同 peer 都提供证据并提交 `rejected` 后，该 lead 才会标记为 rejected；达到当前规范阈值的无进展议题会暂停，后续同根因新证据可重新激活。状态区分为 `CANDIDATE`、`AGENT_REPRODUCED`、`CROSS_REPRODUCED`；两个 peer 报告同一 Lead ID 的本地执行只构成 cross-reproduced，不代表独立根因分析或外部 runner 验证。`--swarm-verifier PATH` 可调用外部 VM 验证协议；协调器会检查结果结构、当前 Linux HEAD、配置摘要、重复正例、负对照、耗时和证据路径，但 VM 隔离仍由已配置的 verifier 实现。`--swarm-norms PATH` 加载冻结的版本策略；`--adapt-swarm-norms FEEDBACK.json --adapt-swarm-norms-output PATH` 根据等总预算的独立盲审反馈和 baseline/norm-guided 事件轨迹生成下一版，保留轨迹画像并归纳软规范建议。独立评审可在运行后用 `--apply-swarm-assessment ASSESSMENT.json` 记录 `REPORTABLE` 和 `SECURITY_CONFIRMED` 状态；Agent 共识不能设置这些终态。`SWARM_EVENTS.jsonl`、`SWARM_INDEX.json`、`SWARM_NORMS.json`、`SWARM_NORM_REVIEW.md`、`SWARM_REVIEW.json` 和 feedback template 保存事件、议题、评审和策略版本。`--prior-finding-index PATH` 可传入先前运行的 `FINDING_INDEX.md` 或其输出目录，重复该参数可导入多份索引，帮助不同输出目录之间排除重复根因。`--multi-agent` 仍是 `--swarm` 的兼容别名。是否改善发现效率和验证质量仍需按文档执行对照评估。

### CVE 派生规则

规则模式默认关闭。`--use-cve-rules` 使用维护的 CVE 派生规则审查源码；可以用 `--focus net/sched` 限定子系统，或用 `--cve-rule CVE-2022-0847` 选择 CVE，也可以重复传入多个 `--cve-rule`。此模式下 `--count` 是规则审查总数上限。规则匹配只用于生成审查线索，不等于发现漏洞。

规则来源和验证边界见[操作指南](docs/kernel-vuln-hunt.md)、[CVE/CWE 索引](docs/kernel-cve-cwe-index.md)和[机器可读规则库](KERNEL_CVE_KNOWLEDGE.json)。

## 运行参数

| 参数 | 作用 |
| --- | --- |
| `--linux-path PATH` | Linux 源码树；建议显式提供。 |
| `--output-dir DIR` | 报告和运行产物目录；README 示例使用 `./kscout-workdir`，相对于启动命令时的当前目录。 |
| `--count N` | 单 agent 候选数，或 swarm 组数；规则模式下是规则审查上限。 |
| `--swarm` | 启用 peer swarm。 |
| `--swarm-agents N` / `--swarm-rounds N` | 配置每轮并发上限和最大论证轮数；后续轮会动态分配 peer。 |
| `--prior-finding-index PATH` | 导入先前运行的排重索引或其输出目录；可重复传入。 |
| `--model NAME` | 覆盖配置文件中的模型。 |
| `--api-key-env NAME` / `--api-base-url URL` | 选择 API key 环境变量和兼容 API 地址。 |
| `--focus TEXT` / `--commit REV` | 指定审查主题和优先检查的提交或 revision。 |
| `--show-progress` | 将 child 的进度和命令输出实时转发到终端；`--verbose` 是别名。 |
| `--stop-on-error` | child 失败后停止后续候选任务。 |
| `--dry-run` | 只生成 prompt 和命令，不启动模型。 |
| `--keep-workspace` | 保留临时 `scratch/`，用于调试；默认清理。 |

完整参数、API 配置、沙箱和 CVE 规则细节见[Linux 漏洞挖掘操作指南](docs/kernel-vuln-hunt.md)。

## 输出目录与空间管理

输出目录会包含运行级日志和候选目录，主要文件包括：

- `PROCESS_LOG.md`：父进程运行时间线、状态和 scratch 清理记录。
- `USAGE.jsonl`：各候选或 swarm 组的耗时与可用 token usage。
- `FINDING_INDEX.md`：本输出目录 finding 摘要与显式导入的历史索引，用于提示 agent 排除重复根因。
- `candidates/candidate-NNN/`：prompt、命令、metadata、完整事件/错误日志、报告和 fingerprint。
- `candidates/candidate-NNN/agents/round-NN/agent-NN/`：swarm peer 的独立持久工作区和论证记录。
- `candidates/candidate-NNN/findings/`：符合归档条件的 swarm finding 副本。

报告、日志、PoC 源码、复现步骤、revision/configuration 信息和正负对照证据会保存在持久目录中，不会为了节省磁盘而压缩或删减文字。临时源码副本、构建树、中间内核、VM 磁盘、临时 rootfs/initramfs 和缓存放在专属 `scratch/` 中：单 agent 完成后清理，swarm 在每轮归档 finding 后清理。若归档失败，swarm 会保留该轮 scratch，避免丢失尚未归档的证据。使用 `--keep-workspace` 可保留 scratch；每个工作区的 `workspace-cleanup.md` 和根级 `PROCESS_LOG.md` 会记录清理结果。

同一输出目录再次运行时，KScout 会跳过已有候选目录并继续分配编号，同时重建排重索引。需要一份独立的实验记录时，请使用新的 `--output-dir`。索引用于提示去重，不保证完全避免重复发现。

查看一轮运行的状态和产物时，可以从输出目录检查：

```shell
less ./kscout-workdir/PROCESS_LOG.md
less ./kscout-workdir/candidates/candidate-001/finding-fingerprint.md
find ./kscout-workdir/candidates/candidate-001 -maxdepth 4 -type f | sort
```

## 安全与结果核查

默认配置不会把 Linux 源码目录加入 child 的可写工作区，研究合同也要求将它作为只读输入。agent 应给出用户态 PoC、可观察 oracle、接近的负对照和重复实验，并披露失败结果与不确定性。不要在宿主机上运行可能导致内核崩溃或状态破坏的触发程序；需要内核触发验证时，应使用可丢弃的隔离 VM。`--dangerously-bypass-approvals-and-sandbox` 会关闭审批和沙箱，因此只应在隔离实验环境中使用。

CLI 正常退出或 fingerprint 写有 `confirmed`，都不能单独证明漏洞有效。请检查报告、PoC、原始日志、触发前提、正负对照和复现结果。单 agent 与 swarm 的工作流和限制见[单 agent 工作流](docs/kernel-vuln-workflow.md)及[修改后的 Peer swarm 工作机制](SWARM_WORKFLOW.md)。

## 源码模块

`codex-rs/cli/src/` 中与 KScout 漏洞审计相关的模块：

- [`kernel_vuln.rs`](codex-rs/cli/src/kernel_vuln.rs)：CLI 参数、运行配置、候选调度和结果汇总。
- [`kernel_vuln_support.rs`](codex-rs/cli/src/kernel_vuln_support.rs)：prompt 渲染、child 命令构造、进度收集和日志输出。
- [`kernel_vuln_swarm.rs`](codex-rs/cli/src/kernel_vuln_swarm.rs)：peer 轮次、共享论证板、finding 归档和交叉确认门槛。
- [`kernel_vuln_swarm_planner.rs`](codex-rs/cli/src/kernel_vuln_swarm_planner.rs)：基于复现与安全影响状态给后续 peer 分配任务。
- [`kernel_vuln_cleanup.rs`](codex-rs/cli/src/kernel_vuln_cleanup.rs)：校验工作区边界后，仅清理专属 `scratch/` 子目录。
- `kernel_vuln_rules.rs`、`kernel_vuln_rule_*.rs`：CVE 规则扫描、知识记录、prompt 和报告。
- `kernel_vuln_dedup.rs`、`kernel_vuln_usage.rs`：finding 索引与耗时/token usage 记录。

## 相关文档

- [Linux 内核漏洞挖掘操作指南](docs/kernel-vuln-hunt.md)
- [单 agent 实际工作流](docs/kernel-vuln-workflow.md)
- [修改后的 Peer swarm 工作机制](SWARM_WORKFLOW.md)
- [CVE/CWE 索引](docs/kernel-cve-cwe-index.md)
- [CVE 规则知识库](KERNEL_CVE_KNOWLEDGE.json)
- [贡献指南](docs/contributing.md)

本项目基于 Codex CLI 运行时。模型和 Codex 配置可参考 [Codex 文档](https://developers.openai.com/codex)。本仓库使用 [Apache-2.0 License](LICENSE)。
