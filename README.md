# Linux 内核漏洞挖掘平台

本仓库是面向 Linux 内核源码与提交历史的专用漏洞挖掘平台。平台基于 Codex CLI 的 agent、模型调用和执行能力构建，主要入口是 `codex kernel-vuln`。

## 平台工作流

- 扫描指定 Linux 源码树，确定性枚举安全相关代码候选；源码树作为审计输入，候选运行材料保存在单独的输出目录。
- 使用可选的 CVE 派生规则，从经过核实的历史修复中提取漏洞成因、危险条件和安全不变量。规则模式默认关闭，可按子系统或 CVE 选择。
- 将相关位置按规则家族合并，交给 agent 做语义审查，并复用已核实的追踪与控制结果。
- 按研究流程尝试 PoC、控制实验和 QEMU 验证，并保存报告、日志和证据。每个结果都需要结合复现证据人工核查；扫描命中本身不代表已确认漏洞。

当前规则库包含 20 条 2022—2026 年高严重性 Linux 内核 CVE 派生规则，按主 CWE 分类。规则说明、命令参数及验证边界见[操作指南](docs/kernel-vuln-hunt.md)，按 CWE 浏览见[CVE/CWE 索引](docs/kernel-cve-cwe-index.md)，机器可读记录见 [KERNEL_CVE_KNOWLEDGE.json](KERNEL_CVE_KNOWLEDGE.json)。

## 快速开始

### 构建 CLI

```shell
cd /root/workspace/codex/codex-rs
cargo build -p codex-cli --bin codex
```

### 先执行 dry-run

生成 prompt 和输出目录结构，但不会调用模型：

```shell
/root/workspace/codex/codex-rs/target/debug/codex kernel-vuln \
  --linux-path /root/workspace/linux \
  --output-dir /root/workspace/linux-vuln-set \
  --count 1 \
  --model test-model \
  --dry-run
```

### 开始实际挖掘

通过环境变量设置 API key。API key 不会出现在命令行参数或过程日志中：

```shell
export OPENAI_API_KEY='your-api-key'

/root/workspace/codex/codex-rs/target/debug/codex kernel-vuln \
  --linux-path /root/workspace/linux \
  --output-dir /root/workspace/linux-vuln-set \
  --count 1 \
  --show-progress
```

### 使用 DeepSeek API

如果 key 位于 `DEEPSEEK_API_KEY`，请这样运行：

```shell
export DEEPSEEK_API_KEY='your-deepseek-api-key'

/root/workspace/codex/codex-rs/target/debug/codex kernel-vuln \
  --api-key-env DEEPSEEK_API_KEY \
  --api-base-url https://api.deepseek.com \
  --model deepseek-flash \
  --disable code_mode_host \
  --linux-path /root/workspace/linux \
  --output-dir /root/workspace/linux-vuln-set \
  --count 1 \
  --show-progress
```

如果 key 是在 zsh 登录配置中设置的，也可以用下面的命令启动。`zsh -lic` 会加载
登录 shell 的环境变量，`exec` 会让 Codex CLI 直接成为该 shell 的前台进程：

```shell
zsh -lic 'exec /root/workspace/codex/codex-rs/target/debug/codex kernel-vuln \
  --api-key-env DEEPSEEK_API_KEY \
  --api-base-url https://api.deepseek.com \
  --model deepseek-flash \
  --disable code_mode_host \
  --linux-path /root/workspace/linux \
  --output-dir /root/workspace/linux-vuln-set \
  --count 1 \
  --show-progress \
  --stop-on-error'
```

运行前可以只检查 key 是否存在，不会打印 key 内容：

```shell
zsh -lic 'if [[ -n "$DEEPSEEK_API_KEY" ]]; then
  echo "DEEPSEEK_API_KEY is set"
else
  echo "DEEPSEEK_API_KEY is not set" >&2
  exit 1
fi'
```

这里省略 `--model` 表示继承 `~/.codex/config.toml` 中的 `model`。如果需要
覆盖模型，再添加 `--model <实际模型名>`；`your-model` 只是占位符，不能原样输入。
`--show-progress`（也可以写成 `--verbose`）会把子进程的思考摘要、命令、命令输出
和最终消息实时转发到终端；不加该参数时只在结束后保存日志。
默认沙箱会把每个 `candidate-NNN` 作为可写工作区，以便保存 PoC 和证据，同时不把
Linux 源码目录加入可写根。需要 QEMU 或挂载等特权操作时，只应在隔离实验环境中显式
使用 `--dangerously-bypass-approvals-and-sandbox`。

### 重复运行与实时观察

上面的命令每次会自动化执行一次独立候选挖掘：读取 Linux 源码和提交历史，调用指定模型
进行审计，尝试构建用户态 PoC，执行控制实验和 QEMU 验证，并把报告、日志和证据保存到
输出目录。`--count 1` 表示本次只执行一个候选任务，并不保证一定能找到有效漏洞；结果也
可能是 `negative`、`inconclusive`、构建失败或 API 失败。

在同一个输出目录再次运行时，工具会跳过已经存在的 `candidate-NNN`，并分配下一个目录，
例如继续生成 `candidate-008`。每轮结束后，工具会从已有候选的
`finding-fingerprint.md`（旧结果则读取 `agent-final.md` 或 `report.md`）重建
`FINDING_INDEX.md`，并要求后续模型只把它用于排除相同根因。每轮也会保存自己的
`finding-fingerprint.md`，记录子系统、代码位置、根因、触发路径和 oracle。该机制依赖模型
比较语义，能降低重复概率，但不能保证绝对零重复；应复核新报告和索引。使用新的输出目录
会从空索引开始，不能沿用旧目录的排除记录。

每个实际启动的候选会把运行时间、子进程结果、发现状态和可用 token usage 写入
`candidates/candidate-NNN/usage.json`，并追加到根目录的 `USAGE.jsonl`。`PROCESS_LOG.md`
记录每轮汇总。若 usage 未报告，token 字段会显示为不可用；若有 turn 用量缺失，记录会标为
`partial`，token 值为最近一次已报告的累计值，可能不包含缺失 turn。原始 usage 也保存在
`agent-events.jsonl` 中。`--dry-run`
不会调用模型，因此不会生成 usage 记录。该功能只记录新版本实际运行的候选；旧候选的历史
耗时无法追溯，不会自动补录。

候选 token 数取自最后一个报告用量的 turn 事件中的线程累计值，不会把各 turn 的累计值重复相加。

另有默认关闭的 `--use-cve-rules` CVE 派生规则模块。可用 `--focus net/sched` 只扫描该子系统中的活动规则，或用 `--cve-rule CVE-2022-0847` 精确选择一条规则；`--cve-rule` 会自动启用规则模式，也可以重复选择多个活动 CVE。当前 20 条知识库记录均有确定性扫描规则：规则从人工核实的修复中提炼漏洞条件、危险使用模式和安全不变量，再遍历对应源码范围中的 C 函数枚举候选。按主 CWE 整理的 [20 条 2022—2026 年高严重性内核 CVE 知识库](KERNEL_CVE_KNOWLEDGE.json)保存修复来源和规则验证状态；便于浏览的 [CWE/CVE 索引](docs/kernel-cve-cwe-index.md)按弱点类型汇总成因和修复不变量。严格安全过滤器只排除经过核实的精确安全形态；同一规则下相关命中合并成一个定向审查，
并且每次只向模型提供对应活动规则家族的知识，未变化的验证路径和控制结果直接复用，避免重复追踪同一数据流。启用规则后，
`--count` 是定向审查的总上限，开放式自主搜索不再并行追加；规则命中较少时只运行实际可审查
的规则组。审查仍沿用现有 PoC、控制实验和证据流程。解析器和过滤器边界、CVE 来源以及扫描报告格式见
[kernel-vuln-hunt.md](docs/kernel-vuln-hunt.md#可选的-cve-派生规则筛选)。

如果希望完全独立地保存一轮实验，使用新的输出目录：

```shell
zsh -lic 'exec /root/workspace/codex/codex-rs/target/debug/codex kernel-vuln \
  --api-key-env DEEPSEEK_API_KEY \
  --api-base-url https://api.deepseek.com \
  --model deepseek-flash \
  --disable code_mode_host \
  --linux-path /root/workspace/linux \
  --output-dir /root/workspace/linux-vuln-set-run-002 \
  --count 1 \
  --show-progress \
  --stop-on-error'
```

`--show-progress` 开启后，终端会显示类似普通 Codex 会话的线程、工具调用、命令输出、
重连和最终消息。按 `Ctrl-C` 会中断当前运行；已经写入磁盘的日志和证据通常仍会保留。
如果只想后台观察已写入的日志，可以使用：

```shell
tail -f /root/workspace/linux-vuln-set/PROCESS_LOG.md
tail -f /root/workspace/linux-vuln-set/candidates/candidate-007/agent-stderr.log
```

### 结果检查命令

进程正常退出不等于已经发现漏洞。应同时检查最终报告、过程日志、PoC 和 oracle 证据：

```shell
less /root/workspace/linux-vuln-set/PROCESS_LOG.md
less /root/workspace/linux-vuln-set/candidates/candidate-007/agent-final.md
less /root/workspace/linux-vuln-set/candidates/candidate-007/report.md
less /root/workspace/linux-vuln-set/candidates/candidate-007/REPRODUCE.md
find /root/workspace/linux-vuln-set/candidates/candidate-007 -maxdepth 2 -type f | sort
rg -n 'ATTACK_RESULT|ESCAPED|confined|inconclusive|negative|ERROR' \
  /root/workspace/linux-vuln-set/candidates/candidate-007
```

确认漏洞时，重点核对报告中的用户态入口、稳定 oracle、控制实验、重复运行结果和现实
影响评估；不能只根据模型的最终一句话或 CLI 的退出码判断。

### 修改平台代码后重新构建

如果修改了 `/root/workspace/codex` 中的 Rust 源码，需要重新构建后再运行；仅修改 Linux
源码时不需要重新构建 Codex：

```shell
cd /root/workspace/codex/codex-rs
cargo build --locked -p codex-cli --bin codex
```

使用 `--count 3` 可以运行 3 个相互独立的候选挖掘任务。使用以下命令查看结果：

```shell
less /root/workspace/linux-vuln-set/PROCESS_LOG.md
less /root/workspace/linux-vuln-set/candidates/candidate-001/agent-final.md
find /root/workspace/linux-vuln-set/candidates/candidate-001 -maxdepth 2 -type f
```

每个候选目录都会保存完整 prompt、执行命令、原始 JSONL/stderr 日志、最终报告、PoC、证据和复现指南。关于自定义 API 地址、沙箱选项、focus/commit 筛选和输出目录结构，请参阅[完整操作指南](./docs/kernel-vuln-hunt.md)。

## 文档

- [Linux 内核漏洞挖掘操作指南](./docs/kernel-vuln-hunt.md)
- [按 CWE 整理的 CVE 规则索引](./docs/kernel-cve-cwe-index.md)
- [结构化 CVE 规则知识库](./KERNEL_CVE_KNOWLEDGE.json)
- [平台开发与贡献说明](./docs/contributing.md)

本平台基于 Codex CLI 运行时；底层配置和模型接入方式可参考 [Codex 文档](https://developers.openai.com/codex)。

本仓库使用 [Apache-2.0 License](LICENSE)。
