# 单 agent 与 swarm 简单对比

先做一组小实验：在同一份 Linux 源码、同一个子系统上，单 agent 和 swarm 各运行一次。这个结果适合初步比较，不足以证明哪种模式整体更好；如果结果有明显差异，再换几个子系统重复。

## 实验条件

- 两次运行使用同一个 Linux 源码 revision、模型、API 配置和 `--focus`。
- 示例目标使用 `net/sched`。`--focus` 表示优先审查该范围，不是硬性文件访问限制。
- 使用不同的输出目录，不传 `--prior-finding-index`，避免输出冲突和通过索引传递发现。同机同用户运行时，两个 agent 仍可能读取对方的文件；tmux 不提供文件隔离。
- 建议先运行一种模式，将其输出目录下载到运行环境之外并移走本机副本，再运行另一种模式。单纯使用两个 tmux 和不同输出目录不会隔离文件读取。
- `count=1` 表示各启动一个审计任务；swarm 任务最多使用 3 个 peer、2 轮，实际资源会多于单 agent。因此同时记录实际 token 和耗时，不把它说成等预算实验。

## 运行命令

先构建一次，并确保 `DEEPSEEK_API_KEY` 已在环境中设置。当前示例使用的 Linux revision 是 `c03c1a14507dfaf8b856c2608f9ac216021fc222`；先运行下面两条检查，revision 必须匹配，工作区状态应为空。两条审计命令之间不要更新或修改 Linux 源码树。

```sh
cd /root/workspace/kscout/codex-rs
cargo build -p codex-cli --bin codex
git -C /root/workspace/linux rev-parse HEAD
git -C /root/workspace/linux status --short
```

单 agent：

```sh
/root/workspace/kscout/codex-rs/target/debug/codex kernel-vuln \
  --linux-path /root/workspace/linux \
  --focus net/sched \
  --output-dir /root/workspace/kscout-single-vs-swarm/single \
  --count 1 \
  --api-key-env DEEPSEEK_API_KEY \
  --api-base-url https://api.deepseek.com \
  --model deepseek-flash \
  --disable code_mode_host \
  --show-progress \
  --stop-on-error
```

Swarm：

```sh
/root/workspace/kscout/codex-rs/target/debug/codex kernel-vuln \
  --linux-path /root/workspace/linux \
  --focus net/sched \
  --output-dir /root/workspace/kscout-single-vs-swarm/swarm \
  --count 1 \
  --swarm \
  --swarm-agents 3 \
  --swarm-rounds 2 \
  --api-key-env DEEPSEEK_API_KEY \
  --api-base-url https://api.deepseek.com \
  --model deepseek-flash \
  --disable code_mode_host \
  --show-progress \
  --stop-on-error
```

要换子系统时，两边同时把 `--focus net/sched` 改成相同目录，并使用新的输出目录。

## 比较结果

先检查两边的 `candidate-report.md`、PoC、复现步骤和正负对照，人工判断哪些是**有效且可报告的唯一安全漏洞**。`confirmed` 只表示相应复现状态，不能单独证明安全影响成立。

每种模式记录：

- 有效、唯一、可报告的漏洞数；误报数；尚未裁定数。
- 根级 `USAGE.jsonl` 中的总 token 和耗时。若 token usage 是 `partial` 或 `unavailable`，照实标记，不能按零计算。
- swarm 实际启动的 peer/session 数，以及总墙钟耗时。

误报率按已裁定的唯一候选计算：`(误报 + 非安全缺陷) / (有效安全漏洞 + 误报 + 非安全缺陷)`；未定候选单独列出。若某模式没有有效漏洞，每个漏洞的时间和 token 记为“不适用”。

本轮只做一次配对，结论应写成“在该子系统和本次预算下的观察”。要判断整体效果，再在其他子系统重复几次。
