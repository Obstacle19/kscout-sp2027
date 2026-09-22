# Linux 内核漏洞挖掘模式

本仓库新增了一个独立的 CLI 子命令：

~~~text
codex kernel-vuln
~~~

它把一次 Linux 内核漏洞挖掘任务拆成多个相互隔离的非交互 Codex exec 子进程。每个子进程只负责一个候选问题，并在独立目录中保存 prompt、JSONL 事件、stderr、最终回答以及模型创建的 PoC、证据和操作指南。

## 构建

在仓库的 Rust workspace 中执行：

~~~sh
cd /root/workspace/codex/codex-rs
cargo fmt --all
cargo build -p codex-cli --bin codex
~~~

如果仓库完整的 `just fmt` 工具链（例如 `dotslash`、`uv`）已经安装，也可以用
`just fmt` 做全仓库格式化。

生成的开发版二进制通常是：

~~~text
/root/workspace/codex/codex-rs/target/debug/codex
~~~

## 最小用法

API key 不作为命令行参数传入，而是从环境变量读取。默认读取 OPENAI_API_KEY，随后只在子进程环境中映射为 CODEX_API_KEY；key 的值不会写入 argv、PROCESS_LOG.md 或 command.txt。

~~~sh
export OPENAI_API_KEY='your-api-key'

/root/workspace/codex/codex-rs/target/debug/codex kernel-vuln \
  --linux-path /root/workspace/linux \
  --output-dir /root/workspace/linux-vuln-set \
  --count 1
~~~

上面的命令省略了 `--model`，因此每个子进程会继承 `~/.codex/config.toml`
中的 `model` 配置。`your-model` 只是占位符，不能原样输入。需要覆盖时，
使用服务商实际支持的模型 ID，例如 `--model <实际模型名>`。可以先查看当前
默认配置：

~~~sh
grep -n '^model' /root/.codex/config.toml
~~~

挖掘多个独立候选：

~~~sh
/root/workspace/codex/codex-rs/target/debug/codex kernel-vuln \
  --linux-path /root/workspace/linux \
  --output-dir /root/workspace/linux-vuln-set \
  --count 3
~~~

如果 API key 放在其他变量中：

~~~sh
export MY_LLM_KEY='your-api-key'

/root/workspace/codex/codex-rs/target/debug/codex kernel-vuln \
  --api-key-env MY_LLM_KEY \
  --api-base-url https://api.example.com/v1 \
  --linux-path /root/workspace/linux \
  --output-dir /root/workspace/linux-vuln-set
~~~

api-base-url 必须兼容 OpenAI Responses API。若没有外部 API key 但希望使用已经保存的 Codex 登录凭据，可以显式增加：

~~~text
--allow-stored-auth
~~~

## 常用参数

- linux-path：待审计的 Linux 源码目录，默认是 /root/workspace/linux。
- output-dir：所有证据和候选目录的根目录，默认是 ./linux-vuln-set。
- count：顺序执行的独立候选数，范围是 1 到 100。
- model：可选，传给每个子进程的模型名；省略时继承 `~/.codex/config.toml` 的 `model`。
- focus：优先审计的子系统、目录或主题，例如 fs、net 或 fs/ntfs3。
- commit：优先检查的 commit 或 revision。
- api-key-env：外部 API key 所在的环境变量名。
- api-base-url：可选的 OpenAI-compatible Responses API 地址。
- sandbox：默认是 read-only；可选 workspace-write 或 danger-full-access。
- dangerously-bypass-approvals-and-sandbox：只建议在隔离研究虚拟机中使用。
- dry-run：只生成 prompt 和执行命令，不调用模型。
- stop-on-error：某一候选失败时立即停止后续候选。

## 输出结构

~~~text
linux-vuln-set/
├── README.md
├── PROMPT_TEMPLATE.md
├── PROCESS_LOG.md
├── source-status-before.txt
├── source-status-after.txt
└── candidates/
    ├── candidate-001/
    │   ├── prompt.md
    │   ├── command.txt
    │   ├── run-metadata.md
    │   ├── agent-events.jsonl
    │   ├── agent-stderr.log
    │   ├── agent-final.md
    │   └── 模型生成的报告、PoC、证据和复现指南
    └── candidate-002/
~~~

PROCESS_LOG.md 记录编排器的启动参数、每个候选的开始和结束状态、失败信息以及源码前后状态。每个 candidate-NNN 目录下的 prompt.md 是该轮实际发送给模型的完整提示词，agent-events.jsonl 和 agent-stderr.log 是原始运行日志。

如果 output-dir 已经存在，工具会跳过已存在的 candidate-NNN 目录，不覆盖旧证据。

## 研究约束

内置 prompt 强制要求：

1. 只选择有明确、稳定用户态 oracle 的问题，排除硬件依赖和仅 KASAN 报告。
2. 不使用 syzkaller 或通用模糊测试。
3. 可以审计上游 commit，但不得把已修复漏洞、公开 PoC 或已有复现直接当作发现结果。
4. 必须提供用户态 PoC、完整命令、控制实验和现实影响评估。
5. 默认不修改 Linux 源码，使用 out-of-tree 构建和候选目录。
6. 找不到稳定候选时必须报告 negative 或 inconclusive，而不是编造漏洞。

默认 read-only 沙箱保护内核源码，output-dir 和 candidate-NNN 会通过 add-dir 授予写权限。若实验确实需要 QEMU、挂载或其他超出沙箱的操作，使用 dangerously-bypass 之前应先确认当前环境是专用隔离实验环境。

## 与已有 codex exec 的关系

kernel-vuln 是编排层，不重新实现模型协议。它为每个候选启动一次当前 CLI 的 codex exec 子命令，因此现有模型、配置、认证、Responses API、JSONL 事件和沙箱能力继续复用。子进程按顺序运行，便于控制成本、隔离日志和定位某一轮的行为。
