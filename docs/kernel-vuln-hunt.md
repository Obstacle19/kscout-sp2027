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
  --count 1 \
  --show-progress
~~~

如果使用 DeepSeek API（例如当前环境把 key 放在 `DEEPSEEK_API_KEY`），请显式指定
环境变量、Responses API 地址和模型：

~~~sh
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
~~~

`--disable code_mode_host` 只关闭可选的 Code Mode 主机，不影响普通命令执行；如果
没有构建 `codex-code-mode-host`，建议保留它。DeepSeek 的 Codex 接入使用
`https://api.deepseek.com` 的 Responses API。

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
- count：模型审查总上限，范围是 1 到 100。关闭规则时表示开放式自主搜索次数；启用规则时表示定向规则组审查次数。
- `--use-cve-rules`：可选开关，默认关闭。启用后使用知识库定向审查代替开放式自主搜索；同一规则家族下的相关源码位置合并到一次审查中。
- `--cve-rule CVE-ID`：只选择指定 CVE 派生的活动规则，并自动启用规则模式。可重复传入多个 CVE ID；未知 CVE 会报错。
- model：可选，传给每个子进程的模型名；省略时继承 `~/.codex/config.toml` 的 `model`。
- focus：优先审计的子系统、目录或主题，例如 fs、net 或 fs/ntfs3。在规则模式下，它会按规则声明的子系统范围筛选规则；与 `--cve-rule` 同用时，两者必须匹配。
- commit：优先检查的 commit 或 revision。
- api-key-env：外部 API key 所在的环境变量名。
- api-base-url：可选的 OpenAI-compatible Responses API 地址。
- sandbox：默认是 workspace-write；可选 read-only 或 danger-full-access。
- dangerously-bypass-approvals-and-sandbox：只建议在隔离研究虚拟机中使用。
- show-progress：实时显示子进程的 Codex 风格进度、命令、命令输出和最终消息；也可写成 verbose。
- dry-run：只生成 prompt 和执行命令，不调用模型。
- stop-on-error：某一候选失败时立即停止后续候选。

## 可选的 CVE 派生规则筛选

`--use-cve-rules` 默认关闭。关闭时，`--count` 个子进程执行开放式自主搜索。启用时，`--count` 变成定向审查总预算：同一 CVE 根因家族下的多个源码命中合并为一个审查包，不再另起开放式搜索子进程。若安全过滤后只剩一个规则家族，即使 `--count 3` 也只启动一个模型审查；若没有可审查命中，则只生成扫描报告、不调用模型。规则模式的工作量随可复用成因数量增长，而不是随每个相似函数重复增长：

~~~sh
/root/workspace/codex/codex-rs/target/debug/codex kernel-vuln \
  --use-cve-rules \
  --count 10 \
  --linux-path /root/workspace/linux \
  --output-dir /root/workspace/linux-vuln-set
~~~

当前知识库中的 20 条 CVE 均已登记为活动规则，覆盖 CWE-125、1284、190、281、282、362、415、416、664、665、680 和 787。规则和 CWE 的完整对应关系、修复提交、危险条件及验证状态以 [KERNEL_CVE_KNOWLEDGE.json](../KERNEL_CVE_KNOWLEDGE.json) 为准；快速查阅见 [按 CWE 整理的 CVE 索引](kernel-cve-cwe-index.md)。规则覆盖 NTFS3、OverlayFS、FUSE、io_uring、pipe、net/9p、netfilter、packet、sched、IPv4 和 TLS 等源码范围；少数通用规则会扫描上层目录以寻找同类数据流。

所有规则都用修复前签名样例和修复后控制形态回放。C 解析失败会出现在扫描报告中，作为覆盖缺口处理；不能解析的文件不会被当成安全。自动过滤只识别经过核实的精确安全形态，其他命中交由一个规则家族级模型审查。

按子系统扫描该范围内的全部活动规则，例如只查 `net/sched`，不会扫描 `fs/ntfs3`：

~~~sh
/root/workspace/codex/codex-rs/target/debug/codex kernel-vuln \
  --use-cve-rules \
  --focus net/sched \
  --linux-path /root/workspace/linux \
  --output-dir /root/workspace/linux-vuln-net-sched \
  --count 1
~~~

按 CVE 精确选择规则时，不需要再写 `--use-cve-rules`；重复参数可选择多个活动 CVE 规则：

~~~sh
/root/workspace/codex/codex-rs/target/debug/codex kernel-vuln \
  --cve-rule CVE-2022-0847 \
  --linux-path /root/workspace/linux \
  --output-dir /root/workspace/linux-vuln-cve-2022-0847 \
  --count 1
~~~

若同时传入 `--use-cve-rules` 和一个或多个 `--cve-rule`，CVE 参数会从活动规则中进一步缩小范围；`--focus` 还可以再按子系统限定。例如 `--focus net/sched` 会选择其中登记的所有活动规则，`--cve-rule` 则能从中精确选取单条或多条。

### 2022—2026 年高严重性 CVE 知识库

仓库中的 [结构化知识库](../KERNEL_CVE_KNOWLEDGE.json) 收录 20 条 Linux 内核历史 CVE，按修复根因的主 CWE 归档；年份按 CVE 编号年份计算。收录门槛是至少一个注明来源的 CVSS v3.x 评分达到 7.0，评分来源不一致时会同时保留。CVE 记录原有的 CWE 映射和人工按补丁根因选出的主 CWE 分开保存，避免把影响结果（例如越界写）误当成唯一根因。

| 主 CWE | 数量 | CVE |
| --- | ---: | --- |
| CWE-125 越界读 | 1 | CVE-2023-52640 |
| CWE-1284 输入数量验证不当 | 1 | CVE-2024-50246 |
| CWE-190 整数溢出或回绕 | 1 | CVE-2025-38193 |
| CWE-281 权限未正确保留 | 1 | CVE-2026-53266 |
| CWE-282 所有权管理不当 | 1 | CVE-2023-0386 |
| CWE-362 共享资源同步竞争 | 1 | CVE-2026-74582 |
| CWE-415 重复释放 | 2 | CVE-2024-1086、CVE-2026-43249 |
| CWE-416 释放后使用 | 7 | CVE-2022-29582、CVE-2022-32250、CVE-2022-3910、CVE-2023-32233、CVE-2024-26739、CVE-2025-68817、CVE-2026-53381 |
| CWE-664 资源生命周期控制不当 | 1 | CVE-2025-21926 |
| CWE-665 初始化不当 | 1 | CVE-2022-0847 |
| CWE-680 整数溢出导致缓冲区溢出 | 1 | CVE-2023-0179 |
| CWE-787 越界写 | 2 | CVE-2024-0646、CVE-2026-53366 |

本次按论文中“从修复提炼触发条件与安全不变量、按 CWE 家族整理”的思路保存证据字段；没有照搬其扫描流程或效果结论。知识库 20 条 CVE 现在全部是活动规则，其中新增 17 条均实现了确定性命中枚举与保守安全过滤，并按主 CWE 归档。每条规则仍按其修复中核实的成因单独实现；同一 CWE 下的案例不会自动合并成一种检测器。修复前签名与修复后控制样例的回放验证，不等同于对 Linux 全树召回率的测量。

知识库对 `alloc_size` 规则区分三类情况：非稀疏属性的卷大小检查、允许超过卷大小的稀疏首段，以及 32 位 cluster 配置下尚未确认的稀疏 VCN 表示边界。已记录的 64 GiB 格式一致稀疏控制不能仅因超过卷大小而报错；candidate-005 的边界行为仍标为“可能”，触发范围的格式有效性尚未证实。

每轮会生成单独的 `rule-scan-<UTC 时间>.md`，记录源码快照、扫描文件数、所有规则命中、过滤结果、无匹配规则和解析覆盖缺口。扫描器按已选规则登记的源码范围遍历 C 源文件和头文件，在函数体中匹配补丁提炼出的危险使用模式；历史修复的文件名和函数名只作为来源信息，不限制扫描位置。规则候选先按与漏洞成因的结构接近程度排序，再按文件、行号和规则 ID 稳定排序；排序只决定审查优先级，不代表漏洞结论。同一规则家族的相关命中合并为一个审查包，避免为相同验证入口和数据流重复启动模型。规则审查仍沿用当前 PoC、控制实验、源码只读和证据目录要求。规则来源 CVE 用于表达根因条件、安全不变量和验证合同；同一 CVE 的原始漏洞不能作为新发现提交。

每条规则的知识记录分开保存已核实事实、已验证安全情况、未决假设和聚焦检查步骤；每个模型任务只收到命中规则家族的记录，不会重复携带整个规则库。目标 revision、保护条件和数据路径未变时，模型复用已核实的源码追踪与控制结果；只有出现变化或疑似绕过时才检查对应差异。安全负例可以省掉重复验证，除非代码或输入格式变化；未决假设不能当作确认漏洞或新发现。

当前解析器是有限范围的 C 词法解析器：忽略注释和字符串，枚举可识别的顶层函数定义并报告行号；它不展开宏、不计算 Kconfig 条件、不证明一般 C 数据流或控制流。解析失败会记为覆盖缺口，扫描器不会把它当成安全。过滤器只识别与已核实修复一致的严格安全形态；不同写法、复杂控制流、条件编译或无法追踪的别名都会保留给模型审查。规则命中本身不证明有漏洞，agent 仍须检查输入可控性、数据流、安全不变量，并按主研究合同执行 PoC、控制实验和证据记录。此次全树 dry-run 扫描 2,791 个 C/H 文件、解析 2,786 个，记录 5 个解析缺口；发现 21 个位置，9 个被严格过滤、12 个保留并归并为 3 个规则组，10 条规则无匹配位置。无匹配不代表安全；无法解析的文件同样是覆盖未知。该扫描没有测量全内核召回率或确认新漏洞。

初始两条规则阶段曾将各自修复提交的父版本目标文件放入隔离临时树回放，解析器解析 2/2 个文件并命中两种修复前危险形态，两个命中都保留审查。该阶段对 `fs/ntfs3` 的扫描结果和人工误报抽查作为历史基线保留；扩库后的当前全树扫描统计见本节解析器说明和知识库 `activation_validation`。过滤测试覆盖错误比较、嵌套条件、switch、绕过检查的 goto/标签、被改写的长度别名、注释/字符串及条件编译中的检查；这些形式不会触发安全过滤。

### CVE-2025-38193 单规则试点

规则扩库前的 `net-sched-perturb-period` 单规则试点先用原始修复提交 `7ca52541c05c832d32b112274f81a985101f9ba8` 的父版本回放：解析 `sch_sfq.c` 1/1，找到并保留 1 个修复前候选。当前全树统计已更新为上面的 20 规则 dry-run 结果；本段 `net/sched` 局部扫描指标保留为该试点的历史记录。

模型最初将唯一候选组判为 negative，理由是单个回调频率有上限。后续在 QEMU/KVM 的 32 位 HZ=1000 访客机中，用同一配置对比 1000 个 flow filter：有效控制 perturb=1 的两次 5 秒样本分别消耗 39、40 个宿主 CPU tick；当前未修复候选 perturb=2147484 的两次样本消耗 249、243 tick。临时加入 INT_MAX/HZ 前置检查的保护版，对同一高值请求返回 EINVAL。该结果表明规则保留了有价值的资源放大线索，并暴露出模型忽略多对象聚合影响；仍不能据此确认新 CVE，因为只测了一个隔离虚拟机配置，尚未验证非特权 user namespace 可达性、原生多租户宿主影响、其他 HZ 及 64 位回绕成短周期的路径。没有把 cls_flow 命中自动过滤。扫描报告、PoC、对照和访客机日志保存在 /root/workspace/linux-vuln-cve-2025-38193-rule/。

漏报风险也仍然存在：候选枚举依赖当前识别的字段名、解码函数和局部使用形态；宏封装、别名、跨函数数据流及不同实现形式可能漏掉。解析器不展开宏或 Kconfig 条件，因此“26/26 可解析”表示词法/函数提取成功，不等于完整 C 语义覆盖。后续新增规则仍须逐条完成修复前回放、确定性命中枚举、安全过滤负例评估和候选审查；不能把这 20 条历史案例或当前一次扫描当作扫描器召回率或新漏洞发现能力的验证。

## 输出结构

~~~text
linux-vuln-set/
├── README.md
├── PROMPT_TEMPLATE.md
├── FINDING_INDEX.md
├── PROCESS_LOG.md
├── USAGE.jsonl
├── rule-scan-<UTC 时间>.md （仅 `--use-cve-rules`）
├── source-status-before.txt
├── source-status-after.txt
└── candidates/
    ├── candidate-001/
    │   ├── prompt.md
    │   ├── finding-fingerprint.md
    │   ├── usage.json
    │   ├── command.txt
    │   ├── run-metadata.md
    │   ├── agent-events.jsonl
    │   ├── agent-stderr.log
    │   ├── agent-final.md
    │   └── 模型生成的报告、PoC、证据和复现指南
    └── candidate-002/
~~~

PROCESS_LOG.md 记录编排器的启动参数、每个候选的开始和结束状态、失败信息以及源码前后状态。每个 candidate-NNN 目录下的 prompt.md 是该轮实际发送给模型的完整提示词，agent-events.jsonl 和 agent-stderr.log 是原始运行日志。

每个实际启动的候选会把墙钟耗时、子进程结果、发现状态和可用 token usage 写入自己的
usage.json，并以一行 JSON 追加到输出根目录的 USAGE.jsonl。PROCESS_LOG.md 会记录本轮每个
候选的指标和整轮汇总。usage_status 为 unavailable 时表示模型事件没有报告用量；为 partial
时表示至少有 turn 用量缺失或失败，token 值是最近一次已报告的累计值，可能不包含缺失 turn。
原始 turn.completed usage 仍保留在 agent-events.jsonl 中。dry-run 不调用模型，因此不会写入 usage 记录。
候选 token 数取自最后一个报告用量的 turn 事件中的线程累计值，不会把各 turn 的累计值重复相加。

如果 output-dir 已经存在，工具会跳过已存在的 candidate-NNN 目录，不覆盖旧证据。每轮
运行会从现有 candidate 的 finding-fingerprint.md 重建 FINDING_INDEX.md；旧 candidate
没有该文件时，会读取 agent-final.md 或 report.md。后续候选会将索引用于排除相同根因，
并在自己的目录里写 finding-fingerprint.md，供同一 output-dir 后续运行使用。

去重依赖模型比较根因、触发路径和 oracle，不能保证语义上的绝对零重复。若改用新的
output-dir，索引从空目录开始，不包含旧目录的排除记录。

## 研究约束

内置 prompt 强制要求：

1. 只选择有明确、稳定用户态 oracle 的问题，排除硬件依赖和仅 KASAN 报告。
2. 不使用 syzkaller 或通用模糊测试。
3. 可以审计上游 commit，但不得把已修复漏洞、公开 PoC 或已有复现直接当作发现结果。
4. 必须提供用户态 PoC、完整命令、控制实验和现实影响评估。
5. 默认不修改 Linux 源码，使用 out-of-tree 构建和候选目录。
6. 找不到稳定候选时必须报告 negative 或 inconclusive，而不是编造漏洞。

子代理不会把 output-dir 之外的既有研究目录、旧 PoC、审查记录或外部漏洞数据库作为
发现证据；如果这些材料可见，只能用来排除候选，不能复制或改写成新结果。FINDING_INDEX.md
只用于检查同一 output-dir 中已经处理过的候选是否重复，不可用作发现证据。

默认 workspace-write 沙箱把 candidate-NNN 作为子代理工作目录，并把 output-dir 和
candidate-NNN 作为可写证据目录；Linux 源码目录只作为显式读取目标，不加入可写根，
因此模型可以保存 PoC 和日志而不会改写源码。不能使用 `--sandbox read-only`，因为
子代理无法保存证据；若实验确实需要 QEMU、挂载或其他超出沙箱的操作，使用
dangerously-bypass 之前应先确认当前环境是专用隔离实验环境。

## 实时观察子进程

默认情况下，编排器会等待候选子进程结束后再把完整事件写入 agent-events.jsonl。
如果希望像普通 Codex 会话一样观察实时进度，增加：

~~~sh
--show-progress
~~~

也可以使用别名 --verbose。该选项会在终端显示命令、命令输出、工具调用、思考摘要
和最终消息，同时仍保存完整的 agent-events.jsonl 与 agent-stderr.log。不加该选项
则保持安静模式，适合脚本或只查看最终证据。

## 与已有 codex exec 的关系

kernel-vuln 是编排层，不重新实现模型协议。它为每个候选启动一次当前 CLI 的 codex exec 子命令，因此现有模型、配置、认证、Responses API、JSONL 事件和沙箱能力继续复用。子进程按顺序运行，便于控制成本、隔离日志和定位某一轮的行为。
