<p align="center"><strong>Codex CLI</strong> is a coding agent from OpenAI that runs locally on your computer.
<p align="center">
  <img src="https://github.com/openai/codex/blob/main/.github/codex-cli-splash.png" alt="Codex CLI splash" width="80%" />
</p>
</br>
If you want Codex in your code editor (VS Code, Cursor, Windsurf), <a href="https://developers.openai.com/codex/ide">install in your IDE.</a>
</br>If you want the desktop app experience, run <code>codex app</code> or visit <a href="https://chatgpt.com/codex?app-landing-page=true">the Codex App page</a>.
</br>If you are looking for the <em>cloud-based agent</em> from OpenAI, <strong>Codex Web</strong>, go to <a href="https://chatgpt.com/codex">chatgpt.com/codex</a>.</p>

---

## Quickstart

### Installing and running Codex CLI

Run the following on Mac or Linux to install Codex CLI:

```shell
curl -fsSL https://chatgpt.com/codex/install.sh | sh
```

Run the following on Windows to install Codex CLI:

```shell
powershell -ExecutionPolicy ByPass -c "irm https://chatgpt.com/codex/install.ps1 | iex"
```

The standalone installers download from `https://releases.openai.com/codex` by default and fall back to GitHub Releases if a metadata or asset download is unavailable. To force GitHub Releases, set `CODEX_INSTALLER_USE_RELEASES_OPENAI_COM` to `false` (`0` and `no` are also accepted):

```shell
curl -fsSL https://chatgpt.com/codex/install.sh | CODEX_INSTALLER_USE_RELEASES_OPENAI_COM=false sh
```

```powershell
$env:CODEX_INSTALLER_USE_RELEASES_OPENAI_COM='false'; irm https://chatgpt.com/codex/install.ps1 | iex
```

Codex CLI can also be installed via the following package managers:

```shell
# Install using npm
npm install -g @openai/codex
```

```shell
# Install using Homebrew
brew install --cask codex
```

Then simply run `codex` to get started.

<details>
<summary>You can also go to the <a href="https://github.com/openai/codex/releases/latest">latest GitHub Release</a> and download the appropriate binary for your platform.</summary>

Each GitHub Release contains many executables, but in practice, you likely want one of these:

- macOS
  - Apple Silicon/arm64: `codex-aarch64-apple-darwin.tar.gz`
  - x86_64 (older Mac hardware): `codex-x86_64-apple-darwin.tar.gz`
- Linux
  - x86_64: `codex-x86_64-unknown-linux-musl.tar.gz`
  - arm64: `codex-aarch64-unknown-linux-musl.tar.gz`

Each archive contains a single entry with the platform baked into the name (e.g., `codex-x86_64-unknown-linux-musl`), so you likely want to rename it to `codex` after extracting it.

</details>

### Using Codex with your ChatGPT plan

Run `codex` and select **Sign in with ChatGPT**. We recommend signing into your ChatGPT account to use Codex as part of your Plus, Pro, Business, Edu, or Enterprise plan. [Learn more about what's included in your ChatGPT plan](https://help.openai.com/en/articles/11369540-codex-in-chatgpt).

You can also use Codex with an API key, but this requires [additional setup](https://developers.openai.com/codex/auth#sign-in-with-an-api-key).

### Linux 内核漏洞挖掘模式

本分支提供 `codex kernel-vuln`，用于进行确定性 Linux 内核漏洞挖掘。首先构建 CLI：

```shell
cd /root/workspace/codex/codex-rs
cargo build -p codex-cli --bin codex
```

先执行 dry-run，生成 prompt 和输出目录结构，但不会调用模型：

```shell
/root/workspace/codex/codex-rs/target/debug/codex kernel-vuln \
  --linux-path /root/workspace/linux \
  --output-dir /root/workspace/linux-vuln-set \
  --count 1 \
  --model test-model \
  --dry-run
```

通过环境变量设置 API key，然后开始实际挖掘。API key 不会出现在命令行参数或过程日志中：

```shell
export OPENAI_API_KEY='your-api-key'

/root/workspace/codex/codex-rs/target/debug/codex kernel-vuln \
  --linux-path /root/workspace/linux \
  --output-dir /root/workspace/linux-vuln-set \
  --count 1
```

这里省略 `--model` 表示继承 `~/.codex/config.toml` 中的 `model`。如果需要
覆盖模型，再添加 `--model <实际模型名>`；`your-model` 只是占位符，不能原样输入。

使用 `--count 3` 可以运行 3 个相互独立的候选挖掘任务。使用以下命令查看结果：

```shell
less /root/workspace/linux-vuln-set/PROCESS_LOG.md
less /root/workspace/linux-vuln-set/candidates/candidate-001/agent-final.md
find /root/workspace/linux-vuln-set/candidates/candidate-001 -maxdepth 2 -type f
```

每个候选目录都会保存完整 prompt、执行命令、原始 JSONL/stderr 日志、最终报告、PoC、证据和复现指南。关于自定义 API 地址、沙箱选项、focus/commit 筛选和输出目录结构，请参阅[完整操作指南](./KERNEL_VULN_HUNT.md)。

## Docs

- [**Codex Documentation**](https://developers.openai.com/codex)
- [**Contributing**](./docs/contributing.md)
- [**Installing & building**](./docs/install.md)
- [**Open source fund**](./docs/open-source-fund.md)
- [**Linux 内核漏洞挖掘模式**](./KERNEL_VULN_HUNT.md)

This repository is licensed under the [Apache-2.0 License](LICENSE).
