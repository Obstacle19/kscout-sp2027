# KScout

**Paradigm-Guided Multi-Agent Coordination for Operating System Kernel Vulnerability Discovery**

KScout is a Linux kernel vulnerability research framework built on the Rust-based Codex agent harness. It coordinates peer agents through evidence-guided task allocation, independent source analysis, and cross-agent verification.

## Build

Install Rust through `rustup` and a native C/C++ build toolchain. The Rust version is pinned in `codex-rs/rust-toolchain.toml`.

```sh
cd codex-rs
cargo build --locked -p codex-cli --bin codex
cd ..
```

## Run

Provide a separate Linux kernel source checkout and credentials for a supported model backend:

```sh
export OPENAI_API_KEY='your-api-key'
export KSCOUT_MODEL='your-model-name'

./codex-rs/target/debug/codex kernel-vuln \
  --linux-path /path/to/linux \
  --output-dir ./runs/swarm \
  --model "$KSCOUT_MODEL" \
  --count 1 \
  --swarm --swarm-agents 3 --swarm-rounds 2 \
  --show-progress
```

Add `--dry-run` to generate prompts and commands without model calls. For a single-agent run, omit the swarm options. Run `./codex-rs/target/debug/codex kernel-vuln --help` for all options.

Use disposable VMs for kernel execution tests. The kernel checkout, VM images, credentials, and generated run outputs are supplied locally.

## Source

The KScout coordinator is implemented in [`codex-rs/cli/src/kernel_vuln*.rs`](codex-rs/cli/src/). The other crates provide the underlying agent runtime.

## License

Based on [OpenAI Codex](https://github.com/openai/codex). See [LICENSE](LICENSE) and [NOTICE](NOTICE) for licensing and attribution.
