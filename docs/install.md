# Building KScout

Use the [build instructions in the repository README](../README.md#build) to build
this snapshot's CLI. The toolchain is pinned in
[`codex-rs/rust-toolchain.toml`](../codex-rs/rust-toolchain.toml), and dependency
versions are recorded in the workspace lockfile.

Run the locally built `codex-rs/target/debug/codex` executable for KScout's
`kernel-vuln` workflow. See [Running KScout experiments](../REPRODUCIBILITY.md) for
smoke checks, model configuration, kernel inputs, and result inspection.
