# KScout

**Paradigm-Guided Multi-Agent Coordination for Operating System Kernel Vulnerability Discovery**

KScout is a research framework for Linux kernel vulnerability discovery. It extends the Rust-based Codex agent harness with a coordinator that launches analysis sessions, assigns follow-up tasks, and preserves source analysis and execution evidence.

The framework implements three collaboration paradigms:

- **Evidence-guided task allocation:** distribute agents between new searches and follow-up checks according to evidence gaps, progress, and cost.
- **Evidence-grounded vulnerability analysis:** require independent source analysis, explicit claims, targeted checks, and traceable evidence.
- **Cross-agent finding verification:** retain each participant's submissions and assess reproduction and security impact separately.

Agents are peers without fixed investigative roles. KScout also supports a single-agent baseline and an optional CVE-derived rule mode.

## Requirements

- A Linux research environment with Git, a native C/C++ build toolchain, and Rust installed through `rustup`. The Rust version is pinned in [rust-toolchain.toml](codex-rs/rust-toolchain.toml).
- A separate Linux kernel source checkout. Kernel source, kernel build outputs, and VM images are not included in this repository.
- For live analysis, access to a model backend supported by the bundled harness. Custom endpoints must support the Responses API used by the harness.
- For kernel execution experiments, a disposable VM and the build tools required by the selected kernel configuration. The repository does not provision a VM automatically.

Building the CLI downloads its locked dependencies and may download native runtime components. The offline smoke check below needs no model credentials after the CLI has been built.

## Quick start

Run these commands from the repository root. Always supply `--linux-path` explicitly.

### Build

```sh
cd codex-rs
cargo build --locked -p codex-cli --bin codex
cd ..
```

The executable is `codex-rs/target/debug/codex`. Use this locally built executable for the KScout commands.

### Check the workflow without calling a model

Replace `/path/to/linux` with an existing kernel source checkout:

```sh
./codex-rs/target/debug/codex kernel-vuln \
  --linux-path /path/to/linux \
  --output-dir ./runs/smoke \
  --count 1 \
  --swarm \
  --swarm-agents 3 \
  --swarm-rounds 2 \
  --dry-run
```

This prepares the run directories, prompts, and child commands without launching model sessions. Inspect `runs/smoke/PROCESS_LOG.md` and the files under `runs/smoke/candidates/`.

### Run a peer swarm

Set the API key and model in your local environment:

```sh
export OPENAI_API_KEY='your-api-key'
export KSCOUT_MODEL='your-model-name'

./codex-rs/target/debug/codex kernel-vuln \
  --linux-path /path/to/linux \
  --output-dir ./runs/swarm \
  --model "$KSCOUT_MODEL" \
  --count 1 \
  --swarm \
  --swarm-agents 3 \
  --swarm-rounds 2 \
  --show-progress
```

For another supported provider, set its key in an environment variable and add `--api-key-env PROVIDER_API_KEY --api-base-url https://api.example.com/v1`. The key itself is passed through the child environment, not through command-line arguments.

To run the single-agent baseline, omit `--swarm`, `--swarm-agents`, and `--swarm-rounds`, and use a separate output directory.

## Main options

| Option | Purpose |
| --- | --- |
| `--linux-path PATH` | Kernel source tree to analyze. |
| `--output-dir DIR` | Persistent reports, evidence, and run records. |
| `--count N` | Number of single-agent passes or swarm groups; in rule mode, the maximum number of grouped rule reviews. |
| `--swarm` | Enable peer collaboration; `--multi-agent` is a compatibility alias. |
| `--swarm-agents N` | Maximum concurrent peers per round, from 2 to 16; default: 3. |
| `--swarm-rounds N` | Maximum rounds per group, from 1 to 4; default: 2. |
| `--focus TEXT` | Prioritize a subsystem, directory, or topic. |
| `--commit REV` | Ask agents to prioritize a revision; this does not check out that revision. |
| `--prior-finding-index PATH` | Import an earlier finding index for duplicate exclusion; repeatable. |
| `--swarm-norms PATH` | Load a frozen, versioned collaboration policy. |
| `--swarm-verifier EXECUTABLE` | Use an external verifier implementing the JSON protocol. |
| `--model NAME` | Select the model for child sessions. |
| `--show-progress` | Stream child progress while retaining raw logs. |
| `--dry-run` | Generate run artifacts without model calls. |
| `--keep-workspace` | Retain temporary `scratch/` directories for investigation. |

The requested swarm session budget, `count × swarm-agents × swarm-rounds`, is limited to 64 sessions per run. Dynamic scheduling and early termination can reduce the number actually launched. `--count` is a workload setting, not an expected number of bugs. See `codex kernel-vuln --help` for all options.

## Results and evidence

Each output directory contains:

| Path | Contents |
| --- | --- |
| `PROCESS_LOG.md` | Run timeline, scheduling decisions, and cleanup records. |
| `USAGE.jsonl` | Runtime and available model token usage. |
| `FINDING_INDEX.md` | Finding summaries used to exclude duplicate root causes. |
| `candidates/candidate-NNN/` | Candidate prompts, commands, reports, and fingerprints. |
| `candidates/candidate-NNN/SWARM_INDEX.json` | Structured lead and evidence states. |
| `candidates/candidate-NNN/SWARM_EVENTS.jsonl` | Structured interaction history. |
| `candidates/candidate-NNN/agents/` | Per-round, per-participant workspaces and logs. |
| `candidates/candidate-NNN/findings/` | Archived finding submissions and evidence. |

Agent-reported reproduction, cross-agent reproduction, external runner verification, and security confirmation are distinct states. A successful CLI exit or agreement between agents does not establish a vulnerability. Review the source reasoning, exact kernel revision and configuration, caller privileges, PoC, positive results, and negative controls.

The default child sandbox permits writes to the run workspace and keeps the supplied kernel tree outside its writable roots. Run potentially disruptive kernel tests inside a disposable VM. Reports and evidence are retained; temporary build trees and VM scratch files are cleaned after archival unless `--keep-workspace` is set.

## Code map

KScout's coordinator is implemented in [`codex-rs/cli/src/`](codex-rs/cli/src/):

| Component | Entry point |
| --- | --- |
| CLI and run orchestration | [kernel_vuln.rs](codex-rs/cli/src/kernel_vuln.rs) |
| Peer rounds and finding archival | [kernel_vuln_swarm.rs](codex-rs/cli/src/kernel_vuln_swarm.rs) |
| Evidence-guided task allocation | [kernel_vuln_swarm_planner.rs](codex-rs/cli/src/kernel_vuln_swarm_planner.rs) |
| Collaboration norms and policy | [kernel_vuln_swarm_norms.rs](codex-rs/cli/src/kernel_vuln_swarm_norms.rs), [kernel_vuln_swarm_policy.rs](codex-rs/cli/src/kernel_vuln_swarm_policy.rs) |
| Submission parsing and evidence checks | [kernel_vuln_swarm_protocol.rs](codex-rs/cli/src/kernel_vuln_swarm_protocol.rs) |
| Reproduction and independent assessment | [kernel_vuln_swarm_consensus.rs](codex-rs/cli/src/kernel_vuln_swarm_consensus.rs), [kernel_vuln_swarm_review.rs](codex-rs/cli/src/kernel_vuln_swarm_review.rs) |
| Child processes and artifact handling | [kernel_vuln_support.rs](codex-rs/cli/src/kernel_vuln_support.rs), [kernel_vuln_cleanup.rs](codex-rs/cli/src/kernel_vuln_cleanup.rs) |

The remaining Rust crates provide the underlying agent runtime. Supporting SDKs, build definitions, dependency patches, and third-party assets are retained for workspace tooling and compatibility.

## Documentation

- [Running experiments and inspecting results](REPRODUCIBILITY.md)
- [Swarm workflow, evidence states, and verifier protocol](SWARM_WORKFLOW.md)
- [Optional CVE-derived rule index](docs/kernel-cve-cwe-index.md)
- [Machine-readable rule knowledge](KERNEL_CVE_KNOWLEDGE.json)

This repository contains the implementation. Original experiment runs, the paper's result tables, and VM images are not bundled; the run instructions describe how to execute and inspect the framework.

## License and provenance

KScout is based on [OpenAI Codex](https://github.com/openai/codex). The repository is distributed under the [Apache License 2.0](LICENSE). Upstream attribution and third-party notices are preserved in [NOTICE](NOTICE) and the relevant dependency directories.
