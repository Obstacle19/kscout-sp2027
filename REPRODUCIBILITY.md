# Running KScout experiments

This guide describes how to build, exercise, and inspect the implementation. Live discovery requires a model backend, a kernel checkout, and a suitable execution environment. Findings and resource usage depend on these inputs; the commands below are not an automated reproduction of the paper's result tables.

## Prepare the environment

Build the local CLI as described in the [README](README.md#build). Keep the kernel checkout outside the run output directory. Install the kernel's build dependencies and provision a disposable VM before attempting execution-based validation. VM images, kernel configurations, credentials, and original experimental run records are not distributed here.

For a controlled comparison, record:

- The KScout source version and the exact kernel commit, including any local kernel changes.
- The model identifier, provider endpoint, model configuration, and additional prompts.
- The audit focus, agent population, round limit, and policy version.
- The kernel configuration, architecture, VM resources, root filesystem, and caller privileges.
- The run budget, repetitions, timing convention, and criteria for accepting and deduplicating findings.

Check the selected kernel revision before each run:

```sh
git -C /path/to/linux rev-parse HEAD
git -C /path/to/linux status --short
```

Check out the desired revision yourself. `--commit REV` adds a research priority to the prompt; it does not change the source checkout.

## Smoke checks without model calls

The following commands exercise both entry points without model credentials:

```sh
./codex-rs/target/debug/codex kernel-vuln --help

./codex-rs/target/debug/codex kernel-vuln \
  --linux-path /path/to/linux \
  --output-dir ./runs/smoke-single \
  --count 1 \
  --dry-run

./codex-rs/target/debug/codex kernel-vuln \
  --linux-path /path/to/linux \
  --output-dir ./runs/smoke-swarm \
  --count 1 \
  --swarm --swarm-agents 3 --swarm-rounds 2 \
  --dry-run
```

Inspect the run log and generated prompts and commands under each output directory. A dry run checks preparation only: it does not establish model connectivity, VM readiness, or vulnerability detection quality.

The existing coordinator tests can be selected through the repository's test helper. Install `just` and `cargo-nextest` if needed, then run from the repository root:

```sh
just test -p codex-cli -E 'test(kernel_vuln)'
```

## Run the comparison modes

With `OPENAI_API_KEY` and `KSCOUT_MODEL` configured locally, a single-agent pass is:

```sh
./codex-rs/target/debug/codex kernel-vuln \
  --linux-path /path/to/linux \
  --output-dir ./runs/single \
  --model "$KSCOUT_MODEL" \
  --count 1 \
  --show-progress
```

A peer swarm uses the same kernel and model:

```sh
./codex-rs/target/debug/codex kernel-vuln \
  --linux-path /path/to/linux \
  --output-dir ./runs/swarm \
  --model "$KSCOUT_MODEL" \
  --count 1 \
  --swarm --swarm-agents 3 --swarm-rounds 2 \
  --show-progress
```

Use separate directories for different modes and repetitions. Reusing a directory continues candidate numbering and incorporates earlier summaries into the finding index; it is not a fresh independent run. Supply an identical `--focus` or `--extra-prompt-file` to both modes when restricting scope.

The example swarm can launch up to six sessions, while the single-agent example launches one. These commands demonstrate the modes; they do not impose equal token or tool-time budgets. Define and enforce the comparison budget separately, retain failed attempts, and compare findings after root-cause deduplication and evidence review.

The optional `--prior-finding-index PATH` imports an earlier index or an output directory. Its summaries are for duplicate exclusion, not discovery evidence. Use the same prior information for conditions that are intended to be comparable.

## Inspect a completed run

Start with `PROCESS_LOG.md` and `USAGE.jsonl`, then inspect each candidate's reports, `finding-fingerprint.md`, and evidence files. In swarm mode, also inspect the coordinator's `candidate-report.md`, `SWARM_INDEX.json`, `SWARM_EVENTS.jsonl`, participant workspaces, and archived submissions under `findings/`.

Assess two questions separately:

1. **Reproduction:** do the recorded commands, kernel conditions, positive oracle, negative controls, and independent repeats support the reported behavior?
2. **Security impact:** under what realistic privileges and preconditions does the behavior cross a security boundary or affect a protected asset?

Keep negative and inconclusive results. Model-reported `confirmed` is an input to review, not an independently verified security verdict. The [swarm workflow](SWARM_WORKFLOW.md) explains the separate reproduction, runner, reportability, and security states.

Usage records contain the token fields returned by the model backend. Missing usage is not zero cost. Keep the source logs and document the aggregation method when reporting cost, elapsed time, or yield.

## Scratch files and persistent evidence

Reports, PoC source, exact commands, execution logs, and finding archives belong in persistent candidate or participant directories. Temporary source copies, kernel build trees, VM disks, and caches belong in each workspace's `scratch/` directory.

KScout normally cleans scratch after a pass or after successful swarm archival. Failed archival preserves the affected scratch directory. Use `--keep-workspace` when retaining the environment is necessary for debugging. Review `workspace-cleanup.md` and the run log to check what was retained.

The sandbox does not supply a kernel test VM. Use disposable guest environments for disruptive PoCs. The `--dangerously-bypass-approvals-and-sandbox` option disables the harness protections and is not needed for the smoke checks.

## Optional CVE-derived rule reviews

Rule mode is disabled by default. It selects candidate source locations from curated signatures and asks the model to review grouped rule families:

```sh
./codex-rs/target/debug/codex kernel-vuln \
  --linux-path /path/to/linux \
  --output-dir ./runs/rules-smoke \
  --use-cve-rules \
  --focus net/sched \
  --count 1 \
  --dry-run
```

Use `--cve-rule CVE-ID` to select a specific entry; the option is repeatable and also enables rule mode. See the [rule index](docs/kernel-cve-cwe-index.md) and [knowledge file](KERNEL_CVE_KNOWLEDGE.json). A signature match is a review lead, and a missing match does not prove safety. This optional mode is separate from open-ended peer swarm discovery.
