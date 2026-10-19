# KScout peer swarm workflow

The optional **--swarm** mode runs an audit group as equal peer researchers. It keeps the existing Linux source-read-only, userland PoC, close-control, and evidence requirements. The mode is intended to let researchers challenge one another and branch into additional leads without imposing a finding count.

## 1. Parent process

1. Parse **--count**, Linux source, output directory, model/provider, and swarm options. **--count 1** schedules one swarm group.
2. Bound the run to at most 64 child sessions. Per-group limits are 2–8 agents and 1–4 rounds.
3. Allocate a candidate directory and write its run metadata, group manifest, and an initially empty SWARM_BOARD.md.
4. Start every agent in a round concurrently, each with an isolated workspace under agents/round-NN/agent-NN/.
5. After the round ends, collect each participant's SWARM_UPDATE.md, fingerprint, peer arguments, and final message onto the board. Board excerpts are bounded so later rounds do not inherit unbounded prompts.
6. Continue until the configured maximum rounds or until every participant explicitly reports Round status: quiescent.
7. Archive every complete confirmed or plausible finding submission under findings/, group repeated submissions by normalized title and root cause in the candidate report, update the duplicate index, and aggregate elapsed time and token usage.

There is no permanent reviewer. Participants rotate their source-audit lens between rounds and can discover, challenge, reproduce, reject, or branch from a lead.

## 2. Peer rounds

### Round 1: independent discovery

All peers start without prior swarm claims. Each picks audit directions, traces source and history, and records any leads and evidence in its own workspace. It can submit multiple distinct findings using findings/<stable-lead-id>/.

### Later rounds: argument and branching

All peers receive the prior SWARM_BOARD.md and can read earlier workspaces. Each participant should state which leads it accepts, rejects, or cannot resolve, cite the commands and evidence, and independently reproduce leads before treating them as confirmed. It can also start a new branch or ask peers to take a follow-up task in SWARM_UPDATE.md.

The orchestrator waits for all sessions in a round before updating the board. Peers exchange arguments between rounds, not as a live shared chat while the current round is running.

### Stop condition

A round is quiescent only when every participant explicitly writes Round status: quiescent in SWARM_UPDATE.md. A missing or active status causes the next round to run, up to --swarm-rounds.

## 3. Evidence and finding status

Each agent keeps its complete artifacts in its own workspace. A promoted finding has a separate archive directory containing its report and fingerprint; source workspaces retain the full event stream, PoC, raw logs, and other experiments. SWARM_EVIDENCE_SOURCE.md links the archive back to that original evidence.

Repeated reports with matching normalized Title and Root cause/invariant are presented as one logical finding in candidate-report.md. Their separate submissions remain in findings/ for auditability. The generated FINDING_INDEX.md includes archived findings and avoids repeating exact normalized title/root-cause pairs.

The coordinator leaves a finding confirmed only when at least two different participants submitted a matching title and root cause as confirmed; otherwise it downgrades that submission to plausible. This is a deterministic text-level gate. It does not establish that the PoC, controls, or matching root-cause descriptions are semantically sound. Review the underlying evidence, especially when peers disagree or paraphrase the same issue differently.

## 4. Cost and use

Use --swarm-agents and --swarm-rounds to set the group size and maximum debate depth. A default count=1 run schedules up to 3 agents × 2 rounds = 6 child sessions. Agents in a round run concurrently; rounds run in sequence so later participants can use earlier arguments. Token use grows with child sessions, and debate rounds add wall-clock time. Early quiescence can skip later rounds.

Example:

~~~sh
codex kernel-vuln \
  --linux-path /root/workspace/linux \
  --output-dir /root/workspace/kscout-mutiagent-workdir/swarm-run \
  --count 1 \
  --swarm \
  --swarm-agents 3 \
  --swarm-rounds 2 \
  --show-progress
~~~

--multi-agent remains an alias for --swarm. Use a fresh output directory for an independent experiment so its duplicate exclusion index starts empty.

## 5. Validation performed for this implementation

The coordinator test uses a local mock child executable to run 2 agents for 2 rounds. It verifies that:
- all four child sessions run and receive individual usage records;
- round 2 can read round 1's argument board;
- 16 positive submissions from those sessions are all archived, then grouped as 7 logical title/root-cause pairs;
- claims supported by only one participant are downgraded to plausible, while the shared claim independently reported by both peers remains confirmed.

A CLI dry-run additionally verified that --swarm --swarm-agents 2 --swarm-rounds 2 creates four separate prompt, command, and metadata files without contacting a model. These checks validate orchestration and output handling. They do not measure vulnerability recall or the real-world false-positive rate; that requires matched live-model audits with the same source revision, scope, model, and evidence standard.
