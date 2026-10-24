# KScout peer swarm workflow

The optional **--swarm** mode runs an audit group as equal peer researchers. It keeps the existing Linux source-read-only, userland PoC, close-control, and evidence requirements. The mode is intended to let researchers challenge one another and branch into additional leads without imposing a finding count.

## 1. Parent process

1. Parse **--count**, Linux source, output directory, model/provider, and swarm options. **--count 1** schedules one swarm group.
2. Bound the run to at most 64 child sessions. Per-group limits are 2–16 agents and 1–4 rounds.
3. Allocate a candidate directory and write its run metadata, group manifest, and an initially empty SWARM_BOARD.md.
4. Start every agent in a round concurrently, each with an isolated workspace under agents/round-NN/agent-NN/.
5. After the round ends, collect each participant's SWARM_UPDATE.md, fingerprint, peer arguments, and final message onto the readable board. Board excerpts are bounded; each later task also receives a compact `SWARM_CONTEXT.md` instead of a full-board prompt.
6. Continue until the configured maximum rounds or until every participant explicitly reports Round status: quiescent.
7. Archive every complete confirmed or plausible finding submission under findings/, group repeated submissions by normalized title and root cause in the candidate report, update the duplicate index, and aggregate elapsed time and token usage.

There is no permanent reviewer. Participants rotate their source-audit lens between rounds and can discover, challenge, reproduce, reject, revise, or branch from a lead. The frozen versioned norm set is recorded in `SWARM_NORMS.json`; trace counts and next-version review suggestions are written to `SWARM_NORM_REVIEW.md` after the run.

## 2. Peer rounds

### Round 1: independent discovery

All peers start without prior swarm claims. Each picks audit directions, traces source and history, and records any leads and evidence in its own workspace. It can submit multiple distinct findings using findings/<stable-lead-id>/.

### Later rounds: evidence gaps and branching

Each peer receives a bounded task context. Later rounds adapt the fresh-exploration share between roughly 25% and 40% based on the actionable lead queue; the remaining sessions challenge leads with the largest evidence gaps. The first challenge for a lead is blind: the peer records an independent source analysis before opening earlier reports. Subsequent challenges receive only that lead's relevant evidence pointers. Each participant should state which leads it accepts, rejects, or cannot resolve, cite the commands and evidence, and independently reproduce leads before treating them as cross-reproduced. It can also start a new branch or ask peers to take a follow-up task in `SWARM_UPDATE.md`.

The coordinator records assignments, reported interactions, evidence references, negative outcomes, and follow-up progress in `SWARM_EVENTS.jsonl`. `SWARM_INDEX.json` provides a structured lead view, including rejected and suspended work. Lead scheduling uses evidence gap, security assessment, and prior no-progress cost. The frozen norm version sets the no-progress threshold (2–4 follow-ups); reaching it suspends a lead for the current run, preserves its evidence, and does not mean rejection. A new archived finding for the same root cause resets the no-progress streak and reactivates a suspended lead.

The orchestrator waits for all sessions in a round before updating the board. Peers exchange arguments between rounds, not as a live shared chat while the current round is running.

### Stop condition

A round is quiescent only when every participant explicitly writes Round status: quiescent in SWARM_UPDATE.md. A missing or active status causes the next round to run, up to --swarm-rounds.

## 3. Evidence and finding status

Each agent keeps its complete artifacts in its own workspace. A promoted finding has a separate archive directory containing its report and fingerprint; source workspaces retain the full event stream, PoC, raw logs, and other experiments. SWARM_EVIDENCE_SOURCE.md links the archive back to that original evidence.

Repeated reports with matching normalized Title and Root cause/invariant are presented as one logical finding in candidate-report.md. Their separate submissions remain in findings/ for auditability. The generated FINDING_INDEX.md includes archived findings and avoids repeating exact normalized title/root-cause pairs.

The coordinator distinguishes `CANDIDATE`, `AGENT_REPRODUCED`, and `CROSS_REPRODUCED`. The last requires two different participants to report local executions for the same stable Lead ID (or legacy normalized title/root-cause match). The coordinator separately records first-round blind analyses. These are reported states, not external runner verification: `RUNNER_VERIFIED`, `REPORTABLE`, and `SECURITY_CONFIRMED` remain unset until separate checks occur. Review the underlying evidence, especially when peers disagree or paraphrase the same issue differently.

## 4. Cost and use

Use `--swarm-agents` (2–16) and `--swarm-rounds` to set the group size and maximum follow-up depth. A default count=1 run schedules up to 3 agents × 2 rounds = 6 child sessions. Agents in a round run concurrently; rounds run in sequence so later participants can use earlier evidence. Token use grows with child sessions, and follow-up rounds add wall-clock time. Early quiescence can skip later rounds.

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

## 5. Evaluation boundary

The event log and norm review expose measurements for controlled comparisons. The runtime counts self-reported actions and evidence progress; it does not establish that a norm caused a finding or validate the semantics of a PoC. Norm versions should change between measured runs and be evaluated against independent finding review, matched source revisions, and comparable total resource budgets.
