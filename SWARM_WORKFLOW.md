# Peer swarm workflow

KScout coordinates peer analysis sessions through evidence-guided task allocation, evidence-grounded analysis, and cross-agent verification. There is no permanent reviewer role. The coordinator schedules tasks and validates structured submissions; agents perform source analysis and experiments.

## 1. Prepare a group

`--count N` schedules N independent swarm groups. Each group has its own candidate directory, shared records, and participant workspaces. The default is three peers per round and at most two rounds. `--swarm-agents` accepts 2–16 and `--swarm-rounds` accepts 1–4; the requested total is limited to 64 child sessions per run.

The coordinator loads a frozen norm policy and the optional prior finding index. Imported summaries help exclude duplicate root causes. They are not evidence for a new discovery.

## 2. Explore independently

All first-round peers start with independent source exploration. They use different research perspectives and can submit multiple findings, negative results, or unresolved candidates. Each session gets a distinct participant identifier, a persistent workspace, and a temporary `scratch/` directory.

Prompts require source references, triggering conditions, realistic caller privileges, a user-visible oracle, negative controls, and evidence files. The coordinator archives eligible submissions before cleaning temporary workspaces.

## 3. Collect submissions and preserve provenance

Participants submit `SWARM_UPDATE.md`, reports, fingerprints, and evidence. The coordinator appends interaction records to `SWARM_BOARD.md` and `SWARM_EVENTS.jsonl`, updates `SWARM_INDEX.json`, and preserves finding submissions under `findings/`.

Stable lead identifiers associate submissions with a root cause. Legacy submissions without an identifier use title and root-cause matching. Multiple submissions about one cause are retained as separate evidence records rather than counted automatically as different bugs.

For assigned challenges, the submission protocol includes:

- Assigned lead, claim, and target claim identifiers.
- Challenge disposition, independent reproduction, and evidence progress.
- Evidence references, the disputed claim, and a falsifiable check.
- Explored areas and suggested follow-up work.

The coordinator checks task identifiers and evidence paths. Accepted evidence references must resolve to existing files within the submitting workspace. These checks establish that evidence is locatable; they do not independently establish the truth of a claim.

## 4. Allocate follow-up work

A lead remains eligible when fewer than two distinct peers report supported reproduction or its security impact remains unresolved. Rejected and suspended leads are excluded from active follow-up scheduling.

The planner ranks eligible leads using evidence gaps, impact, progress, and observed cost. It reserves a share of the round for new searches; the default policy adjusts this share between 25% and 40% according to eligible work and stalled progress. Each selected lead receives one follow-up task in that round. Remaining slots perform new exploration. If no lead is eligible, all peers explore.

For the first follow-up on a lead, the peer receives a reduced context and must save `blind-analysis.md` before consulting earlier conclusions. This is an instruction and context ordering rule. It is not a filesystem isolation guarantee: earlier reports may remain accessible through the runtime's file tools. Later checks receive the relevant evidence index and open questions.

Follow-up peers recheck the source, trigger, PoC, oracle, negative controls, and security assumptions. A new participant identifier is assigned to each session so repeated reports from one session do not count as independent peers.

Two distinct peers must provide valid evidence and an explicit rejection before the planner rejects a lead. Repeated checks without qualifying progress can suspend it at the policy's stall threshold. Suspension retains the evidence and unresolved questions. New archived evidence can reset the stall count and make the lead eligible again.

## 5. Stop or continue

The group stops early when all current peers report quiescence and no eligible lead remains. Otherwise, scheduling continues until the configured round limit. Reaching the limit preserves unresolved states; agreement or exhaustion of the budget does not promote a finding to a security conclusion.

## Evidence states

| State | Meaning |
| --- | --- |
| `CANDIDATE` | A lead has been recorded. |
| `AGENT_REPRODUCED` | An agent reports local reproduction. |
| `CROSS_REPRODUCED` | Two distinct participants report reproduction for the same lead. This does not prove independently derived root-cause reasoning. |
| `RUNNER_VERIFIED` | An external runner result satisfies the verifier protocol checks. |
| `REPORTABLE` | An independent assessment records reviewed root-cause and reproduction evidence with the required reproduction support. |
| `SECURITY_CONFIRMED` | An assessment additionally supports security relevance and identifies the affected boundary or protected asset. |

Reproduction and security impact are separate dimensions. Findings classify impact as `security-relevant`, `correctness-only`, or `unresolved`. Preserve the conditions and limitations behind each conclusion. A peer's local `Outcome: confirmed` is not equivalent to `SECURITY_CONFIRMED`.

## External verifier

`--swarm-verifier EXECUTABLE` invokes an externally supplied runner using:

```text
EXECUTABLE --request REQUEST.json --result RESULT.json
```

The result uses schema version 1 and includes `lead_id`, `verifier`, `status`, `isolation`, `clean_setup`, `positive_repetitions`, `negative_controls`, `vm_queue_seconds`, `vm_execution_seconds`, `kernel_revision`, `kernel_config_sha256`, `evidence_refs`, and `summary`.

To accept `status: verified`, the coordinator requires an `isolated_vm` declaration, a clean setup, at least two positive repetitions, at least one negative control, finite nonnegative timings, a lowercase SHA-256 configuration digest, the expected lead and kernel revision, and existing evidence within the candidate directory. Requests, results, stdout, and stderr are retained under `verification/`.

The runner is responsible for provisioning and operating the VM. The coordinator validates the returned structure and evidence paths; the JSON declaration alone cannot prove that the runner actually provided the claimed isolation. Without an external runner, runner status remains `NOT_RUN`.

## Independent assessment

After a run, an independent reviewer can apply an assessment:

```sh
./codex-rs/target/debug/codex kernel-vuln \
  --apply-swarm-assessment ./assessment.json
```

A minimal assessment has this shape. Replace the lead and evidence path with those from the actual run:

```json
{
  "schema_version": 1,
  "candidate_dir": "./runs/swarm/candidates/candidate-001",
  "reviewer_id": "reviewer-01",
  "independently_reviewed": true,
  "reviewer_blinded_to_architecture": true,
  "assessments": [
    {
      "lead_id": "L012",
      "reportability": "REPORTABLE",
      "root_cause_reviewed": true,
      "reproduction_reviewed": true,
      "security_confirmation": "SECURITY_CONFIRMED",
      "security_impact_class": "security-relevant",
      "security_boundary": "Describe the demonstrated boundary or protected asset.",
      "evidence_refs": ["findings/L012/reproduction.log"],
      "review_notes": "Describe the evidence reviewed and the remaining limitations."
    }
  ]
}
```

`candidate_dir` is resolved relative to the assessment file when it is not absolute. Evidence paths are relative to the candidate directory and must exist. Reportability requires cross-peer reproduction or runner verification, reviewed root-cause and reproduction evidence, and valid references. Security confirmation also requires a supported security impact. Review inputs and history are preserved in `SWARM_REVIEW.json`; the index and candidate report are updated. The reviewer identity and independence fields are declarations, not independently authenticated guarantees.

## Frozen policy and optional updates

Each run stores its policy in `SWARM_NORMS.json`. Behavioral and collaboration norms govern source analysis, challenge specificity, provenance, and evidence reporting. Resource norms govern exploration allocation and stalled work. Some constraints are enforced by state transitions and evidence checks; other norms are instructions reflected in prompts and interaction records.

The policy stays frozen within a run. `SWARM_NORM_FEEDBACK_TEMPLATE.json` provides the input shape for an optional update based on independently reviewed comparisons. The updater checks matched source, model, task, and environment conditions, a shared total token and tool-time budget, and the recorded usage of both conditions. It requires at least three tasks and three repetitions, independent architecture-blinded review, and disjoint valid trace files for the two conditions. Test-split feedback and worsening false-confirmation rates are rejected.

```sh
./codex-rs/target/debug/codex kernel-vuln \
  --adapt-swarm-norms ./evaluation-feedback.json \
  --adapt-swarm-norms-output ./norms-v2.json \
  --swarm-norms ./runs/swarm/candidates/candidate-001/SWARM_NORMS.json
```

The result can be supplied to a later run with `--swarm-norms`. Trace-derived suggestions and resource adjustments are recorded in the policy's `update_record`. These are auditable heuristic changes; their existence does not establish a measured improvement.

## Implementation references

- [Round orchestration and archival](codex-rs/cli/src/kernel_vuln_swarm.rs)
- [Task planner](codex-rs/cli/src/kernel_vuln_swarm_planner.rs)
- [Submission protocol](codex-rs/cli/src/kernel_vuln_swarm_protocol.rs)
- [Norm definitions](codex-rs/cli/src/kernel_vuln_swarm_norms.rs) and [policy](codex-rs/cli/src/kernel_vuln_swarm_policy.rs)
- [Reproduction state](codex-rs/cli/src/kernel_vuln_swarm_consensus.rs) and [lead index](codex-rs/cli/src/kernel_vuln_swarm_index.rs)
- [External runner](codex-rs/cli/src/kernel_vuln_swarm_runner.rs) and [independent review](codex-rs/cli/src/kernel_vuln_swarm_review.rs)
- [Policy update](codex-rs/cli/src/kernel_vuln_swarm_induction.rs), [metrics](codex-rs/cli/src/kernel_vuln_swarm_metrics.rs), and [interaction traces](codex-rs/cli/src/kernel_vuln_swarm_trace.rs)
