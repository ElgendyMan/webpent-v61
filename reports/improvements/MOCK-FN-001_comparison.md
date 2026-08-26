# MOCK-FN-001 — Before/After Comparison

## Status

`comparison_status = implemented_pending_final_independent_review`

The limited design approval was `approved_for_implementation` for `mock-target-fixture-only`. The post-fix behavior was executed locally through the generic lifecycle runner and central proof verifier. This comparison records implementation evidence; it is not a final independent approval and does not qualify P10 or VIP.

## Comparison matrix

| Dimension | Before: default fixture | After: opt-in ready fixture |
|---|---|---|
| fixture state | Default adapter, precondition not ready | Explicit `MockTargetAdapter(ready=True)` instance and ready registration |
| target ID | `mock_target` | `mock_target_ready_fixture` |
| runner result | `blocked` | `confirmed` |
| blocked reason | `mock_target_not_started_and_precondition_not_ready` | N/A for ready path; `verified_replay` |
| observation path | Not reached; `observation_refs = []` | Baseline, candidate, observation, and independent negative-control stages reached |
| candidate/control separation | Not reached | Central verifier accepted distinct candidate/control request digests and target fingerprints |
| causal signal | Absent by design | `true`, produced as verifier input by the deterministic fixture validator path |
| negative control | Absent by design | `true`, independent target-backed control with role `negative_control` |
| ProofBundle | None | Sealed ProofBundle with `verify_seal() = true` |
| replay | Not applicable | `true` using three redacted observations plus `verification.evidence["replay_context"]` |
| sensitive artifacts | None | No raw response bodies, cookies, credentials, or headers saved; CaseResult omits runtime verification |
| network/state mutation | None | None; fixture does not start a server or perform network I/O and has no mutating operation |
| Generic Core changes | None | None; changes remain in Mock adapter and regression coverage |
| targeted regression | Default blocked regression passes | Ready success regression passes |
| full offline suite | Baseline previously passed | `1898 passed in 85.99s`; Ruff and compileall passed |

## Post-fix run identity

| Field | Value |
|---|---|
| Artifact | `audit/mock_ready_fixture_postfix_v1.json` |
| Run ID | `mock-ready-postfix-001` |
| Scope | `mock-target-fixture-only` |
| Ready status | `confirmed` |
| ProofBundle seal | `true` |
| ProofBundle replay | `true` |
| P10 / P9 / VIP | `NOT_QUALIFIED` / `NOT_QUALIFIED` / `NOT_QUALIFIED` |

The artifact contains only redaction-safe metadata, digests, replay context, and the serialized ProofBundle. It intentionally does not contain raw response bodies, cookies, credentials, or an external-target claim.

## Acceptance decision

`implementation_evidence = accepted_for_limited_design_scope`

`final_independent_approval = pending`

`p10_qualification = NOT_QUALIFIED`

`vip_qualification = NOT_QUALIFIED`

The before/after improvement is reproducible for the Mock fixture. It does not establish the approved Juice Shop case mapping, live P10 metrics, three isolated full-set P10 runs, or an independent P10 qualification decision.
