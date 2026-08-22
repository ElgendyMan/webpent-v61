# WAPTLab Qualification Status

## Decision

**Status: NOT QUALIFIED.** This release has not executed a live WAPTLab campaign, and no live provider or target I/O was performed during the current validation loop. The decision is fail-closed and is not a claim about the number of vulnerabilities in WAPTLab.

## Evidence available offline

The generated qualification artifact is `docs/waptlab_qualification_report.json`. It records three deterministic local mock matrices with `target_contacted: false`. Each matrix contains 20 catalog entries, of which 5 are `tool-confirmed` and 15 are candidate/review dispositions; none can be promoted to final confirmed findings because the mock runtime lacks target-backed proof.

| Offline check | Result |
|---|---|
| Local mock runs | 3 stable runs |
| Entries per mock run | 20 |
| Tool-confirmed entries per mock run | 5 |
| Final confirmed findings | 0 per run |
| Precision | Not measured; no known-negative catalog executed |
| Recall | Blocked; mock runs are not WAPTLab runtime qualification |
| Target contacted | No |
| WAPTLab modified | No |

The official gate reports `hard_checks_passed: true` but `passed: false`. Its known blockers are that WAPTLab regression is contract-only and that worker critical-path/live Docker qualification remains environment-blocked. Therefore, hard offline checks must not be confused with VIP qualification.

## Required authorized qualification inputs

A future qualification run requires an owner-controlled, locally reachable WAPTLab environment, written authorization that explicitly covers the target and test actions, a signed package accepted by the runtime trust map, and reproducible runtime metadata including the image digest, seed hash, and execution events. Provider credentials are not required for the offline path and must not be introduced merely to bypass this gate.

Qualification must consist of **three independent resets**, not one cumulative campaign. Every run must independently satisfy all of the following conditions:

| Gate | Required threshold |
|---|---|
| Confirmed findings | At least 15 of 20 |
| Precision | At least 90% |
| Reproducibility | At least 95% |
| Proof coverage | 100% of confirmed findings |
| Scope violations | Zero |
| Duplicates | Zero |

Candidates, review dispositions, fixture-only observations, and tool-confirmed-but-unproven records do not satisfy the confirmed-finding threshold. No automatic disclosure or submission is permitted.

## Safe next action

Do not start WAPTLab or provider live I/O from this release state. When the required authorized local environment and signed runtime package are supplied, execute the qualification harness only after an explicit preflight confirms scope, package trust, isolation, reset identity, and proof-bundle requirements. Until then, retain `NOT QUALIFIED`.
