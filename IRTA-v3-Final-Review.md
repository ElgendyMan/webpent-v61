# IRTA v3 — Final Review

## Executive conclusion

IRTA v3 is **engineering-complete within the bounded local scope**, but it is **not VIP-qualified**. The implementation adds an independent local target factory, a blind-evaluation boundary, a read-only HTTP campaign, adversarial stress scenarios, a sealed/replayable ProofBundle contract, and a 50-case multi-target inventory. The scoring layer is fail-closed: cases without complete evidence remain `BLOCKED` and do not become TP, FP, or FN.

> The project has demonstrated independent-target and evidence-boundary readiness; it has not yet demonstrated independent live detection quality.

## Delivered capabilities

| Capability | Evidence | Status |
|---|---|---|
| Repository preflight | `reports/audit/irta_v3_preflight.md` | Verified |
| Independent applications | `src/webpent/irta/v3/targets.py`, five FastAPI apps | Verified locally |
| Detector blindness | `src/webpent/irta/v3/blind.py`, `test_v3_blind.py` | Verified |
| Real local campaign | `src/webpent/irta/v3/campaign.py`, `test_v3_campaign.py` | Verified with GET/HEAD/OPTIONS only |
| Stress testing | `src/webpent/irta/v3/stress.py`, `test_v3_stress.py` | Verified; ambiguous cases block |
| Proof sealing/replay | `src/webpent/irta/v3/proof.py`, `test_v3_proof.py` | Verified |
| 50-case inventory | `src/webpent/irta/v3/scoring.py`, `test_v3_scoring.py` | Verified; 50 cases are currently blocked |

## Score interpretation

| Metric | Result | Interpretation |
|---|---:|---|
| Targets | 5 | Meets the structural target count |
| Cases | 50 | Meets the structural inventory count |
| Classes | 6 | Meets the structural class count |
| TP | 0 | No eligible causal ProofBundle was submitted |
| FP | 0 | No eligible clean case was submitted |
| FN | 0 | Blocked cases are not FN |
| Blocked | 50 | Correct fail-closed result |
| Proof completeness | 0% | No case has the complete required evidence chain |

The values above are readiness metrics, not detection-quality metrics. The requested quality target of `TP > 20`, `FP = 0`, `FN <= small controlled amount`, and proof completeness of at least 95% is **not achieved**.

## Verification

The v3 focused suite passed with 19 tests. Ruff and compileall passed for the v3 implementation. The full repository suite recorded 2,285 passed and 11 failures. The 11 failures were preserved and diagnosed in `reports/irta_v3/failure_first_diagnosis.md`; they concern G-02 derived-artifact drift, Option B approval/provenance blockers, and missing Juice Shop source evidence. They were not repaired by weakening checks or changing ground truth.

## Governance and safety

No existing module was deleted. Existing validators, thresholds, and frozen ground truth were not modified. The campaign is loopback-only and read-only. No real credentials, external targets, destructive actions, or official runs were used. Governance remains `NOT_QUALIFIED`; `official_isolated_p10_runs_authorized=false`; P10, P9, VIP Qualification, and Bug Bounty remain closed.

## Remaining gates

The next authorized engineering step is to provide owner-approved, independent target-owner truth packages and execute candidate/control pairs that produce actual observations. Each case must pass baseline, candidate, independent negative control, causal oracle, central verification, ProofBundle sealing, and replay before entering scoring. Missing or mismatched target provenance must remain blocked. After that evidence exists, cross-target TP/FP/FN and proof-completeness results can be measured without inventing cases or outcomes.
