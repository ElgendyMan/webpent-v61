# WebPent CQA v1 — Final Audit

## Executive conclusion

CQA v1 successfully activated a safe local evidence-execution path and completed a 50-case campaign shape across five independent FastAPI applications. It did not establish measured autonomous detection quality because no case reached a complete causal ProofBundle with verified replay. The correct status is therefore **evidence activation complete; scored detection quality blocked; qualification gates unchanged**.

## What exists

The repository contains a mandatory CQA repository-protection baseline, an additive `CandidateExecutionLayer`, isolated owner packages under `target_owner/cqa_v1/`, five independent local applications, a blind evaluation boundary, read-only campaign execution, stress contracts, ProofBundle sealing/replay contracts, and learning scorecard output.

## What was measured

| Measure | Result | Interpretation |
|---|---:|---|
| Independent targets | 5 | Local target factory produced five distinct runtime handles |
| Campaign cases | 50 | Ten opaque case requests per target were executed |
| Candidate/control triplets | 50 | Baseline, candidate, and negative-control observations were recorded |
| Eligible causal cases | 0 | No complete causal ProofBundle with replay was available |
| TP / FP / FN | 0 / 0 / 0 | Not evidence of quality; all cases were blocked before scoring |
| BLOCKED | 50 | Honest fail-closed result |
| Proof completeness | 0% | No proof bundle met the scoring contract |
| Learning status | NOT_ESTABLISHED | Cold and learned runs had no scored causal evidence |

## What is proven

The safe execution layer enforces GET/HEAD/OPTIONS-only methods, local ASGI transport, redacted request metadata, semantic response digests, and fail-closed eligibility. The ground-truth packages are separated from detector source paths and have independent provenance and digest files. The campaign can exercise all five local targets and preserve observations without truth labels. The stress suite preserves ambiguous results as blocked.

## What remains blocked or unproven

Causal vulnerability confirmation, TP/FP/FN quality, recall, precision, proof completeness above 95%, and learning improvement are not proven. The target threshold of TP >= 20, FP = 0, FN <= 3, and proof completeness >= 95% is not met. Blocked cases were not converted into FN, clean, confirmed, or scored outcomes.

## Governance and safety

No existing validator, threshold, frozen ground truth, historical report, or qualification gate was changed. No real credentials, external target, state mutation, destructive action, or official run was used. Governance remains `NOT_QUALIFIED`; `official_isolated_p10_runs_authorized=false`; P10/P9/VIP remain closed; Bug Bounty remains blocked.

## Regression disposition

All CQA-focused checks passed: 22 tests passed with one existing deprecation warning. Ruff, compileall, and the external-scope scan passed. Full repository regression recorded 2,288 passed and 11 preserved failures; the failures are in legacy G-02, local causal-lab provenance/approval, Option B runner, and source-backed inventory checks. No failures were hidden or rewritten, and no existing validator or historical artifact was changed.

## Reproduction

Run `PYTHONPATH=src python3 scripts/run_cqa_campaign.py`, then inspect `reports/cqa_v1/campaign_observations.json`. Run `PYTHONPATH=src python3 scripts/run_cqa_learning.py`, then inspect `metrics/cqa_v1_learning.json`. Execute the focused CQA and IRTA suites before any future scoring decision.
