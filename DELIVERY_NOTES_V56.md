# WebPent v56 Delivery Notes

**Delivery date:** 2026-08-15  
**Status:** Ready for local regression use and controlled lab integration.

## What changed

This delivery completes the current surface-security and evidence-safety expansion. Surface analysis is a feature-flagged, passive projection over the target's collected endpoints, forms, headers, and JavaScript intelligence. It emits redacted observations and explicit category coverage gaps; it never emits a Finding and never sends an additional request.

Relational evidence is now represented by a typed `RelationalEvidence` model and is used by BAC identity comparisons while preserving the old relational fields. Edges have deterministic IDs, redacted references, `observed` status, and `Needs Human Review` confidence by default. They are not vulnerability confirmations by themselves.

PoC risk classification is centralized in `shared/poc_policy.py`. Low and medium bounded non-destructive work is allowed by policy, high-risk work requires explicit human approval, destructive work is rejected by the autonomous planner, and unknown risk fails closed. The helper is classification-only and does not execute anything.

## Feature flags

```env
enable_surface_security_analysis=false
max_surface_security_observations=100
```

Both new surface settings default to safe legacy behavior. The CLI and Celery worker initialize `surface_security` to `{}` so old checkpoints and runs remain loadable.

## Verification

Run from the project root:

```bash
PYTHONPATH=src pytest -q
```

Verified result for this delivery:

```text
353 passed, 46 warnings in 7.93s
```

Focused contract tests:

```bash
PYTHONPATH=src pytest -q tests/test_v29_surface_security.py tests/test_v30_evidence_poc_contracts.py
# 12 passed
```

Additional verification completed successfully:

```bash
PYTHONPATH=src python3 -m compileall -q src tests
# compileall=ok
```

The warnings are development-mode warnings for insecure default audit/Celery keys and an Alembic configuration deprecation. For any non-local deployment, set strong random values for `AUDIT_SECRET_KEY` and `CELERY_PAYLOAD_KEY` and review the Alembic configuration.

## Safe operation notes

The passive surface projection is not a substitute for active category validators. A candidate, route signal, missing header, or coverage gap must not be reported as a confirmed vulnerability. Active validators must produce tool-confirmed or human-reviewed evidence before a Finding is created.

The regression pass did not run a live WAPTLab engagement and therefore does not claim a new WAPTLab vulnerability count. This package contains no secrets, cookies, raw response bodies, or local database artifacts.

## Important files

- `audit/v56_coverage_report.md` — detailed coverage, safety, and verification report.
- `audit/coverage_matrix_v55_plus.md` — category maturity matrix and closure criteria.
- `tests/test_v29_surface_security.py` — passive surface contracts.
- `tests/test_v30_evidence_poc_contracts.py` — relational evidence and PoC contracts.
- `src/webpent/shared/poc_policy.py` — central PoC safety classifier.

## Rollback

The pre-expansion rollback archive remains:

```text
/home/ubuntu/webpent_review_baseline_v55.tar.gz
```

Use it only after preserving the current working tree and local test results.
