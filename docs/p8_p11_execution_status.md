# P8–P11 Execution Status

**Release posture:** `NOT_QUALIFIED` for VIP promotion. This document records the bounded execution performed against the WebPent checkout and the authorized local WAPTLab only. It does not promote mock evidence to live qualification.

## Evidence summary

| Area | Evidence obtained | Result | Qualification meaning |
|---|---|---:|---|
| P8 browser/session contracts | Targeted browser, proof, identity, and control-plane tests | 32 passed in 0.39s for the current regression set; earlier P8 suite 33 passed in 0.67s | Contract hardening passed locally; no authenticated target workflow was claimed |
| P8 live proof attempt | Real Chromium/control-plane harness against local WAPTLab on `127.0.0.1:18080` | Stopped at `baseline_observation_missing_or_unusable` | No causal signal, negative control, sealed ProofBundle, seal verification, or replay status was created; no bypass was used |
| P8 additive fixes | Session ID binding in `BrowserActionAdapter`; safe engagement/profile path segments | Implemented | Prevents cross-session execution and profile path traversal |
| P9 recovery contracts | Checkpoint, runtime context, deployment, production qualification, retry, recovery, worker-loop, and idempotency tests, including the cross-process ledger regression | 38 passed in 2.08s | Contract/reliability evidence only; not distributed qualification |
| P11 full regression | Complete project pytest suite after the P9 ledger regression and live evidence updates | 1749 passed in 54.39s | Source regression suite passed locally |
| P9 runtime smoke | Prior auth-enabled local stack smoke on isolated port 18000 plus current Redis loopback runtime on port 16379 with two real Celery workers; current run returned Redis PONG, two worker pongs, four fail-closed resume tasks distributed 2/2, and worker-A controlled restart recovery | Partial | Ledger-layer cross-process idempotency and live broker/worker smoke passed locally, but broker-level idempotency, multi-worker lease, killed-worker redelivery/resume, TLS, and live log/retention qualification remain unproven |
| P10 WAPTLab availability | Authorized local WAPTLab runtime was contacted only through health-only requests on `127.0.0.1:18080`; three rounds returned HTTP 403 for `/health`, `/`, and `/login` with identical response size/hash | Blocked | Natural authenticated workflow and target-backed three-run benchmark were not available; no login, registration, bypass, or scan was attempted |
| P10 benchmark artifact | `docs/waptlab_qualification_report.json` | `live_qualification=false`, `target_contacted=false`, `run_count=3`, `final_confirmed_counts=[0,0,0]` | Mock/contract fixture output only; not a finding or confirmation |

## P8 changes

The browser adapter now rejects a request when `request.session_id` differs from the session object supplied to execution. This binding is checked after engagement binding and before handler invocation, so a mismatched request cannot reach the injected browser handler.

The session manager now validates engagement and profile identifiers as single safe path segments before creating directories. Empty values, traversal segments, separators, and unsupported characters are rejected. This protects the per-engagement/profile directory boundary without persisting raw browser state.

No cookies, passwords, OTPs, reset links, Gmail data, provider credentials, or external target profiles were created or committed.

## P9 and P10 gates

The P9 contract suite and the isolated runtime smoke pass. In the current run, Redis returned `PONG`; two independent Celery workers returned `pong`; four malformed `resume_pentest_task` messages were distributed 2/2 and failed with `PermissionError` before target I/O; and worker-A was stopped and restarted before both workers returned to `ping`. The target-free two-process SQLiteActionLedger probe also passed with `allowed_count=1`, `duplicate_count=1`, `complete_once=true`, and `complete_twice=false`. This is useful live broker/worker and ledger-layer evidence, but it still does not satisfy the distributed gate: broker-level idempotency, multi-worker lease contention, killed-worker redelivery/resume, TLS, and live log/retention qualification require dedicated runtime evidence.

The P8 live harness and P10 gate are recorded in the machine-readable artifacts. The harness contacted only the local WAPTLab origin and stopped before candidate/negative-control execution because the baseline observation was missing or unusable. Separately, WAPTLab was checked only through three rounds of safe health-only requests; all `/health`, `/`, and `/login` requests returned HTTP 403. Because natural authentication remained unavailable, no authenticated workflow, target-backed causal signal, negative control, sealed replayable ProofBundle, or three-run live benchmark was claimed.

## P11 final gate outputs

The latest clean-environment validation produced `1749 passed` in 54.39s, Ruff passed, compileall passed, G-02 precommit passed with `{"errors": [], "external_target_contacted": false, "passed": true}`, and offline release verification passed with `{"errors": [], "offline_only": true, "passed": true, "signature_status": "operator_key_required", "target_contacted": false}`. The isolated P9 runtime smoke also produced API health 200, Redis PONG, two Celery worker pongs, successful API/worker/Redis controlled restarts, two-worker queue distribution, and fail-closed invalid resume handling. The VIP quality gate remains `passed=false` and `hard_checks_passed=true`; its failed-check list is empty, while the WAPTLab live campaign gate and full distributed worker qualification remain blockers.

## Promotion decision

The scorecard now exposes the conservative promotion ladder `NOT_READY → ENGINEERING_READY → EVIDENCE_READY → BENCHMARK_QUALIFIED → DISTRIBUTED_QUALIFIED → VIP_QUALIFIED`. The current offline scorecard can reach `ENGINEERING_READY` only when the regression and behavior contracts pass; it cannot reach `BENCHMARK_QUALIFIED` without three independent live runs, cannot reach `DISTRIBUTED_QUALIFIED` without distributed runtime evidence, and cannot reach `VIP_QUALIFIED` without consistent release artifacts and independent review.

`VIP_QUALIFIED` is **not** assigned. Promotion remains blocked by the live WAPTLab workflow gate and the distributed Docker/Redis/Celery qualification gate. The existing VIP report must remain `passed=false` until those gates have real, reproducible evidence.

## Reproduction commands

```text
PYTHONPATH=src:integrations/bbscout/src .venv/bin/python -m pytest -q tests/test_control_plane_local_harness.py tests/test_browser_target_backed_proof.py tests/test_browser_proof_runner.py tests/test_identity_matrix_facade.py tests/test_cli_identity_profiles_ownership.py

PYTHONPATH=src:integrations/bbscout/src .venv/bin/python -m pytest -q tests/test_cross_process_action_ledger.py tests/test_checkpoint_redaction.py tests/test_checkpoint_runtime_context.py tests/test_production_deployment_contract.py tests/test_production_qualification.py tests/test_structural_rate_limit_retry.py tests/test_superagentic_recovery_contracts.py tests/test_vip_recovery_loop.py tests/test_v58_validator_idempotency.py
```

These commands validate source contracts only. They do not authorize or perform provider I/O, public-target testing, CAPTCHA/OTP bypass, session/database bypass, or live qualification claims. The promotion-state ladder is a governance classification; it does not convert offline or mock evidence into target-backed qualification.
