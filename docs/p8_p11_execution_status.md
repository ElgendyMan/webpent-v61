# P8–P11 Execution Status

**Release posture:** `NOT_QUALIFIED` for VIP promotion. This document records the bounded execution performed against the WebPent checkout and the authorized local WAPTLab only. It does not promote mock evidence to live qualification.

## Evidence summary

| Area | Evidence obtained | Result | Qualification meaning |
|---|---|---:|---|
| P8 browser/session contracts | Targeted browser, proof, identity, and control-plane tests | 33 passed in 0.67s | Contract hardening passed locally; no authenticated target workflow was claimed |
| P8 additive fixes | Session ID binding in `BrowserActionAdapter`; safe engagement/profile path segments | Implemented | Prevents cross-session execution and profile path traversal |
| P9 recovery contracts | Checkpoint, runtime context, deployment, production qualification, retry, recovery, worker-loop, and idempotency tests | 37 passed in 2.08s | Contract/reliability evidence only; not distributed qualification |
| P11 full regression | Complete project pytest suite after removing the temporary env file | 1742 passed in 67.80s | Source regression suite passed locally |
| P9 Docker smoke | Compose initially blocked by missing local `.env`; temporary ignored env was created from `.env.example`. Base image build was attempted but remained in the heavy Go-tool build stage and was stopped after no useful progress | Blocked | No API/Redis/Celery worker restart/resume qualification is asserted |
| P10 WAPTLab availability | Existing authorized local stack: app, Elasticsearch, and MySQL were up; health-only probes to `127.0.0.1:8000` returned HTTP 403 for `/health`, `/`, and `/register` | Blocked | Natural authenticated workflow and target-backed three-run benchmark were not available |
| P10 benchmark artifact | `docs/waptlab_qualification_report.json` | `live_qualification=false`, `target_contacted=false`, `run_count=3`, `final_confirmed_counts=[0,0,0]` | Mock/contract fixture output only; not a finding or confirmation |

## P8 changes

The browser adapter now rejects a request when `request.session_id` differs from the session object supplied to execution. This binding is checked after engagement binding and before handler invocation, so a mismatched request cannot reach the injected browser handler.

The session manager now validates engagement and profile identifiers as single safe path segments before creating directories. Empty values, traversal segments, separators, and unsupported characters are rejected. This protects the per-engagement/profile directory boundary without persisting raw browser state.

No cookies, passwords, OTPs, reset links, Gmail data, provider credentials, or external target profiles were created or committed.

## P9 and P10 gates

The P9 contract suite passing does not satisfy the distributed gate. The required API/Redis/worker stack was not qualified through controlled restart, resume, leases, idempotent redelivery, retry exhaustion, and artifact isolation because the required base image could not be completed in this environment.

The P10 gate was not run as a broad scan. The WAPTLab stack was checked only through safe status and health-only requests. Because natural registration/authentication remained unavailable with HTTP 403 and no lab-provisioned authenticated identity/session existed, no authenticated multi-step workflow, target-backed causal signal, negative control, sealed replayable ProofBundle, or three-run live benchmark was claimed.

## P11 final gate outputs

The final local validation produced `1742 passed`, Ruff passed, compileall passed, G-02 precommit passed with `{"errors": [], "external_target_contacted": false, "passed": true}`, and offline release verification passed with `{"errors": [], "offline_only": true, "passed": true, "signature_status": "operator_key_required", "target_contacted": false}`. The VIP quality gate returned `passed=false` and `hard_checks_passed=true`; its failed-check list was empty, while its two known blockers remained the WAPTLab live campaign gate and distributed worker qualification.

## Promotion decision

`VIP_QUALIFIED` is **not** assigned. Promotion remains blocked by the live WAPTLab workflow gate and the distributed Docker/Redis/Celery qualification gate. The existing VIP report must remain `passed=false` until those gates have real, reproducible evidence.

## Reproduction commands

```text
PYTHONPATH=src:integrations/bbscout/src .venv/bin/python -m pytest -q tests/test_control_plane_local_harness.py tests/test_browser_target_backed_proof.py tests/test_browser_proof_runner.py tests/test_identity_matrix_facade.py tests/test_cli_identity_profiles_ownership.py

PYTHONPATH=src:integrations/bbscout/src .venv/bin/python -m pytest -q tests/test_checkpoint_redaction.py tests/test_checkpoint_runtime_context.py tests/test_production_deployment_contract.py tests/test_production_qualification.py tests/test_structural_rate_limit_retry.py tests/test_superagentic_recovery_contracts.py tests/test_vip_recovery_loop.py tests/test_v58_validator_idempotency.py
```

These commands validate source contracts only. They do not authorize or perform provider I/O, public-target testing, CAPTCHA/OTP bypass, session/database bypass, or live qualification claims.
