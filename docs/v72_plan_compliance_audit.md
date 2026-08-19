# WebPent v72 Plan Compliance Audit

**Status:** Updated after the master-branch review on 2026-08-20.

This document is the current compliance record for `/home/ubuntu/upload/pasted_content_3.txt` and the v72 Sprint 0–5 implementation plan. It supersedes stale v60/v70 delivery summaries for the purpose of release status. It does not claim live WAPTLab qualification or a 15–18 confirmed-finding campaign.

## Executive result

The security-hardening and dependency-upgrade work described by the v72 plan is present on `master`. The post-upgrade verification remains green for the hard checks: **934 pytest tests passed**, Ruff reported zero findings, compileall passed, Bandit high-severity checks passed, and strict pip-audit reported no known vulnerabilities from the lock-derived requirements.

The project is not VIP-qualified. The overall quality gate intentionally remains `passed: false` because live WAPTLab qualification and worker/Docker qualification are not established. The honest classification remains **Evidence-Aware Bounded Autonomous Bug Hunter / Smart Research Beta**.

| Area | Current status | Evidence | Remaining work |
|---|---|---|---|
| Sprint 0 security hardening | Implemented | PBKDF2 v2 envelopes, key rotation, canonical scope, fail-closed promotion guards, regression tests | None identified in this review |
| Sprint 1 smart profile and convergence | Implemented | Smart profiles, public profile state, GoalTree helpers, autonomous stop rules, contract tests | End-to-end live campaign measurement remains external |
| Sprint 2 proof and promotion guards | Implemented | ProofBundle, causal signal, negative-control, sealed-bundle gates across validator paths | Broader validator reachability remains partial |
| Sprint 3 lab safety/fallback preservation | Implemented as non-contacting contracts | WAPTLab safety artifact and local fixtures | Live authorized qualification is still absent |
| Sprint 4 dependency upgrade | Implemented and verified | LangGraph/LangChain 1.x lock, 934 tests, pip-audit clean | Monitor future provider deprecations |
| Sprint 4 dead-code cleanup | Implemented conservatively | Removed only unreferenced disclosed-report helper and legacy vulnerable import fallback; retained wired wrappers and public/contract-facing methods | None identified in this review |
| Release manifest hygiene | Fixed in this review | Redacted manifest excludes runtime databases, outputs, caches, raw logs, and historical live-output folders; regression contract added | Operator signature remains optional and external |
| Live WAPTLab 15–18 confirmed findings | Not demonstrated | Gate records `live_qualification: false`; no target contacted by the release gate | Requires an authorized live environment and reproducible campaign evidence |
| Worker/Docker qualification | Blocked by environment | Docker client and Compose exist, but Docker daemon access returns permission denied on `/var/run/docker.sock` | Run the qualification from an environment with permitted Docker daemon access |

## Checklist against the v72 plan

| Planned item | Result | Notes |
|---|---|---|
| Versioned PBKDF2-HMAC-SHA256 envelopes with legacy read-back and rotation | Complete | Implemented in task crypto and re-auth vault paths |
| Canonical engagement scope and reference lookup boundaries | Complete | IDNA, IPv6, scheme, port, path, and userinfo cases are covered by contract tests |
| Smart profiles and effective-policy CLI status | Complete | Smart, smart-observe, and vip-qualification profiles are wired into graph construction |
| Cached LLM caller wiring | Complete with contract coverage | The planned LLM callers route through `try_get_llm`/`get_cached_llm`; TaskType cache separation and fallback/circuit-breaker behavior are covered by v90 and v72 contracts |
| Convergence stop rules | Complete | Repeated action, no-new-evidence, information-gain threshold, negative-control contradiction, and budget rules are enforced |
| GoalTree unification | Complete | Shared root/branch/budget helpers are used by rabbit-hole planning |
| ProofBundle promotion gates | Complete | Causal evidence, negative control, and sealed bundle are required before Tool-Confirmed promotion |
| Swagger SSRF, OOB, JWT, BAC/IDOR, XSS, cloud, subdomain, structural, and generic guards | Complete with conservative dispositions | Heuristic-only cases remain Needs Human Review; they are not promoted as confirmed |
| LangGraph/LangChain dependency generation upgrade | Complete | Lock and runtime environment use the resolved 1.x generation |
| Vulnerability audit closure | Complete for the lock-derived release requirements | `pip-audit --strict` reports no known vulnerabilities |
| Dead-code removal | Complete conservatively | Only code proven outside runtime wiring was removed |
| Full quality gate | Hard checks complete; overall qualification blocked | `hard_checks_passed: true`, `passed: false` by design because known blockers remain |
| Commit and push to `master` | Pending for this review | The current review adds manifest hygiene, LLM caller contracts, documentation consistency, and full-tree Ruff gate coverage before the follow-up commit |
| Redacted ZIP delivery | Complete previously; rebuild required after this review | The updated archive must include the manifest hygiene fix and current documentation |

## Evidence boundaries

The local WAPTLab artifacts are contract or mock artifacts. They are useful for checking safety, determinism, and disposition handling, but they are not evidence that the real WAPTLab application was contacted or that 15–18 vulnerabilities were confirmed in one run. No source, deployment, database, or live target belonging to WAPTLab or Juice Shop was modified.

The release manifest reports integrity hashes, not a cryptographic signature. Because no operator signing key is configured in this sandbox, its signature status must remain `not_configured` or `operator_required`; generating a fake signature would violate the release contract.

## Review additions in this pass

This review added a manifest-redaction contract, a repository-level LLM-caller contract, corrected the manifest builder so that mutable runtime state and stale target-specific outputs are excluded from release inventory, and changed the quality gate Ruff check from a curated file list to the full `src`, `tests`, and `scripts` tree. The LLM contract verifies that the planned callers reach the shared cached router and preserve TaskType isolation. The review also marks old audit summaries as superseded by v72 and updates the current traceability and README status to avoid stale metrics being mistaken for current verification.

## Reproduction commands

```bash
project=/tmp/webpent_v60_smart_implementation
venv=/tmp/webpent_v60_review_stage/webpent_v60_smart_stage/.venv
cd "$project"
export PYTHONPATH="$project/src"
export PATH="$venv/bin:$PATH"
"$venv/bin/python" scripts/build_release_manifest.py
"$venv/bin/pytest" -q
"$venv/bin/ruff" check src tests scripts --line-length 100
"$venv/bin/python" scripts/run_vip_quality_gate.py
```

The quality gate may return exit code `1` while the documented qualification blockers remain. That exit code is intentional and must not be changed into a false VIP pass.

**Release posture:** hard checks green; live qualification and worker/Docker qualification still blocked; VIP status not claimed.

**Author:** Manus AI
