# WebPent v72 Release Notes

## Scope

This release applies the Sprint 0–4 hardening and Smart Autonomous Bug Hunter work on the existing WebPent codebase. It does not modify WAPTLab or Juice Shop, and it does not claim live WAPTLab findings from the local quality gate.

## Implemented changes

The release includes versioned PBKDF2-HMAC-SHA256 envelopes with legacy read-back and key rotation support, canonical engagement-scope matching for IDNA/IPv6/scheme/port/path boundaries, Smart scan profiles, convergent autonomous stop rules, centralized GoalTree helpers, and ProofBundle promotion guards.

Confirmation paths now require behavior-based evidence. The relevant validators enforce causal evidence, a completed negative control, and a sealed ProofBundle before a finding can become Tool-Confirmed. Swagger SSRF, JWT, BAC/IDOR, XSS replay, OOB callbacks, cloud-storage markers, subdomain fingerprints, structural heuristics, and generic validator paths are covered by fail-closed guards. Heuristic-only paths remain Needs Human Review.

The dependency set was upgraded to the resolved LangGraph/LangChain 1.x generation. The legacy `langchain` text-splitter fallback was removed in favor of `langchain_text_splitters`, and the unused internal `search_disclosed_reports` helper was removed while the runtime disclosed-report ingestion and advisory path remains intact.

## Verification

| Gate | Result |
|---|---|
| Compileall | Passed |
| Ruff, project source/tests/scripts | Passed with 0 errors |
| Pytest | 930 passed, 0 failed |
| Bandit high severity | Passed |
| pip-audit strict | Passed; no known vulnerabilities in the lock-derived requirements |
| CycloneDX SBOM generation | Passed |
| Release manifest | Passed |
| WAPTLab safety artifact | Passed as non-contacting local contract artifact |

The quality artifact records `hard_checks_passed: true` and `passed: false`. The overall release flag is intentionally false because two unresolved qualification blockers remain: the WAPTLab regression is local contract-only with no live campaign confirmation, and live worker/Docker qualification is environment-blocked. This is deliberate and preserves the project’s honest classification as an **Evidence-Aware Bounded Autonomous Bug Hunter / Smart Research Beta**, not VIP-qualified.

## Reproducibility

Run the final gate from the project root with the project virtual environment active:

```bash
export PYTHONPATH="$PWD/src"
python scripts/run_vip_quality_gate.py
```

The machine-readable result is written to `docs/vip_quality_gate.json`. The gate may return exit code `1` while the two known qualification blockers remain, even when every hard check passes.

## Safety boundary

No WAPTLab or Juice Shop source, deployment, database, or live target was modified by this release. No unverified finding is promoted to confirmed status, and no live count of WAPTLab vulnerabilities is asserted by the release artifacts.

## Cleanup audit

The cleanup removed only code proven to be outside runtime wiring: the unused internal disclosed-report search helper and the obsolete import fallback to the vulnerable legacy `langchain` package. FastAPI route handlers, graph nodes, request-smuggling outcome probes, GoalTree methods, and console helpers were retained because they are route-registered, graph-wired, contract-facing, or intentionally preserved for backward compatibility.

---

**Release posture:** hard checks green; live qualification blockers explicit; VIP status not claimed.

**Author:** Manus AI
