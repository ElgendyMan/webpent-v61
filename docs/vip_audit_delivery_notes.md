# WebPent v60 — VIP Audit Delivery Notes

## Verification

This release was checked locally on 2026-08-18.

| Gate | Result |
|---|---|
| Full pytest suite | 576 passed, 66 warnings |
| Preserved test-function verifier | 537 functions, minimum 498 |
| Ruff on remediation files | Passed |
| Local WAPTLab regression | 20/20 dispositions; 13 inconclusive, 7 missing-validator; target-free |
| WAPTLab source tree | Not modified |

## Included remediation

The release includes the VIP authorization and deployment hardening, shared token revocation, atomic resume consumption, transactional HTTP/WebSocket/Playwright SSRF protection, tenant-aware authorization, login-specific throttling, bounded re-auth vault sweeping, raw request deadlines and byte budgets, centralized subprocess manifest enforcement, structured deserialization flag validation, opaque secret references, recursive checkpoint and metadata redaction, coverage ledger and fixed-top-N removal, Surface Evidence Graph identity/workflow enrichment, deterministic campaign planner and hypothesis DAG, validator capability registry, offline evidence/oracle/cleanup adapters for the seven unsupported campaign classes, redaction-safe Evidence Ledger, approval-gated Proof Engine with causal/cleanup/confidence transitions, target-free WAPTLab regression harness, and deployment/CI contract tests.

## Honest limitations

The compliance matrix at `docs/vip_audit_compliance_matrix.md` is the authoritative status record. In particular, the release does not claim that every WAPTLab class has a complete validator or that any local synthetic case is a confirmed vulnerability. The local harness records 13 campaigns as inconclusive and 7 as missing-validator; no target was contacted. Full-suite worker coverage remains 23%, below the audit target of 85%, and remains documented as partial/blocked because closing it safely requires a dedicated Celery/graph integration harness rather than superficial tests. LangChain/LangGraph dependency advisories also remain a documented blocker because a forced major upgrade would violate the project's compatibility requirement.

Before production exposure, set strong random values for `AUDIT_SECRET_KEY` and `CELERY_PAYLOAD_KEY`, use TLS Redis, configure trusted proxies correctly, and perform an authorized deployment smoke test.
