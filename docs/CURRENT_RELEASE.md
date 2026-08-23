# WebPent Current Release Identity

## Canonical identity

This document is the source of truth for the current WebPent release candidate. Historical v55, v60, v61, v63, v70, and v72 reports remain preserved as historical evidence and do not redefine the current release identity.

| Field | Value |
|---|---|
| Package version | `0.3.0` |
| Tested Python runtime | `3.12.3` |
| Declared Python compatibility | `==3.12.3` for this release line |
| Resolved LangGraph | `1.2.11` in `uv.lock` |
| Resolved LangGraph checkpoint SQLite | `3.1.1` in `uv.lock` |
| Implementation source revision | `85b4202` (`integrate reviewed bbscout bridge and guarded runtime`; source baseline `8b47b04`) |
| Benchmark contract revision | `e4f8c74` (`add proof-gated VIP benchmark efficiency metrics`) |
| Manifest generation revision | generated from the stable release tree containing implementation source revision `85b4202`; the manifest records the final metadata commit that created it |
| Final metadata commit | the Git commit that adds the verified `docs/release_manifest.json`; it is recorded in the delivery report and is distinct from the implementation source revision |
| Qualification state | `NOT QUALIFIED` for VIP status |

## What is validated offline

The release candidate is validated through deterministic unit and regression tests, static checks, secret scans, direct-I/O inventory checks, G-02 checks, provider fixture checks, signed-package checks, and the WebPent/bbscout integration contracts. The checkout-only environment passed **1,589 tests**, skipped 6 optional external-source tests, and emitted 56 warnings. With the explicitly configured external reviewed bbscout source, the complete regression passed **1,613 tests** with 56 warnings. The reviewed bbscout source is available only as an explicitly configured external tree; it is not vendored into this checkout. Production Compose passes the same safe bbscout policy/reference variables and read-only package mount to API and worker, while the release verifier rejects SQLite sidecars and logs. The hard checks pass, while live Docker/worker and target qualification remain blocked; no optional skip is treated as a live qualification pass. The offline proof/replay simulation contacts no target and therefore does not qualify as live evidence. LLM use remains advisory and cannot authorize target actions, promote evidence, or disclose findings automatically.

The final regression after the bbscout bridge, external-source gate, production Compose parity, and release-verifier hardening completed with **1,613 passed** and 56 warnings when the external reviewed bbscout source was explicitly configured. The checkout-only run completed with 1,589 passed and 6 skipped optional external-source tests. These are offline/source regression results; it does not prove live target contact, distributed worker readiness, or qualification. The lock file records resolved dependency versions for reproducibility. This release line intentionally declares Python `==3.12.3` and validates against that interpreter; changing the compatibility range requires a separate compatibility policy and migration test set.

## LLM cost and fallback boundary

Managed graph runs enforce a deterministic per-run provider-attempt cap through `LLM_MAX_CALLS_PER_RUN` (default `32`); fallback attempts count toward the same cap and are blocked before another provider request after exhaustion. Reported token usage is tracked without pricing assumptions, and `LLM_WARNING_TOKENS_PER_RUN` (default `100000`) emits one redaction-safe advisory warning. The runtime summary is appended to `llm_budget_trace` and contains counters only, never API keys, prompts, responses, or authorization.

The router continues to use deterministic fallback behavior when LLM use is disabled, unavailable, or budget-exhausted. Direct library calls made outside the managed `llm_usage_scope` remain backward-compatible and are intentionally not budget-enforced; production workers and the CLI open the managed scope around graph execution.

## Qualification boundary

No provider or target live I/O was performed in the current bbscout/WebPent integration validation. WAPTLab and Juice Shop qualification are therefore fail-closed and remain pending. The repository retains a redacted historical live-smoke artifact, and the release manifest labels it `historical_live_artifact`; its `target_contacted=true` value must not be interpreted as contact made during the current validation. The offline proof/replay simulation observed three reproducible fixture runs with replay agreement, but `live_qualification_proven=false` for that simulation. VIP qualification requires three independent authorized local WAPTLab runs, each meeting all of the following: at least 15 confirmed findings out of 20, precision of at least 90%, reproducibility of at least 95%, complete proof coverage, zero scope violations, and zero duplicates. A cumulative result or fixture-only result cannot satisfy that gate.

## Release identity procedure

The release process records the implementation source revision in this document and regenerates the manifest from that source tree in a final metadata-only commit. The manifest identifies the source tree and its parent revision; the delivery report records the metadata commit separately. Self-referential hashes are not claimed.

## Operator safety

Required secrets are intentionally blank in `.env.example`. Operators must inject secrets at runtime through their deployment secret store. Placeholder strings must not be promoted to staging or production. The production profile continues to require authentication, strong signing/audit/payload secrets, explicit non-wildcard CORS, secure Redis transport where applicable, and trusted-proxy configuration.

**Status:** production-hardened release candidate for offline validation; conditionally usable only for controlled single-node authorized operation. It is not production-qualified for horizontal/multi-tenant deployment and is not a VIP Smart Autonomous Bug Hunter until the independent authorized qualification gate passes.
