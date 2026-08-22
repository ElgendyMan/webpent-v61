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
| Implementation source revision | `267dcf9cfba39439ea1c3878666630dc9e8e34ec` (`Execute roadmap hardening and offline release gates`) |
| Manifest generation revision | `267dcf9cfba39439ea1c3878666630dc9e8e34ec` (regenerated from the source commit before the metadata-only commit) |
| Final metadata commit | recorded after manifest regeneration; it must not be confused with the implementation source revision |
| Qualification state | `NOT QUALIFIED` for VIP status |

## What is validated offline

The release candidate is validated through deterministic unit and regression tests, static checks, secret scans, direct-I/O inventory checks, G-02 checks, provider fixture checks, signed-package checks, and the WebPent/bbscout integration contracts. LLM use remains advisory and cannot authorize target actions, promote evidence, or disclose findings automatically.

The lock file records resolved dependency versions for reproducibility. This release line intentionally declares Python `==3.12.3` and validates against that interpreter; changing the compatibility range requires a separate compatibility policy and migration test set.

## LLM cost and fallback boundary

Managed graph runs enforce a deterministic per-run provider-attempt cap through `LLM_MAX_CALLS_PER_RUN` (default `32`); fallback attempts count toward the same cap and are blocked before another provider request after exhaustion. Reported token usage is tracked without pricing assumptions, and `LLM_WARNING_TOKENS_PER_RUN` (default `100000`) emits one redaction-safe advisory warning. The runtime summary is appended to `llm_budget_trace` and contains counters only, never API keys, prompts, responses, or authorization.

The router continues to use deterministic fallback behavior when LLM use is disabled, unavailable, or budget-exhausted. Direct library calls made outside the managed `llm_usage_scope` remain backward-compatible and are intentionally not budget-enforced; production workers and the CLI open the managed scope around graph execution.

## Qualification boundary

No provider or target live I/O is part of this release validation. WAPTLab qualification is therefore fail-closed and remains pending. VIP qualification requires three independent authorized local WAPTLab runs, each meeting all of the following: at least 15 confirmed findings out of 20, precision of at least 90%, reproducibility of at least 95%, complete proof coverage, zero scope violations, and zero duplicates. A cumulative result or fixture-only result cannot satisfy that gate.

## Release identity procedure

The release process records the implementation source revision in this document and regenerates the manifest from that source tree before the final metadata-only commit. The manifest therefore identifies the parent/source revision, while the final metadata commit is recorded separately. Self-referential hashes must not be claimed.

## Operator safety

Required secrets are intentionally blank in `.env.example`. Operators must inject secrets at runtime through their deployment secret store. Placeholder strings must not be promoted to staging or production. The production profile continues to require authentication, strong signing/audit/payload secrets, explicit non-wildcard CORS, secure Redis transport where applicable, and trusted-proxy configuration.

**Status:** production-hardened release candidate for offline validation; not production-qualified and not a VIP Smart Autonomous Bug Hunter until the independent authorized qualification gate passes.
