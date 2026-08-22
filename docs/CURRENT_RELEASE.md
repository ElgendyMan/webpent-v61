# WebPent Current Release Identity

## Canonical identity

This document is the source of truth for the current WebPent release candidate. Historical v55, v60, v61, v63, v70, and v72 reports remain preserved as historical evidence and do not redefine the current release identity.

| Field | Value |
|---|---|
| Package version | `0.3.0` |
| Tested Python runtime | `3.12.3` |
| Declared Python compatibility | `>=3.10` |
| Resolved LangGraph | `1.2.11` in `uv.lock` |
| Resolved LangGraph checkpoint SQLite | `3.1.1` in `uv.lock` |
| Current source revision | `f51c8bcd61f1923473fd6f5660049425121bf680` (`harden offline autonomy and llm budget controls`) |
| Qualification state | `NOT QUALIFIED` for VIP status |

## What is validated offline

The release candidate is validated through deterministic unit and regression tests, static checks, secret scans, direct-I/O inventory checks, G-02 checks, provider fixture checks, signed-package checks, and the WebPent/bbscout integration contracts. LLM use remains advisory and cannot authorize target actions, promote evidence, or disclose findings automatically.

The lock file records resolved dependency versions for reproducibility. The project intentionally keeps the declared Python range at `>=3.10`; the release evidence identifies Python `3.12.3` as the runtime used for this validation rather than silently changing the project's compatibility policy.

## LLM cost and fallback boundary

Managed graph runs enforce a deterministic per-run provider-attempt cap through `LLM_MAX_CALLS_PER_RUN` (default `32`); fallback attempts count toward the same cap and are blocked before another provider request after exhaustion. Reported token usage is tracked without pricing assumptions, and `LLM_WARNING_TOKENS_PER_RUN` (default `100000`) emits one redaction-safe advisory warning. The runtime summary is appended to `llm_budget_trace` and contains counters only, never API keys, prompts, responses, or authorization.

The router continues to use deterministic fallback behavior when LLM use is disabled, unavailable, or budget-exhausted. Direct library calls made outside the managed `llm_usage_scope` remain backward-compatible and are intentionally not budget-enforced; production workers and the CLI open the managed scope around graph execution.

## Qualification boundary

No provider or target live I/O is part of this release validation. WAPTLab qualification is therefore fail-closed and remains pending. VIP qualification requires three independent authorized local WAPTLab runs, each meeting all of the following: at least 15 confirmed findings out of 20, precision of at least 90%, reproducibility of at least 95%, complete proof coverage, zero scope violations, and zero duplicates. A cumulative result or fixture-only result cannot satisfy that gate.

## Release identity procedure

After the final source and documentation commit, the release process must record the exact commit SHA in the generated release manifest and in this document. Any subsequent documentation-only commit must either update the recorded parent/source revision explicitly or regenerate the manifest; self-referential hashes must not be claimed.

## Operator safety

Required secrets are intentionally blank in `.env.example`. Operators must inject secrets at runtime through their deployment secret store. Placeholder strings must not be promoted to staging or production. The production profile continues to require authentication, strong signing/audit/payload secrets, explicit non-wildcard CORS, secure Redis transport where applicable, and trusted-proxy configuration.

**Status:** production-hardened release candidate for offline validation; not production-qualified and not a VIP Smart Autonomous Bug Hunter until the independent authorized qualification gate passes.
