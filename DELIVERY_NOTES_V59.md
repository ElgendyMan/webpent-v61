# WebPent v59 Delivery Notes

## Delivery status

WebPent v59 completes the current P0 hardening cycle without changing the default safety posture or introducing target-specific logic. The release preserves the evidence-first boundary: passive observations, JavaScript sinks, redacted secret candidates, and relational metadata remain separate from reportable Findings until an approved validator, a tool, or a human-reviewed artifact supplies sufficient proof.

| Verification item | Result |
|---|---|
| Python bytecode compilation | Passed with `PYTHONPATH=src python -m compileall src -q` |
| Full pytest suite | **398 passed, 0 failed** |
| Focused P0 and wiring suite | **31 passed, 0 failed** |
| Existing v58 baseline | 385 passed before v59 additions; no regression detected |
| Default feature flags | Preserved as disabled unless explicitly configured |
| Sensitive archive content | Excluded from the delivery ZIP; cookies, databases, environment files, bytecode, logs, and nested archives are not packaged |

## Implemented P0 hardening

### Checkpoint-safe `auto_approve`

The operator’s `auto_approve` decision is now part of the optional, backward-compatible `PentestState` contract. The initial-state factory records the value, the Celery run task passes it into the state, and the resume task restores it from the checkpoint before rebuilding the graph. Older checkpoints without the field continue to load through the default-safe policy.

This closes a policy drift risk in which a resumed engagement could rebuild the graph with a different approval boundary from the original run. The implementation does not allow an LLM or a finding to change the policy; the value remains an explicit operator input.

### Optional Anthropic routing and prompt-caching capability

The shared LLM router now recognizes Anthropic in the provider preference chains, API-key lookup, model builder dispatch, and prompt-caching capability detection. The builder follows the existing provider contract: lazy SDK import, configured temperature and token limits, request timeout, and zero implicit retries. `langchain-anthropic` is declared in `pyproject.toml`, while the import remains lazy so deterministic/offline startup does not require a provider call.

If the Anthropic key or SDK is unavailable, the router records a bounded provider failure and follows the configured fallback order. API keys are never included in diagnostics, logs, findings, reports, or archives.

### Feature-flagged bug-bounty reporter

A new `enable_bug_bounty_reporter` setting, exposed through the project’s `WEBPENT_` environment alias convention, controls reporter selection. The default remains the existing enterprise reporter. When enabled, the graph registers the existing bug-bounty reporter as a drop-in replacement and emits the structured Markdown format intended for triage workflows.

The reporter continues to use the report-quality gate. It does not convert hypotheses or surface observations into Findings. Its JavaScript appendix is explicitly redaction-safe and is populated only from the bounded `crawled_data.js_secrets` projection.

## JavaScript intelligence wiring fix

The audit identified an ordering gap: the crawler computes passive surface coverage before the JavaScript intelligence node runs. Consequently, JavaScript-derived routes and sinks could be present in `javascript_intelligence` but absent from `surface_security`.

The JavaScript node now performs a second bounded, passive-only surface projection when `enable_surface_security_analysis` is enabled. It passes the completed, typed JavaScript projection explicitly to `analyze_security_surface`, so DOM/client-side sink, GraphQL client route, prototype-pollution pattern, and related observations are available to downstream review. The output remains an observation projection; no Finding is emitted by this bridge.

The same node now maps static secret candidates into the legacy `crawled_data.js_secrets` report projection using only the candidate kind, `[REDACTED]` marker, source asset, evidence reference, and value hash. Existing crawler secrets are preserved and deduplicated. Raw source text and raw secret values are not copied into checkpoint state or report output.

> **Evidence rule:** A JavaScript sink or secret candidate is an investigation lead. It still requires safe validation, appropriate authorization, and evidence review before it can affect a reportable vulnerability.

## Regression coverage added

The v59 tests cover the critical contracts rather than only importability.

| Test area | Coverage added |
|---|---|
| Anthropic router | API-key resolution, optional provider routing, and prompt-caching capability when Anthropic is the first live provider |
| Bug-bounty selection | Reporter selection with the feature flag enabled and the default enterprise reporter when disabled |
| JavaScript bridge | Static JS output reaches surface security after the node runs; DOM sink observations retain their non-Finding status |
| Secret redaction | Static secret candidates are bridged only as `[REDACTED]` metadata and raw values do not appear in returned state |
| Bug-bounty appendix | The report includes the redacted JavaScript appendix without exposing internal evidence identifiers as report values |
| Checkpoint policy | `auto_approve` is persisted in initial state and restored during resume |

## Files changed in v59

| File | Change |
|---|---|
| `src/webpent/config/settings.py` | Added the default-off bug-bounty reporter flag with the `WEBPENT_` alias convention |
| `src/webpent/graph/builder.py` | Added settings-driven reporter node selection |
| `src/webpent/shared/llm.py` | Added Anthropic key lookup, preference entries, lazy builder, and dispatch |
| `pyproject.toml` | Declared `langchain-anthropic` as an optional-compatible runtime dependency through the project dependency set |
| `src/webpent/agents/javascript_intelligence/agent.py` | Added post-JS surface projection and redaction-safe secret bridge |
| `src/webpent/state/state.py` | Added backward-compatible `auto_approve` state field |
| `src/webpent/state/initial_state.py` | Added `auto_approve` to the canonical initial-state factory |
| `src/webpent/workers/pentest_worker.py` | Preserved approval policy across run and resume paths |
| `tests/test_v25_javascript_intelligence.py` | Added surface/report wiring and redaction regressions |
| `tests/test_v57_readability_wiring.py` | Added Anthropic routing and caching regressions |
| `tests/test_v59_p0_hardening.py` | Added reporter selection and checkpoint policy regressions |
| `README.md` | Documented v59 behavior, configuration, debugging, and safe JS/report wiring |

## Operational guidance

For a deterministic local run, keep `LLM_ENABLED=false` and enable only the bounded discovery features needed for the engagement. For an online run, configure a provider through environment variables and run `scripts/doctor.py --json` before scanning. Do not place real credentials, cookies, databases, `.env` files, or runtime output in a delivery archive.

For the new report format, set `WEBPENT_ENABLE_BUG_BOUNTY_REPORTER=true` only when the operator wants the Markdown bug-bounty layout. To combine JavaScript surface observations with the report appendix, enable both `WEBPENT_ENABLE_JS_INTELLIGENCE=true` and `WEBPENT_ENABLE_SURFACE_SECURITY_ANALYSIS=true`; the latter still produces passive observations only.

The release remains target-agnostic. It does not promise a fixed number of vulnerabilities, does not assume DVWA or WAPTLab routes, and does not claim that the presence of a JavaScript sink, API route, or secret pattern proves exploitability.

## Known non-blocking warnings

The full suite reports existing development-mode warnings for weak local audit and Celery payload keys, plus an Alembic configuration deprecation warning. These warnings do not indicate a v59 test failure, but production deployments must set strong random secrets and should migrate the Alembic path configuration before relying on it in a production pipeline.

The repository-wide Ruff baseline is not clean: the current configuration reports legacy style findings across the project, including six `SIM105` findings in the worker's existing exception-suppression blocks. The v59 verification therefore treats `compileall`, the focused contracts, and the full pytest suite as the release gates; no blanket auto-fix was applied because it would change unrelated legacy code. The v59 JavaScript and test additions do not introduce a new lint class, and the remaining lint debt is recorded rather than hidden.

## Reproducibility commands

```bash
cd /home/ubuntu/webpent_review
PYTHONPATH=src python -m compileall src -q
PYTHONPATH=src python -m pytest -q
```

Expected result for this delivery: `398 passed, 0 failed`.

## Delivery boundary

This document records implementation and verification status. It is not a claim that WebPent automatically confirms all requested vulnerability categories on every application. Findings remain subject to scope, authorization, active-tool evidence, human approval for destructive proof-of-concept actions, and the report-quality gate.
