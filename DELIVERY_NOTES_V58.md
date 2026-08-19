# WebPent v58 Delivery Notes

**Date:** 2026-08-15  
**Project:** WebPent — autonomous, evidence-first web penetration testing framework  
**Scope of this delivery:** POST-form request context, validator/tool wiring, convergence hardening, configurable local-target budgets, and structural evidence gating.

## Verification

The complete test suite passes:

| Check | Result |
|---|---:|
| Full pytest suite | **385 passed, 0 failed** |
| Affected/regression suite | **94 passed, 0 failed** |
| Python compile/import checks | Passed |
| Structural evidence-gate regressions | Passed |
| POST form hypothesis regressions | Passed |
| SQLMap POST argv/budget regressions | Passed |
| Validator idempotency/offline regressions | Passed |

Warnings emitted by the suite are existing development-security and dependency deprecation warnings. They do not represent test failures. Production deployments must replace the development `AUDIT_SECRET_KEY` and `CELERY_PAYLOAD_KEY` values.

## Implemented in v58

The `Hypothesis` and `Finding` models now carry backward-compatible `request_method`, `request_data`, and `target_param` fields. POST forms discovered dynamically from the target surface can be represented without hardcoded DVWA-specific routes. Form context is propagated through hypothesis generation, finding promotion, validator dispatch, SQLMap, and Dalfox. Existing GET-only callers remain supported through defaults and a TypeError-compatible fallback.

SQLMap and Dalfox wrappers now accept POST form data. SQLMap builds `--data`, `--method POST`, and optional parameter targeting while protecting sensitive values in logs. POST URL normalization removes only query keys duplicated in the form body and retains unrelated query context. POST budgets, retry limits, and concurrency-related settings are configurable through the supported `WEBPENT_` aliases.

Validator and graph convergence were hardened so terminal tool failures, missing validators, and final findings cannot be re-entered indefinitely through optimizer or chaining routes. Offline LLM supervisor paths fail closed without invoking methods on `None`. Business-logic request limits remain configurable and backward-compatible.

Static JavaScript sink detection and API-surface detection now follow the evidence-first policy. A dangerous JavaScript sink without proven attacker-controlled data flow is recorded as **Needs Human Review**, with explicit static-observation evidence. JSON/OpenAPI/GraphQL surface detection without a demonstrated security impact is also **Needs Human Review**, not **Tool-Confirmed**. Tool-Confirmed is reserved for an executable validator or human-reviewed evidence bundle.

## DVWA Medium validation

The latest completed DVWA Medium scan artifact was `audit/dvwa_medium_v23_alias_safe.log`, with the generated report captured in `output/report.json` at scan time. The sanitized scan summary recorded **21 candidate findings**, including **5 pre-final-gate Tool-Confirmed records**. Three SQL injection records carried tool evidence. Structural JavaScript/API records were subsequently corrected by the v58 evidence gate so that static observations cannot be counted as confirmed vulnerabilities without runtime or impact proof.

The report also contained AI-Assessed and Needs Human Review records, including RCE candidates without OOB confirmation and an LFI candidate without a registered automated validator. These are deliberately not counted as confirmed vulnerabilities. The scan was performed only against the authorized local DVWA instance at `127.0.0.1:4280`.

The v23 JSON/HTML/PDF runtime artifacts are intentionally excluded from the clean source ZIP because they were generated before the final structural evidence-gate correction and may contain target-specific runtime data. Historical logs remain available in the working directory for local audit, but no session cookie file is included in the delivery archive.

## Security and packaging

The clean delivery archive excludes `webpent.db`, runtime output, Python caches, pytest caches, local session/cookie files, environment files, generated logs, and other local state. No `PHPSESSID`, DVWA security cookie, API key, private key, or vault value is included in the archive. The archive contains source code, tests, documentation, scripts, configuration templates, and this delivery note.

## Known limitations

The current DVWA result is not a claim that every DVWA module is confirmed. Dynamic browser/runtime proof for DOM and stored XSS, OOB confirmation for command injection/SSRF, and a full multi-identity authorization matrix still require target-specific execution paths and evidence. A static observation remains useful for prioritization, but it is intentionally not promoted to a confirmed vulnerability.

The project remains dynamic: target routes, forms, request methods, and parameters are discovered from the target surface rather than encoded as a fixed DVWA manifest. Local-lab budgets can be reduced with environment settings, while default behavior remains backward-compatible for general targets.

## Recommended next validation loop

For the next authorized lab run, use a fresh session, enable structure-aware triage, select conservative local budgets, and preserve the raw log separately from the source archive. Review every Needs Human Review item, then add a validator only when it can produce a reproducible evidence bundle. Do not increase the confirmed count by relabeling observations.
