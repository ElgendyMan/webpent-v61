# WebPent v60 — VIP Autonomous Bug Hunter Traceability Matrix

> **Current v72 note:** This matrix is maintained as a technical traceability record. Current release numbers and final qualification status are in [`v72_plan_compliance_audit.md`](v72_plan_compliance_audit.md). It is still forbidden to treat local fixtures, LLM narratives, or heuristic markers as confirmed findings.

## Purpose

This document converts `pasted_content_3.txt` and the final audit plan into an executable backlog. A row is not considered complete merely because an enum, helper, or declarative list exists; completion requires a live code path, behavioral test, observable status, and a measurable acceptance condition.

## Status vocabulary

| Status | Meaning |
|---|---|
| implemented | Live path and behavioral evidence exist in the current release. |
| partial | A safe foundation exists, but an end-to-end capability or target-dependent proof is still missing. |
| missing-validator | The campaign or class is represented, but no authoritative detector/executor/validator bundle exists yet. |
| blocked | Completion requires an external dependency, production environment, or a larger integration harness that cannot be safely faked. |
| planned | No implementation has started; the row is an explicit next deliverable. |

## Security and reliability traceability

| Finding / requirement | Component | Change or interface | Test / evidence | Acceptance | Priority | Status |
|---|---|---|---|---|---|---|
| Authentication enabled by default and auth-off public-bind fail-closed | `api/auth.py`, `shared/preflight.py` | `/token` guard and preflight exception | `test_vip_auth_posture.py` | Public bind with auth disabled cannot start; token endpoint cannot mint JWT | P0 | implemented |
| Global admin versus tenant admin | `api/auth.py`, `api/app.py` | `User.tenant_id`, `User.is_global_admin`, scoped resource authorization | VIP tenant regressions | Same-tenant allowed, cross-tenant denied, global admin retains legacy access | P0 | implemented |
| Shared token revocation | `memory/db.py`, `api/auth.py` | Shared `auth_token_versions` store | Revocation regressions | Revocation is visible across workers and survives process boundaries | P0 | implemented |
| Resume consume-once, lease, and redelivery idempotency | `api/scan_registry.py`, `workers/pentest_worker.py` | Atomic claim/consume path | Resume and worker regressions | Duplicate deliveries cannot execute the graph twice | P0 | implemented |
| Transactional Playwright SSRF guard | `shared/http.py` | Registration succeeds only if all HTTP/WS handlers are protected | Playwright guard regressions | Partial registration fails closed and leaves no unprotected browser | P0 | implemented |
| Exact OriginPolicy across transports | `shared/engagement_scope.py`, `shared/http.py` | Scheme/host/effective-port/path policy shared by HTTP, redirects, WS, Playwright, raw/OOB context | Origin matrix regressions | Same policy decision for equivalent origins; mismatch is blocked | P1 | implemented/verify |
| Raw socket bounded execution | `agents/request_smuggling/agent.py` | Monotonic total deadline, idle timeout, byte and connection budgets | Raw socket budget tests | No probe can exceed configured wall-clock or byte budget | P1 | implemented |
| Parser rejection versus confirmation | `agents/request_smuggling/agent.py` | `confirmed`, `parser_rejected`, `inconclusive` taxonomy | Request-smuggling outcome tests | Only confirmed outcomes can promote a finding | P1 | implemented |
| Central executable allowlist | `tools/utils/subprocess.py` | Canonical executable manifest and explicit custom registration | Manifest rejection tests | Unknown executable is rejected before process creation | P1 | implemented |
| Deserialization flag policy | `shared/deserialization.py` | Structured allowlist/denylist for output/file/proxy/redirect flags | Structured flag tests | Dangerous or unknown flags fail closed | P1 | implemented |
| Secret-taint and checkpoint redaction | `state/initial_state.py`, `graph/checkpoints.py` | Opaque `secret_refs`, recursive deny-by-default redaction | Checkpoint and nested metadata tests | Passwords, cookies, API keys, TOTP, and secret-shaped fields are absent from persisted state | P0 | implemented |
| Re-auth vault TTL and cleanup | `auth/reauth_vault.py`, worker/CLI lifecycle | Bounded sweep, stats, terminal cleanup | Vault lifecycle tests | Expired entries are removed; terminal paths clear secrets | P1 | implemented/verify |
| Registry failure visibility | `api/scan_registry.py`, `api/app.py` | Readiness/error state and degraded health | Registry health tests | Initialization failure is operator-visible and read/write paths fail closed | P1 | implemented |
| Login throttling | `api/rate_limit.py`, `api/app.py` | Independent IP/account buckets and generic 429 | Login limiter tests | Brute-force attempts are bounded without user enumeration | P1 | implemented |
| Dependency advisories | `uv.lock`, CI, audit evidence | Resolved lock plus strict audit evidence | `docs/pip_audit_release.json`, `docs/sbom.cdx.json` | No known vulnerabilities in the lock-derived release requirements; future upgrades require regression testing | P1 | implemented/verified |

## Autonomous Bug Hunter foundations

| Finding / requirement | Component | Change or interface | Test / evidence | Acceptance | Priority | Status |
|---|---|---|---|---|---|---|
| Surface Evidence Graph schemas | `models/surface_security.py`, `shared/http_discovery.py`, new graph package | `SurfaceNode`, `SurfaceEdge`, source/disposition/evidence references | Schema and serialization tests | Every discovered surface has stable identity, source, scope, and disposition | P1 | partial |
| Rich surface metadata | crawler/browser/discovery modules | Method, path, query, headers, body, content type, forms, redirects, fingerprints, identity, tenant, workflow | Discovery fixture tests | Required metadata survives normalization and checkpoint/report serialization | P1 | partial |
| Browser/XHR/fetch/OpenAPI/GraphQL/multipart extraction | crawler and browser instrumentation | Additive extractors feeding the same surface graph | Local fixture tests | Each supported source creates graph nodes without duplicate side effects | P1 | partial |
| Fixed top-N removal | strategist/crawler | Coverage-based selection and ledger | Top-N regression | Six or more candidates remain represented; only explicit safety budgets bound work | P1 | implemented |
| Mandatory surface disposition | state and coverage ledger | `tested`, `tested-negative`, `missing-validator`, `blocked-by-auth`, `blocked-by-scope`, `inconclusive`, `not-observed` | Ledger regressions | No class disappears silently as “no finding” | P1 | implemented/partial |
| Application Intent Model | `models/application_intent.py`, `shared/application_intent_graph.py` | Actors, objects, fields, trust boundaries, sinks, transitions, jobs, services | `test_vip_application_intent_graph.py`, smart-wiring tests | Route renaming/order changes do not erase core intent when evidence is equivalent | P1 | implemented |
| Identity Matrix | auth/workflow state | Anonymous, owner, foreign user, tenant admin, global admin contexts | Cross-identity fixture tests | Each identity has explicit preconditions and cleanup | P1 | partial |
| Workflow replay and cleanup | `models/workflow_replay.py`, `shared/workflow_replay.py` | Bounded replay plans for login, resource, upload/worker, tenant, and Swagger-fetch workflows | `test_vip_workflow_replay.py` | Replay plans are bounded and expose cleanup/identity requirements; live executor reachability remains target-dependent | P1 | partial |
| LLM evidence discipline | strategist/intent builder | LLM may suggest/summarize only; evidence references required | Missing-evidence tests | LLM output cannot create or drop a campaign without evidence-backed disposition | P1 | partial |

## Campaign and validator traceability

| Campaign family | Required executor/oracle | Component | Test / evidence | Acceptance | Priority | Status |
|---|---|---|---|---|---|---|
| Header SQLi / `X-Forwarded-For` | Header mutation plus differential/error/time oracle | campaign planner, validator plugin | Positive/negative header fixture | Request and negative control are recorded; generic 200 is not confirmation | P1 | partial |
| CSV ingestion / worker SQLi | Multipart/CSV body plus worker result oracle | crawler, worker campaign, validator | CSV fixture | Worker side effect and cleanup are evidenced | P1 | missing-validator |
| JWT/base64/opaque-token traversal | Token mutation plus file/path oracle | auth campaign, validator | Token fixture | Decode/normalization variants are covered without leaking tokens | P1 | missing-validator |
| Double-slash and OAuth redirect/state/PKCE | Redirect graph and state binding oracle | HTTP discovery, workflow runner | Redirect/OAuth fixture | Open redirect and state/PKCE failures are differentiated | P1 | missing-validator |
| IDOR/BOLA and mass assignment | Owner/foreign identity differential | `bac_identity_tester.py`, validator registry | Cross-identity fixture | Foreign access or unauthorized field mutation requires causal evidence | P0 | partial |
| Tenant isolation/context switching | Tenant A/B identity differential | auth/app/workflow | Tenant fixture | Cross-tenant read/write is blocked or confirmed with evidence | P0 | partial |
| Training/export template SSTI | Template input and rendered output oracle | post-exploit/campaign | Template fixture | Rendering semantics and negative control are captured | P1 | missing-validator |
| Swagger/image SSRF and OOB | Browser/HTTP origin policy plus OOB correlation | `shared/http.py`, campaign planner | Local OOB fixture | OOB event is correlated to request and in-scope origin | P1 | partial |
| XML/XXE and XSLT `document()` | XML parser and transform oracle | validator plugins | XML/XSLT fixture | External entity/transform behavior is proven, not inferred from parser errors | P1 | missing-validator |
| Elasticsearch snapshot/index exposure | Service fingerprint and authorization oracle | service discovery, validator | Local ES fixture | Exposure is classified with authenticated/negative controls | P1 | missing-validator |
| Backup/info disclosure | Artifact discovery and content fingerprint | crawler, validator | Backup fixture | Sensitive artifact evidence includes path, response hash, and cleanup | P1 | missing-validator |
| Laravel debug/error fingerprint | Error-trigger and response fingerprint oracle | crawler, validator | Debug fixture | Debug exposure is separated from ordinary error pages | P1 | missing-validator |
| Frontend dependency intelligence | Lockfile/bundle extraction and advisory mapping | new dependency intelligence module | Static fixture | Dependency evidence is versioned and linked to advisory state | P1 | missing-validator |

## Evidence and proof-engine traceability

| Requirement | Component | Deliverable | Test / evidence | Acceptance | Priority | Status |
|---|---|---|---|---|---|---|
| Validator plugin contract | `agents/validator/registry.py`, validator package | `discover`, `prepare_state`, `execute_probe`, `collect_oracle`, `classify_evidence`, `cleanup`, `render_finding` contract | Registry contract tests | Unsupported classes cannot register as confirmed-capable | P1 | partial |
| Evidence Ledger | `models/evidence.py`, `shared/evidence_contract.py`, new ledger store | Request/response metadata, identity, baseline, negative control, oracle, OOB/browser events, timestamps, hashes, cleanup | Evidence serialization/integrity tests | Every confirmed finding has a causal evidence bundle | P0 | partial |
| Conservative promotion | validator agent | Typed evidence states and no LLM/status-code promotion | Validator regressions | Parser rejection, weak oracle, and missing controls become review/inconclusive | P0 | implemented/partial |
| Information-gain planner | `shared/adaptive_hunt.py`, strategist | Gap taxonomy and new action selection | Adaptive-hunt fixture | No duplicate probe without new evidence; each action has budget and exit condition | P1 | partial |
| Scope/approval authority | scope enforcer and planner boundary | Planner cannot mutate scope or approval state | Scope boundary tests | Scope violations remain zero | P0 | implemented |
| Observability | state/report/health | Coverage, confirmations, blocks, retries, budgets, latency, evidence quality, dropped tasks, guard failures | Metrics schema tests | Every scan emits bounded counters and disposition reasons | P1 | partial |

## Release gates

| Gate | Minimum | Current evidence | Status |
|---|---:|---|---|
| Full pytest | At least 916 passed | 934 passed, 0 failures in the v72 LangGraph/LangChain 1.x environment | implemented |
| Ruff | Zero findings across `src`, `tests`, and `scripts` | Passed | implemented |
| Surface discovery coverage | 95% | No reproducible full fixture measurement yet | planned |
| Workflow coverage | 90% | No reproducible workflow fixture measurement yet | planned |
| P0/P1 validator reachability | 100% | Several campaign families remain missing-validator | partial |
| Evidence completeness before confirmation | 100% | Conservative promotion exists; full ledger coverage remains partial | partial |
| Unexplained skip rate | 0 | Explicit dispositions exist; fixture measurement pending | partial |
| Scope violations | 0 | Scope/origin regression suite passes | implemented |
| Duplicate side effects | 0 | Atomic resume and bounded execution regressions pass | implemented |
| Worker/Docker qualification | Dedicated worker integration and permitted Docker runtime | Docker daemon access is denied in the current sandbox; live worker qualification is not claimed | blocked |
| CI reproducibility | 100% | CI/test-count/Ruff contracts present; provider-specific external CI run pending | partial |

## Execution order

The safe implementation order is: baseline and traceability, production blockers, surface graph, intent and identity workflows, campaign planner, validator/evidence plugins, proof engine, local WAPTLab fixtures, then coverage and release gates. Any row marked `blocked` must remain visible in release notes and cannot be silently converted to `implemented`.
