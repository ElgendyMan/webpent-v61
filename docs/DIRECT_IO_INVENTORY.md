# G-02 Direct-I/O Inventory

> This artifact is generated from the current `src/**/*.py` AST and is
> enforced by the G-02 static/runtime gate. New direct transports,
> unclassified sites, or artifact drift fail closed until reviewed.

## Logical transport contract

| Transport | Boundary | Authority | Promotion/evidence contract |
|---|---|---|---|
| `http` | webpent.shared.http.make_safe_httpx_client | ActionAuthority/action_family=http_read|validation | response evidence plus verifier contract where promotion is requested |
| `browser` | Playwright sites listed in APPROVED_DIRECT_FILES | scope checks, playwright_enabled, and action policy | browser observation; confirmation additionally requires ProofBundle |
| `api` | http | API testing action family and target-origin scope | replay observation and strict verifier |
| `graphql` | http | API/validation action family and target-origin scope | query/response replay observation and strict verifier |
| `file_upload` | http | form_submit/file_upload policy and target-origin scope | upload response/replay observation and strict verifier |
| `oob` | http plus configured callback receiver | OOB preconditions, callback secret and target scope | correlated callback plus negative control and strict verifier |
| `subprocess` | webpent.tools.utils.subprocess.run_command or catalogued probes | tool allowlist, timeout, argv validation and action policy | bounded tool result; no confirmation without verifier evidence |
| `raw_tcp_dns` | catalogued request_smuggling/subdomain_takeover validators | target scope and validator-specific bounded controls | validator observation; no implicit promotion |
| `websocket` | registered HTTP/WebSocket adapter | target-origin scope, endpoint policy, and action ledger | bounded handshake/response observation plus strict verifier |
| `cloud` | registered cloud adapter | endpoint policy, credential restriction, and action ledger | redacted provider response plus strict verifier |
| `ssh` | registered SSH adapter | host/port allowlist, timeout, credential restriction | redacted bounded command result plus strict verifier |

## Source-level records

Total records: **63**.

| File | Line | Kind | Symbol | Transport | Approval |
|---|---:|---|---|---|---|
| `src/webpent/agents/access_control/agent.py` | 380 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/authentication/agent.py` | 189 | `import` | `playwright.sync_api.sync_playwright` | `browser_implementation` | `approved` |
| `src/webpent/agents/business_logic_fuzzer/agent.py` | 231 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/cloud_storage/agent.py` | 109 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/crawler/agent.py` | 183 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/crawler/agent.py` | 255 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/execution_sandbox/agent.py` | 71 | `import` | `playwright.sync_api.sync_playwright` | `browser_implementation` | `approved` |
| `src/webpent/agents/javascript_intelligence/agent.py` | 92 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/post_exploit/agent.py` | 256 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/agents/post_exploit/agent.py` | 337 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/recon/agent.py` | 673 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/recon/agent.py` | 684 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/request_smuggling/agent.py` | 36 | `import` | `socket` | `raw_tcp_dns_implementation` | `approved` |
| `src/webpent/agents/request_smuggling/agent.py` | 95 | `call` | `socket.create_connection` | `raw_tcp_dns` | `approved` |
| `src/webpent/agents/smart_campaigns/agent.py` | 1166 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/subdomain_takeover/agent.py` | 13 | `import` | `socket` | `raw_tcp_dns_implementation` | `approved` |
| `src/webpent/agents/subdomain_takeover/agent.py` | 89 | `call` | `socket.gethostbyname_ex` | `raw_tcp_dns` | `approved` |
| `src/webpent/agents/subdomain_takeover/agent.py` | 140 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/active_checks.py` | 163 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/agent.py` | 714 | `import` | `playwright.sync_api.sync_playwright` | `browser_implementation` | `approved` |
| `src/webpent/agents/validator/agent.py` | 897 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/agent.py` | 1353 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/agent.py` | 1692 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/agent.py` | 1752 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/agent.py` | 2284 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/agent.py` | 3577 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/agent.py` | 3677 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/structural_checks.py` | 103 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/structural_checks.py` | 573 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/structural_checks.py` | 1108 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/cli/__init__.py` | 189 | `import` | `playwright.sync_api.sync_playwright` | `browser_implementation` | `approved` |
| `src/webpent/cli/git_source.py` | 6 | `import` | `subprocess` | `subprocess_implementation` | `approved` |
| `src/webpent/cli/git_source.py` | 71 | `call` | `subprocess.run` | `subprocess` | `approved` |
| `src/webpent/cli/ingest.py` | 105 | `dynamic_import` | `importlib.import_module` | `dynamic_import` | `approved_with_expiry` |
| `src/webpent/integrations/webhook.py` | 256 | `safe_boundary_call` | `make_safe_httpx_async_client` | `http_async` | `approved` |
| `src/webpent/shared/capability_manifest.py` | 14 | `import` | `subprocess` | `subprocess_implementation` | `approved` |
| `src/webpent/shared/capability_manifest.py` | 59 | `call` | `subprocess.run` | `subprocess` | `approved` |
| `src/webpent/shared/grounding.py` | 590 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/shared/grounding.py` | 612 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/shared/http.py` | 131 | `import` | `socket` | `raw_tcp_dns_implementation` | `approved` |
| `src/webpent/shared/http.py` | 135 | `import` | `httpx` | `http_implementation` | `approved` |
| `src/webpent/shared/http.py` | 273 | `call` | `socket.getaddrinfo` | `raw_tcp_dns` | `approved` |
| `src/webpent/shared/http.py` | 322 | `call` | `socket.getaddrinfo` | `raw_tcp_dns` | `approved` |
| `src/webpent/shared/http.py` | 910 | `call` | `httpx.Client` | `http_sync` | `approved` |
| `src/webpent/shared/http.py` | 966 | `call` | `httpx.AsyncClient` | `http_async` | `approved` |
| `src/webpent/shared/http_discovery.py` | 359 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/shared/preflight.py` | 78 | `import` | `playwright` | `browser_implementation` | `approved` |
| `src/webpent/shared/reference_lookup.py` | 111 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/tools/exploitation/dalfox.py` | 172 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/exploitation/dalfox.py` | 214 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/exploitation/phpggc.py` | 141 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/exploitation/sqlmap.py` | 442 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/exploitation/ysoserial.py` | 170 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/recon/ffuf.py` | 103 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/recon/httpx.py` | 107 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/recon/katana.py` | 167 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/recon/nuclei.py` | 194 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/recon/subfinder.py` | 64 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/registry.py` | 215 | `dynamic_import` | `importlib.reload` | `dynamic_import` | `approved_with_expiry` |
| `src/webpent/tools/registry.py` | 217 | `dynamic_import` | `importlib.import_module` | `dynamic_import` | `approved_with_expiry` |
| `src/webpent/tools/utils/subprocess.py` | 68 | `import` | `subprocess` | `subprocess_implementation` | `approved` |
| `src/webpent/tools/utils/subprocess.py` | 243 | `call` | `subprocess.Popen` | `subprocess` | `approved` |
| `src/webpent/tools/utils/subprocess.py` | 257 | `call` | `subprocess.Popen` | `subprocess` | `approved` |

## Enforcement rules

Raw imports and raw transport calls are permitted only in reviewed boundary files and symbol-scoped approvals. Application code uses hardened HTTP helpers, the bounded subprocess wrapper, or an explicitly catalogued validator exception.

Unknown and indirect transport resolution remain missing-validator states; they are never promoted to confirmation by this artifact.
