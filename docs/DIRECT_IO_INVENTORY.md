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

Total records: **280**.

| File | Line | Kind | Symbol | Transport | Approval |
|---|---:|---|---|---|---|
| `src/webpent/agents/access_control/agent.py` | 381 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/access_control/agent.py` | 586 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/access_control/agent.py` | 666 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/access_control/agent.py` | 819 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/access_control/agent.py` | 898 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/access_control/agent.py` | 987 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/access_control/agent.py` | 1039 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/access_control/agent.py` | 1040 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/access_control/agent.py` | 1041 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/access_control/agent.py` | 1143 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/api_testing/agent.py` | 121 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/api_testing/agent.py` | 123 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/api_testing/agent.py` | 616 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/authentication/agent.py` | 250 | `import` | `playwright.sync_api.sync_playwright` | `browser_implementation` | `approved` |
| `src/webpent/agents/authentication/agent.py` | 1015 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/business_impact/agent.py` | 133 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/business_logic_fuzzer/agent.py` | 46 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/business_logic_fuzzer/agent.py` | 49 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/business_logic_fuzzer/agent.py` | 63 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/business_logic_fuzzer/agent.py` | 85 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/business_logic_fuzzer/agent.py` | 231 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/business_logic_fuzzer/agent.py` | 319 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/business_logic_fuzzer/agent.py` | 387 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/business_logic_fuzzer/agent.py` | 485 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/cloud_storage/agent.py` | 109 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/crawler/agent.py` | 184 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/crawler/agent.py` | 256 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/crawler/agent.py` | 466 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/crawler/agent.py` | 480 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/crawler/agent.py` | 572 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/crawler/agent.py` | 573 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/crawler/agent.py` | 750 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/crawler/agent.py` | 756 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/crawler/agent.py` | 768 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/cross_reasoning/agent.py` | 264 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/disclosed_report_intel/agent.py` | 63 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/execution_sandbox/agent.py` | 72 | `import` | `playwright.sync_api.sync_playwright` | `browser_implementation` | `approved` |
| `src/webpent/agents/execution_sandbox/agent.py` | 566 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/executive_summary/agent.py` | 124 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/executive_summary/agent.py` | 198 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/exploit_chainer/agent.py` | 88 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/hypothesis_analyzer/agent.py` | 1033 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/hypothesis_analyzer/agent.py` | 1155 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/javascript_intelligence/agent.py` | 26 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/javascript_intelligence/agent.py` | 93 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/javascript_intelligence/agent.py` | 153 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/javascript_intelligence/agent.py` | 161 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/payload_generator/agent.py` | 238 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/payload_generator/agent.py` | 240 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/payload_generator/agent.py` | 270 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/payload_generator/agent.py` | 271 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/payload_generator/agent.py` | 370 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/planner/agent.py` | 113 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/planner/agent.py` | 114 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/planner/agent.py` | 125 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/planner/agent.py` | 140 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/post_exploit/agent.py` | 256 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/agents/post_exploit/agent.py` | 337 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/post_exploit/agent.py` | 438 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/post_exploit/agent.py` | 510 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/recon/agent.py` | 681 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/recon/agent.py` | 692 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/reflection/agent.py` | 138 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/reflection/agent.py` | 139 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/reflection/agent.py` | 375 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/reflection/agent.py` | 396 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/reporter/agent.py` | 52 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/reporter/agent.py` | 519 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/reporter/agent.py` | 719 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/reporter/agent.py` | 831 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/request_smuggling/agent.py` | 36 | `import` | `socket` | `raw_tcp_dns_implementation` | `approved` |
| `src/webpent/agents/request_smuggling/agent.py` | 95 | `call` | `socket.create_connection` | `raw_tcp_dns` | `approved` |
| `src/webpent/agents/request_smuggling/agent.py` | 339 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/request_smuggling/agent.py` | 538 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/smart_campaigns/agent.py` | 114 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/smart_campaigns/agent.py` | 133 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/smart_campaigns/agent.py` | 207 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/smart_campaigns/agent.py` | 778 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/smart_campaigns/agent.py` | 955 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/smart_campaigns/agent.py` | 957 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/smart_campaigns/agent.py` | 958 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/smart_campaigns/agent.py` | 961 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/smart_campaigns/agent.py` | 968 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/smart_campaigns/agent.py` | 1061 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/smart_campaigns/agent.py` | 1063 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/smart_campaigns/agent.py` | 1085 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/smart_campaigns/agent.py` | 1257 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/smart_campaigns/agent.py` | 1623 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/smart_campaigns/agent.py` | 1669 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/strategist/agent.py` | 103 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/strategist/agent.py` | 504 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/strategist/agent.py` | 544 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/strategist/agent.py` | 556 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/strategist/agent.py` | 585 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/strategist/agent.py` | 627 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/subdomain_takeover/agent.py` | 14 | `import` | `socket` | `raw_tcp_dns_implementation` | `approved` |
| `src/webpent/agents/subdomain_takeover/agent.py` | 91 | `call` | `socket.gethostbyname_ex` | `raw_tcp_dns` | `approved` |
| `src/webpent/agents/subdomain_takeover/agent.py` | 142 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/subdomain_takeover/agent.py` | 223 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/validator/active_checks.py` | 164 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/agent.py` | 499 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/validator/agent.py` | 596 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/validator/agent.py` | 745 | `import` | `playwright.sync_api.sync_playwright` | `browser_implementation` | `approved` |
| `src/webpent/agents/validator/agent.py` | 928 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/agent.py` | 1322 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/validator/agent.py` | 1340 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/validator/agent.py` | 1384 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/agent.py` | 1535 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/validator/agent.py` | 1723 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/agent.py` | 1783 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/agent.py` | 2319 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/agent.py` | 2580 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/validator/agent.py` | 2581 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/validator/agent.py` | 2582 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/validator/agent.py` | 2918 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/validator/agent.py` | 2920 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/validator/agent.py` | 2967 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/validator/agent.py` | 3019 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/validator/agent.py` | 3026 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/validator/agent.py` | 3061 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/validator/agent.py` | 3192 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/validator/agent.py` | 3574 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/validator/agent.py` | 3614 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/agent.py` | 3715 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/structural_checks.py` | 89 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/validator/structural_checks.py` | 104 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/structural_checks.py` | 575 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/validator/structural_checks.py` | 1111 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/agents/waf_detector/agent.py` | 92 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/agents/waf_detector/agent.py` | 93 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/cli/__init__.py` | 285 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/cli/__init__.py` | 304 | `import` | `playwright.sync_api.sync_playwright` | `browser_implementation` | `approved` |
| `src/webpent/cli/__init__.py` | 982 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/cli/__init__.py` | 984 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/cli/__init__.py` | 1093 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/cli/git_source.py` | 6 | `import` | `subprocess` | `subprocess_implementation` | `approved` |
| `src/webpent/cli/git_source.py` | 71 | `call` | `subprocess.run` | `subprocess` | `approved` |
| `src/webpent/cli/ingest.py` | 105 | `dynamic_import` | `importlib.import_module` | `dynamic_import` | `approved_with_expiry` |
| `src/webpent/cli/ingest.py` | 106 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/graph/builder.py` | 855 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/graph/builder.py` | 1010 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/integrations/webhook.py` | 256 | `safe_boundary_call` | `make_safe_httpx_async_client` | `http_async` | `approved` |
| `src/webpent/memory/db.py` | 845 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/memory/embeddings.py` | 80 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/memory/embeddings.py` | 88 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/action_authority.py` | 159 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/adaptive_hunt.py` | 71 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/adaptive_hunt.py` | 79 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/adaptive_hunt.py` | 537 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/adaptive_hunt.py` | 538 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/capability_manifest.py` | 14 | `import` | `subprocess` | `subprocess_implementation` | `approved` |
| `src/webpent/shared/capability_manifest.py` | 59 | `call` | `subprocess.run` | `subprocess` | `approved` |
| `src/webpent/shared/capability_manifest.py` | 144 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/capability_manifest.py` | 145 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/causal_research.py` | 29 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/confidence.py` | 369 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/control_plane_spine.py` | 181 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/differential_workflow.py` | 160 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/direct_io_inventory.py` | 522 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/direct_io_inventory.py` | 523 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/ensemble.py` | 19 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/ensemble.py` | 35 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/finding_aggregation.py` | 39 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/grounding.py` | 590 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/shared/grounding.py` | 612 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/shared/http.py` | 131 | `import` | `socket` | `raw_tcp_dns_implementation` | `approved` |
| `src/webpent/shared/http.py` | 135 | `import` | `httpx` | `http_implementation` | `approved` |
| `src/webpent/shared/http.py` | 312 | `call` | `socket.getaddrinfo` | `raw_tcp_dns` | `approved` |
| `src/webpent/shared/http.py` | 361 | `call` | `socket.getaddrinfo` | `raw_tcp_dns` | `approved` |
| `src/webpent/shared/http.py` | 949 | `call` | `httpx.Client` | `http_sync` | `approved` |
| `src/webpent/shared/http.py` | 1005 | `call` | `httpx.AsyncClient` | `http_async` | `approved` |
| `src/webpent/shared/http.py` | 1311 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/http.py` | 1361 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/http.py` | 1373 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/http.py` | 1438 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/http_discovery.py` | 338 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/http_discovery.py` | 365 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/shared/http_discovery.py` | 402 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/http_discovery.py` | 428 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/http_discovery.py` | 431 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/http_discovery.py` | 448 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/http_discovery.py` | 473 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/http_discovery.py` | 581 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/identity_provisioning.py` | 368 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/identity_provisioning.py` | 378 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/identity_provisioning.py` | 384 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/javascript_intelligence.py` | 407 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/kev.py` | 20 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/kev.py` | 24 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/kev.py` | 25 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/llm.py` | 166 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/llm.py` | 242 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/llm.py` | 529 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/llm.py` | 533 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/llm.py` | 536 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/llm.py` | 540 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/llm.py` | 1285 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/package_preflight.py` | 73 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/planner_decisions.py` | 70 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/planner_decisions.py` | 74 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/planner_decisions.py` | 250 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/poc_policy.py` | 44 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/poc_policy.py` | 80 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/poc_policy.py` | 84 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/preflight.py` | 54 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/preflight.py` | 78 | `import` | `playwright` | `browser_implementation` | `approved` |
| `src/webpent/shared/preflight.py` | 80 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/preflight.py` | 120 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/preflight.py` | 125 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/preflight.py` | 160 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/preflight.py` | 306 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/preflight.py` | 348 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/preflight.py` | 406 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/preflight.py` | 415 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/preflight.py` | 417 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/preflight.py` | 420 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/preflight.py` | 522 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/prioritization.py` | 194 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/prioritization.py` | 197 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/prioritization.py` | 206 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/prioritization.py` | 265 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/prioritization.py` | 287 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/prioritization.py` | 288 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/prioritization.py` | 297 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/prioritization.py` | 303 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/prioritization.py` | 434 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/prioritization.py` | 564 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/prioritization.py` | 728 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/prioritization.py` | 730 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/rate_governor.py` | 317 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/rate_governor.py` | 318 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/reference_lookup.py` | 111 | `safe_boundary_call` | `make_safe_httpx_client` | `http_sync` | `approved` |
| `src/webpent/shared/runtime.py` | 622 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/safety_gate.py` | 191 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/safety_gate.py` | 199 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/safety_gate.py` | 201 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/secondary_io_scanner.py` | 18 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/self_critique.py` | 299 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/self_critique.py` | 318 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/self_critique.py` | 337 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/self_critique.py` | 350 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/self_critique.py` | 355 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/self_critique.py` | 688 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/stealth.py` | 56 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/target_workspace.py` | 174 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/shared/trust_matrix.py` | 17 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/state/initial_state.py` | 158 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/state/initial_state.py` | 190 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/state/initial_state.py` | 191 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/state/reducers.py` | 33 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/state/reducers.py` | 52 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/tools/exploitation/dalfox.py` | 172 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/exploitation/dalfox.py` | 214 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/exploitation/phpggc.py` | 141 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/exploitation/sqlmap.py` | 315 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/tools/exploitation/sqlmap.py` | 316 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/tools/exploitation/sqlmap.py` | 317 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/tools/exploitation/sqlmap.py` | 442 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/exploitation/ysoserial.py` | 170 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/recon/ffuf.py` | 107 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/tools/recon/ffuf.py` | 109 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/recon/httpx.py` | 107 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/recon/katana.py` | 173 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/recon/nuclei.py` | 201 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/recon/subfinder.py` | 64 | `safe_boundary_call` | `run_command` | `subprocess_boundary` | `approved` |
| `src/webpent/tools/registry.py` | 215 | `dynamic_import` | `importlib.reload` | `dynamic_import` | `approved_with_expiry` |
| `src/webpent/tools/registry.py` | 217 | `dynamic_import` | `importlib.import_module` | `dynamic_import` | `approved_with_expiry` |
| `src/webpent/tools/utils/subprocess.py` | 68 | `import` | `subprocess` | `subprocess_implementation` | `approved` |
| `src/webpent/tools/utils/subprocess.py` | 243 | `call` | `subprocess.Popen` | `subprocess` | `approved` |
| `src/webpent/tools/utils/subprocess.py` | 257 | `call` | `subprocess.Popen` | `subprocess` | `approved` |
| `src/webpent/utils/compliance.py` | 154 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/utils/task_crypto.py` | 134 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/workers/pentest_worker.py` | 102 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/workers/pentest_worker.py` | 116 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/workers/pentest_worker.py` | 135 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/workers/pentest_worker.py` | 136 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/workers/pentest_worker.py` | 137 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/workers/pentest_worker.py` | 235 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/workers/pentest_worker.py` | 1083 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |
| `src/webpent/workers/pentest_worker.py` | 1188 | `dynamic_resolution` | `getattr` | `dynamic_resolution` | `not_applicable` |

## Enforcement rules

Raw imports and raw transport calls are permitted only in reviewed boundary files and symbol-scoped approvals. Application code uses hardened HTTP helpers, the bounded subprocess wrapper, or an explicitly catalogued validator exception.

Unknown and indirect transport resolution remain missing-validator states; they are never promoted to confirmation by this artifact.
