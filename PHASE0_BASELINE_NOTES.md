# Phase 0 baseline notes

## Inputs

- Reviewed archive: `/home/ubuntu/upload/webpent_v60_final_reviewed.zip`
- Archive SHA-256: `d7c344c600a9ab021938988998febc732dcb60e9c4ada58990f86523ca46e35a`
- Combined execution plan SHA-256: `a6bad1c2ae9f62b20269007edfdc878693d306f45b4a822aed48418e55a7f35c`
- Isolated workspace: `/tmp/webpent_v60_smart_implementation`
- WAPTLab and Juice Shop are outside this workspace and must not be modified.

## Source-verified observations

1. `src/webpent/shared/llm.py` contains a real `get_cached_llm()` implementation. It uses `_CACHED_LLMS`, `_CACHED_LLMS_LOCK`, dynamic provider resolution, and circuit-breaker-aware cache eviction. The claim that the helper has zero real implementation is stale; caller reachability still needs a source/runtime call-site audit.
2. `src/webpent/graph/builder.py` registers 31 base nodes plus optional `attack_graph`, and registers `smart_campaigns` and `smart_campaigns_execution` nodes. Smart campaigns are explicitly gated by `smart_mode`, `enable_smart_campaigns`, or governance profiles `safe-smart`/`authorized-active`.
3. The current graph path is planner -> auth -> optional recon/crawler/JS/infrastructure/target-understanding/scope/WAF -> hypothesis -> access control -> API testing -> business logic fuzzer -> request smuggling -> disclosed report intel -> optional attack graph/smart campaigns -> strategist -> payload generator -> execution sandbox -> validator -> bounded optimizer retry or devil's advocate -> exploit chainer -> bounded post-exploit -> rabbit-hole -> CVSS -> business impact -> cross-reasoning -> executive summary -> reporter -> reflection.
4. `execution_sandbox` is the approval boundary. `interrupt_before` is used unless `auto_approve=True`.
5. `src/webpent/memory/lessons.py` contains RAG moderation and cross-engagement lesson/hypothesis persistence. Detailed client/engagement read/write behavior must be audited before changing it.
6. `src/webpent/shared/self_critique.py` contains public APIs `recommend_self_critique_action()`, `should_fire_before_promotion()`, and `should_fire_every_n_discoveries()`. Actual graph/promotion callers must be traced before wiring new calls.
7. The previous final review baseline was 744 passed tests and Ruff zero; this new implementation must preserve or exceed it.

## Plan qualification boundary

The attached plan explicitly states that architecture claims are not proof. A feature is complete only when it is present in source, wired into graph/worker, exercised by integration tests, and visible in a redacted runtime trace. Qualification target is staged: Bounded Smart Autonomous Candidate -> Smart Research Beta -> VIP only after the three-run gates pass. No VIP claim will be made unless the local qualification evidence is actually produced.

## Baseline execution result (2026-08-19)

- Extracted archive test run: **700 passed, 110 warnings, 26.55s**.
- Extracted archive Ruff run with `ruff 0.16.3`, line length 100, configured rules E/F/I/N/W/UP/B/C4/SIM: **104 errors**.
- The archive therefore does not reproduce the previous claimed `744 passed / Ruff 0`; its `FINAL_REVIEW_REPORT.md` is inconsistent with executable contents. This is a release-blocking documentation/artifact regression and must be corrected before any Smart Hunter feature work is treated as complete.
- Because pytest passed, the current archive is functionally testable; because Ruff failed, the implementation baseline is not clean. No WAPTLab or Juice Shop files were modified.

## Additional source audit

- `src/webpent/memory/lessons.py` exposes `save_lesson`, `get_lessons`, `save_hypothesis`, `get_hypotheses`, `save_structured_hypothesis`, and `get_structured_hypotheses`; the audited section contains no `search_lessons` method. The current legacy lesson schema stores target URL/content/timestamp without a mandatory `client_id` or optional `engagement_id` retrieval contract. This is a concrete P0 memory-gap, not merely a documentation concern.
- `src/webpent/shared/llm.py` already has a dynamic circuit-breaker-aware cache, but static caller search found zero callers outside `llm.py`; existing agents use `try_get_llm` instead.
- `src/webpent/shared/confidence.py` already provides deterministic `compute_confidence_score()` and `recompute_hypothesis_confidence()`, but `hypothesis_analyzer` still creates several hypotheses with literal scores `0.6`, `0.5`, `0.3`, and `0.65/0.5`. The integration gap is real.
- `src/webpent/shared/self_critique.py` exposes deterministic/LLM-bounded recommendation functions, but static caller search found no callers outside the module; strategist has a decision-log label but needs actual recommendation wiring.
