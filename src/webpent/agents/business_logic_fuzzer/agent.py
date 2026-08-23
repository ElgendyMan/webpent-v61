# src/webpent/agents/business_logic_fuzzer/agent.py
"""webpent.agents.business_logic_fuzzer.agent

V7 Sprint 2.7 — Business Logic Fuzzer (Race Conditions + State Abuse).

Detects business-logic vulnerabilities that traditional scanners miss:
race conditions (double-spend, TOCTOU in balance updates), workflow
bypass (skipping required steps), and state-machine abuse (applying a
discount code twice, using a coupon after expiry).

The agent identifies state-changing endpoints (POST/PUT/DELETE) from
crawled data, then sends concurrent request bursts to detect race
conditions. All bursts are gated by the
:class:`RequestRateGovernor <webpent.shared.rate_governor.RequestRateGovernor>`
to prevent accidental DoS.
"""

from __future__ import annotations

import logging
import threading
from typing import Any
from urllib.parse import urljoin, urlparse
from uuid import NAMESPACE_URL, uuid5

from langchain_core.messages import AIMessage

from webpent.models.findings import Finding, Severity, VulnClass
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)

# Concurrent burst size for race-condition testing.
_BURST_SIZE = 10
# Maximum endpoints to fuzz per engagement (bounds engagement time).
_MAX_ENDPOINTS = 10


def _runtime_business_logic_limits() -> tuple[int, int]:
    """Return bounded, operator-tunable burst and endpoint limits."""
    try:
        from webpent.config.settings import get_settings

        settings = get_settings()
        burst_size = int(
            getattr(settings, "business_logic_burst_size", _BURST_SIZE)
        )
        max_endpoints = int(
            getattr(settings, "business_logic_max_endpoints", _MAX_ENDPOINTS)
        )
        return (
            max(1, min(burst_size, 20)),
            max(1, min(max_endpoints, 25)),
        )
    except Exception as exc:  # noqa: BLE001 - safe compatibility fallback
        logger.debug("Using default business-logic limits: %s", exc)
        return _BURST_SIZE, _MAX_ENDPOINTS


def _target_url(target: Any) -> str:
    if isinstance(target, dict):
        return str(target.get("url") or "")
    return str(getattr(target, "url", "") or "")


def _workflow_enrichment(
    state: PentestState,
    crawled_data: dict[str, Any],
    target: Any,
) -> dict[str, Any]:
    """Passively enrich state when the additive workflow flag is enabled."""
    try:
        from webpent.config.settings import get_settings

        if not get_settings().enable_workflow_understanding:
            return {}
        from webpent.models.hypothesis import Hypothesis, HypothesisOrigin
        from webpent.shared.workflow_understanding import (
            extract_workflow_observations,
            generate_business_logic_hypotheses,
            workflow_coverage_gaps,
        )

        target_url = _target_url(target)
        scope_checker = getattr(target, "is_in_scope", None)
        observations = extract_workflow_observations(
            crawled_data,
            target_url=target_url,
            scope_checker=scope_checker if callable(scope_checker) else None,
        )
        specs = generate_business_logic_hypotheses(observations, target_url=target_url)
        hypotheses = [
            Hypothesis(
                id=uuid5(NAMESPACE_URL, f"webpent:workflow:{spec.fingerprint}"),
                target_url=spec.target_url,
                statement=spec.statement,
                vuln_class=spec.vuln_class,
                confidence_score=spec.confidence_score,
                evidence_refs=spec.evidence_refs,
                origin=HypothesisOrigin.HEURISTIC,
                origin_detail=spec.origin_detail,
                evidence_contract=spec.evidence_contract,
                hint_provenance=spec.hint_provenance or ["business_logic"],
                estimated_cost=float(spec.request_budget),
            )
            for spec in specs
        ]
        logger.info(
            "Workflow understanding: %d observations, %d bounded hypotheses, %d gaps",
            len(observations),
            len(hypotheses),
            len(workflow_coverage_gaps(crawled_data, observations)),
        )
        return {
            "workflow_observations": [item.model_dump(mode="json") for item in observations],
            "workflow_coverage_gaps": workflow_coverage_gaps(crawled_data, observations),
            "hypotheses": hypotheses,
        }
    except Exception as exc:
        logger.warning("Workflow understanding skipped safely: %s", exc)
        return {
            "workflow_coverage_gaps": [
                {
                    "gap": "workflow_understanding_error",
                    "reason": "The passive workflow projection failed closed.",
                    "status": "error",
                }
            ],
        }


def _extract_state_changing_endpoints(
    crawled_data: dict[str, Any],
    max_endpoints: int = _MAX_ENDPOINTS,
) -> list[dict[str, Any]]:
    """Extract POST/PUT/DELETE endpoints from crawled data.

    Returns a list of dicts: ``{"url": str, "method": str, "form_data": dict}``.

    V9 P0 B5: previously this function fell back to treating every
    entry in ``crawled_data["endpoints"]`` (a list of URL strings) as
    a POST target — sending blind POST bursts to arbitrary URLs the
    crawler discovered. That's a broad attack surface with no signal
    that the endpoint actually accepts POST or has state-changing
    semantics. Now we ONLY act on structured form metadata in
    ``crawled_data["forms"]`` — each form dict must have an ``action``
    (or ``url``) and a ``method``. If no forms are populated, the
    fuzzer returns no endpoints (safe degradation — no findings, no
    broad POST noise). The crawler can be enhanced separately to
    populate ``crawled_data["forms"]`` with real form metadata.
    """
    endpoints: list[dict[str, Any]] = []

    if isinstance(crawled_data, dict):
        # V9 P0 B5: ONLY look at structured form metadata. Do NOT fall
        # back to bare endpoint URL strings — a blind POST to every
        # crawled URL is a broad attack with no exploitability signal.
        forms = crawled_data.get("forms") or []
        if isinstance(forms, list):
            for form in forms:
                if isinstance(form, dict):
                    method = str(form.get("method", "POST")).upper()
                    if method in ("POST", "PUT", "PATCH", "DELETE"):
                        url = form.get("action") or form.get("url")
                        if url:
                            endpoints.append(
                                {
                                    "url": url,
                                    "method": method,
                                    "form_data": form.get("data") or form.get("fields") or {},
                                }
                            )

    # Deduplicate by (url, method)
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for ep in endpoints:
        key = (ep["url"], ep["method"])
        if key not in seen:
            seen.add(key)
            unique.append(ep)

    return unique[:max(1, min(int(max_endpoints), 25))]


def _send_concurrent_burst(
    url: str,
    method: str,
    form_data: dict[str, Any],
    cookies: dict[str, str] | None = None,
    burst_size: int = _BURST_SIZE,
) -> list[int]:
    """Send ``burst_size`` concurrent identical requests to ``url``.

    Returns a list of HTTP status codes received. Uses the
    :class:`RequestRateGovernor` to enforce the concurrent cap and
    error-rate abort.

    All requests use ``make_safe_httpx_client`` (SSRF guard +
    engagement-scope allowlist).

    V9 P0 B1: worker threads now inherit the parent thread's
    contextvars via ``contextvars.copy_context().run()``. Without this,
    the engagement-scope allowlist (a ContextVar) is empty inside the
    worker thread, so ``make_safe_httpx_client``'s SSRF guard blocks
    the operator-declared private-IP target — the module fails closed
    with zero requests reaching the target.
    """
    import contextvars

    from webpent.shared.http import make_safe_httpx_client
    from webpent.shared.rate_governor import get_rate_governor

    governor = get_rate_governor()
    host = urlparse(url).hostname or "unknown"

    results: list[int] = []
    results_lock = threading.Lock()

    def _worker():
        try:
            with governor.acquire(host) as permit:
                if permit.aborted:
                    logger.debug("Race-condition burst aborted: %s", permit.reason)
                    return
                headers: dict[str, str] = {}
                if cookies:
                    from webpent.shared.http import build_cookie_header

                    headers["Cookie"] = build_cookie_header(cookies)
                with make_safe_httpx_client(
                    timeout=10.0, follow_redirects=False, verify=True
                ) as client:
                    if method == "POST":
                        resp = client.post(url, data=form_data, headers=headers)
                    elif method == "PUT":
                        resp = client.put(url, data=form_data, headers=headers)
                    elif method == "PATCH":
                        resp = client.patch(url, data=form_data, headers=headers)
                    elif method == "DELETE":
                        resp = client.delete(url, headers=headers)
                    else:
                        resp = client.post(url, data=form_data, headers=headers)
                governor.record_response(host, resp.status_code)
                with results_lock:
                    results.append(resp.status_code)
        except Exception as exc:
            logger.debug("Race-condition burst worker error: %s", exc)

    # V9 P0 B1: capture the parent thread's contextvars (including the
    # engagement-scope allowlist) and run each worker inside a copy.
    # ``contextvars.copy_context()`` returns a snapshot of the current
    # context; ``ctx.run(_worker)`` executes _worker with that context
    # active, so ContextVar lookups inside _worker see the parent's
    # values. This is the standard Python way to propagate contextvars
    # across thread boundaries.
    #
    # V9 P1 FIX: a ``contextvars.Context`` object is NOT reentrant
    # across concurrently-running threads — only one thread may be
    # "inside" ``ctx.run()`` at a time. The previous code called
    # ``contextvars.copy_context()`` ONCE and handed the SAME Context
    # object to every burst thread's ``target=``. As soon as two
    # threads were inside ``_worker`` at once (guaranteed here, since
    # ``_worker`` blocks on network I/O), every thread after the first
    # raised ``RuntimeError: cannot enter context: ... is already
    # entered`` — silently, since it propagates out of the Thread's
    # ``run()`` and is only ever printed to stderr by the default
    # excepthook, never caught by ``_worker``'s own try/except. Net
    # effect: a "burst_size-request concurrent burst" only ever ran
    # ONE request; the other burst_size-1 threads died before calling
    # the target at all. Since ``_detect_race_condition`` requires
    # more than one 2xx in the burst, race conditions were essentially
    # undetectable regardless of the cookie fix above.
    #
    # Fix: call ``contextvars.copy_context()`` separately for EACH
    # thread (still from this parent thread, so each copy still
    # carries the parent's ContextVar values — including the
    # engagement-scope allowlist) so every thread gets its own,
    # independently-enterable Context object.
    threads = [
        threading.Thread(target=contextvars.copy_context().run, args=(_worker,))
        for _ in range(burst_size)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30.0)

    return results


def _detect_race_condition(status_codes: list[int]) -> bool:
    """Check if the status codes indicate a race condition.

    A race condition is detected when more than one request in the
    burst succeeded (returned 2xx) for an operation that should only
    succeed once (e.g., a withdrawal, a coupon application, a vote).
    """
    success_count = sum(1 for sc in status_codes if 200 <= sc < 300)
    return success_count > 1


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).
def business_logic_fuzzer_node(state: PentestState) -> dict:
    """LangGraph node: fuzz business-logic vulnerabilities via concurrent bursts.

    V7 Sprint 2.7: Identifies state-changing endpoints, sends
    concurrent request bursts (size 10) to each, and raises a finding
    if more than one request in the burst succeeds (indicating a race
    condition in the target's state update logic).
    """
    target = state.get("target")
    findings: list[Finding] = list(state.get("findings") or [])
    crawled_data: dict[str, Any] = state.get("crawled_data") or {}
    workflow_update = _workflow_enrichment(state, crawled_data, target)

    logger.info(
        "Business Logic Fuzzer (V7 Sprint 2.7) entered for target=%s (%d findings)",
        getattr(target, "url", "<unknown>"),
        len(findings),
    )

    # Verify the RequestRateGovernor is available (wiring test per
    # Principle 4: no dead guardrails).
    try:
        from webpent.shared.rate_governor import get_rate_governor

        governor = get_rate_governor()
        logger.debug(
            "Business Logic Fuzzer: RequestRateGovernor available (max_concurrent=%d)",
            governor._max_concurrent,
        )
    except ImportError:
        logger.warning(
            "Business Logic Fuzzer: RequestRateGovernor not importable — skipping bursts."
        )
        return {
            **workflow_update,
            "messages": [
                AIMessage(content="Business Logic Fuzzer: rate governor unavailable — skipped.")
            ],
            "current_phase": "business_logic_fuzzing",
        }

    # Extract state-changing endpoints using bounded operator settings.
    burst_size, max_endpoints = _runtime_business_logic_limits()
    endpoints = _extract_state_changing_endpoints(
        crawled_data,
        max_endpoints=max_endpoints,
    )
    if not endpoints:
        logger.info("Business Logic Fuzzer: no state-changing endpoints found")
        return {
            **workflow_update,
            "messages": [
                AIMessage(content="Business Logic Fuzzer: no state-changing endpoints found.")
            ],
            "current_phase": "business_logic_fuzzing",
        }

    # Extract session cookies.
    #
    # V9 P1 FIX: auth_node ALWAYS stores state["auth_state"]["cookies"]
    # as list[{"name": ..., "value": ..., "domain": ...}] — see
    # authentication/agent.py (both the operator-supplied-cookies path
    # and the Playwright-login path build this same list shape). The
    # previous `isinstance(auth_state.get("cookies"), dict)` check here
    # therefore always evaluated False, so auth_cookies was always None
    # and every fuzzer burst request went out unauthenticated.
    #
    # auth_node writes the SAME cookies to state["session_cookies"] as a
    # flat dict[str, str] — that field is the canonical, already-
    # flattened session-cookie jar every other cookie-consuming agent
    # reads from (crawler, recon/nuclei, validator/sqlmap+dalfox,
    # api_testing, request_smuggling). Match that established pattern
    # here instead of parsing the list form.
    auth_cookies: dict[str, str] | None = state.get("session_cookies") or None

    new_findings: list[Finding] = []

    for ep in endpoints:
        url = ep["url"]
        method = ep["method"]
        form_data = ep["form_data"]

        # Resolve relative URLs against the target.
        base_url = getattr(target, "url", "")
        if not url.startswith("http") and base_url:
            url = urljoin(base_url, url)

        logger.info(
            "Business Logic Fuzzer: bursting %s %s (%d requests)",
            method,
            url,
            burst_size,
        )

        status_codes = _send_concurrent_burst(
            url,
            method,
            form_data,
            cookies=auth_cookies,
            burst_size=burst_size,
        )

        if _detect_race_condition(status_codes):
            success_count = sum(1 for sc in status_codes if 200 <= sc < 300)
            # V10 RESIDUAL FIX: wrap Finding construction in a narrow
            # try/except so a pydantic ValidationError (or any other
            # construction bug) is logged at ERROR and the for loop
            # continues to the next endpoint, instead of crashing the
            # business_logic_fuzzer_node entirely (which would lose all
            # subsequent race-condition findings and abort the graph
            # node). Mirrors access_control / request_smuggling pattern.
            status_histogram: dict[str, int] = {}
            for status_code in status_codes:
                key = str(status_code)
                status_histogram[key] = status_histogram.get(key, 0) + 1
            try:
                finding = Finding(
                    title=f"Race condition: {method} {urlparse(url).path}",
                    description=(
                        f"The endpoint {url} accepted {success_count} concurrent "
                        f"{method} requests in a burst of {len(status_codes)}. "
                        f"This indicates a race condition in the server's state "
                        f"update logic — an attacker can exploit this to "
                        f"double-spend, apply a coupon multiple times, or "
                        f"bypass a use-count limit."
                    ),
                    severity=Severity.HIGH,
                    confidence_level="AI-Assessed",
                    # V10 P0-1: VulnClass.RACE_CONDITION is now a real enum
                    # member (added in V9 P1 FIX). Use the enum value for
                    # type-safety instead of the raw string.
                    vuln_class=VulnClass.RACE_CONDITION.value,
                    url=url,
                    tool_name="business_logic_fuzzer",
                    payload=str(form_data)[:200] if form_data else "",
                    reasoning=(
                        f"Sent {_BURST_SIZE} concurrent {method} requests to "
                        f"{url}. {success_count} returned 2xx (status codes: "
                        f"{status_codes}). More than one success in a burst "
                        f"indicates the server does not atomically serialize "
                        f"state-changing operations."
                    ),
                    evidence={
                        "race_probe": {
                            "observation_type": "candidate_burst_summary",
                            "target_backed": True,
                            "proof_ready": False,
                            "method": method,
                            "path": urlparse(url).path,
                            "burst_size": len(status_codes),
                            "candidate_successes": success_count,
                            "status_code_histogram": status_histogram,
                            "requires_baseline_negative_control_replay": True,
                        }
                    },
                )
            except Exception as exc:
                logger.error(
                    "business_logic_fuzzer: failed to construct race-condition "
                    "finding for %s %s: %s",
                    method,
                    url,
                    exc,
                )
                finding = None
            if finding is not None:
                new_findings.append(finding)
                logger.warning(
                    "Race condition detected at %s %s (%d/%d succeeded)",
                    method,
                    url,
                    success_count,
                    len(status_codes),
                )

    logger.info("Business Logic Fuzzer: %d findings generated", len(new_findings))

    # V7 Cognitive Upgrade — Phase 2: extract Mental Model updates for
    # the state-changing endpoints this node fuzzed. Pure additive —
    # does not change any existing fuzzer logic. Deterministic
    # regex/heuristic, NO LLM.
    mental_model_update: dict[str, Any] = {"nodes": {}, "edges": []}
    try:
        from webpent.models.mental_model import extract_mental_model_updates

        # `endpoints` is a list[dict[str, Any]] with a "url" key —
        # extract just the URLs for the Mental Model extractor.
        fuzzer_endpoint_urls: list[str] = []
        for ep in endpoints:
            if isinstance(ep, dict):
                u = ep.get("url") or ep.get("endpoint") or ""
                if u:
                    fuzzer_endpoint_urls.append(u)
            elif isinstance(ep, str):
                fuzzer_endpoint_urls.append(ep)
        mental_model_update = extract_mental_model_updates(
            discovery_source="business_logic_fuzzer_node",
            endpoints=fuzzer_endpoint_urls,
            target_url=getattr(target, "url", None),
        )
    except Exception as exc:
        logger.debug("Mental Model extraction (business_logic_fuzzer) failed: %s", exc)

    message = (
        f"Business Logic Fuzzer: fuzzed {len(endpoints)} "
        f"endpoints with {_BURST_SIZE}-request bursts. Found "
        f"{len(new_findings)} race conditions."
    )
    if workflow_update:
        message += (
            f" Workflow understanding added "
            f"{len(workflow_update.get('workflow_observations', []))} observations "
            f"and {len(workflow_update.get('hypotheses', []))} bounded hypotheses."
        )
    return {
        **workflow_update,
        # merge_findings reducer dedup by id — safe
        "findings": findings + new_findings,
        "mental_model": mental_model_update,
        "messages": [AIMessage(content=message)],
        "current_phase": "business_logic_fuzzing",
    }
