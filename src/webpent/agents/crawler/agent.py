# src/webpent/agents/crawler/agent.py
"""webpent.agents.crawler.agent

LangGraph node that performs deep crawling with katana and LLM-based
endpoint triage.

Phase 5 introduces a **Hybrid Supervisor** architecture:

  1. **Tool does the heavy lifting.** Katana recursively crawls the
     target to depth 3, discovering every reachable endpoint (including
     JavaScript-rendered routes that single-page fetchers miss).
  2. **LLM acts as a supervisor.** The discovered URLs are passed to
     the LLM, which ranks them by exploitability potential (parameters,
     login pages, API routes) and returns a prioritized endpoint list.
     Coverage-aware selection keeps the downstream validator's
     work queue bounded without dropping entire endpoint families.

Resilience:
    Both katana and the LLM supervisor are wrapped in ``try/except``.
    If katana fails (not installed, timeout, non-zero exit), the node
    returns an empty endpoint list. If the LLM supervisor fails (all
    providers unavailable, malformed JSON), the node falls back to a bounded
    raw discovery sample.

"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlsplit

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from webpent.shared.exceptions import ToolExecutionError, ToolNotFoundError
from webpent.shared.http_discovery import discover_http_surface
from webpent.shared.identity_provisioning import project_signup_form_events
from webpent.shared.llm import (
    TaskType,
    get_cached_llm,
    get_safety_system_instruction,
    is_llm_enabled,
    safe_prompt_format,
)
from webpent.shared.recon_triage import build_coverage_preserving_queue
from webpent.state.state import PentestState
from webpent.tools.recon.katana import run_katana


def get_llm(task_type: TaskType) -> Any:
    """Legacy patch point routed through the shared LLM cache."""
    return get_cached_llm(task_type)


logger = logging.getLogger(__name__)


# V7 Sprint 3.1b: Regex patterns for extracting secrets from JavaScript.
# Each pattern matches common API key / token formats. The patterns
# are deliberately conservative — they require a key-like prefix
# (e.g. "api_key", "apiKey", "AWS_SECRET") to avoid matching arbitrary
# base64 strings.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "AWS Secret Key",
        re.compile(
            r"aws_secret_access_key[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9/+=]{40})[\"']", re.IGNORECASE
        ),
    ),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Stripe Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{24}")),
    ("Stripe Publishable Key", re.compile(r"pk_live_[0-9a-zA-Z]{24}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,48}")),
    ("GitHub Token", re.compile(r"gh[ps]_[0-9a-zA-Z]{36}")),
    (
        "Generic API Key",
        re.compile(
            r"(?:api[_-]?key|apikey)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9\-_]{20,})[\"']", re.IGNORECASE
        ),
    ),
    (
        "Generic Secret",
        re.compile(
            r"(?:secret|token|auth[_-]?token|access[_-]?token)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9\-_\.]{20,})[\"']",
            re.IGNORECASE,
        ),
    ),
    ("JWT Token", re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Firebase Config", re.compile(r"apiKey\s*:\s*[\"']([a-zA-Z0-9\-_]{39})[\"']")),
]


def _extract_secrets_from_js(js_content: str, source_url: str) -> list[dict[str, str]]:
    """V7 Sprint 3.1b: Extract secrets from JavaScript content.

    Scans ``js_content`` for common API key / token patterns using
    regex. Returns a list of dicts: ``{"type": str, "value": str,
    "source": str}`` for each secret found. The patterns are
    conservative — they require key-like prefixes to avoid false
    positives on arbitrary base64 strings.

    This is the V7 Roadmap's "secrets hygiene" feature — scanning
    discovered JS bundles for exposed keys that could be leveraged
    for further attacks (API access, cloud account takeover, etc.).
    """
    secrets: list[dict[str, str]] = []
    for secret_type, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(js_content):
            # Use the full match or the first capture group (if the
            # pattern uses a capture group to extract just the value).
            value = match.group(1) if match.groups() else match.group(0)
            # Truncate long values for the report (full value is still
            # in the evidence bundle).
            display_value = value[:40] + "..." if len(value) > 40 else value
            secrets.append(
                {
                    "type": secret_type,
                    "value": display_value,
                    "source": source_url,
                }
            )
    return secrets


def _discover_html_forms(
    endpoints: list[str],
    base_url: str,
    session_cookies: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """V9 P0 B5: discover HTML forms on the curated endpoints.

    Fetches each endpoint with the SSRF-safe httpx client (so the
    engagement-scope allowlist is respected for private-IP targets),
    parses ``<form>`` elements via a lightweight regex (avoids a
    heavy BeautifulSoup dependency), and returns structured form
    metadata for the business_logic_fuzzer.

    Returns a list of dicts, each shaped as::

        {
            "action": <absolute URL>,
            "method": "POST" | "GET" | "PUT" | ...,
            "data": {<input_name>: <input_value>, ...},
            "source_url": <the page the form was found on>,
        }

    Only forms with method POST/PUT/PATCH/DELETE are returned (GET
    forms are not state-changing). Forms without an ``action``
    attribute default to the page URL they were found on.

    Safe degradation: network/parse errors return an empty list —
    the fuzzer will simply have no targets (no broad POST noise).
    """
    import re as _re

    from webpent.shared.http import make_safe_httpx_client

    # Lightweight <form>...</form> + <input> parser. Not a full HTML
    # parser — good enough for typical DVWA-like forms and avoids a
    # BeautifulSoup dependency. Handles action="" (defaults to current
    # URL) and method defaults to GET.
    form_re = _re.compile(
        r"<form\b([^>]*)>(.*?)</form>",
        _re.IGNORECASE | _re.DOTALL,
    )
    attr_re = _re.compile(r'(\w+)\s*=\s*"([^"]*)"', _re.IGNORECASE)
    input_re = _re.compile(
        r"<input\b([^>]*?)(?:/?>)",
        _re.IGNORECASE,
    )

    forms: list[dict[str, Any]] = []
    headers: dict[str, str] = {}
    if session_cookies:
        from webpent.shared.http import build_cookie_header

        headers["Cookie"] = build_cookie_header(session_cookies)

    for ep_url in endpoints[:10]:  # cap at 10 to bound engagement time
        try:
            with make_safe_httpx_client(
                timeout=10.0,
                follow_redirects=True,
                verify=True,
            ) as client:
                resp = client.get(ep_url, headers=headers)
            if resp.status_code != 200 or not resp.text:
                continue
            html = resp.text
        except Exception:
            continue

        for form_match in form_re.finditer(html):
            form_attrs_str, form_inner = form_match.group(1), form_match.group(2)
            form_attrs = dict(attr_re.findall(form_attrs_str))
            method = (form_attrs.get("method") or "GET").upper()
            if method not in ("POST", "PUT", "PATCH", "DELETE"):
                continue  # only state-changing methods
            action = form_attrs.get("action") or ""
            # Resolve relative action against the page URL.
            if not action:
                action = ep_url
            elif not action.startswith("http"):
                action = urljoin(ep_url, action)

            # Extract input fields.
            data: dict[str, str] = {}
            for input_match in input_re.finditer(form_inner):
                input_attrs = dict(attr_re.findall(input_match.group(1)))
                name = input_attrs.get("name")
                if name:
                    data[name] = input_attrs.get("value", "")

            forms.append(
                {
                    "action": action,
                    "method": method,
                    "data": data,
                    "source_url": ep_url,
                }
            )

    return forms


def _fetch_and_analyze_js(endpoints: list[str], base_url: str) -> list[dict[str, str]]:
    """V7 Sprint 3.1b: Fetch JS files from discovered endpoints and extract secrets.

    Filters the crawled endpoints for JavaScript files (``.js`` extension
    or ``Content-Type: application/javascript``), fetches their content
    via the SSRF-hardened httpx client, and scans for exposed secrets.

    Returns a list of secret dicts (see :func:`_extract_secrets_from_js`).
    """
    try:
        from webpent.shared.http import make_safe_httpx_client
    except ImportError:
        logger.debug("make_safe_httpx_client not importable — skipping JS secret extraction")
        return []

    all_secrets: list[dict[str, str]] = []

    # Filter for JS files by extension.
    js_urls = [ep for ep in endpoints if ep.endswith(".js")]
    # Also check non-.js URLs that might serve JS (e.g., /static/bundle).
    # We'll fetch a few non-.js endpoints and check Content-Type.
    non_js_urls = [ep for ep in endpoints if not ep.endswith(".js")]
    # Cap at 10 JS files + 5 non-JS to bound network traffic.
    urls_to_check = js_urls[:10] + non_js_urls[:5]

    for js_url in urls_to_check:
        try:
            with make_safe_httpx_client(timeout=10.0, follow_redirects=True, verify=True) as client:
                resp = client.get(js_url)
            if resp.status_code != 200:
                continue
            content_type = resp.headers.get("content-type", "")
            # Only analyze if it's actually JavaScript.
            if not (
                js_url.endswith(".js") or "javascript" in content_type or "text" in content_type
            ):
                continue
            js_content = resp.text
            secrets = _extract_secrets_from_js(js_content, js_url)
            if secrets:
                all_secrets.extend(secrets)
                logger.info(
                    "JS secret extraction: found %d secret(s) in %s",
                    len(secrets),
                    js_url,
                )
        except Exception as exc:
            logger.debug("JS fetch/analysis failed for %s: %s", js_url, exc)
            continue

    return all_secrets


_SYSTEM_PROMPT = (
    "You are a Recon Supervisor. Analyze the provided list of crawled "
    "URLs and return a JSON list of endpoints that should be crawled next. "
    "Prioritize parameters, login pages, API routes, and diverse endpoint "
    "families; do not discard an entire signal family just because another "
    "endpoint scores higher."
)

_HUMAN_TEMPLATE = (
    "Target URL: {url}\n\n"
    "Discovered endpoints ({count} total):\n{endpoints}\n\n"
    "Return a JSON list of endpoints to crawl next, preserving useful "
    "coverage across distinct endpoint families."
)

# Maximum number of raw katana URLs to send to the LLM. Sending all
# discovered URLs could blow up the token budget on large crawls; the
# first 50 (in discovery order) is a representative sample.
_MAX_URLS_FOR_LLM = 50


def _format_endpoints_for_llm(endpoints: list[str]) -> str:
    """Format the endpoint list for inclusion in the LLM prompt."""
    if not endpoints:
        return "(none)"
    lines = [f"  {i + 1}. {url}" for i, url in enumerate(endpoints)]
    return "\n".join(lines)


def _parse_llm_url_list(raw_response: str, fallback: list[str]) -> list[str]:
    """Parse the LLM's JSON list response into a list of URLs.

    The LLM is instructed to emit a JSON array of URLs, but we defend
    against common drift: markdown code fences, a bare URL per line,
    trailing text, or a completely malformed response. On any parse
    failure we fall back to the supplied ``fallback`` list so the graph
    never stalls.
    """
    text = raw_response.strip()

    # Strip markdown code fences if present.
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    # Attempt JSON parse.
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            urls = [str(u).strip() for u in parsed if str(u).strip()]
            if urls:
                return urls[:_MAX_URLS_FOR_LLM]
    except json.JSONDecodeError:
        pass

    # Fallback: extract anything that looks like a URL (http/https).
    urls: list[str] = []
    for line in text.splitlines():
        line = line.strip().strip("-").strip().strip('"').strip("'").strip(",")
        if line.startswith(("http://", "https://")):
            urls.append(line)
    if urls:
        return urls[:_MAX_URLS_FOR_LLM]

    logger.warning(
        "Could not parse LLM URL list response; falling back to bounded raw "
        "discovery sample (max=%d)",
        _MAX_URLS_FOR_LLM,
    )
    return fallback[:_MAX_URLS_FOR_LLM]


def crawler_node(state: PentestState) -> dict:
    """LangGraph node implementing the hybrid crawl + LLM-supervision phase.

    Args:
        state: Current graph state. Must contain a ``target`` key with
            a :class:`Target` instance.

    Returns:
        A partial state update with three keys:
          * ``crawled_data`` — a dict with an ``"endpoints"`` key
            containing the bounded, coverage-aware endpoint queue.
          * ``messages`` — a single :class:`AIMessage` summarising the
            crawl outcome.
          * ``current_phase`` — set to ``"crawling"``.
    """
    target = state["target"]
    url = target.url

    logger.info("Crawler phase starting for target=%s", url)

    # ---- Step 1: Deep crawl with katana ---------------------------------
    # V9 P0 Fix 1: cookie observability. Log cookie COUNT + sorted NAMES
    # (never values) immediately before run_katana so the operator can
    # confirm authenticated crawling is actually happening. If auth_state
    # indicates a successful login but session_cookies is empty, that's
    # a hard error — the crawl will be unauthenticated.
    # V9 P0 Fix 1-B: filter out neutralised cookies (empty-string
    # values, written by authentication/agent.py's fail-closed
    # clearing when operator-supplied cookies failed validation) so
    # they don't get counted as "present" or sent to katana as
    # Name=<empty> — they are placeholders that explicitly mean
    # "known invalid," not real session state.
    _session_cookies = {k: v for k, v in (state.get("session_cookies") or {}).items() if v}
    _session_headers = dict(state.get("session_headers") or {})
    _auth_state = state.get("auth_state") or {}
    _cookie_count = len(_session_cookies)
    _cookie_names = sorted(_session_cookies.keys()) if _session_cookies else []
    _auth_source = _auth_state.get("source", "none") if isinstance(_auth_state, dict) else "none"
    _auth_succeeded = _auth_source in ("playwright_login", "operator_supplied")
    logger.info(
        "Crawler pre-katana cookie check: N=%d names=%s auth_source=%s auth_succeeded=%s",
        _cookie_count,
        _cookie_names,
        _auth_source,
        _auth_succeeded,
    )
    if _auth_succeeded and _cookie_count == 0:
        logger.error(
            "Crawler: auth_state indicates successful login (source=%s) "
            "but session_cookies is EMPTY — crawl will be UNAUTHENTICATED. "
            "This is a wiring bug: auth_node did not propagate cookies "
            'into state["session_cookies"].',
            _auth_source,
        )

    http_fallback_surface: dict[str, Any] = {}
    try:
        raw_endpoints = run_katana(
            url,
            session_cookies=_session_cookies,
            extra_headers=_session_headers,
        )
    except ToolNotFoundError as exc:
        logger.warning("katana not found — switching to bounded HTTP fallback: %s", exc)
        raw_endpoints = []
    except ToolExecutionError as exc:
        logger.warning("katana execution failed for %s — switching to HTTP fallback: %s", url, exc)
        raw_endpoints = []
    except Exception as exc:  # noqa: BLE001 — defensive catch-all
        logger.exception("Unexpected error during katana crawl of %s: %s", url, exc)
        raw_endpoints = []

    # Optional binaries are accelerators, not a coverage prerequisite.  When
    # katana is missing or returns no output, perform bounded authenticated
    # same-origin GET discovery.  This is target-agnostic and never submits
    # forms; validators still require independent evidence before Findings.
    if not raw_endpoints:
        try:
            http_fallback_surface = discover_http_surface(
                url,
                session_cookies=_session_cookies,
                extra_headers=_session_headers,
            )
            raw_endpoints = list(http_fallback_surface.get("endpoints") or [])
            logger.info(
                "HTTP fallback discovered %d endpoint(s), fetched=%d, forms=%d, gaps=%s",
                len(raw_endpoints),
                int(http_fallback_surface.get("pages_fetched") or 0),
                len(http_fallback_surface.get("forms") or []),
                http_fallback_surface.get("coverage_gaps") or [],
            )
        except Exception as exc:  # noqa: BLE001 — fallback must never abort a scan
            logger.warning("HTTP discovery fallback failed safely for %s: %s", url, exc)
            http_fallback_surface = {"endpoints": [], "coverage_gaps": ["fallback_error"]}

    # Optional crawlers such as katana can return successfully while missing
    # authenticated or JavaScript-hidden surfaces.  In the qualification
    # profile, run one bounded GET-only supplement as well; this is discovery
    # evidence only and never promotes a finding by itself.  The explicit
    # setting makes the behavior available to other authorized operators while
    # keeping ordinary scans unchanged.
    if raw_endpoints and not http_fallback_surface:
        try:
            from webpent.config.settings import get_settings

            _settings = get_settings()
            profile_value = str(state.get("profile") or "").strip().lower()
            configured_supplement = bool(
                getattr(_settings, "enable_http_discovery_supplement", False)
            )
            supplement_enabled = configured_supplement or profile_value == "vip-qualification"
            logger.info(
                "HTTP supplement check: raw_endpoints=%d http_fallback_surface=%s "
                "profile=%r configured=%s enabled=%s",
                len(raw_endpoints),
                bool(http_fallback_surface),
                profile_value,
                configured_supplement,
                supplement_enabled,
            )
            if supplement_enabled:
                supplement_pages = int(
                    getattr(_settings, "http_discovery_supplement_pages", 20)
                )
                supplement_surface = discover_http_surface(
                    url,
                    session_cookies=_session_cookies,
                    extra_headers=_session_headers,
                    max_pages=max(1, min(supplement_pages, 50)),
                )
                supplement_endpoints = list(supplement_surface.get("endpoints") or [])
                if supplement_endpoints:
                    # Route-seed URLs are placed first so the bounded LLM/
                    # deterministic queue cannot hide known critical surfaces
                    # behind a noisy katana result set.  All URLs remain
                    # observations; validators still establish confirmation.
                    seed_paths = {
                        str(item).strip()
                        for item in list(
                            (supplement_surface.get("discovery_metadata") or {}).get(
                                "route_seed_candidates", []
                            )
                        )
                        if str(item).strip().startswith("/")
                    }
                    parsed_seed_endpoints = [
                        endpoint
                        for endpoint in supplement_endpoints
                        if urlsplit(endpoint).path in seed_paths
                    ]
                    supplement_order = list(
                        dict.fromkeys(parsed_seed_endpoints + supplement_endpoints)
                    )
                    raw_endpoints = list(dict.fromkeys(supplement_order + raw_endpoints))
                    http_fallback_surface = dict(supplement_surface)
                    http_fallback_surface["discovery_mode"] = "katana_plus_http_supplement"
                    logger.info(
                        "HTTP supplement added %d endpoint(s) after katana; fetched=%d, "
                        "route_seeds=%d, gaps=%s",
                        len(supplement_endpoints),
                        int(supplement_surface.get("pages_fetched") or 0),
                        int(
                            (supplement_surface.get("discovery_metadata") or {}).get(
                                "route_seed_queued", 0
                            )
                        ),
                        supplement_surface.get("coverage_gaps") or [],
                    )
        except Exception as exc:  # noqa: BLE001 — supplement must never abort a scan
            logger.warning("HTTP discovery supplement failed safely for %s: %s", url, exc)

    if not raw_endpoints:
        logger.info("Crawler found 0 endpoints for %s — skipping LLM supervision", url)
        # V9 P0 Fix 1: if cookies were present but both crawlers returned 0
        # endpoints, log only cookie names/counts; values never enter logs.
        if _cookie_count > 0:
            logger.warning(
                "Crawler: %d cookie(s) present but katana and HTTP fallback "
                "returned 0 endpoints. Authenticated discovery coverage is 0.",
                _cookie_count,
            )
        return {
            "crawled_data": {
                "endpoints": [],
                "http_discovery": {
                    key: value for key, value in http_fallback_surface.items() if key != "forms"
                },
            },
            "messages": [
                AIMessage(
                    content=f"Crawler found 0 endpoints for {url} after katana and HTTP fallback."
                )
            ],
            "current_phase": "crawling",
        }

    logger.info(
        "%s discovered %d endpoint(s); invoking LLM supervisor for triage",
        "HTTP fallback" if http_fallback_surface else "katana",
        len(raw_endpoints),
    )

    # ---- Step 2: LLM supervisor triage ----------------------------------
    # The legacy path sends only URLs to the supervisor.  When the additive
    # structure-aware flag is enabled, a deterministic coverage queue is
    # built first; the LLM remains advisory and cannot hide a signal family.
    structure_aware = False
    triage_limit = _MAX_URLS_FOR_LLM
    triage_audit: dict[str, Any] | None = None
    coverage_queue: list[str] = []
    try:
        from webpent.config.settings import get_settings

        _settings = get_settings()
        structure_aware = bool(getattr(_settings, "enable_structure_aware_triage", False))
        triage_limit = int(getattr(_settings, "max_structure_aware_triage_endpoints", 25))
    except Exception:
        # Partial settings stubs are used by integrations and tests; fail
        # closed to the compatibility path if the new setting is unavailable.
        structure_aware = False

    if structure_aware:
        coverage_queue, triage_audit = build_coverage_preserving_queue(
            raw_endpoints,
            max_items=triage_limit,
        )
        endpoints_for_llm = list(dict.fromkeys(raw_endpoints[:_MAX_URLS_FOR_LLM] + coverage_queue))[
            :_MAX_URLS_FOR_LLM
        ]
        fallback = coverage_queue or raw_endpoints[:_MAX_URLS_FOR_LLM]
    else:
        endpoints_for_llm = raw_endpoints[:_MAX_URLS_FOR_LLM]
        fallback = raw_endpoints[:_MAX_URLS_FOR_LLM]

    # Respect both the per-run state override and the shared LLM toggle. In
    # no-LLM mode, do not even construct a provider: deterministic discovery
    # and the coverage-preserving queue are the complete triage path.
    llm_disabled = state.get("llm_enabled_override") is False
    if not llm_disabled:
        try:
            llm_disabled = not is_llm_enabled()
        except Exception:
            # Preserve the historical provider-fallback behavior if a partial
            # settings object cannot report the effective LLM state.
            llm_disabled = False

    if llm_disabled:
        curated_endpoints = list(fallback)
        logger.info(
            "Crawler LLM triage disabled; using deterministic endpoint fallback (%d endpoint(s)).",
            len(curated_endpoints),
        )
    else:
        try:
            llm = get_llm(TaskType.ANALYSIS)
        except Exception as exc:
            logger.info("Crawler LLM unavailable; using deterministic endpoint fallback: %s", exc)
            llm = None
        human_prompt = safe_prompt_format(
            _HUMAN_TEMPLATE,
            url=url,
            count=len(raw_endpoints),
            endpoints=_format_endpoints_for_llm(endpoints_for_llm),
        )

        llm_selected = list(fallback)
        try:
            if llm is None:
                raise RuntimeError("LLM unavailable")
            response = llm.invoke(
                [
                    SystemMessage(content=get_safety_system_instruction()),
                    SystemMessage(content=_SYSTEM_PROMPT),
                    HumanMessage(content=human_prompt),
                ]
            )
            raw_text: str = (
                response.content if isinstance(response.content, str) else str(response.content)
            )
            llm_selected = _parse_llm_url_list(raw_text, fallback)
            if structure_aware:
                # Deterministic coverage is authoritative for surface inclusion.
                # Keep the LLM selection as an advisory ordering hint only when a
                # slot remains; never replace a selected coverage representative.
                curated_endpoints = list(coverage_queue)
                for candidate in llm_selected:
                    if candidate in raw_endpoints and candidate not in curated_endpoints:
                        if len(curated_endpoints) >= triage_limit:
                            break
                        curated_endpoints.append(candidate)
            else:
                curated_endpoints = llm_selected
            logger.info(
                "LLM supervisor selected %d endpoint(s) from %d candidates; final queue=%d",
                len(llm_selected),
                len(raw_endpoints),
                len(curated_endpoints),
            )
        except Exception as exc:  # noqa: BLE001 — all LLM providers failed
            fallback_label = (
                "the structure-aware coverage queue"
                if structure_aware
                else f"bounded raw discovery sample (max={_MAX_URLS_FOR_LLM})"
            )
            logger.error(
                "LLM supervisor failed for crawler triage: %s. Falling back to %s.",
                exc,
                fallback_label,
            )
            curated_endpoints = fallback

    crawled_data: dict[str, Any] = {"endpoints": curated_endpoints}
    if http_fallback_surface:
        crawled_data["http_discovery"] = {
            key: value for key, value in http_fallback_surface.items() if key != "forms"
        }
        discovery_metadata = http_fallback_surface.get("discovery_metadata") or {}
        observed_js_urls = [
            str(item).strip()
            for item in list(discovery_metadata.get("javascript_urls") or [])
            if isinstance(item, str) and str(item).strip()
        ]
        observed_js_urls.extend(
            str(item).strip()
            for item in curated_endpoints
            if isinstance(item, str)
            and item.lower().split("?", 1)[0].endswith((".js", ".mjs"))
        )
        if observed_js_urls:
            crawled_data["javascript_urls"] = list(dict.fromkeys(observed_js_urls))[:200]
        discovered_surface_records = [
            item
            for item in list(http_fallback_surface.get("surface_records") or [])
            if isinstance(item, dict)
        ]
        if discovered_surface_records:
            crawled_data["surface_records"] = discovered_surface_records[:200]
        fallback_forms = list(http_fallback_surface.get("forms") or [])
        if fallback_forms:
            crawled_data["forms"] = fallback_forms[:100]
    if structure_aware and triage_audit is not None:
        triage_audit["llm_advisory_selection"] = list(llm_selected)
        crawled_data["endpoint_triage"] = triage_audit

    # V7 Sprint 3.1b: JavaScript secret extraction. Fetch discovered
    # JS files and scan them for exposed API keys, tokens, and private
    # keys. Results are stored in crawled_data["js_secrets"] so the
    # reporter can include them in the final report.
    js_secrets: list[dict[str, str]] = []
    try:
        js_secrets = _fetch_and_analyze_js(curated_endpoints, url)
        if js_secrets:
            crawled_data["js_secrets"] = js_secrets
            logger.info(
                "JS secret extraction: %d secret(s) found across %d endpoints",
                len(js_secrets),
                len(curated_endpoints),
            )
    except Exception as exc:
        logger.debug("JS secret extraction failed: %s", exc)

    # V9 P0 B5: discover HTML forms on the curated endpoints so the
    # business_logic_fuzzer has real state-changing targets instead of
    # doing blind POST bursts. Fetches each curated endpoint with the
    # SSRF-safe httpx client (engagement-scope allowlist respected),
    # parses <form> elements, and stores structured form metadata in
    # crawled_data["forms"]. Pure additive — does not change existing
    # crawler logic. Safe degradation: if fetching/parsing fails, no
    # forms are populated (the fuzzer returns no endpoints).
    try:
        discovered_forms = _discover_html_forms(
            curated_endpoints, url, state.get("session_cookies")
        )
        if discovered_forms:
            existing_forms = list(crawled_data.get("forms") or [])
            seen_form_keys = {
                (str(item.get("action")), str(item.get("method")), str(item.get("source_url")))
                for item in existing_forms
                if isinstance(item, dict)
            }
            for form in discovered_forms:
                key = (
                    str(form.get("action")),
                    str(form.get("method")),
                    str(form.get("source_url")),
                )
                if key not in seen_form_keys:
                    existing_forms.append(form)
                    seen_form_keys.add(key)
            if existing_forms:
                crawled_data["forms"] = existing_forms[:100]
            logger.info(
                "Form discovery: %d form(s) found across %d endpoints; total forms=%d",
                len(discovered_forms),
                len(curated_endpoints),
                len(existing_forms),
            )
    except Exception as exc:
        logger.debug("Form discovery failed: %s", exc)

    # V55+: bounded passive surface-security coverage. This is deliberately
    # placed after endpoint/form/JS collection so it sees the same evidence
    # that downstream agents will consume. It performs no requests and never
    # writes to state["findings"]. The feature flag defaults to False, so the
    # legacy crawler output and graph topology remain unchanged.
    surface_security_update: dict[str, Any] = {}
    try:
        from webpent.config.settings import get_settings
        from webpent.shared.surface_security import analyze_security_surface

        surface_settings = get_settings()
        if bool(getattr(surface_settings, "enable_surface_security_analysis", False)):
            surface_security_update = analyze_security_surface(
                crawled_data,
                url,
                javascript_intelligence=state.get("javascript_intelligence") or {},
                max_observations=int(
                    getattr(surface_settings, "max_surface_security_observations", 100)
                ),
            )
            logger.info(
                "Surface-security analysis: %d observation(s), %d coverage gap(s)",
                len(surface_security_update.get("observations", [])),
                len(surface_security_update.get("coverage_gaps", [])),
            )
    except Exception as exc:  # noqa: BLE001 — additive analysis must degrade safely
        logger.warning("Surface-security analysis skipped safely: %s", exc)
        surface_security_update = {}

    scope_runtime_handle = getattr(
        state.get("runtime_context"), "scope_runtime_handle", None
    )
    scope_runtime_fingerprint = ""
    if scope_runtime_handle is not None:
        scope_runtime_fingerprint = str(scope_runtime_handle.fingerprint)
        curated_endpoints = [
            endpoint
            for endpoint in curated_endpoints
            if scope_runtime_handle.permits_url(endpoint)
        ]

    # V7 Cognitive Upgrade — Phase 2: extract Mental Model updates from
    # crawler's discoveries (curated endpoints + JS-extracted secrets
    # as credential nodes + any artifact-looking URLs). Pure additive
    # — does not change any existing crawler logic. Deterministic
    # regex/heuristic, NO LLM. See
    # webpent.models.mental_model.extract_mental_model_updates.
    mental_model_update: dict[str, Any] = {"nodes": {}, "edges": []}
    try:
        from webpent.models.mental_model import (
            classify_artifact_type,
            extract_mental_model_updates,
        )

        # Build artifacts list from URLs that match a known artifact
        # pattern (archive / config / git_marker / sql_dump / backup).
        crawler_artifacts: list[dict[str, str]] = []
        for ep_url in curated_endpoints:
            art_type = classify_artifact_type(ep_url)
            if art_type:
                crawler_artifacts.append({"type": art_type, "url": ep_url})
        mental_model_update = extract_mental_model_updates(
            discovery_source="crawler_node",
            endpoints=curated_endpoints,
            credentials=js_secrets,  # JS-extracted secrets become credential nodes
            artifacts=crawler_artifacts,
            target_url=url,
        )
    except Exception as exc:
        logger.debug("Mental Model extraction (crawler) failed: %s", exc)

    summary = (
        f"Crawler completed for {url}. "
        f"{('HTTP fallback' if http_fallback_surface else 'katana')} discovered "
        f"{len(raw_endpoints)} endpoint(s); "
        f"LLM supervisor selected {len(curated_endpoints)} for testing."
    )
    if structure_aware and triage_audit is not None:
        summary += (
            f" Structure-aware triage covered "
            f"{len(triage_audit.get('covered_signal_groups') or [])} signal group(s) "
            f"with {len(triage_audit.get('coverage_gaps') or [])} documented gap(s)."
        )
    if crawled_data.get("js_secrets"):
        summary += f" JS analysis found {len(crawled_data['js_secrets'])} exposed secret(s)."
    if mental_model_update.get("nodes"):
        summary += (
            f" Mental Model: added {len(mental_model_update['nodes'])} node(s) "
            f"+ {len(mental_model_update.get('edges') or [])} edge(s)."
        )
    logger.info(summary)

    signup_forms_detected = project_signup_form_events(
        crawled_data,
        engagement_id=str(state.get("engagement_id") or ""),
        client_id=str(state.get("client_id") or ""),
        source="crawler",
    )
    result = {
        "crawled_data": crawled_data,
        "mental_model": mental_model_update,
        "messages": [AIMessage(content=summary)],
        "current_phase": "crawling",
    }
    if signup_forms_detected:
        result["signup_forms_detected"] = signup_forms_detected
    if scope_runtime_fingerprint:
        result["scope_runtime_fingerprint"] = scope_runtime_fingerprint
    if surface_security_update:
        result["surface_security"] = surface_security_update
    return result
