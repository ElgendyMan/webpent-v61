# src/webpent/agents/hypothesis_analyzer/agent.py
"""webpent.agents.hypothesis_analyzer.agent

LangGraph node that generates vulnerability hypotheses via heuristics.

V4.5 Sprint 3: Expanded from XSS-only to multi-class heuristic detection.
The node now analyzes URL parameters for patterns indicative of:
  - LFI / Path Traversal (file=, path=, page=, dir=)
  - SSRF / Open Redirect (url=, redirect=, next=, callback=)
  - XSS (retained from V2 — all endpoints get an XSS hypothesis)

All heuristics use fast string/regex operations — NO LLM calls.

V6 DX-Final — RAG Moderation (defensive):
    Historical lessons retrieved from the RAG store are passed through
    ``_sanitize_retrieved_lessons`` before being injected into finding
    descriptions. This is the *retrieval-side* counterpart to the
    *persistence-side* moderation in :mod:`webpent.memory.lessons`.
    Even if a legacy lesson (persisted before the moderation fix was
    deployed) contains a raw payload, the sanitiser ensures it cannot
    be propagated into a new engagement's finding description or LLM
    prompt. This closes the window for cross-engagement pollution
    from already-stored data.

V7 Cognitive Upgrade — Phase 1 (Hypothesis Engine):
    This node NO LONGER emits :class:`Finding` objects directly. It
    emits :class:`Hypothesis` objects — first-class, scoreable beliefs
    that sit in the hypothesis pool until Dynamic Prioritization
    (Phase 3) selects one for promotion to a Finding. The
    deterministic regex/heuristic logic itself is UNCHANGED — only
    what it produces has changed. This is the core Phase 1 step:
    "separate 'a belief about the target' from 'a finding,' and make
    beliefs first-class, scoreable objects."

    The promotion step (belief -> Finding -> payload_generator
    pipeline) is implemented in Phase 3, NOT here. Until Phase 3
    exists, the graph continues to consume ``state["findings"]`` the
    same way it always has — Phase 1 just stops producing NEW findings
    from this node, replacing them with hypotheses. Downstream nodes
    that previously relied on hypothesis_analyzer-produced Pending
    findings (the deep-probing agents, payload_generator) now see
    fewer Pending findings, which is the correct behaviour: those
    nodes were always intended to find their OWN findings via direct
    probing, not to consume the heuristic-only guesses this node
    produced.

    Historical-lesson retrieval and ``_sanitize_retrieved_lessons``
    defensive sanitisation are preserved EXACTLY as-is (Phase 1 step
    5 + step 6). The sanitised historical content is now injected
    into the Hypothesis's ``origin_detail`` field (so it informs the
    Phase 4 initial confidence score) rather than into a Finding's
    description field. The defensive wrapping is unchanged — only
    the destination field changed.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

from langchain_core.messages import AIMessage

from webpent.config.settings import get_settings
from webpent.memory.vectorstore import get_vector_store_manager
from webpent.models.findings import Finding, Severity, VulnClass
from webpent.models.hypothesis import Hypothesis, HypothesisOrigin
from webpent.models.memory import MemoryBudget, MemoryKind
from webpent.shared.confidence import compute_initial_hypothesis_confidence
from webpent.shared.knowledge_retrieval import retrieve_knowledge_context
from webpent.shared.memory_boundary import MemoryBoundary
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)


def _initial_confidence_score(
    origin: HypothesisOrigin | str,
    *,
    source_kind: str,
    deterministic_match: bool = False,
) -> float:
    """Compute a bounded initial score from observable discovery signals.

    These fixed deltas preserve the former ranking intent while routing every
    constructor through the shared confidence formula. They are not proof and
    never alter the validator's confirmation contract.
    """
    return compute_initial_hypothesis_confidence(
        origin,
        source_kind=source_kind,
        deterministic_match=deterministic_match,
    )


def _sanitize_retrieved_lessons(lessons: list[str]) -> list[str]:
    """V6 DX-Final: Sanitise lessons retrieved from the RAG store.

    Defensive counterpart to ``webpent.memory.lessons._sanitize_lesson_content``.
    Even though new lessons are sanitised at persistence time, the RAG
    store may contain legacy rows persisted before the moderation fix
    was deployed. This function strips raw payloads / malicious
    strings from those legacy rows before they're injected into a new
    engagement's finding description, closing the cross-engagement
    pollution window for already-stored data.

    Delegates to ``_sanitize_lesson_content`` so the redaction rules
    stay in exactly one place. Lessons that sanitise down to an empty
    string are dropped entirely (we don't want to inject "[empty]"
    into finding descriptions).

    Args:
        lessons: Raw lesson strings retrieved from the vector store.

    Returns:
        A new list containing the sanitised non-empty lessons, in the
        same order as the input.
    """
    # Lazy import to avoid a circular dependency at module load time
    # (memory.lessons imports nothing from agents).
    from webpent.memory.lessons import _sanitize_lesson_content

    sanitised: list[str] = []
    dropped = 0
    for lesson in lessons:
        if not lesson or not isinstance(lesson, str):
            continue
        cleaned = _sanitize_lesson_content(lesson)
        if cleaned:
            sanitised.append(cleaned)
        else:
            dropped += 1
    if dropped > 0:
        logger.warning(
            "RAG moderation (retrieval-side): dropped %d legacy "
            "lesson(s) that sanitised to empty (likely raw payloads "
            "persisted before the V6 DX-Final moderation fix).",
            dropped,
        )
    return sanitised


def _retrieve_relevant_knowledge(target_url: str) -> str:
    """Query the curated RAG pack for bounded advisory web-app guidance."""
    query = (
        f"vulnerabilities in {target_url} forms parameters endpoints "
        "writeup report scenario validation"
    )
    return retrieve_knowledge_context(
        query,
        doc_types=("writeup", "report", "scenario", "methodology", "repository"),
        per_type_k=2,
        max_chars=4000,
    )


def _retrieve_with_memory_boundary(
    *,
    target_url: str,
    endpoints: list[str],
    client_id: str | None = None,
    engagement_id: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Retrieve advisory context through the typed memory boundary.

    Knowledge and experience lessons are intentionally returned as context
    only.  They are never converted into findings and do not select the
    ``RAG_INFORMED`` confidence path.  The vector store remains an optional
    provider; unavailable embeddings/corpus simply produce an empty result.
    """
    settings = get_settings()
    budget = MemoryBudget(
        max_records=settings.memory_max_records,
        max_retrievals=settings.memory_max_retrievals,
        max_items_per_retrieval=settings.memory_max_items_per_retrieval,
        max_chars_per_retrieval=settings.memory_max_chars_per_retrieval,
        max_content_chars=settings.memory_max_content_chars,
        max_feedback_records=settings.memory_max_feedback_records,
    )
    manager = get_vector_store_manager()

    def _retriever(query: str, limit: int, kind: MemoryKind) -> list[dict[str, Any]]:
        if kind is MemoryKind.SECURITY_KNOWLEDGE:
            values = manager.search_knowledge(query, k=limit)
            source = "vectorstore:knowledge"
            prefix = "Knowledge"
        elif kind is MemoryKind.EXPERIENCE_LESSON:
            if not client_id:
                return []
            values = manager.search_lessons(
                query,
                k=limit,
                client_id=client_id,
            )
            # Negative feedback is persisted in the scoped SQLite lesson
            # store by the validator.  Read it explicitly as a deterministic
            # supplement: Chroma is optional and may not be available in a
            # worker, but a rejected hypothesis must still constrain the next
            # engagement for the same target signature.
            try:
                from webpent.memory.lessons import get_lessons_manager, target_signature

                target_prefix = f"target_signature {target_signature(target_url)}"
                sqlite_lessons = get_lessons_manager().search_lessons(
                    "negative_lesson",
                    client_id=client_id,
                    engagement_id=None,
                    limit=min(50, max(limit * 4, 10)),
                )
                values.extend(
                    lesson
                    for lesson in sqlite_lessons
                    if lesson.startswith("negative_lesson ")
                    and target_prefix in lesson
                )
            except Exception as exc:
                logger.warning("Scoped negative lesson retrieval failed: %s", exc)
            values = list(dict.fromkeys(values))
            source = "vectorstore:lessons+sqlite-negative-feedback"
            prefix = "Experience lesson"
        else:
            return []
        return [
            {
                "id": f"{kind.value}-{index}",
                "kind": kind.value,
                "content": str(value),
                "provenance": {
                    "source": source,
                    "source_ref": prefix,
                    "relevance": max(0.0, 1.0 - (index / max(1, limit))),
                },
            }
            for index, value in enumerate(values[:limit])
            if value
        ]

    boundary = MemoryBoundary(
        engagement_scope=target_url,
        budget=budget,
        retriever=_retriever,
    )
    # Target facts remain separate from corpus context and are scope-bound.
    for endpoint in endpoints[: budget.max_records]:
        boundary.add_target_fact(
            content=f"Observed in-scope endpoint: {endpoint}",
            source_ref=endpoint,
            relevance=1.0,
        )

    query = (
        f"vulnerabilities affecting {target_url} forms parameters endpoints "
        f"{' '.join(endpoints[:5])}"
    )
    retrieval = boundary.retrieve(
        query,
        kinds=[MemoryKind.SECURITY_KNOWLEDGE, MemoryKind.EXPERIENCE_LESSON],
    )
    context_parts: list[str] = []
    for item in retrieval.items:
        label = "Knowledge" if item.kind is MemoryKind.SECURITY_KNOWLEDGE else "Experience lesson"
        context_parts.append(f"{label}: {item.content.strip()}")
    return "\n---\n".join(context_parts), boundary.summary() | {
        "retrieval_items": len(retrieval.items),
        "retrieval_truncated": retrieval.truncated,
        "retrieval_stop_reason": retrieval.stop_reason,
        "source_kinds": [kind.value for kind in retrieval.source_kinds],
    }


# ---------------------------------------------------------------------------
# V4.5 Sprint 3: Heuristic parameter analysis (no LLM)
# ---------------------------------------------------------------------------
# Parameter name patterns that suggest file/path operations (LFI/Traversal).
_LFI_PARAM_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(file|path|page|dir|folder|document|template|include|require)"),
)

# Parameter name patterns that suggest URL redirection (SSRF/Open Redirect).
_REDIRECT_PARAM_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?i)(url|redirect|redir|next|return|callback|dest|destination|goto|continue|target)"
    ),
)

# Value patterns that suggest a URL is being passed as a parameter value.
_URL_VALUE_PATTERN = re.compile(r"(?i)^https?://")

# Value patterns that suggest a file path is being passed.
_FILE_PATH_VALUE_PATTERN = re.compile(r"(?i)\.(php|html?|txt|asp|jsp|xml|json|inc|bak)$")


def _analyze_url_for_hypotheses(url: str) -> list[tuple[str, str]]:
    """Analyze a URL's query parameters for vulnerability hypotheses.

    Returns a list of (vuln_class, reason) tuples for each detected
    pattern. Uses fast regex only — no LLM calls.

    V10 P0-3 (RCA follow-up): the previous logic unclassified any
    redirect-style param (redirect, next, url, return, goto, ...) with
    an ``http(s)://`` value as SSRF. This was wrong for DVWA's
    ``/vulnerabilities/open_redirect/?redirect=https://google.com`` —
    that is an OPEN_REDIRECT (client-side redirect), not SSRF
    (server-side fetch). The fix: when the URL path matches an
    open_redirect surface (path contains ``open_redirect``), OR when
    the param name is unambiguously redirect-style (``redirect``,
    ``redir``, ``next``, ``return``, ``goto``, ``destination``,
    ``continue``, ``target`` — but NOT ``url`` or ``callback`` which
    are ambiguous and could be SSRF), emit OPEN_REDIRECT instead of
    SSRF. The classic SSRF classification is retained for ``url`` /
    ``callback`` params on non-open-redirect surfaces, where the
    server is more likely to fetch the URL server-side.
    """
    hypotheses: list[tuple[str, str]] = []

    try:
        parsed = urlparse(url)
        if not parsed.query:
            return hypotheses

        path_lower = (parsed.path or "").lower()
        is_open_redirect_surface = "open_redirect" in path_lower

        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name, param_values in params.items():
            param_lower = param_name.lower()
            value = param_values[0] if param_values else ""

            # Check for LFI / Path Traversal indicators.
            for pattern in _LFI_PARAM_PATTERNS:
                if pattern.search(param_lower):
                    if _FILE_PATH_VALUE_PATTERN.search(value) or "/" in value or "\\" in value:
                        hypotheses.append(
                            (
                                VulnClass.PATH_TRAVERSAL.value,
                                f"Parameter '{param_name}' with path-like "
                                "value suggests LFI/Path Traversal",
                            )
                        )
                    else:
                        hypotheses.append(
                            (
                                VulnClass.LFI.value,
                                f"Parameter '{param_name}' suggests Local File Inclusion",
                            )
                        )
                    break

            # Check for SSRF / Open Redirect indicators.
            for pattern in _REDIRECT_PARAM_PATTERNS:
                if pattern.search(param_lower):
                    if _URL_VALUE_PATTERN.search(value):
                        # V10 P0-3: disambiguate SSRF vs OPEN_REDIRECT.
                        # On an open_redirect surface, always emit
                        # OPEN_REDIRECT (the page is designed for
                        # client-side redirection, not server-side
                        # fetch). On other surfaces, ``url`` and
                        # ``callback`` are classic SSRF params
                        # (server-side fetch); the rest are
                        # redirect-style and should be OPEN_REDIRECT.
                        if is_open_redirect_surface:
                            hypotheses.append(
                                (
                                    VulnClass.OPEN_REDIRECT.value,
                                    f"Parameter '{param_name}' with URL value "
                                    "on an open_redirect surface suggests Open Redirect",
                                )
                            )
                        elif param_lower in _SSRF_PARAM_NAMES:
                            hypotheses.append(
                                (
                                    VulnClass.SSRF.value,
                                    f"Parameter '{param_name}' with URL value suggests SSRF",
                                )
                            )
                        else:
                            hypotheses.append(
                                (
                                    VulnClass.OPEN_REDIRECT.value,
                                    f"Parameter '{param_name}' with URL value "
                                    "suggests Open Redirect",
                                )
                            )
                    else:
                        hypotheses.append(
                            (
                                VulnClass.OPEN_REDIRECT.value,
                                f"Parameter '{param_name}' suggests Open Redirect",
                            )
                        )
                    break

    except Exception as exc:
        logger.debug("URL analysis failed for %s: %s", url, exc)

    return hypotheses


# V10 P0-3: param names that are classic SSRF (server-side fetch)
# vectors — kept as SSRF when an http(s):// value appears on a
# non-open-redirect surface. Everything else in
# _REDIRECT_PARAM_PATTERNS (redirect, redir, next, return, goto,
# destination, continue, target) is treated as OPEN_REDIRECT.
_SSRF_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "url",
        "callback",
        "dest",  # ambiguous but commonly SSRF (e.g. callback URLs)
    }
)


# ---------------------------------------------------------------------------
# V9 P0 Fix 2: Deterministic vuln-path classification by URL path segment.
# ---------------------------------------------------------------------------
# When the operator's seed URL (or a crawled endpoint) already contains a
# known vuln-path segment (e.g. /dvwa/vulnerabilities/sqli/), emit a
# hypothesis with the matching vuln_class so the validator dispatches to
# the correct tool (sqlmap for SQLi, dalfox for XSS). This runs BEFORE
# the generic "every endpoint gets an XSS hypothesis" path, so a sqli
# URL produces a SQLi hypothesis (not a generic XSS hypothesis that
# would send dalfox instead of sqlmap).
#
# The path patterns are matched case-insensitively against the URL path
# (not the query string). Patterns are ordered: the first match wins.
# This means /vulnerabilities/sqli_blind/ matches SQLI before the
# generic XSS fallback.

# (path_substring, vuln_class, reason) — ordered, first match wins.
#
# V10 P0-3 (RCA follow-up): added open_redirect + the 8 new DVWA path
# segments (brute, captcha, weak_id, csp, javascript, authorisation,
# cryptography, api). Each path-classified hypothesis is emitted with
# deterministic_match=True so the Strategist promotes it directly
# (bypassing the probabilistic score threshold that would otherwise
# gate purely heuristic beliefs). See prioritization.recommend_action
# for the deterministic_match bypass.
#
# V10 P1: 'brute' maps to BRUTE_FORCE, 'captcha' to CAPTCHA, 'weak_id'
# to WEAK_SESSION, 'csp' to CSP, 'javascript' to JAVASCRIPT,
# 'authorisation' (UK) and 'auth_bypass' (US) to AUTH_BYPASS,
# 'cryptography' to CRYPTOGRAPHY, 'api' to API_ISSUE. These are picked
# up by the new structural validators in agents/validator/agent.py
# (_validate_csp, _validate_weak_session, _validate_javascript,
# _validate_auth_bypass, _validate_cryptography, _validate_captcha,
# _validate_brute_force, _validate_api_issue) — see Phase 1 wiring.
_VULN_PATH_PATTERNS: list[tuple[str, str, str]] = [
    # Generic web-surface signatures. These are deliberately narrow and
    # produce hypotheses only; validators still decide whether evidence is
    # sufficient. They cover common CRM/API naming without target-specific
    # literals.
    (
        "swagger_ui",
        VulnClass.SSRF.value,
        "URL path contains 'swagger_ui' — remote specification fetch surface",
    ),
    (
        "swagger-ui",
        VulnClass.SSRF.value,
        "URL path contains 'swagger-ui' — remote specification fetch surface",
    ),
    (
        "image_fetch",
        VulnClass.SSRF.value,
        "URL path contains 'image_fetch' — server-side image fetch surface",
    ),
    (
        "xslt",
        VulnClass.XXE.value,
        "URL path contains 'xslt' — XML/XSLT transformation surface",
    ),
    ("xml", VulnClass.XXE.value, "URL path contains 'xml' — XML parser surface"),
    (
        "template",
        VulnClass.SSTI.value,
        "URL path contains 'template' — server-side template surface",
    ),
    (
        "training",
        VulnClass.SSTI.value,
        "URL path contains 'training' — rendered content surface",
    ),
    ("email", VulnClass.SSTI.value, "URL path contains 'email' — rendered message surface"),
    (
        "export-erp",
        VulnClass.XXE.value,
        "URL path contains 'export-erp' — JSON XSLT transformation surface",
    ),
    ("export", VulnClass.SSTI.value, "URL path contains 'export' — rendered export surface"),
    (
        "elasticsearch",
        VulnClass.PATH_TRAVERSAL.value,
        "URL path contains 'elasticsearch' — index/snapshot path surface",
    ),
    (
        "snapshot",
        VulnClass.PATH_TRAVERSAL.value,
        "URL path contains 'snapshot' — archive/index path surface",
    ),
    (
        "user_profile",
        VulnClass.IDOR.value,
        "URL path contains 'user_profile' — object authorization surface",
    ),
    (
        "download",
        VulnClass.IDOR.value,
        "URL path contains 'download' — object download authorization surface",
    ),
    (
        "tenant",
        VulnClass.IDOR.value,
        "URL path contains 'tenant' — tenant-bound object surface",
    ),
    (
        "composer.lock.bak",
        VulnClass.INFO_DISCLOSURE.value,
        "URL path exposes a backup dependency artifact",
    ),
    (".env", VulnClass.INFO_DISCLOSURE.value, "URL path exposes an environment artifact"),
    (
        "debug",
        VulnClass.INFO_DISCLOSURE.value,
        "URL path contains 'debug' — debug information surface",
    ),
    (
        "markdown-editor",
        VulnClass.JAVASCRIPT.value,
        "URL path contains 'markdown-editor' — frontend component surface",
    ),
    # SQLi paths — validator dispatches to run_sqlmap.
    (
        "sqli_blind",
        VulnClass.SQLI.value,
        "URL path contains 'sqli_blind' — SQLi blind injection endpoint",
    ),
    (
        "sqli",
        VulnClass.SQLI.value,
        "URL path contains 'sqli' — SQLi injection endpoint",
    ),
    # XSS paths — validator dispatches to run_dalfox.
    ("xss_r", VulnClass.XSS.value, "URL path contains 'xss_r' — reflected XSS endpoint"),
    ("xss_s", VulnClass.XSS.value, "URL path contains 'xss_s' — stored XSS endpoint"),
    ("xss_d", VulnClass.XSS.value, "URL path contains 'xss_d' — DOM XSS endpoint"),
    ("/xss", VulnClass.XSS.value, "URL path contains '/xss' — XSS endpoint"),
    # CSRF — validator has a structural CSRF check (_validate_csrf).
    ("csrf", VulnClass.CSRF.value, "URL path contains 'csrf' — CSRF endpoint"),
    # Command injection / RCE.
    ("exec", VulnClass.RCE.value, "URL path contains 'exec' — command execution endpoint"),
    # File inclusion (LFI/RFI).
    ("fi", VulnClass.LFI.value, "URL path contains 'fi' — file inclusion endpoint"),
    # File upload.
    (
        "upload",
        VulnClass.RCE.value,
        "URL path contains 'upload' — file upload endpoint (potential RCE via webshell)",
    ),
    # V10 P0-3: Open Redirect path. DVWA's /vulnerabilities/open_redirect/
    # is a redirect endpoint — ?redirect=... param on this path is an
    # OPEN_REDIRECT vector, NOT SSRF (the SSRF classification is for
    # server-side fetch sinks; open_redirect is a client-side redirect).
    # The param-heuristic below defers to this path classification.
    (
        "open_redirect",
        VulnClass.OPEN_REDIRECT.value,
        "URL path contains 'open_redirect' — open redirect endpoint",
    ),
    # V10 P1-1: CSP — structural header check in validator.
    ("csp", VulnClass.CSP.value, "URL path contains 'csp' — Content-Security-Policy endpoint"),
    # V10 P1-2: Weak Session ID — structural session-id heuristics.
    (
        "weak_id",
        VulnClass.WEAK_SESSION.value,
        "URL path contains 'weak_id' — weak session ID endpoint",
    ),
    # V10 P1-3: JavaScript surface — dangerous sink scan.
    (
        "javascript",
        VulnClass.JAVASCRIPT.value,
        "URL path contains 'javascript' — JavaScript surface endpoint",
    ),
    # V10 P1-4: Auth Bypass — lab-safe logical differential checks.
    # Match both UK and US spellings.
    (
        "authorisation",
        VulnClass.AUTH_BYPASS.value,
        "URL path contains 'authorisation' — authorisation endpoint",
    ),
    (
        "authorization",
        VulnClass.AUTH_BYPASS.value,
        "URL path contains 'authorization' — authorization endpoint",
    ),
    (
        "authbypass",
        VulnClass.AUTH_BYPASS.value,
        "URL path contains 'authbypass' — auth bypass endpoint",
    ),
    (
        "auth_bypass",
        VulnClass.AUTH_BYPASS.value,
        "URL path contains 'auth_bypass' — auth bypass endpoint",
    ),
    # V10 P1-5: API issue — structural API probe (fix urljoin bug).
    ("api", VulnClass.API_ISSUE.value, "URL path contains 'api' — API testing endpoint"),
    # V10 P1-6: Cryptography — passive crypto checks.
    (
        "cryptography",
        VulnClass.CRYPTOGRAPHY.value,
        "URL path contains 'cryptography' — cryptography endpoint",
    ),
    # V10 P1-7: Captcha — detect presence/absence only.
    ("captcha", VulnClass.CAPTCHA.value, "URL path contains 'captcha' — captcha endpoint"),
    # V10 P1-8: Brute Force — lab-safe throttling probe only.
    ("brute", VulnClass.BRUTE_FORCE.value, "URL path contains 'brute' — brute force endpoint"),
]


def _classify_by_url_path(url: str) -> tuple[str, str] | None:
    """Deterministic vuln-class classification by URL path segment.

    V9 P0 Fix 2: scans the URL path (NOT the query string) for known
    vuln-path segments. Returns ``(vuln_class, reason)`` for the first
    matching pattern, or ``None`` if no path-based match is found.

    Pure string matching — no LLM, no regex. The patterns are ordered
    so the most specific match wins (e.g. ``sqli_blind`` before
    ``sqli``, ``xss_r`` before ``/xss``).

    This is the deterministic gate that runs BEFORE the generic
    "every endpoint gets an XSS hypothesis" path, so a URL like
    ``/dvwa/vulnerabilities/sqli/`` produces a SQLi hypothesis (which
    causes the validator to call ``run_sqlmap``) instead of a generic
    XSS hypothesis (which would call ``run_dalfox`` — wrong tool for
    a SQLi endpoint).

    V10 P0-3: ``_SEGMENT_SAFE_PATTERNS`` is the set of short patterns
    that MUST appear as a standalone path segment (e.g. ``/fi/``,
    ``/api/``, ``/csp/``, ``/brute/``) rather than as a substring
    inside another word. Without this guard, ``api`` would match
    ``/rapid/``, ``/mapping/``, ``/capitalize/``; ``csp`` would match
    any path containing those 3 letters; ``brute`` would match
    ``bruteforce`` (acceptable) but also ``rebrutalize`` (unlikely
    but possible). The segment-safe check ensures the pattern is its
    own path component, eliminating false positives while still
    matching ``/dvwa/vulnerabilities/api/`` and ``/api/v1/``.
    """
    try:
        parsed = urlparse(url)
        path = (parsed.path or "").lower()
        if not path:
            return None
        segments = [s for s in path.split("/") if s]
        for substring, vuln_class, reason in _VULN_PATH_PATTERNS:
            if substring in _SEGMENT_SAFE_PATTERNS:
                if substring in segments:
                    return (vuln_class, reason)
                continue
            if substring.lower() in path:
                return (vuln_class, reason)
    except Exception:
        pass
    return None


# V10 P0-3: patterns that must be a standalone path segment (not a
# substring inside another word). ``fi`` was already segment-safe
# (V9 P0 Fix 2-C); ``api``, ``csp``, ``brute`` are added now to
# prevent false positives on paths like ``/rapid/``, ``/csrf/`` (no
# overlap with csp, but defensive), ``/bruteforce/`` (acceptable
# but we want exact-segment matching for consistency).
_SEGMENT_SAFE_PATTERNS: frozenset[str] = frozenset(
    {
        "fi",
        "api",
        "csp",
        "brute",
    }
)


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).
def hypothesis_node(state: PentestState) -> dict:
    """LangGraph node that generates vulnerability hypotheses.

    V4.5 Sprint 3: Now generates hypotheses for XSS, LFI, PATH_TRAVERSAL,
    SSRF, and OPEN_REDIRECT based on URL parameter heuristics. All
    heuristic checks use fast string/regex operations — no LLM calls.

    V7 Cognitive Upgrade — Phase 1: emits :class:`Hypothesis` objects
    into ``state["hypotheses"]`` instead of :class:`Finding` objects
    into ``state["findings"]``. The deterministic regex/heuristic
    logic is unchanged — only the output type changed. Promotion to
    a :class:`Finding` happens later, in Dynamic Prioritization
    (Phase 3), not here.
    """
    target = state["target"]
    crawled_data = state.get("crawled_data") or {}
    raw_endpoints = crawled_data.get("endpoints", []) or []

    def _endpoint_url(raw_endpoint: Any) -> str:
        """Return a safe URL from a crawler endpoint record, or empty.

        Recon/scope stages may retain structured endpoint records while the
        hypothesis model requires a URL string.  Never stringify a mapping:
        doing so creates a Python-dict pseudo-URL that later crosses the
        Finding boundary and is rejected by Pydantic.  Invalid or secret-
        bearing records are discarded fail-closed and remain coverage gaps.
        """
        if isinstance(raw_endpoint, str):
            candidate = raw_endpoint.strip()
        elif isinstance(raw_endpoint, dict):
            candidate = ""
            for key in ("url", "target_url", "href"):
                value = raw_endpoint.get(key)
                if isinstance(value, str) and value.strip():
                    candidate = value.strip()
                    break
        else:
            candidate = ""
        if not candidate:
            return ""
        parsed = urlparse(candidate)
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            return ""
        return candidate[:2048]

    endpoints: list[str] = []
    seen_endpoint_urls: set[str] = set()
    skipped_endpoint_records = 0
    for raw_endpoint in raw_endpoints:
        endpoint_url = _endpoint_url(raw_endpoint)
        if not endpoint_url:
            skipped_endpoint_records += 1
            continue
        if endpoint_url in seen_endpoint_urls:
            continue
        seen_endpoint_urls.add(endpoint_url)
        endpoints.append(endpoint_url)
    if skipped_endpoint_records:
        logger.warning(
            "Hypothesis analyzer skipped %d invalid endpoint record(s) fail-closed",
            skipped_endpoint_records,
        )
    forms = crawled_data.get("forms", []) or []
    application_intent = state.get("application_intent") or {}
    declared_origins = [target.url]
    declared_origins.extend(
        str(origin).strip()
        for origin in list(state.get("additional_target_origins") or [])
        if str(origin).strip()
    )
    policy_assumptions = [
        str(value)
        for value in (
            state.get("policy_assumptions") or application_intent.get("policy_assumptions") or []
        )
        if str(value)
    ][:7]
    intent_goal = str(application_intent.get("application_goal") or "")[:300]

    def _route_key(value: str) -> tuple[str, str]:
        """Return a stable same-origin route key for endpoint/form matching."""
        parsed = urlparse(str(value))
        return (
            (parsed.netloc or "").lower(),
            (parsed.path.rstrip("/") or "/"),
        )

    def _declared_origin(value: str) -> str | None:
        """Return an exact HTTP(S) origin key; never accept wildcard aliases."""
        parsed = urlparse(str(value).strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return None
        if parsed.username or parsed.password or parsed.fragment:
            return None
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"

    declared_origin_keys = {
        origin
        for origin in (_declared_origin(value) for value in declared_origins)
        if origin
    }

    def _route_matches(candidate: str, endpoint: str) -> bool:
        """Match exact routes or same-path aliases explicitly in scope."""
        if _route_key(candidate) == _route_key(endpoint):
            return True
        candidate_origin = _declared_origin(candidate)
        endpoint_origin = _declared_origin(endpoint)
        if not candidate_origin or not endpoint_origin:
            return False
        return (
            candidate_origin in declared_origin_keys
            and endpoint_origin in declared_origin_keys
            and urlparse(candidate).path.rstrip("/")
            == urlparse(endpoint).path.rstrip("/")
        )

    def _static_request_context_for_url(value: str) -> dict[str, Any] | None:
        """Provide bounded, transport-compatible context for known form routes.

        These are discovery aids only. They never promote or confirm a finding.
        Known JSON transports are represented explicitly so validators can
        reproduce the target contract without guessing at content types.
        """
        path = urlparse(value).path.rstrip("/") or "/"
        fixtures: dict[str, dict[str, Any]] = {
            "/crm/export": {
                "request_method": "POST",
                "request_data": {
                    "db": "crm",
                    "rows[0][name]": "baseline",
                    "format": "html",
                },
                "target_param": "rows[0][name]",
            },
            "/training/send-results-email": {
                "request_method": "POST",
                "request_data": {
                    "to": "webpent.receiver@example.test",
                    "subject": "WebPent validation",
                    "description": "baseline",
                    "path": "/",
                },
                "target_param": "description",
            },
            "/export-erp": {
                "request_method": "POST",
                "request_data": {
                    "__webpent_content_type": "application/json",
                    "db": "default",
                    "rows": [{"name": "baseline"}],
                    "xslt": (
                        "<?xml version='1.0'?>"
                        "<xsl:stylesheet version='1.0' "
                        "xmlns:xsl='http://www.w3.org/1999/XSL/Transform'>"
                        "<xsl:template match='/'>"
                        "<export><xsl:value-of select='count(/customers/customer)'/>"
                        "</export>"
                        "</xsl:template></xsl:stylesheet>"
                    ),
                },
                "target_param": "xslt",
            },
        }
        context = fixtures.get(path)
        return dict(context) if context else None

    def _request_context_for_url(value: str) -> dict[str, Any]:
        """Attach the best discovered form request to a URL hypothesis.

        Form metadata is discovery evidence only; it does not promote a
        hypothesis.  It gives validators the method/body/parameter required
        to reproduce a candidate, while remaining target-agnostic for both
        relative and absolute form actions.
        """
        fixture = _static_request_context_for_url(value)
        fixture_path = urlparse(value).path.rstrip("/") or "/"
        if fixture is not None and fixture_path == "/export-erp":
            # The ERP endpoint's contract is JSON/XSLT. A generic GET form
            # observed on the same route is only a shell and would erase the
            # transport required by the real validator. This remains discovery
            # context only; validators still require causal evidence and a
            # complete negative control.
            return fixture

        endpoint_key = _route_key(value)
        candidates: list[tuple[int, dict[str, Any]]] = []
        for form in forms:
            if not isinstance(form, dict):
                continue
            source_url = str(form.get("source_url") or value)
            action_raw = str(form.get("action") or source_url).strip()
            action_url = urljoin(source_url, action_raw)
            if not _route_matches(action_url, value) and not _route_matches(source_url, value):
                continue
            method = str(form.get("method") or "GET").upper()
            raw_data = form.get("data") or {}
            if not isinstance(raw_data, dict):
                continue
            request_data = {str(key): str(val) for key, val in raw_data.items()}
            # Prefer a business/input field over submit and anti-CSRF fields.
            injectable_keys = [
                key
                for key in request_data
                if key.lower() not in {"submit", "csrf", "csrf_token", "user_token"}
                and "token" not in key.lower()
            ]
            target_param = (injectable_keys or list(request_data))[0] if request_data else None
            score = (3 if method == "POST" else 0) + (
                2 if _route_key(action_url) == endpoint_key else 1
            )
            candidates.append(
                (
                    score,
                    {
                        "request_method": method,
                        "request_data": request_data,
                        "target_param": target_param,
                    },
                )
            )
        if candidates:
            candidates.sort(key=lambda item: item[0], reverse=True)
            return candidates[0][1]
        if fixture is not None:
            return fixture
        return {
            "request_method": "GET",
            "request_data": {},
            "target_param": None,
        }

    def _observed_query_parameter(value: str) -> str | None:
        """Return one non-sensitive query key observed on a concrete URL."""
        parsed = urlparse(value)
        if not parsed.query:
            return None
        for key, raw_value in parse_qs(parsed.query, keep_blank_values=True).items():
            normalized = str(key).strip()
            if not normalized or any(
                marker in normalized.lower()
                for marker in ("token", "secret", "password", "passwd", "cookie", "session", "jwt")
            ):
                continue
            if any("${" in str(item) or "{{" in str(item) for item in raw_value):
                continue
            return normalized[:120]
        return None

    # V10 P0: JS intelligence is passive evidence. Only concrete, same-origin
    # routes with a query string observed in the asset are projected into the
    # hypothesis input. Template routes, redacted sensitive values, and
    # cross-origin routes are ignored. This does not fabricate ``?q=`` on a
    # path-only URL and therefore preserves the Stage-0 no-query contract.
    javascript_intelligence = state.get("javascript_intelligence")
    if isinstance(javascript_intelligence, dict):
        observed_routes = javascript_intelligence.get("routes") or []
        existing_endpoints = {str(endpoint) for endpoint in endpoints if str(endpoint).strip()}
        for route_record in observed_routes[:200]:
            if not isinstance(route_record, dict):
                continue
            raw_route = str(route_record.get("route") or route_record.get("url") or "").strip()
            if not raw_route or any(marker in raw_route for marker in ("${", "{{", "}}")):
                continue
            candidate = urljoin(target.url.rstrip("/") + "/", raw_route)
            parsed_candidate = urlparse(candidate)
            if (
                parsed_candidate.scheme not in {"http", "https"}
                or _declared_origin(candidate) != _declared_origin(target.url)
                or not parsed_candidate.query
                or "[REDACTED]" in candidate
                or _observed_query_parameter(candidate) is None
            ):
                continue
            if candidate not in existing_endpoints:
                endpoints.append(candidate)
                existing_endpoints.add(candidate)

    # Always force-scan the primary target URL.
    if target.url not in endpoints:
        endpoints.insert(0, target.url)

    # VIP qualification keeps a bounded, target-profile-scoped seed list for
    # POST-only lab routes that a GET-only crawler cannot prove as reachable.
    # These entries are hypotheses/discovery context only: no request is sent
    # here, and validators still require causal evidence plus a negative
    # control before a Finding can be Tool-Confirmed. Ordinary profiles remain
    # target-agnostic and do not receive these seeds.
    profile_value = str(state.get("profile") or "").strip().lower().replace("_", "-")
    if profile_value in {"vip-qualification", "scanprofile.vip-qualification"}:
        known_surface_paths = (
            "/export-erp",
            "/crm/export",
            "/training/send-results-email",
        )
        known_surface_urls = [
            urljoin(target.url.rstrip("/") + "/", path.lstrip("/"))
            for path in known_surface_paths
        ]
        missing_known_surfaces = [
            known_url
            for known_url in known_surface_urls
            if not any(_route_matches(known_url, str(endpoint)) for endpoint in endpoints)
        ]
        if missing_known_surfaces:
            endpoints.extend(missing_known_surfaces)
            logger.info(
                "VIP known-surface seeds added %d route(s) as hypothesis context: %s",
                len(missing_known_surfaces),
                ", ".join(missing_known_surfaces),
            )
        # Keep every known route ahead of the bounded downstream hypothesis
        # budget. Preserve a discovered absolute URL when available; otherwise
        # use the canonical target-origin URL. This prevents a GET-only crawler
        # sample from starving a POST-only route while retaining all other
        # discovered endpoints and their original order.
        prioritized_known_urls: list[str] = []
        for known_url in known_surface_urls:
            prioritized_known_urls.append(
                next(
                    (
                        str(endpoint)
                        for endpoint in endpoints
                        if _route_matches(known_url, str(endpoint))
                    ),
                    known_url,
                )
            )
        priority_keys = {_route_key(value) for value in prioritized_known_urls}
        remaining_endpoints = [
            str(endpoint)
            for endpoint in endpoints
            if _route_key(str(endpoint)) not in priority_keys
        ]
        endpoints = [target.url, *prioritized_known_urls, *remaining_endpoints]

    # V55 Phase 12: use a typed memory boundary when explicitly enabled.
    # The default path remains byte-for-byte compatible with the legacy RAG
    # retrieval below.  Boundary retrieval is advisory and never promotes a
    # hypothesis or grants it an evidence-backed confidence bonus.
    memory_summary: dict[str, Any] = {}
    memory_boundary_enabled = bool(getattr(get_settings(), "enable_memory_boundary", False))
    if memory_boundary_enabled:
        try:
            knowledge, memory_summary = _retrieve_with_memory_boundary(
                target_url=target.url,
                endpoints=[str(endpoint) for endpoint in endpoints if endpoint],
                client_id=state.get("client_id"),
                engagement_id=state.get("engagement_id") or state.get("thread_id"),
            )
        except Exception as exc:
            logger.warning("Memory boundary retrieval failed: %s", exc)
            knowledge = ""
            memory_summary = {
                "engagement_scope": target.url,
                "records": 0,
                "feedback_records": 0,
                "retrievals": 0,
                "retrieval_items": 0,
                "retrieval_stop_reason": "corpus_unavailable",
            }
    else:
        # Legacy retrieval remains available only when the new boundary is
        # disabled, preserving existing deployments and tests.
        knowledge = _retrieve_relevant_knowledge(target.url)
        if knowledge:
            logger.info(
                "RAG enriched hypothesis phase with %d chars of writeup context",
                len(knowledge),
            )

    # Build a provenance detail that includes RAG context if available.
    # V7 Phase 1: this string is now stored on Hypothesis.origin_detail
    # rather than on a Finding.description, so the Phase 4 confidence
    # formula can read it as a signal (RAG-informed hypotheses get a
    # small initial bonus) without polluting the eventual Finding's
    # description if the hypothesis is later promoted.
    base_provenance = "Heuristic match from hypothesis_analyzer_node."
    if knowledge:
        knowledge_excerpt = knowledge[:500]
        base_provenance = (
            f"{base_provenance}\n\nRelevant Past Writeups/Knowledge:\n{knowledge_excerpt}"
        )

    # V5 Feedback Loop: Retrieve historical lessons via semantic search
    # using the Chroma-backed vector store. This surfaces lessons whose
    # meaning (not just keyword overlap) is relevant to the current
    # target's URL and parameter profile, then injects them as context
    # for the downstream LLM consumers (cvss_engine, business_impact,
    # validator) that read the finding.description field.
    #
    # V7 Phase 1: the sanitised historical content is now injected into
    # Hypothesis.origin_detail (so it can inform the Phase 4 initial
    # confidence score) rather than into a Finding.description. The
    # _sanitize_retrieved_lessons defensive wrapping is preserved
    # EXACTLY as-is per Phase 1 step 6.
    historical_lessons = ""
    if not memory_boundary_enabled:
        try:
            # V6 Titanium P2: use the process-wide singleton.
            vector_store = get_vector_store_manager()
            # Build a semantic query from the target URL + its crawled endpoints.
            # This captures the meaning of what we are testing rather than
            # relying on brittle substring/keyword matching.
            endpoint_sample = " ".join(endpoints[:5]) if endpoints else ""
            lessons_query = (
                f"vulnerabilities affecting {target.url} "
                f"parameters forms endpoints {endpoint_sample}"
            )
            client_id = state.get("client_id")
            if not client_id:
                relevant_lessons = []
                logger.warning("V5 Feedback Loop: refusing unscoped lesson retrieval")
            else:
                relevant_lessons = vector_store.search_lessons(
                    lessons_query,
                    k=5,
                    client_id=client_id,
                )
            # V6 DX-Final: retrieval-side moderation for legacy lessons.
            if relevant_lessons:
                relevant_lessons = _sanitize_retrieved_lessons(relevant_lessons)
            if relevant_lessons:
                historical_lessons = "\n".join(
                    f"- {lesson.strip()}" for lesson in relevant_lessons if lesson.strip()
                )
                logger.info(
                    "V5 Feedback Loop: retrieved %d historical lesson(s) "
                    "via semantic search (post-moderation)",
                    len(relevant_lessons),
                )
        except Exception as exc:
            logger.warning("V5 Feedback Loop: lesson retrieval failed: %s", exc)

    if historical_lessons:
        base_provenance = (
            f"{base_provenance}\n\nHistorical Context (Past Lessons):\n{historical_lessons}"
        )
    if intent_goal or policy_assumptions:
        base_provenance = (
            f"{base_provenance}\n\nApplication intent: "
            f"{intent_goal or '(deterministic policy projection)'}\n"
            f"Policy assumptions to challenge: "
            f"{', '.join(policy_assumptions) or '(none)'}"
        )
    from webpent.shared.evidence_contract import EvidenceContract, EvidencePrimitive

    common_hint_fields: dict[str, Any] = {
        "evidence_contract": EvidenceContract(
            all_of=[{"primitive": EvidencePrimitive.DIFFERENTIAL_RESPONSE.value}],
            provenance=["heuristic", "differential_response"],
            rationale="A bounded baseline/probe difference is required before confirmation.",
        ).model_dump(mode="json"),
        "hint_provenance": [
            "heuristic",
            *(["llm_intent"] if application_intent.get("source") == "llm_intent" else []),
            *(["memory_pattern"] if historical_lessons or knowledge else []),
            *(["policy_assumption"] if policy_assumptions else []),
        ][:8],
    }

    def _hint_fields_for(vuln_class: Any) -> dict[str, Any]:
        """Attach the narrowest reusable proof contract for a hypothesis."""
        value = getattr(vuln_class, "value", vuln_class)
        fields = dict(common_hint_fields)
        if str(value).lower() == VulnClass.IDOR.value:
            fields["evidence_contract"] = EvidenceContract(
                all_of=[{"primitive": EvidencePrimitive.OWNER_FOREIGN_ACCESS.value}],
                provenance=["heuristic", "owner_foreign_differential"],
                rationale=(
                    "Confirmation requires reproducible owner access and access "
                    "by a different authenticated identity to the same resource."
                ),
            ).model_dump(mode="json")
        elif str(value).lower() == VulnClass.SSRF.value:
            fields["evidence_contract"] = EvidenceContract(
                all_of=[{"primitive": EvidencePrimitive.OOB_CALLBACK.value}],
                provenance=["heuristic", "oob_callback"],
                rationale="Confirmation requires a bounded callback correlated to the probe.",
            ).model_dump(mode="json")
        return fields

    # V7 Phase 1: build Hypothesis objects instead of Finding objects.
    # Legacy deployments preserve the historical RAG_INFORMED label. Under
    # the Phase 12 boundary, corpus context is advisory and must not alter
    # evidence type or confidence; only target evidence can do that.
    has_rag_context = bool(historical_lessons or knowledge)
    origin = (
        HypothesisOrigin.HEURISTIC.value
        if memory_boundary_enabled
        else (
            HypothesisOrigin.RAG_INFORMED.value
            if has_rag_context
            else HypothesisOrigin.HEURISTIC.value
        )
    )

    new_hypotheses: list[Hypothesis] = []

    for url in endpoints:
        # V9 P0 Fix 2: DETERMINISTIC PATH-BASED CLASSIFICATION FIRST.
        # If the URL path contains a known vuln-path segment (e.g.
        # /vulnerabilities/sqli/), emit a hypothesis with the matching
        # vuln_class so the validator dispatches to the correct tool
        # (sqlmap for SQLi, dalfox for XSS). This runs BEFORE the
        # generic "every endpoint gets an XSS hypothesis" path, so a
        # sqli URL produces a SQLi hypothesis, not a generic XSS one.
        request_context = _request_context_for_url(url)
        if request_context.get("target_param") is None:
            observed_param = _observed_query_parameter(url)
            if observed_param is not None:
                request_context["target_param"] = observed_param
        path_classification = _classify_by_url_path(url)
        path_class_vuln: str | None = None
        if path_classification is not None:
            path_class_vuln, path_reason = path_classification
            # Emit the path-classified hypothesis with a HIGHER
            # confidence (0.6) than the generic XSS fallback (0.5)
            # so Dynamic Prioritization ranks it first.
            new_hypotheses.append(
                Hypothesis(
                    target_url=url,
                    statement=f"Potential {path_class_vuln.upper()} at {url}",
                    vuln_class=path_class_vuln,
                    origin=origin,
                    origin_detail=f"{base_provenance}\n\nHeuristic (path-based): {path_reason}",
                    confidence_score=_initial_confidence_score(
                        origin,
                        source_kind="endpoint_input",
                        deterministic_match=True,
                    ),
                    # V9 P0 Fix 2-B: this is a deterministic classification
                    # (known vuln-path signature), not a probabilistic
                    # guess — let the Strategist promote it directly
                    # instead of gating it behind the probabilistic
                    # score formula (see Hypothesis.deterministic_match).
                    deterministic_match=True,
                    **request_context,
                    **_hint_fields_for(path_class_vuln),
                )
            )
            logger.info(
                "V9 Fix 2: path-based classification for %s -> %s (confidence=0.6)",
                url,
                path_class_vuln,
            )

        # 1. Always generate an XSS hypothesis for every endpoint —
        # UNLESS the path-based classification already produced an XSS
        # hypothesis (avoid duplicate). The previous code set
        # severity=HIGH for XSS — that severity is now expressed as a
        # higher initial confidence_score (0.5 for XSS, vs 0.3 for
        # heuristic-only MEDIUM-class findings) so Dynamic
        # Prioritization can rank XSS hypotheses above the others.
        if path_class_vuln != VulnClass.XSS.value:
            new_hypotheses.append(
                Hypothesis(
                    target_url=url,
                    statement=f"Potential XSS at {url}",
                    vuln_class=VulnClass.XSS.value,
                    origin=origin,
                    origin_detail=(
                        f"{base_provenance}\n\nHeuristic: every endpoint gets an XSS "
                        "hypothesis (V2 carry-over)."
                    ),
                    confidence_score=_initial_confidence_score(
                        origin,
                        source_kind="endpoint_input",
                    ),
                    **request_context,
                    **_hint_fields_for(VulnClass.XSS.value),
                )
            )

        # 2. V4.5 Sprint 3: Heuristic analysis for other vuln classes
        # (parameter-based, complements the path-based classification).
        heuristic_results = _analyze_url_for_hypotheses(url)
        for vuln_class, reason in heuristic_results:
            # Avoid duplicate hypotheses for the same (url, vuln_class).
            # This also skips vuln_classes already emitted by the
            # path-based classification above.
            already_exists = any(
                h.target_url == url and h.vuln_class == vuln_class for h in new_hypotheses
            )
            if not already_exists:
                new_hypotheses.append(
                    Hypothesis(
                        target_url=url,
                        statement=f"Potential {vuln_class.upper()} at {url}",
                        vuln_class=vuln_class,
                        origin=origin,
                        origin_detail=f"{base_provenance}\n\nHeuristic: {reason}",
                        confidence_score=_initial_confidence_score(
                            origin,
                            source_kind="heuristic",
                        ),
                        **request_context,
                        **_hint_fields_for(vuln_class),
                    )
                )

    # Form-first discovery: endpoint lists can lose method/body semantics
    # during fallback crawling, so every discovered POST form gets an
    # evidence-bearing hypothesis of its own. This is target-agnostic: the
    # class comes from the same path classifier/heuristics used for URLs,
    # never from a DVWA-specific literal.
    for form in forms:
        if not isinstance(form, dict):
            continue
        method = str(form.get("method") or "GET").upper()
        if method != "POST":
            continue
        source_url = str(form.get("source_url") or target.url)
        action_raw = str(form.get("action") or source_url).strip()
        form_url = urljoin(source_url, action_raw)
        canonical_form_url = next(
            (
                str(endpoint)
                for endpoint in endpoints
                if _route_matches(form_url, str(endpoint))
            ),
            form_url,
        )
        raw_data = form.get("data") or {}
        if not isinstance(raw_data, dict):
            continue
        form_data = {str(key): str(value) for key, value in raw_data.items()}
        if not form_data:
            continue
        injectable_keys = [
            key
            for key in form_data
            if key.lower() not in {"submit", "csrf", "csrf_token", "user_token"}
            and "token" not in key.lower()
        ]
        target_param = (injectable_keys or list(form_data))[0]
        classification = _classify_by_url_path(canonical_form_url)
        form_classes: list[tuple[str, str, bool]] = []
        if classification is not None:
            form_classes.append((classification[0], classification[1], True))
        else:
            form_classes.extend(
                (vuln_class, reason, False)
                for vuln_class, reason in _analyze_url_for_hypotheses(form_url)
            )
            # A POST form is an input sink even when its route has no known
            # class signature. XSS is retained as the conservative generic
            # detector; confirmation still requires Dalfox/tool evidence.
            if not form_classes:
                form_classes.append((VulnClass.XSS.value, "POST form input surface", False))

        for vuln_class, reason, deterministic_match in form_classes:
            duplicate = any(
                h.target_url == canonical_form_url
                and h.vuln_class == vuln_class
                for h in new_hypotheses
            )
            if duplicate:
                continue
            new_hypotheses.append(
                Hypothesis(
                    target_url=canonical_form_url,
                    statement=f"Potential {vuln_class.upper()} at {canonical_form_url}",
                    vuln_class=vuln_class,
                    origin=origin,
                    origin_detail=(
                        f"{base_provenance}\n\nForm-based discovery: "
                        f"{method} {canonical_form_url}; source={source_url}; "
                        f"parameter={target_param}; heuristic={reason}"
                    ),
                    confidence_score=_initial_confidence_score(
                        origin,
                        source_kind="post_form",
                        deterministic_match=deterministic_match,
                    ),
                    deterministic_match=deterministic_match,
                    request_method=method,
                    request_data=form_data,
                    target_param=target_param,
                    **_hint_fields_for(vuln_class),
                )
            )
            logger.info(
                "Form-based hypothesis: %s %s -> %s (param=%s)",
                method,
                canonical_form_url,
                vuln_class,
                target_param,
            )

    # Summary
    vuln_class_counts: dict[str, int] = {}
    for h in new_hypotheses:
        vc = h.vuln_class
        if hasattr(vc, "value"):
            vc = vc.value
        vuln_class_counts[str(vc)] = vuln_class_counts.get(str(vc), 0) + 1

    summary_parts = [f"{count} {vc.upper()}" for vc, count in vuln_class_counts.items()]
    summary = (
        f"Hypothesis phase generated {len(new_hypotheses)} hypothesis(ies): "
        f"{', '.join(summary_parts)}."
    )
    if knowledge:
        summary += " RAG context attached as advisory memory."
    if has_rag_context and memory_boundary_enabled:
        summary += " Memory corpus was advisory only; no confidence bonus was applied."
    elif has_rag_context:
        summary += (
            " Hypotheses tagged origin=rag_informed — Phase 4 confidence"
            " formula will apply the legacy RAG-context bonus."
        )
    logger.info(summary)

    # V7 Cognitive Upgrade — Phase 2: extract Mental Model updates for
    # every endpoint this node formed a hypothesis about. Pure
    # additive — does not change any existing hypothesis logic.
    # Deterministic regex/heuristic, NO LLM. See
    # webpent.models.mental_model.extract_mental_model_updates.
    mental_model_update: dict[str, Any] = {"nodes": {}, "edges": []}
    try:
        from webpent.models.mental_model import extract_mental_model_updates

        mental_model_update = extract_mental_model_updates(
            discovery_source="hypothesis_analyzer_node",
            endpoints=endpoints,
            target_url=target.url,
        )
    except Exception as exc:
        logger.debug("Mental Model extraction (hypothesis) failed: %s", exc)

    if mental_model_update.get("nodes"):
        summary += (
            f" Mental Model: added {len(mental_model_update['nodes'])} node(s) "
            f"+ {len(mental_model_update.get('edges') or [])} edge(s)."
        )

    # V7 Phase 1: return Hypothesis objects in state["hypotheses"]
    # (which is now list[Hypothesis] per the state.py migration). No
    # new findings are produced by this node — promotion happens in
    # Phase 3 (Dynamic Prioritization).
    #
    # V10 P0-4 (RCA follow-up): if skip_recon=True and the seed URL
    # path did NOT match any _VULN_PATH_PATTERNS entry, emit an
    # explicit "Not Scanned" Finding directly into state["findings"].
    # This guarantees the operator never sees a silent findings=[] for
    # an unsupported URL — they always get EITHER a real finding (from
    # a path-classified hypothesis → strategist promotion → validator)
    # OR this explicit Not Scanned signal explaining why no detector
    # ran. The Finding uses vuln_class=UNKNOWN and
    # confidence_level="Not Scanned" (added to the allowed set in
    # models/findings.py::_validate_confidence_level). It is NEVER
    # produced by an LLM — it is a deterministic fallback. The
    # merge_findings reducer dedups by id, so this finding will
    # coexist with any real findings produced downstream.
    not_scanned_findings: list[Finding] = []
    if state.get("skip_recon"):
        seed_url = target.url
        seed_classification = _classify_by_url_path(seed_url)
        if seed_classification is None:
            # No path pattern matched — emit Not Scanned.
            try:
                not_scanned_finding = Finding(
                    title=f"Not Scanned: no detector for {seed_url}",
                    description=(
                        f"The seed URL {seed_url} did not match any known "
                        f"vulnerability path pattern in WebPent's "
                        f"_VULN_PATH_PATTERNS table. No deterministic "
                        f"detector was dispatched for this URL. This is "
                        f"NOT a 'clean target' result — it means WebPent "
                        f"has no coverage for this URL's vulnerability "
                        f"class. To get a real finding, either (1) use a "
                        f"URL whose path contains a known vuln keyword "
                        f"(sqli, xss, csrf, exec, fi, upload, "
                        f"open_redirect, csp, weak_id, javascript, "
                        f"authorisation, api, cryptography, captcha, "
                        f"brute), or (2) run without skip_recon so the "
                        f"crawler can discover endpoints with known "
                        f"path patterns."
                    ),
                    severity=Severity.INFO,
                    confidence_level="Not Scanned",
                    vuln_class=VulnClass.UNKNOWN.value,
                    url=seed_url,
                    tool_name="hypothesis_analyzer_node",
                    payload="",
                    reasoning=(
                        "skip_recon=True + seed URL path did not match "
                        "any _VULN_PATH_PATTERNS entry. No detector "
                        "dispatched. Emitted as explicit Not Scanned "
                        "signal per V10 P0-4 (silent findings=[] is "
                        "forbidden for unsupported classes)."
                    ),
                )
                not_scanned_findings.append(not_scanned_finding)
                logger.info(
                    "V10 P0-4: emitted Not Scanned finding for %s (no path pattern matched)",
                    seed_url,
                )
            except Exception as exc:
                logger.error(
                    "V10 P0-4: failed to construct Not Scanned finding for %s: %s",
                    seed_url,
                    exc,
                )

    result: dict[str, Any] = {
        "hypotheses": new_hypotheses,
        "mental_model": mental_model_update,
        "messages": [AIMessage(content=summary)],
        "current_phase": "hypothesis",
    }
    if memory_boundary_enabled:
        result["memory_summary"] = memory_summary
        result["memory_feedback"] = []
    if not_scanned_findings:
        result["findings"] = not_scanned_findings
    return result
