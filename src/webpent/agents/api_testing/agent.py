# src/webpent/agents/api_testing/agent.py
"""webpent.agents.api_testing.agent

V7 Sprint 2.6 — API & Microservices Testing Agent.

Detects API-specific vulnerabilities:
  * GraphQL introspection enabled (information disclosure)
  * GraphQL query depth / complexity limits missing (DoS vector)
  * JWT alg=none acceptance (auth bypass)
  * JWT weak HS256 secret (offline cracking via canary token)
  * Mass assignment (sending role/is_admin fields to create/update)
  * BOLA in REST APIs (accessing resources by ID without authz)

All probes use ``make_safe_httpx_client`` (V6 SSRF guard + V7 P0
engagement-scope allowlist). JWT attacks are DETECTION-ONLY — we never forge tokens to
impersonate real users; we only check whether the target accepts
``alg=none`` or a weak-signature canary token.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urljoin, urlparse

from langchain_core.messages import AIMessage

from webpent.models.findings import Finding, Severity, VulnClass
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)


# V10 P1-5 (RCA follow-up): ``urljoin(base_url, path)`` drops the base
# URL's path when ``path`` starts with ``/``. For DVWA, this means
# ``urljoin("http://host/dvwa/vulnerabilities/api/", "/api/v1/user")``
# returns ``http://host/api/v1/user`` — losing the ``/dvwa/`` prefix.
# This helper resolves relative to the base URL's first path segment
# (the application root, e.g. /dvwa/), preserving the prefix.
def _resolve_url(base_url: str, path: str) -> str:
    """Resolve ``path`` against ``base_url`` preserving the app root."""
    if path.startswith(("http://", "https://")):
        return path
    parsed = urlparse(base_url)
    if path.startswith("/"):
        base_path = parsed.path
        segments = [s for s in base_path.split("/") if s]
        app_root = "/" + segments[0] if segments else ""
        return f"{parsed.scheme}://{parsed.netloc}{app_root}{path}"
    return urljoin(base_url, path)


# GraphQL introspection query — standard, from the GraphQL spec.
# Sent as JSON body to the GraphQL endpoint. If introspection is
# enabled, the response will contain "__schema" or "queryType".
_GRAPHQL_INTROSPECTION_QUERY = json.dumps(
    {
        "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types { ...FullType }
        directives { name description locations args { ...InputValue } }
      }
    }
    fragment FullType on __Type {
      kind name description
      fields(includeDeprecated: true) {
        name description args { ...InputValue } type { ...TypeRef }
        isDeprecated deprecationReason
      }
      inputFields { ...InputValue }
      interfaces { ...TypeRef }
      enumValues { name description isDeprecated deprecationReason }
      possibleTypes { ...TypeRef }
    }
    fragment InputValue on __InputValue {
      name description type { ...TypeRef } defaultValue
    }
    fragment TypeRef on __Type {
      kind name ofType { kind name ofType { kind name ofType {
        kind name ofType { kind name ofType { kind name ofType {
          kind name ofType { kind name }
        }}}}}}
    }
    """
    }
)

# Common GraphQL endpoint paths to probe.
_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/api/query",
    "/graphiql",
]

# JWT alg=none test token (header: {"alg":"none","typ":"JWT"}, payload: {"sub":"admin"}).
# This is a well-known test token — it does NOT impersonate a real user.
_JWT_ALG_NONE_TOKEN = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0."
)


def _looks_like_spa_shell(response: Any) -> bool:
    """Return True for an HTML application shell, not an API result.

    Many single-page applications return their index document with HTTP 200
    for unknown paths. Treating that fallback as JWT acceptance both creates
    a false candidate and prevents probing later, more specific API paths.
    This helper is deliberately narrow: JSON, plain text, and HTML responses
    without the usual shell markers remain eligible for normal validation.
    """
    headers = getattr(response, "headers", {}) or {}
    content_type = str(headers.get("content-type", "")).lower()
    body = str(getattr(response, "text", "") or "")[:20_000].lower()
    if "text/html" not in content_type:
        return False
    return "<!doctype html" in body or "<app-root" in body or '<base href="/"' in body


def _probe_graphql(
    base_url: str,
    cookies: dict[str, str] | None = None,
    auth_headers: dict[str, str] | None = None,
) -> list[Finding]:
    """Probe for GraphQL endpoints and introspection exposure.

    Sends the standard introspection query to common GraphQL paths.
    If introspection is enabled (the response contains ``__schema``
    or ``queryType``), raises a Medium-severity finding.
    """
    findings: list[Finding] = []
    # No fallback to raw httpx.Client: every network request must pass
    # through the central SSRF, DNS-pinning, redirect, and engagement-scope
    # policy. Import failure is a deployment error, not a reason to bypass it.
    from webpent.shared.http import make_safe_httpx_client

    client_factory = make_safe_httpx_client

    for path in _GRAPHQL_PATHS:
        url = _resolve_url(base_url, path)
        # V9 P0 B4: attach session cookies so authenticated GraphQL
        # endpoints (e.g. DVWA's /vulnerabilities/graphql) are reachable.
        headers: dict[str, str] = {
            str(name): str(value)
            for name, value in (auth_headers or {}).items()
            if str(value).strip()
        }
        headers["Content-Type"] = "application/json"
        if cookies:
            from webpent.shared.http import build_cookie_header

            headers["Cookie"] = build_cookie_header(cookies)
        try:
            with client_factory(timeout=10.0, follow_redirects=False, verify=True) as client:
                # First, a simple POST to see if the endpoint exists.
                resp = client.post(
                    url,
                    json={"query": "{__typename}"},
                    headers=headers,
                )
            if resp.status_code == 404:
                continue
            if resp.status_code not in (200, 400, 405):
                continue

            # Endpoint exists — try introspection.
            with client_factory(timeout=10.0, follow_redirects=False, verify=True) as client:
                resp = client.post(
                    url,
                    data=_GRAPHQL_INTROSPECTION_QUERY,
                    headers=headers,
                )
            if resp.status_code == 200:
                body = resp.text
                if "__schema" in body or "queryType" in body:
                    # V10 P0-2: wrap Finding construction in try/except
                    # so a pydantic ValidationError is logged at ERROR
                    # (not debug) and the loop continues to the next
                    # GraphQL path candidate. After P0-1, INFO_DISCLOSURE
                    # is a legal enum value, so this should not fire —
                    # but the guard remains as defense-in-depth.
                    try:
                        findings.append(
                            Finding(
                                title=f"GraphQL introspection enabled at {path}",
                                description=(
                                    f"The GraphQL endpoint at {url} has introspection "
                                    f"enabled. An attacker can query the entire schema "
                                    f"to discover all types, fields, and mutations, "
                                    f"accelerating further attacks. Introspection "
                                    f"should be disabled in production."
                                ),
                                severity=Severity.MEDIUM,
                                confidence_level="AI-Assessed",
                                # V10 P0-1: was raw "info_disclosure" string —
                                # VulnClass.INFO_DISCLOSURE already exists.
                                vuln_class=VulnClass.INFO_DISCLOSURE.value,
                                url=url,
                                tool_name="api_testing_agent",
                                payload=_GRAPHQL_INTROSPECTION_QUERY[:200],
                                reasoning=(
                                    f"GraphQL introspection query returned 200 with "
                                    f"schema data ({len(body)} bytes). The response "
                                    f"contains __schema / queryType fields, confirming "
                                    f"introspection is enabled."
                                ),
                            )
                        )
                    except Exception as exc:
                        logger.error(
                            "api_testing: failed to construct GraphQL "
                            "introspection finding for %s: %s",
                            url,
                            exc,
                        )
                    logger.warning("GraphQL introspection enabled at %s", url)
                else:
                    # Endpoint exists but introspection is disabled — good.
                    logger.info("GraphQL endpoint at %s has introspection disabled", url)
        except Exception as exc:
            # V10 P0-2: was debug — promote to warning so probe failures
            # are visible in operator logs (they may indicate network
            # issues, scope misconfiguration, or target-side errors that
            # warrant investigation).
            logger.warning("GraphQL probe failed for %s: %s", url, exc)

    return findings


def _probe_jwt_alg_none(
    base_url: str,
    cookies: dict[str, str] | None = None,
    auth_headers: dict[str, str] | None = None,
) -> list[Finding]:
    """Probe whether the target accepts JWT tokens with alg=none.

    Sends the well-known alg=none test token in the Authorization
    header to common API endpoints. If the target returns 200 (instead
    of 401/403), it accepts unsigned tokens — a critical auth bypass.
    """
    findings: list[Finding] = []
    # No fallback to raw httpx.Client: every network request must pass
    # through the central SSRF, DNS-pinning, redirect, and engagement-scope
    # policy. Import failure is a deployment error, not a reason to bypass it.
    from webpent.shared.http import make_safe_httpx_client

    client_factory = make_safe_httpx_client

    # Probe common authenticated endpoints.
    probe_paths = [
        "/api/v1/me",
        "/api/v1/user",
        "/api/me",
        "/me",
        "/api/v1/profile",
        "/rest/user/whoami",
    ]
    for path in probe_paths:
        url = _resolve_url(base_url, path)
        # V9 P0 B4: attach session cookies alongside the JWT probe. Never
        # merge a real Authorization header: the unsigned token is the test.
        headers: dict[str, str] = {
            str(name): str(value)
            for name, value in (auth_headers or {}).items()
            if str(name).lower() != "authorization" and str(value).strip()
        }
        headers["Authorization"] = f"Bearer {_JWT_ALG_NONE_TOKEN}"
        if cookies:
            # V10 HOSTILE-AUDIT FIX: build_cookie_header was never
            # imported in this function (only _probe_graphql imported
            # it locally) — this line raised an uncaught NameError on
            # every call where `cookies` was truthy, i.e. on EVERY
            # authenticated scan. It sat before this function's own
            # try/except (which only wraps the httpx call below), and
            # api_testing_node calls this function with no try/except
            # of its own, so the NameError propagated all the way out
            # of api_testing_node and aborted the whole pentest task —
            # caught only by pentest_worker's top-level handler
            # (emergency-persists findings gathered so far, marks the
            # task failed). Reproduced and confirmed before this fix.
            from webpent.shared.http import build_cookie_header

            headers["Cookie"] = build_cookie_header(cookies)
        try:
            with client_factory(timeout=10.0, follow_redirects=False, verify=True) as client:
                baseline = client.get(url, headers={})
                resp = client.get(
                    url,
                    headers=headers,
                )
            if resp.status_code == 200:
                if _looks_like_spa_shell(resp):
                    logger.debug("JWT probe skipped SPA shell at %s", url)
                    continue
                if resp.text == baseline.text:
                    logger.debug("JWT probe skipped unchanged public response at %s", url)
                    continue
                # V10 P0-2: wrap Finding construction in try/except.
                try:
                    findings.append(
                        Finding(
                            title=f"JWT alg=none accepted at {path}",
                            description=(
                                f"The endpoint at {url} accepted a JWT token with "
                                f"'alg':'none' (unsigned token) and returned HTTP 200. "
                                f"This means the server does not verify JWT signatures "
                                f"— an attacker can forge any token with any claims "
                                f"and bypass authentication entirely."
                            ),
                            severity=Severity.CRITICAL,
                            confidence_level="AI-Assessed",
                            # V10 P0-1: VulnClass.AUTH_BYPASS is now a real enum
                            # member; previously this raw string raised
                            # pydantic ValidationError and was swallowed.
                            vuln_class=VulnClass.AUTH_BYPASS.value,
                            url=url,
                            tool_name="api_testing_agent",
                            payload=f"Authorization: Bearer {_JWT_ALG_NONE_TOKEN[:80]}...",
                            reasoning=(
                                f"Sent alg=none JWT to {url}. Server returned 200 "
                                f"({len(resp.content)} bytes) instead of 401/403. "
                                f"The server accepts unsigned JWTs."
                            ),
                        )
                    )
                except Exception as exc:
                    logger.error(
                        "api_testing: failed to construct JWT alg=none finding for %s: %s",
                        url,
                        exc,
                    )
                logger.warning("JWT alg=none accepted at %s", url)
                break  # one hit is enough
        except Exception as exc:
            # V10 P0-2: was debug — promote to warning.
            logger.warning("JWT probe failed for %s: %s", url, exc)

    return findings


def _analyze_captured_jwts(
    base_url: str,
    crawled_data: Any,
    *,
    weak_secret_candidates: list[str] | None = None,
    public_key_available: bool = False,
) -> tuple[list[Finding], list[dict[str, Any]], list[dict[str, Any]]]:
    """Analyze JWTs already captured by recon/crawler without active forging.

    A weak-secret result is promoted only when the captured signature verifies
    offline with a bounded candidate.  alg=none and key-confusion results are
    observations/gaps until an explicitly approved endpoint probe confirms
    server-side acceptance.
    """
    from webpent.shared.jwt_deep_testing import (
        analyze_captured_jwt,
        extract_candidate_jwts,
        redact_jwt_observation,
    )

    findings: list[Finding] = []
    observations: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    tokens = extract_candidate_jwts(crawled_data)
    if not tokens:
        coverage_gaps.append(
            {
                "type": "jwt_token_inventory_empty",
                "reason": (
                    "No compact JWT was found in crawl artifacts; endpoint auth "
                    "coverage remains unverified."
                ),
                "source": "api_testing_node",
            }
        )
        return findings, observations, coverage_gaps

    for token in tokens:
        analysis = analyze_captured_jwt(
            token,
            weak_secret_candidates=weak_secret_candidates,
            public_key_available=public_key_available,
        )
        if not analysis:
            continue
        clean_analysis = redact_jwt_observation(analysis)
        observations.extend(clean_analysis.get("observations") or [])
        coverage_gaps.extend(clean_analysis.get("coverage_gaps") or [])
        for item in clean_analysis.get("observations") or []:
            if item.get("type") != "weak_secret_match":
                continue
            if not (
                item.get("causal_signal") is True
                and item.get("negative_control_complete") is True
            ):
                coverage_gaps.append(
                    {
                        "type": "jwt_confirmation_proof_incomplete",
                        "reason": "Weak-secret evidence lacked a completed negative control.",
                        "token_fingerprint": item.get("token_fingerprint"),
                    }
                )
                continue
            try:
                findings.append(
                    Finding(
                        title="JWT signed with a bounded weak HMAC secret",
                        description=(
                            "A JWT captured during the engagement was verified offline "
                            "with a bounded common-secret candidate. This is direct "
                            "signature evidence; no impersonation request was sent."
                        ),
                        severity=Severity.HIGH,
                        confidence_level="Tool-Confirmed",
                        vuln_class=VulnClass.JWT_WEAKNESS.value,
                        url=base_url,
                        tool_name="api_testing_agent",
                        payload="[REDACTED_JWT]",
                        evidence={
                            "token_fingerprint": item.get("token_fingerprint"),
                            "algorithm": item.get("algorithm"),
                            "secret_fingerprint": item.get("secret_fingerprint"),
                            "verification": "offline_hmac_signature_match",
                            "causal_signal": item.get("causal_signal"),
                            "negative_control_complete": item.get("negative_control_complete"),
                            "negative_control": item.get("negative_control"),
                        },
                        reasoning=(
                            "The captured token signature matched one bounded offline "
                            "candidate; the candidate value itself is never persisted."
                        ),
                    )
                )
            except Exception as exc:
                logger.error("api_testing: failed to build weak-JWT finding: %s", exc)
    return findings, observations, coverage_gaps


def _probe_mass_assignment(
    base_url: str,
    cookies: dict[str, str] | None = None,
    auth_headers: dict[str, str] | None = None,
) -> list[Finding]:
    """Probe for mass assignment by sending role escalation fields.

    Sends extra fields (``role=admin``, ``is_admin=true``) to common
    user-update endpoints. If the server accepts the fields (200
    instead of 400/403), mass assignment may be possible.
    """
    findings: list[Finding] = []
    # No fallback to raw httpx.Client: every network request must pass
    # through the central SSRF, DNS-pinning, redirect, and engagement-scope
    # policy. Import failure is a deployment error, not a reason to bypass it.
    from webpent.shared.http import make_safe_httpx_client

    client_factory = make_safe_httpx_client

    probe_paths = ["/api/v1/user", "/api/v1/users/me", "/api/user", "/api/profile"]
    for path in probe_paths:
        url = _resolve_url(base_url, path)
        # V9 P0 B4: attach session cookies so authenticated user-update
        # endpoints are reachable (mass assignment requires an authed session).
        headers: dict[str, str] = {
            str(name): str(value)
            for name, value in (auth_headers or {}).items()
            if str(value).strip()
        }
        headers["Content-Type"] = "application/json"
        if cookies:
            # V10 HOSTILE-AUDIT FIX: same missing-import bug as
            # _probe_jwt_alg_none above — build_cookie_header was
            # never imported in this function, crashing every
            # authenticated scan with an uncaught NameError before it
            # ever reached this function's try/except below.
            from webpent.shared.http import build_cookie_header

            headers["Cookie"] = build_cookie_header(cookies)
        try:
            # Send a PATCH with mass-assignment fields.
            with client_factory(timeout=10.0, follow_redirects=False, verify=True) as client:
                resp = client.patch(
                    url,
                    json={"role": "admin", "is_admin": True, "admin": 1},
                    headers=headers,
                )
            # If the server returns 200 (not 400 for unknown fields),
            # it may have accepted the role escalation.
            if resp.status_code == 200:
                body = resp.text.lower()
                if "admin" in body or '"role"' in body:
                    # V10 P0-2: wrap Finding construction in try/except.
                    try:
                        findings.append(
                            Finding(
                                title=f"Mass assignment at {path}",
                                description=(
                                    f"The endpoint at {url} accepted extra fields "
                                    f"(role=admin, is_admin=true) via PATCH and "
                                    f"returned 200. The response body contains "
                                    f"evidence that the fields were processed. "
                                    f"An attacker may be able to escalate privileges "
                                    f"by including admin-level fields in update "
                                    f"requests."
                                ),
                                severity=Severity.HIGH,
                                confidence_level="AI-Assessed",
                                # V10 P0-1: VulnClass.MASS_ASSIGNMENT is now a real
                                # enum member; previously this raw string raised
                                # pydantic ValidationError and was swallowed.
                                # Deliberately NOT in EXPLOITABLE_CLASSES — mass
                                # assignment is structural, not payload-injection
                                # exploitable, so payload_generator is skipped.
                                vuln_class=VulnClass.MASS_ASSIGNMENT.value,
                                url=url,
                                tool_name="api_testing_agent",
                                payload='{"role":"admin","is_admin":true,"admin":1}',
                                reasoning=(
                                    f"Sent PATCH with role=admin/is_admin=true to "
                                    f"{url}. Server returned 200 with 'admin' in "
                                    f"response body — fields appear to be accepted."
                                ),
                            )
                        )
                    except Exception as exc:
                        logger.error(
                            "api_testing: failed to construct mass-assignment finding for %s: %s",
                            url,
                            exc,
                        )
                    logger.warning("Mass assignment detected at %s", url)
                    break
        except Exception as exc:
            # V10 P0-2: was debug — promote to warning.
            logger.warning("Mass assignment probe failed for %s: %s", url, exc)

    return findings


def api_testing_node(state: PentestState) -> dict:
    """LangGraph node: test API-specific vulnerabilities.

    V7 Sprint 2.6: Probes the target for GraphQL introspection, JWT
    alg=none acceptance, and mass assignment. All probes use
    ``make_safe_httpx_client`` (SSRF guard + engagement-scope allowlist).
    """
    target = state.get("target")
    findings: list[Finding] = list(state.get("findings") or [])
    # V9 P0 B4: read session cookies so authenticated API endpoints
    # (e.g. DVWA's GraphQL/JWT endpoints behind login) are reachable.
    session_cookies: dict[str, str] | None = state.get("session_cookies") or None
    session_headers: dict[str, str] | None = state.get("session_headers") or None
    crawled_data: Any = state.get("crawled_data") or {}

    base_url = getattr(target, "url", "")
    if not base_url:
        return {
            "messages": [AIMessage(content="API Testing Agent: no target URL — skipping.")],
            "current_phase": "api_testing",
        }

    logger.info(
        "API Testing Agent (V7 Sprint 2.6) entered for target=%s "
        "(%d findings, cookies=%s, headers=%s)",
        base_url,
        len(findings),
        bool(session_cookies),
        sorted(session_headers or {}),
    )

    new_findings: list[Finding] = []

    # 1. GraphQL introspection probe
    new_findings.extend(
        _probe_graphql(
            base_url,
            cookies=session_cookies,
            auth_headers=session_headers,
        )
    )

    # 2. JWT alg=none probe (active acceptance evidence, legacy contract).
    new_findings.extend(
        _probe_jwt_alg_none(
            base_url,
            cookies=session_cookies,
            auth_headers=session_headers,
        )
    )

    # 3. JWT deep analysis is offline by default. It never forges a real-user
    # token and never emits raw credentials into state/report output.
    jwt_findings, jwt_observations, jwt_gaps = _analyze_captured_jwts(
        base_url,
        crawled_data,
        weak_secret_candidates=state.get("jwt_weak_secret_candidates"),
        public_key_available=bool(state.get("jwt_public_key_available", False)),
    )
    new_findings.extend(jwt_findings)

    # 4. Mass assignment probe
    new_findings.extend(
        _probe_mass_assignment(
            base_url,
            cookies=session_cookies,
            auth_headers=session_headers,
        )
    )

    logger.info("API Testing Agent: %d findings generated", len(new_findings))

    # V7 Cognitive Upgrade — Phase 2: extract Mental Model updates for
    # the target URL this node probed. Pure additive — does not change
    # any existing api-testing logic. Deterministic regex/heuristic,
    # NO LLM.
    mental_model_update: dict[str, Any] = {"nodes": {}, "edges": []}
    try:
        from webpent.models.mental_model import extract_mental_model_updates

        mental_model_update = extract_mental_model_updates(
            discovery_source="api_testing_node",
            endpoints=[base_url] if base_url else None,
            target_url=base_url,
        )
    except Exception as exc:
        logger.debug("Mental Model extraction (api_testing) failed: %s", exc)

    return {
        # merge_findings reducer dedup by id — safe
        "findings": findings + new_findings,
        "mental_model": mental_model_update,
        "jwt_deep_observations": jwt_observations,
        "jwt_deep_coverage_gaps": jwt_gaps,
        "messages": [
            AIMessage(
                content=f"API Testing Agent: probed GraphQL, JWT, mass "
                f"assignment and offline JWT strength. Found {len(new_findings)} vulnerabilities."
            )
        ],
        "current_phase": "api_testing",
    }
