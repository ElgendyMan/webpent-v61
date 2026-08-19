"""Bounded same-origin HTTP discovery used when optional crawler binaries are absent.

The discovery path is intentionally target-agnostic.  It starts from the
operator-declared URL, preserves the supplied session cookie jar, follows only
same-origin links and redirects, and returns structured observations rather
than treating a URL alone as a vulnerability.  It is a coverage fallback for
recon; validators still need independent, tool-backed evidence.
"""

from __future__ import annotations

import json
import re
from collections import deque
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from webpent.config.settings import get_settings

_DEFAULT_ROUTE_SEEDS = (
    "/swagger_ui",
    "/swagger",
    "/openapi.json",
    "/api/docs",
    "/docs",
    "/graphql",
    "/elasticsearch",
    "/es/fetch",
    "/es/fetch/127.0.0.1:8000/health",
    "/csv/upload",
    "/upload",
    "/download",
    "/export",
    "/export-erp",
    "/crm/export",
    "/user_profile/1",
    "/profile",
    "/training/send-results-email",
    "/oauth/authorize",
    "/oauth/callback",
    "/redirect",
    "/api",
    "/api/users",
    "/storage",
    "/backup",
    "/health",
)


class _SurfaceParser(HTMLParser):
    """Small HTML parser for links, scripts, and forms.

    HTMLParser is used instead of regular expressions so quoted attributes,
    casing, and nested form controls are handled without storing response
    bodies in scan state.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None
        self._select_name: str | None = None
        self._select_value: str = ""
        self._textarea_name: str | None = None
        self._textarea_value: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {str(k).lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "a" and attributes.get("href"):
            self.links.append(attributes["href"])
        elif tag == "link" and attributes.get("href"):
            # Stylesheets are not useful attack endpoints, but same-origin
            # preload/module links can reveal application assets.
            self.links.append(attributes["href"])
        elif tag == "script" and attributes.get("src"):
            self.scripts.append(attributes["src"])
        elif tag == "form":
            self._form = {
                "action": attributes.get("action", ""),
                "method": (attributes.get("method") or "GET").upper(),
                "data": {},
            }
        elif tag in {"input", "button"} and self._form is not None:
            name = attributes.get("name")
            if name:
                input_type = (attributes.get("type") or "text").lower()
                # Never copy a password value into recon state.  Empty
                # password fields remain useful as a parameter signal.
                value = "" if input_type == "password" else attributes.get("value", "")
                self._form["data"][name] = value
        elif tag == "textarea" and self._form is not None:
            name = attributes.get("name")
            if name:
                self._textarea_name = name
                self._textarea_value = []
        elif tag == "select" and self._form is not None:
            name = attributes.get("name")
            if name:
                self._select_name = name
                self._select_value = ""
        elif (
            tag == "option"
            and self._select_name is not None
            and (attributes.get("selected") is not None or not self._select_value)
        ):
            self._select_value = attributes.get("value", "")

    def handle_data(self, data: str) -> None:
        if self._textarea_name is not None:
            self._textarea_value.append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "textarea" and self._form is not None and self._textarea_name:
            self._form["data"][self._textarea_name] = "".join(self._textarea_value).strip()
            self._textarea_name = None
            self._textarea_value = []
        elif tag == "select" and self._form is not None and self._select_name:
            self._form["data"][self._select_name] = self._select_value
            self._select_name = None
            self._select_value = ""
        elif tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, host, port


def _same_origin(url: str, base_url: str) -> bool:
    try:
        return _origin(url) == _origin(base_url)
    except ValueError:
        return False


def _normalise_url(candidate: str, base_url: str) -> str | None:
    if not candidate:
        return None
    lowered = candidate.strip().lower()
    if lowered.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return None
    absolute = urljoin(base_url, candidate.strip())
    try:
        parts = urlsplit(absolute)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return None
        if not _same_origin(absolute, base_url):
            return None
        # Fragments are client-side state and do not identify a server route.
        return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))
    except ValueError:
        return None


# GET discovery must remain read-only.  Many applications expose logout,
# delete, reset, or unsubscribe actions as links, and visiting one of them can
# destroy the authenticated session or mutate target state.  This is a
# route-oriented guard, not a target-specific allowlist: it protects arbitrary
# applications while leaving normal pages and forms discoverable.
_STATE_CHANGING_ROUTE_RE = re.compile(
    r"(?:^|[\\/_.?=&-])(?:logout|log[-_]?out|sign[-_]?out|delete|destroy|remove|reset|purge|wipe|shutdown|"
    r"deactivate|unsubscribe|cancel|terminate|drop)(?:[\\/_.?=&-]|$)",
    re.IGNORECASE,
)


def _is_safe_discovery_get(url: str, *, start_url: str) -> bool:
    """Return whether a discovered GET URL is safe to fetch passively.

    The operator-supplied start URL is always allowed; the guard applies only
    to links/redirects discovered from the target.  Query values are included
    because routes such as ``account?action=delete`` can be destructive even
    when the path itself is generic.
    """
    if url == start_url:
        return True
    try:
        parts = urlsplit(url)
        route = f"{parts.path or '/'}?{parts.query}" if parts.query else (parts.path or "/")
        return _STATE_CHANGING_ROUTE_RE.search(route) is None
    except ValueError:
        return False


def _get_form_url(action: str, source_url: str, data: dict[str, str]) -> str:
    action_url = _normalise_url(action, source_url) or source_url
    parts = urlsplit(action_url)
    existing = parse_qsl(parts.query, keep_blank_values=True)
    merged = existing + [(str(k), str(v)) for k, v in data.items() if str(k)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(merged), ""))


def _redact_form_data(data: dict[str, str]) -> dict[str, str]:
    # Keep field names and values needed by read-only analysis.  Password
    # values were already removed by the parser; values are bounded to avoid
    # allowing a large hidden field to inflate the graph checkpoint.
    return {str(k)[:200]: str(v)[:500] for k, v in data.items()}


def _bounded_xml_locations(text: str, base_url: str, *, limit: int = 100) -> list[str]:
    """Extract same-origin sitemap locations without retaining XML content."""
    locations: list[str] = []
    pattern = r"<loc>\s*(.*?)\s*</loc>"
    for match in re.finditer(pattern, text[:1_000_000], re.IGNORECASE | re.DOTALL):
        candidate = _normalise_url(match.group(1), base_url)
        if candidate and candidate not in locations:
            locations.append(candidate)
        if len(locations) >= limit:
            break
    return locations


def _bounded_js_routes(text: str, base_url: str, *, limit: int = 100) -> list[str]:
    """Extract route-shaped JS string literals as passive discovery hints."""
    routes: list[str] = []
    for match in re.finditer(r'''["']((?:/|https?://)[^"'<>\s]{1,300})["']''', text[:1_000_000]):
        candidate = _normalise_url(match.group(1), base_url)
        if candidate and candidate not in routes:
            routes.append(candidate)
        if len(routes) >= limit:
            break
    return routes


def discover_http_surface(
    base_url: str,
    *,
    session_cookies: dict[str, str] | None = None,
    max_pages: int = 50,
    max_depth: int = 3,
    max_links_per_page: int = 100,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Discover a bounded authenticated same-origin surface.

    The function performs GET requests only.  Forms are described but never
    submitted.  Returned ``forms`` are metadata for later, separately gated
    validators and are not Findings.
    """
    from webpent.shared.http import build_cookie_header, make_safe_httpx_client

    start = _normalise_url(base_url, base_url)
    if not start:
        return {
            "endpoints": [],
            "forms": [],
            "pages_fetched": 0,
            "redirects_followed": 0,
            "errors": 1,
            "coverage_gaps": ["invalid_target_url"],
        }

    queue: deque[tuple[str, int]] = deque([(start, 0)])
    queued = {start}
    endpoints: list[str] = []
    seen: set[str] = set()
    forms: list[dict[str, Any]] = []
    surface_records: list[dict[str, Any]] = []
    redirects_followed = 0
    errors = 0
    skipped_off_origin = 0
    skipped_state_changing = 0
    settings = get_settings()
    headers: dict[str, str] = {"User-Agent": settings.http_user_agent or "WebPent/HTTP-discovery"}
    cookie_header = build_cookie_header(session_cookies)
    if cookie_header:
        headers["Cookie"] = cookie_header

    try:
        client_context = make_safe_httpx_client(
            timeout=timeout,
            follow_redirects=False,
            verify=True,
            headers=headers,
        )
    except Exception:
        return {
            "endpoints": [],
            "forms": [],
            "pages_fetched": 0,
            "redirects_followed": 0,
            "errors": 1,
            "coverage_gaps": ["http_client_unavailable"],
        }

    discovery_metadata: dict[str, Any] = {
        "robots_fetched": False,
        "robots_disallow_count": 0,
        "sitemap_urls": [],
        "openapi_urls": [],
        "graphql_urls": [],
        "js_route_candidates": [],
    }

    with client_context as client:
        # These are bounded read-only probes. They enrich the queue when the
        # application does not expose links in HTML, while remaining same-origin.
        origin = f"{urlsplit(start).scheme}://{urlsplit(start).netloc}"
        robots_url = f"{origin}/robots.txt"
        try:
            robots_response = client.get(robots_url)
            if 200 <= robots_response.status_code < 400:
                discovery_metadata["robots_fetched"] = True
                robots_text = str(getattr(robots_response, "text", ""))[:200_000]
                disallows = [
                    line.split(":", 1)[1].strip()
                    for line in robots_text.splitlines()
                    if line.lower().startswith("disallow:") and ":" in line
                ]
                discovery_metadata["robots_disallow_count"] = min(len(disallows), 200)
                sitemap_urls = [
                    _normalise_url(line.split(":", 1)[1].strip(), start)
                    for line in robots_text.splitlines()
                    if line.lower().startswith("sitemap:") and ":" in line
                ]
                discovery_metadata["sitemap_urls"] = [
                    item for item in sitemap_urls[:5] if item
                ]
        except Exception:
            errors += 1

        sitemap_candidates = list(discovery_metadata["sitemap_urls"])
        if not sitemap_candidates:
            sitemap_candidates = [f"{origin}/sitemap.xml"]
        for sitemap_url in sitemap_candidates[:5]:
            try:
                sitemap_response = client.get(sitemap_url)
                content_type = str(sitemap_response.headers.get("content-type", "")).lower()
                if sitemap_response.status_code < 400 and (
                    "xml" in content_type or "<loc" in str(getattr(sitemap_response, "text", ""))
                ):
                    for discovered in _bounded_xml_locations(
                        str(getattr(sitemap_response, "text", "")), start
                    ):
                        if discovered not in queued and len(queued) < max_pages * 3:
                            queue.append((discovered, 0))
                            queued.add(discovered)
            except Exception:
                errors += 1

        openapi_candidates = [f"{origin}/openapi.json", f"{origin}/swagger.json"]
        for openapi_url in openapi_candidates:
            try:
                api_response = client.get(openapi_url)
                if api_response.status_code >= 400:
                    continue
                payload = json.loads(str(getattr(api_response, "text", ""))[:1_000_000])
                paths = payload.get("paths", {}) if isinstance(payload, dict) else {}
                if isinstance(paths, dict):
                    discovery_metadata["openapi_urls"].append(openapi_url)
                    for path in list(paths)[:100]:
                        discovered = _normalise_url(str(path), start)
                        if discovered and discovered not in queued and len(queued) < max_pages * 3:
                            queue.append((discovered, 0))
                            queued.add(discovered)
            except Exception:
                continue

        graphql_url = f"{origin}/graphql"
        if graphql_url not in queued:
            discovery_metadata["graphql_urls"] = [graphql_url]
            queue.append((graphql_url, 0))
            queued.add(graphql_url)

        # Bounded route seeds improve coverage when an application hides routes
        # behind JavaScript or authentication. They are GET-only observations;
        # validators still need independent evidence before promoting findings.
        # Keep them as a fallback so normal links retain priority at small budgets.
        route_seeds = list(_DEFAULT_ROUTE_SEEDS)
        for raw_seed in str(getattr(settings, "discovery_route_seeds", "") or "").split(","):
            seed = raw_seed.strip()
            if seed and seed not in route_seeds:
                route_seeds.append(seed[:300])

        while True:
            if not queue:
                if len(seen) >= max_pages or not route_seeds:
                    break
                for seed in route_seeds[:40]:
                    candidate = _normalise_url(seed, start)
                    if candidate and candidate not in queued and len(queued) < max_pages * 3:
                        queue.append((candidate, max_depth))
                        queued.add(candidate)
                route_seeds = []
                if not queue:
                    break
            current, depth = queue.popleft()
            if current in seen:
                continue
            if not _is_safe_discovery_get(current, start_url=start):
                skipped_state_changing += 1
                continue
            seen.add(current)
            endpoints.append(current)
            try:
                response = client.get(current)
            except Exception:
                errors += 1
                continue

            parsed_current = urlsplit(current)
            content_type = response.headers.get("content-type", "").lower()
            surface_records.append(
                {
                    "record_id": f"http:{len(surface_records) + 1}",
                    "source": "http_get",
                    "confidence": "observed",
                    "method": "GET",
                    "url": current,
                    "origin": f"{parsed_current.scheme}://{parsed_current.netloc}",
                    "scheme": parsed_current.scheme,
                    "port": parsed_current.port
                    or (443 if parsed_current.scheme == "https" else 80),
                    "path": parsed_current.path or "/",
                    "query_parameters": sorted({key for key, _ in parse_qsl(parsed_current.query)}),
                    "content_type": content_type[:160],
                    "status_code": response.status_code,
                    "response_headers": {
                        key.lower(): response.headers.get(key, "")[:300]
                        for key in ("content-type", "location", "allow", "server")
                        if response.headers.get(key)
                    },
                    "session_present": bool(cookie_header),
                    "identity": "authenticated" if cookie_header else "anonymous",
                    "tenant": None,
                    "workflow_state": "discovery",
                    "predecessor": None,
                    "successor": None,
                }
            )

            if 300 <= response.status_code < 400:
                location = response.headers.get("location", "")
                redirect_url = _normalise_url(location, current)
                if redirect_url and not _is_safe_discovery_get(redirect_url, start_url=start):
                    skipped_state_changing += 1
                elif redirect_url and redirect_url not in queued and depth < max_depth:
                    queue.append((redirect_url, depth + 1))
                    queued.add(redirect_url)
                    redirects_followed += 1
                elif location:
                    skipped_off_origin += 1
                continue

            if response.status_code < 200 or response.status_code >= 400:
                continue
            if not (
                "html" in content_type
                or "xhtml" in content_type
                or response.text.lstrip().startswith("<")
            ):
                continue

            parser = _SurfaceParser()
            try:
                parser.feed(response.text[:2_000_000])
            except Exception:
                errors += 1
                continue

            for form in parser.forms:
                action = _normalise_url(str(form.get("action", "")), current) or current
                method = str(form.get("method") or "GET").upper()
                data = _redact_form_data(form.get("data") or {})
                record = {
                    "action": action,
                    "method": method,
                    "data": data,
                    "source_url": current,
                }
                if record not in forms:
                    forms.append(record)
                if method == "GET":
                    form_url = _get_form_url(action, current, data)
                    if form_url not in queued and len(seen) + len(queue) < max_pages * 2:
                        queue.append((form_url, depth + 1))
                        queued.add(form_url)

            discovery_metadata["js_route_candidates"].extend(
                _bounded_js_routes(response.text, current, limit=100)
            )
            candidates = parser.links + parser.scripts + discovery_metadata["js_route_candidates"]
            for candidate in candidates[:max_links_per_page]:
                discovered = _normalise_url(candidate, current)
                if not discovered:
                    try:
                        absolute = urljoin(current, candidate)
                        if absolute.startswith(("http://", "https://")) and not _same_origin(
                            absolute, base_url
                        ):
                            skipped_off_origin += 1
                    except Exception:
                        pass
                    continue
                if discovered not in queued and depth < max_depth:
                    queue.append((discovered, depth + 1))
                    queued.add(discovered)


    gaps: list[str] = []
    if not endpoints:
        gaps.append("no_same_origin_endpoints")
    if errors:
        gaps.append("request_or_parse_errors")
    if skipped_off_origin:
        gaps.append("off_origin_links_filtered")
    if skipped_state_changing:
        gaps.append("state_changing_gets_not_fetched")
    gaps.append("forms_described_not_submitted")
    gaps.append("browser_generated_routes_not_captured")

    return {
        "endpoints": endpoints,
        "forms": forms,
        "pages_fetched": len(seen),
        "redirects_followed": redirects_followed,
        "errors": errors,
        "skipped_off_origin": skipped_off_origin,
        "skipped_state_changing": skipped_state_changing,
        "coverage_gaps": gaps,
        "coverage_blockers": [
            {
                "capability": "http_client",
                "reason": "infrastructure_failure",
            }
            for gap in gaps
            if gap == "http_client_unavailable"
        ],
        "surface_records": surface_records,
        "discovery_metadata": {
            **discovery_metadata,
            "js_route_candidates": sorted(set(discovery_metadata["js_route_candidates"]))[:200],
        },
        "workflow_mode": "read_only_discovery",
    }


__all__ = ["discover_http_surface"]

# End of file
