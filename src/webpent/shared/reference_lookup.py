"""V7 Phase 2 — Live Reference Lookup with allowlist + bounded lookups."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus, urlparse

logger = logging.getLogger(__name__)
MAX_LOOKUPS_PER_FINDING = 3
MAX_REFERENCE_CHARS = 4000
_MANIFEST_PATH = Path(__file__).resolve().parents[3] / "knowledge_sources.yaml"
_lookup_count: dict[str, int] = {}


def _load_allowlist() -> list[dict[str, Any]]:
    try:
        import yaml

        if not _MANIFEST_PATH.is_file():
            return []
        with open(_MANIFEST_PATH) as f:
            return yaml.safe_load(f).get("live_references", [])
    except Exception:
        return []


def _is_url_allowed(url: str, allowlist: list[dict[str, Any]]) -> bool:
    for entry in allowlist:
        base = entry.get("base_url", "")
        if not base or not url.startswith(base):
            continue
        allowed_paths = entry.get("allowed_paths", [])
        if not allowed_paths:
            return True
        path = urlparse(url).path
        return any(path.startswith(ap) for ap in allowed_paths)
    return False


def reference_lookup(
    query: str, finding_id: str, *, source: str = "hacktricks", max_results: int = 3
) -> str:
    count = _lookup_count.get(finding_id, 0)
    if count >= MAX_LOOKUPS_PER_FINDING:
        logger.info(
            "reference_lookup: budget exceeded for %s (%d/%d)",
            finding_id,
            count,
            MAX_LOOKUPS_PER_FINDING,
        )
        return ""
    _lookup_count[finding_id] = count + 1
    allowlist = _load_allowlist()
    if not allowlist:
        return ""
    entry = next((e for e in allowlist if e.get("name") == source), None)
    if not entry:
        return ""
    base_url = entry.get("base_url", "")
    # V7 Ready-For-Kali P0 FIX: query.replace(' ', '+') is not proper
    # URL encoding. `query` is typically derived from a skill name or
    # finding title/description -- content that can itself be
    # influenced by the scanned target's responses. An unescaped `&`,
    # `#`, or `%` in `query` could inject extra query parameters or
    # break the URL structure. Fixed with quote_plus (proper encoding,
    # including spaces -> '+').
    search_url = f"{base_url}/search?q={quote_plus(query)}" if source == "hacktricks" else base_url
    if not _is_url_allowed(search_url, allowlist):
        return ""
    try:
        from webpent.shared.http import make_safe_httpx_client

        # V7 Ready-For-Kali P0 FIX: removed verify=True. This request
        # goes to a FIXED, supposedly-trusted reference site (from
        # knowledge_sources.yaml), not an arbitrary pentest target —
        # there is no legitimate reason to accept an invalid TLS cert
        # here. Disabling cert verification for a "trusted reference"
        # lookup opens exactly the kind of MITM-spoofed-content risk
        # this whole knowledge-source system is supposed to guard
        # against (feeding the LLM fake "trusted" reference material).
        with make_safe_httpx_client(timeout=15.0, follow_redirects=True) as c:
            resp = c.get(search_url)
        if resp.status_code != 200:
            return ""
        content = resp.text[:MAX_REFERENCE_CHARS]
    except Exception as e:
        logger.debug("reference_lookup: %s", e)
        return ""
    # V7 Ready-For-Kali P0 FIX: use safe_prompt_format (the same
    # sanitization every other untrusted-content path in this codebase
    # goes through — structural cleanup + injection-defense framing),
    # not the raw _UNTRUSTED_WRAPPER.format() which skips it.
    from webpent.shared.llm import safe_prompt_format

    framed = safe_prompt_format("{content}", content=content)
    logger.info(
        "reference_lookup: %d chars from %s for %s (%d/%d)",
        len(content),
        source,
        finding_id,
        count + 1,
        MAX_LOOKUPS_PER_FINDING,
    )
    return framed


def reset_lookup_budget(finding_id: str | None = None) -> None:
    if finding_id:
        _lookup_count.pop(finding_id, None)
    else:
        _lookup_count.clear()
