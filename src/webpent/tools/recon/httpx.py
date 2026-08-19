# src/webpent/tools/recon/httpx.py
"""webpent.tools.recon.httpx

Wrapper around ProjectDiscovery's ``httpx`` CLI for live-host probing.

V4.5: Custom timeout (120s) with partial-output recovery on timeout.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from webpent.config.settings import get_settings
from webpent.shared.exceptions import ToolExecutionError
from webpent.tools.registry import register_tool
from webpent.tools.utils.subprocess import run_command

logger = logging.getLogger(__name__)


@register_tool(name="httpx", category="recon", description="HTTP toolkit for live-host probing")
def run_httpx(
    domains: list[str], stealth_mode: bool = False
) -> list[dict[str, Any]]:
    """Probe a list of hosts with httpx and return parsed JSON results.

    Args:
        domains: List of hostnames or URLs to probe.
        stealth_mode: V5 Sprint 6/8 — when True, insert randomized
            jitter and enforce minimum inter-request spacing before
            launching httpx. Recon tools generate the highest traffic
            volume, so stealth is most impactful here.

    Returns:
        A list of dictionaries, one per valid JSONL record emitted by
        httpx. Lines that fail JSON parsing are silently skipped.

    Raises:
        ToolNotFoundError: If ``httpx`` is not installed.
        ToolExecutionError: If httpx exits non-zero (non-timeout).
    """
    # V5 Sprint 8: pre-tool stealth delay. httpx probes many hosts in
    # a burst — pacing matters for WAF/IDS evasion.
    if stealth_mode:
        from webpent.shared.stealth import (
            apply_jitter,
            enforce_min_interval,
            extract_host,
        )
        apply_jitter(stealth_mode, label="httpx")
        # Rate-limit per first domain (httpx probes many at once; we
        # use the first as a proxy for the batch).
        if domains:
            enforce_min_interval(stealth_mode, extract_host(domains[0]))

    settings = get_settings()
    cmd = [
        settings.httpx_path,
        "-silent",
        "-json",
    ]

    # V10 HOSTILE P2-1 FIX: scope gate — filter the input domains through
    # the engagement_scope allowlist before probing. httpx runs as a
    # subprocess and is NOT wrapped by make_safe_httpx_client, so the
    # SSRF guard does not cover it. A subfinder-discovered subdomain
    # that resolves to an internal IP (e.g. internal.corp.example.com
    # → 10.0.0.5) would be probed by httpx, exfiltrating internal
    # service banners into the recon data. Gate: only probe domains
    # whose hostname matches the engagement's declared target host.
    from urllib.parse import urlparse

    from webpent.shared.engagement_scope import is_engagement_target_host
    _scoped_domains: list[str] = []
    _dropped_count = 0
    for d in domains:
        d_stripped = d.strip() if d else ""
        if not d_stripped:
            continue
        # Normalize to a hostname for the scope check.
        _host = d_stripped
        if "://" not in _host:
            _host = "http://" + _host
        _hostname = (urlparse(_host).hostname or "").lower()
        if _hostname and is_engagement_target_host(_hostname):
            _scoped_domains.append(d_stripped)
        else:
            _dropped_count += 1
            logger.debug(
                "httpx scope gate: dropping %s (host %s not in engagement target)",
                d_stripped, _hostname,
            )
    if _dropped_count:
        logger.info(
            "httpx scope gate: dropped %d/%d domain(s) not in engagement "
            "target scope (SSRF safety).",
            _dropped_count, len(domains),
        )
    domains = _scoped_domains

    input_data = "\n".join(d.strip() for d in domains if d and d.strip())

    # V4.5: Custom timeout + partial-output recovery.
    try:
        raw_output = run_command(cmd, input_data=input_data, timeout=120)
    except ToolExecutionError as exc:
        if "timed out" in (exc.stderr or "").lower() and exc.stdout:
            logger.warning(
                "httpx timed out after 120s — processing partial output (%d bytes)",
                len(exc.stdout),
            )
            raw_output = exc.stdout
        else:
            logger.error(
                "httpx FAILED (exit=%d, error_reason=%s)",
                exc.returncode, (exc.stderr or "")[:200],
            )
            raise

    results: list[dict[str, Any]] = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            results.append(record)

    # V7 Phase 6: Classify tool failure mode.
    if not raw_output.strip():
        logger.warning("TOOL_INFRA_FAILURE: httpx produced no output.")

    return results
