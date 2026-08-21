"""LangGraph node for bounded, evidence-first JavaScript intelligence."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urljoin

from langchain_core.messages import AIMessage

from webpent.config.settings import get_settings
from webpent.models.javascript_intelligence import JavaScriptIntelligence
from webpent.shared.javascript_intelligence import (
    analyze_javascript_source,
    merge_javascript_intelligence,
)
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)


def _js_candidate_urls(state: PentestState) -> list[str]:
    crawled = state.get("crawled_data") or {}
    target = state.get("target")
    target_url = str(getattr(target, "url", "") or "").strip()
    values: list[Any] = []
    for key in ("javascript_urls", "js_urls", "endpoints", "urls", "links"):
        candidate = crawled.get(key)
        if isinstance(candidate, list):
            values.extend(candidate)
    urls: list[str] = []
    seen: set[str] = set()
    for item in values:
        raw = item.get("url") or item.get("href") if isinstance(item, dict) else item
        if not isinstance(raw, str):
            continue
        raw = raw.strip()
        if not raw:
            continue
        absolute = raw if raw.startswith(("http://", "https://")) else urljoin(
            target_url.rstrip("/") + "/", raw
        )
        if not absolute.startswith(("http://", "https://")):
            continue
        is_script = absolute.lower().split("?", 1)[0].endswith((".js", ".mjs"))
        if not is_script and not isinstance(item, dict):
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        urls.append(absolute)
    return urls


def _empty_result(reason: str = "js_intelligence_disabled") -> dict[str, Any]:
    return {
        "javascript_intelligence": JavaScriptIntelligence(coverage_gaps=[reason]).model_dump(
            mode="json"
        ),
        "js_targeted_tasks": [],
    }


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).
def javascript_intelligence_node(state: PentestState) -> dict[str, Any]:
    """Collect and statically review same-scope JavaScript assets.

    The node is advisory and fail-closed: a fetch failure becomes a coverage
    gap, never a finding. Source text is analyzed in memory and only hashes,
    redacted metadata, and non-destructive tasks are returned in state.
    """
    settings = get_settings()
    if not settings.enable_js_intelligence:
        return _empty_result()

    target = state.get("target")
    if target is None:
        return _empty_result("js_target_missing")

    candidates = _js_candidate_urls(state)[: settings.max_js_assets]
    if not candidates:
        return _empty_result("no_javascript_assets_observed")

    try:
        from webpent.shared.http import make_safe_httpx_client
    except ImportError:
        return _empty_result("safe_http_client_unavailable")

    results: list[JavaScriptIntelligence] = []
    fetch_gaps: list[str] = []
    try:
        with make_safe_httpx_client(
            timeout=min(15.0, float(settings.http_timeout)),
            follow_redirects=True,
            verify=True,
        ) as client:
            for asset_url in candidates:
                if not target.is_in_scope(asset_url):
                    fetch_gaps.append("js_asset_out_of_scope")
                    continue
                try:
                    response = client.get(asset_url)
                    content_type = str(response.headers.get("content-type", "unknown"))
                    if response.status_code != 200:
                        fetch_gaps.append(f"js_fetch_status:{response.status_code}")
                        continue
                    raw = response.content
                    if len(raw) > settings.max_js_asset_bytes:
                        results.append(
                            analyze_javascript_source(
                                asset_url=asset_url,
                                source=raw[: settings.max_js_asset_bytes].decode(
                                    "utf-8", "replace"
                                ),
                                target_url=target.url,
                                content_type=content_type,
                                status_code=response.status_code,
                                max_bytes=settings.max_js_asset_bytes,
                            )
                        )
                        continue
                    source = raw.decode("utf-8", "replace")
                    results.append(
                        analyze_javascript_source(
                            asset_url=asset_url,
                            source=source,
                            target_url=target.url,
                            content_type=content_type,
                            status_code=response.status_code,
                            max_bytes=settings.max_js_asset_bytes,
                        )
                    )
                except Exception as exc:  # noqa: BLE001 - one asset must not abort the scan
                    logger.debug("JS intelligence failed for %s: %s", asset_url, exc)
                    fetch_gaps.append("js_fetch_failed")
    except Exception as exc:  # noqa: BLE001 - safe degradation for optional node
        logger.warning("JS intelligence HTTP phase unavailable: %s", exc)
        fetch_gaps.append("js_http_phase_failed")

    intelligence = merge_javascript_intelligence(results)
    if fetch_gaps:
        intelligence.coverage_gaps = list(dict.fromkeys(intelligence.coverage_gaps + fetch_gaps))
    intelligence.targeted_tasks = intelligence.targeted_tasks[: settings.max_js_targeted_tasks]
    output = intelligence.model_dump(mode="json")

    # V59 P0: the crawler computes passive surface coverage before this
    # node runs, so JS-derived routes/sinks/secrets were previously absent
    # from ``surface_security``. Re-run the bounded, observation-only
    # projection after the static review and pass the JS projection
    # explicitly; no observation is promoted to a Finding here.
    surface_security_update: dict[str, Any] = {}
    if bool(getattr(settings, "enable_surface_security_analysis", False)):
        try:
            from webpent.shared.surface_security import analyze_security_surface

            surface_security_update = analyze_security_surface(
                state.get("crawled_data") or {},
                target.url,
                javascript_intelligence=output,
                max_observations=int(getattr(settings, "max_surface_security_observations", 100)),
            )
        except Exception as exc:  # noqa: BLE001 - optional projection boundary
            logger.warning("JS surface-security projection skipped safely: %s", exc)

    # Bridge the redaction-safe static secret candidates into the legacy
    # ``crawled_data.js_secrets`` projection consumed by the bug-bounty
    # appendix. Raw secret values are never present in this projection.
    redacted_secrets = [
        {
            "type": candidate.get("kind", "JavaScript secret candidate"),
            "value": candidate.get("redacted_value", "[REDACTED]"),
            "source": candidate.get("source_asset", "—"),
            "evidence_ref": candidate.get("evidence_ref", ""),
            "value_sha256": candidate.get("value_sha256", ""),
        }
        for candidate in output.get("secret_candidates", [])
        if isinstance(candidate, dict)
    ]
    crawled_data_update: dict[str, Any] = {}
    if redacted_secrets:
        existing_secrets = list((state.get("crawled_data") or {}).get("js_secrets") or [])
        seen = {
            (
                str(item.get("type", "")),
                str(item.get("source", "")),
                str(item.get("value", "")),
            )
            for item in existing_secrets
            if isinstance(item, dict)
        }
        merged_secrets = list(existing_secrets)
        for secret in redacted_secrets:
            key = (secret["type"], secret["source"], secret["value"])
            if key not in seen:
                merged_secrets.append(secret)
                seen.add(key)
        crawled_data_update["js_secrets"] = merged_secrets[:500]

    message = (
        f"JavaScript intelligence reviewed {len(output['assets'])} asset(s), "
        f"identified {len(output['routes'])} route(s), {len(output['sinks'])} sink(s), "
        f"and {len(output['targeted_tasks'])} bounded targeted task(s)."
    )
    result: dict[str, Any] = {
        "javascript_intelligence": output,
        "js_targeted_tasks": output["targeted_tasks"],
        "messages": [AIMessage(content=message)],
    }
    if surface_security_update:
        result["surface_security"] = surface_security_update
    if crawled_data_update:
        result["crawled_data"] = crawled_data_update
    return result


__all__ = ["javascript_intelligence_node"]
