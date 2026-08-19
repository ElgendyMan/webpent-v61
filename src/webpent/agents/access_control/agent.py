"""Evidence-first multi-identity access-control mapper.

The node remains in the existing LangGraph position, but its probe contract is
now explicit: it compares read-only responses across identities and only emits
a Tool-Confirmed IDOR when ownership provenance plus a reproducible foreign
access differential are both present.  A numeric URL permutation alone is
never treated as confirmation.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from langchain_core.messages import AIMessage

from webpent.models.findings import Finding, Severity, VulnClass
from webpent.shared.authorization_matrix import build_authorization_matrix
from webpent.shared.bac_identity_tester import (
    IdentityProfile,
    assess_access_control,
    build_relational_evidence,
    extract_object_id,
    normalise_identity_profiles,
    profile_owns_resource,
    sanitise_probe_result,
)
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("webpent.audit.access_control")

_ID_PATTERN = re.compile(
    r"/(?:"
    r"(?:users?|accounts?|orders?|documents?|files?|messages?|posts?|"
    r"items?|products?|invoices?|payments?|transactions?|profiles?|"
    r"settings?|configs?|projects?|tasks?|tickets?|reports?)"
    r"/(\d+|[a-f0-9-]{8,}|[a-zA-Z0-9_-]{10,})"
    r")",
    re.IGNORECASE,
)


def _extract_candidate_records(crawled_data: Any) -> list[dict[str, Any]]:
    """Extract dynamic resource records from common crawler shapes.

    Structured crawler artifacts may provide ``owner_identity`` or
    ``object_id``.  Plain URLs remain supported for backward compatibility,
    but are deliberately treated as ownership-unknown later.
    """
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    values: list[Any] = []
    if isinstance(crawled_data, dict):
        for key in ("urls", "endpoints", "links", "pages", "resources"):
            value = crawled_data.get(key)
            if isinstance(value, list):
                values.extend(value)
        for key, value in crawled_data.items():
            if isinstance(key, str) and key.startswith("http"):
                if isinstance(value, dict):
                    values.append({"url": key, **value})
                else:
                    values.append(key)
    elif isinstance(crawled_data, list):
        values.extend(crawled_data)

    for value in values:
        if isinstance(value, dict):
            url = value.get("url") or value.get("href") or value.get("endpoint")
            if not isinstance(url, str):
                continue
            record = dict(value)
        else:
            url = str(value)
            record = {}
        if not url.startswith("http") or not _ID_PATTERN.search(urlparse(url).path):
            continue
        canonical = url.rstrip("/")
        if canonical in seen:
            continue
        seen.add(canonical)
        record["url"] = url
        record.setdefault("object_id", extract_object_id(url))
        owner = (
            record.get("owner_identity")
            or record.get("owner")
            or record.get("owner_id")
            or (record.get("metadata") or {}).get("owner_identity")
            if isinstance(record.get("metadata") or {}, dict)
            else record.get("owner_identity")
        )
        if owner:
            record["owner_identity"] = str(owner)
        records.append(record)
    return records


def _extract_idor_candidates(crawled_data: dict[str, Any]) -> list[str]:
    """Backward-compatible URL-only candidate extractor."""
    return [str(record["url"]) for record in _extract_candidate_records(crawled_data)]


def _probe_url(
    url: str,
    cookies: dict[str, str] | None = None,
    timeout: float = 10.0,
    headers: dict[str, str] | None = None,
) -> tuple[int, int]:
    """Probe a URL read-only and return ``(status_code, content_length)``."""
    try:
        from webpent.config.settings import get_settings
        from webpent.shared.http import build_cookie_header, make_safe_httpx_client

        request_headers: dict[str, str] = dict(headers or {})
        if cookies:
            request_headers["Cookie"] = build_cookie_header(cookies)
        allow_insecure_tls = bool(get_settings().allow_insecure_tls)
        if allow_insecure_tls:
            audit_logger.warning(
                "Access-control probe is using disabled TLS verification "
                "for an authorized lab target"
            )
        with make_safe_httpx_client(
            timeout=timeout,
            follow_redirects=False,
            verify=not allow_insecure_tls,
        ) as client:
            response = client.get(url, headers=request_headers)
        return response.status_code, len(response.content)
    except Exception as exc:
        logger.debug("BAC probe failed for %s: %s", url, exc)
        return 0, 0


def _create_idor_finding(
    url: str,
    status_code: int,
    content_length: int,
    auth_context: str,
    *,
    evidence: dict[str, Any] | None = None,
    confidence_level: str = "AI-Assessed",
    description_suffix: str = "",
) -> Finding:
    """Create a finding while keeping the legacy four-argument contract."""
    path = urlparse(url).path or url
    return Finding(
        title=f"IDOR: Unauthorized access to {path}"[:120],
        description=(
            f"The endpoint {url} returned HTTP {status_code} with "
            f"{content_length} bytes of content when accessed {auth_context}. "
            "This observation requires authorization comparison against an "
            f"explicit resource owner. {description_suffix}"
        ).strip(),
        severity=Severity.HIGH,
        confidence="confirmed" if confidence_level == "Tool-Confirmed" else "tentative",
        confidence_level=confidence_level,
        evidence=evidence,
        vuln_class=VulnClass.IDOR.value,
        url=url,
        tool_name="access_control_mapper",
        payload="",
        reasoning=(
            f"Read-only access-control differential: {auth_context}; "
            f"HTTP {status_code}, {content_length} bytes."
        ),
    )


def _public_identity_rows(profiles: list[IdentityProfile]) -> dict[str, dict[str, Any]]:
    return {profile.name: profile.public_metadata for profile in profiles}


def _identity_profiles_from_state(state: PentestState) -> list[IdentityProfile]:
    raw = state.get("identity_profiles") or state.get("bac_identities") or state.get("identities")
    fallback = state.get("session_cookies") or None
    return normalise_identity_profiles(raw, fallback_cookies=fallback)


def access_control_node(state: PentestState) -> dict:
    """Compare resource access across anonymous and available identities."""
    target = state.get("target")
    findings: list[Finding] = list(state.get("findings") or [])
    crawled_data: Any = state.get("crawled_data") or {}
    records = _extract_candidate_records(crawled_data)
    if not records:
        logger.info("Access Control Mapper: no IDOR candidates found")
        return {
            "messages": [AIMessage(content="Access Control Mapper: no IDOR candidates found.")],
            "current_phase": "access_control_mapping",
        }

    profiles = _identity_profiles_from_state(state)
    # Anonymous is always tested, but never carries ownership metadata.
    probe_profiles = [IdentityProfile(name="anonymous", role="unauthenticated")] + profiles
    # A legacy single session remains useful, but the result is a coverage gap
    # rather than a claimed cross-user confirmation.
    max_candidates = int(state.get("bac_max_candidates") or 20)
    max_identities = int(state.get("bac_max_identities") or 8)
    probe_profiles = probe_profiles[: max(2, max_identities)]

    new_findings: list[Finding] = []
    observations_out: list[dict[str, Any]] = []
    gaps_out: list[dict[str, Any]] = []
    relational_out: list[dict[str, Any]] = []
    matrix_inputs: list[dict[str, Any]] = []
    confirmed_count = 0

    for record in records[:max_candidates]:
        url = str(record["url"])
        object_id = str(record.get("object_id") or extract_object_id(url) or "") or None
        owner_identity = str(record.get("owner_identity") or "").strip() or None
        if not owner_identity:
            owners = [
                profile.name
                for profile in profiles
                if profile_owns_resource(profile, url, object_id)
            ]
            if len(owners) == 1:
                owner_identity = owners[0]

        rows: list[dict[str, Any]] = []
        for profile in probe_profiles:
            status, content_length = _probe_url(
                url,
                cookies=profile.cookies or None,
                headers=profile.headers or None,
            )
            row = sanitise_probe_result(
                profile=profile,
                url=url,
                status_code=status,
                content_length=content_length,
            )
            rows.append(row)
            matrix_inputs.append(
                {
                    **row,
                    "owner_identity": owner_identity,
                    "object_id": object_id,
                    "endpoint": url,
                    "method": str(
                        record.get("method") or record.get("http_method") or "GET"
                    ).upper(),
                    "evidence_refs": [
                        "bac:"
                        f"{object_id or 'unknown'}:{profile.name}:"
                        f"{row.get('response_fingerprint', '')[:24]}"
                    ],
                }
            )

        assessment = assess_access_control(rows, owner_identity=owner_identity)
        edges = build_relational_evidence(rows, owner_identity=owner_identity, object_id=object_id)
        for edge in edges:
            edge["target_url"] = getattr(target, "url", None)
        relational_out.extend(edges)
        observations_out.append(
            {
                "resource_url": url,
                "object_id": object_id,
                "owner_identity": owner_identity,
                "identities_tested": [row["identity"] for row in rows],
                "observations": rows,
                "assessment": assessment,
            }
        )

        if assessment["status"] == "confirmed":
            foreign = next(
                row for row in rows if row["identity"] != owner_identity and row["accessible"]
            )
            evidence = {
                "type": "relational_access_control",
                "owner_identity": owner_identity,
                "object_id": object_id,
                "identity_observations": rows,
                "relational_edges": edges,
                "redaction": "cookies, authorization headers, and raw bodies omitted",
            }
            finding = _create_idor_finding(
                url,
                int(foreign["status_code"]),
                int(foreign["content_length"]),
                f"with non-owner identity {foreign['identity']}",
                evidence=evidence,
                confidence_level="Tool-Confirmed",
                description_suffix=(
                    f"Identity {owner_identity} was recorded as the owner, while "
                    f"identity {foreign['identity']} reproduced successful access."
                ),
            )
            new_findings.append(finding)
            confirmed_count += 1
            audit_logger.warning("Tool-confirmed BAC differential for %s", url)
        elif assessment["status"] in {"coverage_gap", "needs_review", "inconclusive"}:
            gaps_out.append(
                {
                    "resource_url": url,
                    "object_id": object_id,
                    "owner_identity": owner_identity,
                    "status": assessment["status"],
                    "confidence_level": assessment["confidence_level"],
                    "reason": assessment["reason"],
                    "identities_tested": [row["identity"] for row in rows],
                }
            )

    matrix_update: dict[str, Any] = {}
    try:
        from webpent.config.settings import get_settings

        configured_enabled = bool(get_settings().enable_authorization_matrix)
        enabled = (
            bool(state.get("enable_authorization_matrix"))
            if "enable_authorization_matrix" in state
            else configured_enabled
        )
        if enabled:
            settings = get_settings()
            target_url = getattr(target, "url", None)
            if isinstance(target, dict):
                target_url = target.get("url") or target_url
            matrix_update = build_authorization_matrix(
                matrix_inputs,
                target_url=target_url,
                max_rows=int(
                    state.get("max_authorization_matrix_rows")
                    or settings.max_authorization_matrix_rows
                ),
                max_comparisons=int(
                    state.get("max_authorization_matrix_comparisons")
                    or settings.max_authorization_matrix_comparisons
                ),
            )
    except Exception as exc:
        logger.debug("Authorization Matrix projection failed: %s", exc)
        matrix_update = {
            "version": "1",
            "rows": [],
            "comparisons": [],
            "coverage_gaps": ["matrix_projection_failed"],
        }

    mental_model_update: dict[str, Any] = {"nodes": {}, "edges": []}
    try:
        from webpent.models.mental_model import extract_mental_model_updates

        mental_model_update = extract_mental_model_updates(
            discovery_source="access_control_node",
            endpoints=[str(record["url"]) for record in records[:max_candidates]],
            target_url=getattr(target, "url", None),
        )
    except Exception as exc:
        logger.debug("Mental Model extraction (access_control) failed: %s", exc)

    # Do not return runtime cookie material.  The identity profile state is
    # supplied by the auth layer and is intentionally left untouched.
    return {
        "findings": findings + new_findings,
        "bac_observations": observations_out,
        "bac_coverage_gaps": gaps_out,
        "relational_evidence": relational_out,
        "authorization_matrix": matrix_update,
        "mental_model": mental_model_update,
        "messages": [
            AIMessage(
                content=(
                    f"Access Control Mapper: probed {len(records[:max_candidates])} resources "
                    f"across {len(probe_profiles)} identities; "
                    f"confirmed {confirmed_count}, coverage gaps {len(gaps_out)}."
                )
            )
        ],
        "current_phase": "access_control_mapping",
    }


__all__ = [
    "_create_idor_finding",
    "_extract_idor_candidates",
    "_probe_url",
    "access_control_node",
]
