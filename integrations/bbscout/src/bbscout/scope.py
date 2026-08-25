"""Fail-closed scope normalization.

This module only turns *structured provider scope* into local policy rules.  It never
crawls, resolves DNS, follows redirects, or makes target requests.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

from .models import NormalizedRule, ScopeAssessment, ScopeAsset, ScopeStatus, utc_now

HOST_RE = re.compile(r"^(?:\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$", re.IGNORECASE)


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def _normalize_url(asset: ScopeAsset, action: str) -> tuple[NormalizedRule | None, list[str]]:
    raw = asset.value.strip()
    warnings: list[str] = []
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None, [f"{asset.asset_id}: URL غير صالح أو بدون scheme/host صريح."]
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        warnings.append(
            f"{asset.asset_id}: URL فيه credentials/query/fragment؛ "
            "تم تجاهل الأجزاء غير المصرح بها."
        )
    host = parsed.hostname.lower().rstrip(".")
    wildcard = host.startswith("*.")
    if wildcard and host.count("*") != 1:
        return None, [f"{asset.asset_id}: wildcard غير صالح."]
    if not HOST_RE.fullmatch(host):
        return None, [f"{asset.asset_id}: hostname غير صالح."]
    try:
        port = parsed.port
    except ValueError:
        return None, [f"{asset.asset_id}: port غير صالح."]
    return NormalizedRule(
        rule_id=f"{action}:{asset.asset_id}",
        action=action,
        asset_type="url",
        scheme=parsed.scheme.lower(),
        host=host,
        port=port,
        path=parsed.path or "/",
        wildcard=wildcard,
        raw_value=raw,
        decision_reason=(
            "Structured provider URL scope; apex remains excluded for wildcard rules "
            "unless separately included."
        ),
        source_asset_id=asset.asset_id,
    ), warnings


def _normalize_host(asset: ScopeAsset, action: str) -> tuple[NormalizedRule | None, list[str]]:
    raw = asset.value.strip().lower().rstrip(".")
    wildcard = raw.startswith("*.")
    if not HOST_RE.fullmatch(raw) or raw.count("*") > 1:
        return None, [f"{asset.asset_id}: domain/wildcard غير صالح."]
    return NormalizedRule(
        rule_id=f"{action}:{asset.asset_id}",
        action=action,
        asset_type="domain",
        scheme=None,
        host=raw,
        port=None,
        path=None,
        wildcard=wildcard,
        raw_value=asset.value,
        decision_reason=(
            "Structured provider domain scope; wildcard does not include apex "
            "unless separately listed."
        ),
        source_asset_id=asset.asset_id,
    ), []


def _normalize_network(asset: ScopeAsset, action: str) -> tuple[NormalizedRule | None, list[str]]:
    raw = asset.value.strip()
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None, [f"{asset.asset_id}: IP/CIDR غير صالح."]
    return NormalizedRule(
        rule_id=f"{action}:{asset.asset_id}",
        action=action,
        asset_type="cidr" if "/" in raw else "ip",
        scheme=None,
        host=str(network),
        port=None,
        path=None,
        wildcard=False,
        raw_value=raw,
        decision_reason="Structured provider network scope; no adjacent addresses are implied.",
        source_asset_id=asset.asset_id,
    ), []


def normalize_asset(asset: ScopeAsset, action: str) -> tuple[NormalizedRule | None, list[str]]:
    kind = asset.asset_type.strip().lower()
    if kind in {"url", "website"}:
        return _normalize_url(asset, action)
    if kind in {"domain", "wildcard"}:
        return _normalize_host(asset, action)
    if kind in {"ip", "cidr", "ip_address"}:
        return _normalize_network(asset, action)
    return None, [
        f"{asset.asset_id}: asset_type '{asset.asset_type}' غير مدعوم آليًا؛ محتاج مراجعة."
    ]


def compile_scope(
    assets: list[ScopeAsset],
    *,
    max_age_days: int = 90,
    now: datetime | None = None,
) -> ScopeAssessment:
    """Normalize provider assets without inventing broad scope from policy prose."""
    now = now or datetime.now(UTC)
    rules: list[NormalizedRule] = []
    warnings: list[str] = []
    include_count = 0
    exclusion_count = 0
    stale_found = False
    ambiguous = False

    if not assets:
        return ScopeAssessment(
            status=ScopeStatus.PARTIAL.value,
            normalized_rules=[],
            warnings=["لا توجد structured scope assets؛ لا يمكن إنشاء تصريح تشغيل."],
            exclusion_count=0,
            include_count=0,
            assessed_at=utc_now(),
        )

    for asset in assets:
        # A provider asset that cannot be submitted is treated as an exclusion in
        # the execution policy. This is intentionally stricter than catalog display.
        action = (
            "include"
            if asset.included and asset.eligible_for_submission is not False
            else "exclude"
        )
        rule, asset_warnings = normalize_asset(asset, action)
        warnings.extend(asset_warnings)
        if rule:
            rules.append(rule)
            if action == "include":
                include_count += 1
            else:
                exclusion_count += 1
        else:
            ambiguous = True

        timestamp = _parse_timestamp(asset.updated_at)
        if asset.updated_at and timestamp is None:
            warnings.append(f"{asset.asset_id}: updated_at غير قابل للقراءة؛ freshness غير مؤكدة.")
            ambiguous = True
        elif timestamp and now - timestamp > timedelta(days=max_age_days):
            stale_found = True
            warnings.append(f"{asset.asset_id}: scope asset أقدم من {max_age_days} يوم.")

    if ambiguous:
        status = ScopeStatus.AMBIGUOUS.value
        if include_count == 0:
            warnings.append("لا يوجد include rule صالح؛ التنفيذ ممنوع.")
    elif include_count == 0:
        status = ScopeStatus.PARTIAL.value
        warnings.append("لا يوجد include rule صالح؛ التنفيذ ممنوع.")
    elif stale_found:
        status = ScopeStatus.STALE.value
    else:
        status = ScopeStatus.READY.value

    return ScopeAssessment(
        status=status,
        normalized_rules=rules,
        warnings=warnings,
        exclusion_count=exclusion_count,
        include_count=include_count,
        assessed_at=utc_now(),
    )


def decision_for_url(assessment: ScopeAssessment, candidate_url: str) -> tuple[bool, str]:
    """Pure local scope check intended for WebPent integration preflight.

    It does not make HTTP requests. Redirect destinations must be checked by the
    caller as separate URLs.
    """
    if assessment.status != ScopeStatus.READY.value:
        return False, f"scope status is {assessment.status}"
    parsed = urlparse(candidate_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False, "candidate is not an absolute HTTP(S) URL"
    host = parsed.hostname.lower().rstrip(".")
    path = parsed.path or "/"
    port = parsed.port

    def matches(rule: NormalizedRule) -> bool:
        if rule.asset_type not in {"url", "domain"} or not rule.host:
            return False
        if rule.scheme and rule.scheme != parsed.scheme:
            return False
        if rule.port is not None and rule.port != port:
            return False
        if rule.wildcard:
            suffix = rule.host[2:]
            if host == suffix or not host.endswith("." + suffix):
                return False
        elif host != rule.host:
            return False
        return not (rule.path and not path.startswith(rule.path))

    if any(rule.action == "exclude" and matches(rule) for rule in assessment.normalized_rules):
        return False, "matched explicit exclusion"
    if any(rule.action == "include" and matches(rule) for rule in assessment.normalized_rules):
        return True, "matched explicit include"
    return False, "no explicit include matched"
