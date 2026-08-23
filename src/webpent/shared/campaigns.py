"""Application-aware campaign inventory and coverage accounting.

The inventory is deliberately declarative.  It does not execute probes and it
never turns a campaign into a confirmed finding.  A campaign can only become
``tested`` when an executor records evidence through the existing state
channels; otherwise the ledger exposes why coverage is absent.
"""

from __future__ import annotations

from typing import Any, Final

from webpent.agents.validator.registry import validator_id_for

# Campaigns remain human-review-only only when no deterministic live
# validator contract exists.  Vertical campaigns that reuse a registered base
# validator (for example IDOR or information disclosure) must still enter the
# normal planner/executor path; strict evidence/proof gates decide confirmation.
CAMPAIGN_HUMAN_REVIEW: Final[frozenset[str]] = frozenset(
    {
        "elasticsearch_snapshot_traversal",
        "xslt_injection",
    }
)

# Stable identifiers mirror the final audit's WAPTLab matrix.  Surface hints
# are signals, not authoritative route names; this keeps the inventory useful
# when a target changes its URL layout.
VERTICAL_PROOF_CONTRACTS: Final[dict[str, dict[str, Any]]] = {
    "download_idor": {
        "oracle_family": "idor",
        "proof_contract": "owner_foreign_access",
        "negative_control": "foreign_denied_control",
    },
    "tenant_context_switching": {
        "oracle_family": "idor",
        "proof_contract": "tenant_owner_foreign_access",
        "negative_control": "same_tenant_authorized_control",
    },
    "stored_profile_xss": {
        "oracle_family": "stored_xss",
        "proof_contract": "browser_execution_marker",
        "negative_control": "encoded_and_literal_safe_controls",
    },
    "image_fetch_ssrf": {
        "oracle_family": "ssrf",
        "proof_contract": "correlated_oob_callback",
        "negative_control": "absent_control_callback",
    },
    "csv_ingestion_sqli": {
        "oracle_family": "csv_sqli",
        "proof_contract": "controlled_parser_dataflow_differential",
        "negative_control": "inert_csv_control",
    },
}

WAPTLAB_CAMPAIGNS: Final[tuple[dict[str, Any], ...]] = (
    {
        "id": 1,
        "key": "header_sqli",
        "surfaces": ("headers", "query", "logging"),
        "validator": "sqli",
    },
    {
        "id": 2,
        "key": "csv_ingestion_sqli",
        "surfaces": ("multipart", "csv", "worker"),
        "validator": "sqli",
    },
    {
        "id": 3,
        "key": "jwt_path_traversal",
        "surfaces": ("jwt", "path", "download"),
        "validator": "path_traversal",
    },
    {
        "id": 4,
        "key": "double_slash_redirect",
        "surfaces": ("redirect", "path"),
        "validator": "open_redirect",
    },
    {
        "id": 5,
        "key": "oauth_redirect_uri",
        "surfaces": ("oauth", "redirect", "callback"),
        "validator": "open_redirect",
    },
    {
        "id": 6,
        "key": "download_idor",
        "surfaces": ("download", "object", "identity"),
        "validator": "idor",
    },
    {
        "id": 7,
        "key": "tenant_context_switching",
        "surfaces": ("tenant", "identity", "object"),
        "validator": "idor",
    },
    {
        "id": 8,
        "key": "training_email_ssti",
        "surfaces": ("template", "email", "workflow"),
        "validator": "ssti",
    },
    {
        "id": 9,
        "key": "export_blade_ssti",
        "surfaces": ("export", "template", "download"),
        "validator": "ssti",
    },
    {
        "id": 10,
        "key": "swagger_url_ssrf",
        "surfaces": ("swagger", "openapi", "url"),
        "validator": "ssrf",
    },
    {
        "id": 11,
        "key": "image_fetch_ssrf",
        "surfaces": ("profile", "image", "url"),
        "validator": "ssrf",
    },
    {
        "id": 12,
        "key": "stored_profile_xss",
        "surfaces": ("profile", "stored", "browser"),
        "validator": "xss",
    },
    {
        "id": 13,
        "key": "quoted_field_xss",
        "surfaces": ("profile", "form", "attribute"),
        "validator": "xss",
    },
    {
        "id": 14,
        "key": "elasticsearch_snapshot_traversal",
        "surfaces": ("elasticsearch", "snapshot", "service"),
        "validator": None,
    },
    {
        "id": 15,
        "key": "public_backup_disclosure",
        "surfaces": ("backup", "artifact", "download"),
        "validator": "info_disclosure",
    },
    {
        "id": 16,
        "key": "laravel_app_debug",
        "surfaces": ("error", "debug", "laravel"),
        "validator": "info_disclosure",
    },
    {
        "id": 17,
        "key": "frontend_dependency_exposure",
        "surfaces": ("javascript", "sbom", "bundle"),
        "validator": "javascript",
    },
    {
        "id": 18,
        "key": "public_elasticsearch_exposure",
        "surfaces": ("elasticsearch", "service", "network"),
        "validator": "info_disclosure",
    },
    {"id": 19, "key": "oob_xxe", "surfaces": ("xml", "multipart", "oob"), "validator": "xxe"},
    {
        "id": 20,
        "key": "xslt_injection",
        "surfaces": ("xml", "xslt", "multipart"),
        "validator": None,
    },
)


# Target-neutral campaigns are intentionally surface-driven.  They describe
# only validator-backed classes and never assert that a target exposes them.
GENERIC_CAMPAIGNS: Final[tuple[dict[str, Any], ...]] = (
    {
        "id": 1,
        "key": "xss_reflected",
        "surfaces": ("form", "input", "query", "xss"),
        "validator": "xss",
    },
    {
        "id": 2,
        "key": "xss_stored",
        "surfaces": ("profile", "stored", "browser"),
        "validator": "xss",
    },
    {
        "id": 3,
        "key": "sqli_param",
        "surfaces": ("query", "form", "search", "sqli"),
        "validator": "sqli",
    },
    {
        "id": 4,
        "key": "idor_object",
        "surfaces": ("object", "id", "identity", "idor"),
        "validator": "idor",
    },
    {
        "id": 5,
        "key": "auth_bypass_jwt",
        "surfaces": ("jwt", "auth", "token", "auth_bypass"),
        "validator": "auth_bypass",
    },
    {
        "id": 6,
        "key": "open_redirect",
        "surfaces": ("redirect", "url", "callback", "open_redirect"),
        "validator": "open_redirect",
    },
    {
        "id": 7,
        "key": "info_disclosure",
        "surfaces": ("error", "debug", "api", "info_disclosure"),
        "validator": "info_disclosure",
    },
    {
        "id": 8,
        "key": "ssrf_url_param",
        "surfaces": ("url", "fetch", "import", "ssrf"),
        "validator": "ssrf",
    },
    {
        "id": 9,
        "key": "api_issue",
        "surfaces": ("api", "rest", "json", "api_issue"),
        "validator": "api_issue",
    },
    {
        "id": 10,
        "key": "path_traversal",
        "surfaces": ("path", "file", "download", "path_traversal"),
        "validator": "path_traversal",
    },
)


def _status_for_campaign(campaign: dict[str, Any], observed: set[str]) -> str:
    campaign_key = str(campaign["key"])
    validator = campaign.get("validator")
    if campaign_key in CAMPAIGN_HUMAN_REVIEW:
        return "missing-validator"
    if validator is None or validator_id_for(str(validator)) is None:
        return "missing-validator"
    if campaign["key"] in observed:
        return "tested"
    return "not_observed"


def _build_campaign_ledger(
    campaigns: tuple[dict[str, Any], ...],
    *,
    source: str,
    observed_campaigns: set[str] | None = None,
    blocked_by: dict[str, str] | None = None,
) -> dict[str, Any]:
    observed = set(observed_campaigns or ())
    blocked = blocked_by or {}
    entries: list[dict[str, Any]] = []
    for campaign in campaigns:
        key = str(campaign["key"])
        status = _status_for_campaign(campaign, observed)
        if key in blocked:
            status = str(blocked[key])
        entries.append(
            {
                "id": int(campaign["id"]),
                "key": key,
                "surfaces": list(campaign["surfaces"]),
                "validator": campaign.get("validator"),
                "validator_id": validator_id_for(str(campaign["validator"]))
                if campaign.get("validator")
                else None,
                "proof_contract": VERTICAL_PROOF_CONTRACTS.get(key, {}).get("proof_contract"),
                "oracle_family": VERTICAL_PROOF_CONTRACTS.get(key, {}).get("oracle_family"),
                "negative_control": VERTICAL_PROOF_CONTRACTS.get(key, {}).get("negative_control"),
                "status": status,
                "disposition": "human_review_only" if status == "missing-validator" else status,
                "human_review_only": status == "missing-validator",
                "evidence_complete": status == "tested",
            }
        )

    summary: dict[str, int] = {}
    for entry in entries:
        status = str(entry["status"])
        summary[status] = summary.get(status, 0) + 1
    return {"version": 1, "source": source, "entries": entries, "summary": summary}


def build_waptlab_campaign_ledger(
    *,
    observed_campaigns: set[str] | None = None,
    blocked_by: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build the legacy WAPTLab matrix without changing its public contract."""
    return _build_campaign_ledger(
        WAPTLAB_CAMPAIGNS,
        source="waptlab_audit_campaign_matrix",
        observed_campaigns=observed_campaigns,
        blocked_by=blocked_by,
    )


def build_generic_campaign_ledger(
    *,
    observed_campaigns: set[str] | None = None,
    blocked_by: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build a validator-backed inventory for arbitrary discovered surfaces."""
    return _build_campaign_ledger(
        GENERIC_CAMPAIGNS,
        source="generic_surface_campaign_inventory",
        observed_campaigns=observed_campaigns,
        blocked_by=blocked_by,
    )


__all__ = [
    "CAMPAIGN_HUMAN_REVIEW",
    "VERTICAL_PROOF_CONTRACTS",
    "WAPTLAB_CAMPAIGNS",
    "GENERIC_CAMPAIGNS",
    "build_generic_campaign_ledger",
    "build_waptlab_campaign_ledger",
]
