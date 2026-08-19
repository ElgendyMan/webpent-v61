"""Deterministic, passive campaign planner for the VIP bug-hunter loop."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from webpent.models.campaigns import (
    CampaignExecutionContract,
    CampaignPlanEntry,
    CampaignPlannerResult,
    HypothesisDAGEdge,
    HypothesisDAGNode,
)
from webpent.models.evidence import redact_sensitive
from webpent.shared.campaigns import build_waptlab_campaign_ledger
from webpent.shared.validator_plugins import build_validator_plugin_registry

_CONTRACTS: dict[str, dict[str, Any]] = {
    "header_sqli": {
        "preconditions": ["header injection point is in scope", "baseline response captured"],
        "identities": ["anonymous", "owner"],
        "actions": ["replay a harmless header differential", "compare downstream response"],
        "payload_strategy": ["non-destructive SQLi canary in X-Forwarded-For"],
        "oracle": ["controlled response differential", "no generic parser error alone"],
        "negative_control": ["equivalent benign header value"],
        "cleanup": ["no persistent state expected"],
        "budget": 2,
    },
    "csv_ingestion_sqli": {
        "preconditions": ["authorized CSV upload or import workflow", "worker result observable"],
        "identities": ["owner", "tenant_admin"],
        "actions": ["submit a bounded fixture", "compare worker outcome"],
        "payload_strategy": ["single-field non-destructive SQLi differential"],
        "oracle": ["causal worker evidence", "correlated result change"],
        "negative_control": ["same CSV with inert value"],
        "cleanup": ["remove fixture artifact", "record worker cleanup status"],
        "budget": 3,
    },
    "jwt_path_traversal": {
        "preconditions": ["token-bearing path or download route", "scope allows read-only replay"],
        "identities": ["owner", "foreign_user"],
        "actions": ["compare canonical and encoded object references"],
        "payload_strategy": ["bounded traversal encoding variants"],
        "oracle": ["authorization-preserving differential", "object ownership mismatch"],
        "negative_control": ["owner object with canonical token"],
        "cleanup": ["read-only; no mutation"],
        "budget": 3,
    },
    "double_slash_redirect": {
        "preconditions": ["redirect-capable route observed"],
        "identities": ["anonymous"],
        "actions": ["compare canonical and double-slash paths"],
        "payload_strategy": ["same-origin redirect canary only"],
        "oracle": ["location and final origin comparison"],
        "negative_control": ["canonical same-origin path"],
        "cleanup": ["no persistent state expected"],
        "budget": 2,
    },
    "oauth_redirect_uri": {
        "preconditions": ["OAuth/OIDC flow and callback observed", "controlled identity available"],
        "identities": ["anonymous", "owner"],
        "actions": ["replay state/PKCE variations", "verify callback origin"],
        "payload_strategy": ["approved same-origin callback canary"],
        "oracle": ["state binding", "PKCE binding", "callback origin"],
        "negative_control": ["invalid state and mismatched verifier"],
        "cleanup": ["revoke temporary session", "remove test authorization"],
        "budget": 4,
    },
    "download_idor": {
        "preconditions": ["download object reference observed", "two identities available"],
        "identities": ["owner", "foreign_user"],
        "actions": ["compare owner and foreign-object reads"],
        "payload_strategy": ["bounded opaque identifier substitution"],
        "oracle": ["foreign denial or equivalent safe response", "no object disclosure"],
        "negative_control": ["owner reads own object"],
        "cleanup": ["read-only; delete no user data"],
        "budget": 3,
    },
    "tenant_context_switching": {
        "preconditions": [
            "tenant marker or switch workflow observed",
            "tenant identities configured",
        ],
        "identities": ["tenant_admin", "global_admin", "foreign_user"],
        "actions": ["compare tenant A/B context", "verify post-switch authorization"],
        "payload_strategy": ["bounded tenant-context transition"],
        "oracle": ["tenant isolation invariant", "context and object ownership"],
        "negative_control": ["same-tenant authorized operation"],
        "cleanup": ["restore original tenant context", "revoke temporary sessions"],
        "budget": 4,
    },
    "training_email_ssti": {
        "preconditions": [
            "training/email template workflow observed",
            "approval for rendered fixture",
        ],
        "identities": ["owner", "tenant_admin"],
        "actions": ["submit inert template marker", "compare rendered output"],
        "payload_strategy": ["non-executing expression canary"],
        "oracle": ["server-side rendering differential", "no execution claim from reflection"],
        "negative_control": ["literal marker"],
        "cleanup": ["remove test template/message"],
        "budget": 3,
    },
    "export_blade_ssti": {
        "preconditions": ["export/template surface observed", "artifact cleanup available"],
        "identities": ["owner", "tenant_admin"],
        "actions": ["request bounded export", "inspect generated artifact"],
        "payload_strategy": ["inert template expression marker"],
        "oracle": ["rendered server-side marker with causal artifact"],
        "negative_control": ["literal export field"],
        "cleanup": ["delete generated artifact"],
        "budget": 3,
    },
    "swagger_url_ssrf": {
        "preconditions": ["Swagger/OpenAPI URL fetch observed", "approved OOB/local canary"],
        "identities": ["anonymous", "owner"],
        "actions": ["submit isolated fetch canary", "correlate OOB event"],
        "payload_strategy": ["scope-approved canary URL only"],
        "oracle": ["OOB correlation with request fingerprint"],
        "negative_control": ["same-origin documentation URL"],
        "cleanup": ["expire canary", "remove imported specification"],
        "budget": 3,
    },
    "image_fetch_ssrf": {
        "preconditions": ["image URL fetch workflow observed", "approved OOB/local canary"],
        "identities": ["owner"],
        "actions": ["submit isolated image fetch canary", "correlate fetch evidence"],
        "payload_strategy": ["approved canary URL, no internal targets"],
        "oracle": ["OOB/browser event correlation"],
        "negative_control": ["owned static image URL"],
        "cleanup": ["remove profile image and expire canary"],
        "budget": 3,
    },
    "stored_profile_xss": {
        "preconditions": ["profile update and view workflow observed", "test account available"],
        "identities": ["owner", "viewer"],
        "actions": ["store inert marker", "view through approved browser"],
        "payload_strategy": ["non-executing context marker first"],
        "oracle": ["sanitized vs unsanitized DOM evidence"],
        "negative_control": ["literal text marker"],
        "cleanup": ["restore profile field"],
        "budget": 3,
    },
    "quoted_field_xss": {
        "preconditions": ["quoted attribute field observed", "browser evidence available"],
        "identities": ["owner"],
        "actions": ["submit inert attribute marker", "compare rendered attribute"],
        "payload_strategy": ["context-specific non-executing marker"],
        "oracle": ["attribute encoding differential"],
        "negative_control": ["literal quoted value"],
        "cleanup": ["restore field value"],
        "budget": 2,
    },
    "elasticsearch_snapshot_traversal": {
        "preconditions": ["in-scope snapshot/service surface observed", "read-only approval"],
        "identities": ["anonymous", "service_account"],
        "actions": ["inspect bounded snapshot metadata", "compare canonical paths"],
        "payload_strategy": ["read-only path normalization variants"],
        "oracle": ["unexpected snapshot metadata access"],
        "negative_control": ["authorized snapshot metadata"],
        "cleanup": ["no mutation; close service session"],
        "budget": 2,
    },
    "public_backup_disclosure": {
        "preconditions": ["backup/artifact route observed", "artifact ownership established"],
        "identities": ["anonymous", "owner"],
        "actions": ["request metadata-only artifact probe"],
        "payload_strategy": ["known test artifact identifier"],
        "oracle": ["public access to owned test backup"],
        "negative_control": ["nonexistent artifact"],
        "cleanup": ["remove test artifact"],
        "budget": 2,
    },
    "laravel_app_debug": {
        "preconditions": ["error response or Laravel fingerprint observed"],
        "identities": ["anonymous", "owner"],
        "actions": ["trigger bounded harmless error", "compare redacted response"],
        "payload_strategy": ["invalid read-only parameter"],
        "oracle": ["framework debug disclosure beyond expected baseline"],
        "negative_control": ["normal endpoint response"],
        "cleanup": ["no persistent state expected"],
        "budget": 2,
    },
    "frontend_dependency_exposure": {
        "preconditions": ["JavaScript bundle or lockfile reference observed"],
        "identities": ["anonymous"],
        "actions": ["collect version metadata", "compare advisory intelligence"],
        "payload_strategy": ["none; passive artifact analysis"],
        "oracle": ["version/evidence mapping with source hash"],
        "negative_control": ["unrelated asset"],
        "cleanup": ["no target mutation"],
        "budget": 1,
    },
    "public_elasticsearch_exposure": {
        "preconditions": ["in-scope Elasticsearch service fingerprint observed"],
        "identities": ["anonymous", "service_account"],
        "actions": ["collect bounded cluster/index metadata"],
        "payload_strategy": ["read-only metadata request"],
        "oracle": ["unauthorized metadata exposure"],
        "negative_control": ["authorized metadata baseline"],
        "cleanup": ["close connection"],
        "budget": 2,
    },
    "oob_xxe": {
        "preconditions": ["XML parser route observed", "approved local/OOB canary"],
        "identities": ["owner", "tenant_admin"],
        "actions": ["submit bounded XML fixture", "correlate parser event"],
        "payload_strategy": ["safe external-entity canary without local targets"],
        "oracle": ["causal OOB correlation or parser-safe rejection"],
        "negative_control": ["equivalent XML without entity"],
        "cleanup": ["remove uploaded XML and expire canary"],
        "budget": 3,
    },
    "xslt_injection": {
        "preconditions": ["XSLT transform workflow observed", "approval for inert fixture"],
        "identities": ["owner", "tenant_admin"],
        "actions": ["submit bounded transform", "inspect output and parser telemetry"],
        "payload_strategy": ["non-destructive document() marker"],
        "oracle": ["causal transform-side access evidence"],
        "negative_control": ["baseline transform"],
        "cleanup": ["remove transform fixture and output"],
        "budget": 3,
    },
}


def _as_mapping(item: Any) -> Mapping[str, Any]:
    if isinstance(item, Mapping):
        return item
    if hasattr(item, "model_dump"):
        return item.model_dump(mode="json")
    return {}


def _observation_ref(item: Mapping[str, Any], prefix: str) -> str:
    return str(item.get("fingerprint") or item.get("evidence_ref") or item.get("ref") or prefix)[
        :200
    ]


def _safe_gap(value: Any) -> str:
    clean, _ = redact_sensitive(str(value))
    return re.sub(
        r"(?i)\b(token|secret|password|api[-_]?key)\s*[:=]\s*[^,\s]+",
        r"\1=[REDACTED]",
        clean,
    )[:200]


def _observation_tokens(item: Mapping[str, Any]) -> set[str]:
    values: list[str] = []
    for key in (
        "category",
        "title",
        "reason",
        "signal_refs",
        "signals",
        "intent_tags",
        "surfaces",
        "url",
        "endpoint",
        "path",
        "method",
    ):
        value = item.get(key)
        if isinstance(value, (list, tuple, set)):
            values.extend(str(x).lower() for x in value)
        elif value:
            values.append(str(value).lower())
    return {
        token for value in values for token in value.replace("/", " ").replace("-", " ").split()
    }


def _contract(key: str, *, status: str, gaps: list[str]) -> CampaignExecutionContract:
    raw = dict(_CONTRACTS.get(key, {}))
    raw["confidence_state"] = (
        "blocked" if status.startswith("blocked") else "ready" if not gaps else "unplanned"
    )
    return CampaignExecutionContract(**raw)


def build_campaign_plan(
    *,
    target_url: str,
    observed_campaigns: set[str] | None = None,
    blocked_by: dict[str, str] | None = None,
    surface_observations: Iterable[Any] = (),
    workflow_observations: Iterable[Any] = (),
    explicit_gaps: Iterable[str] = (),
) -> dict[str, Any]:
    """Create a passive plan and DAG; executor evidence remains authoritative."""
    ledger = build_waptlab_campaign_ledger(
        observed_campaigns=observed_campaigns,
        blocked_by=blocked_by,
    )
    surfaces = [_as_mapping(item) for item in surface_observations]
    workflows = [_as_mapping(item) for item in workflow_observations]
    workflow_ref_set = {_observation_ref(item, "") for item in workflows}
    plugin_by_campaign = {
        plugin.campaign_key: plugin for plugin in build_validator_plugin_registry()
    }
    observations = surfaces + workflows
    explicit = [_safe_gap(item) for item in explicit_gaps if item]
    nodes: list[HypothesisDAGNode] = []
    edges: list[HypothesisDAGEdge] = []
    entries: list[CampaignPlanEntry] = []
    all_gaps: list[str] = list(explicit)

    for campaign in ledger["entries"]:
        key = str(campaign["key"])
        campaign_id = f"campaign:{key}"
        tokens = {str(x).lower() for x in campaign["surfaces"]}
        matches = [item for item in observations if tokens & _observation_tokens(item)]
        refs = [_observation_ref(item, f"surface:{index}") for index, item in enumerate(matches)][
            :20
        ]
        gaps: list[str] = []
        status = str(campaign["status"])
        if not campaign.get("validator_id"):
            gaps.append(f"missing-validator:{key}")
        if not refs and status == "not_observed":
            gaps.append(f"missing-surface:{key}")
        if status.startswith("blocked"):
            gaps.append(f"{status}:{key}")
        if any("identity" in str(item).lower() for item in campaign["surfaces"]) and not any(
            _observation_tokens(item) & {"identity", "authenticated", "role"}
            for item in workflows + surfaces
        ):
            gaps.append(f"missing-identity-context:{key}")
        entry = CampaignPlanEntry(
            id=int(campaign["id"]),
            key=key,
            surfaces=list(campaign["surfaces"]),
            validator=campaign.get("validator"),
            validator_id=campaign.get("validator_id"),
            plugin_id=(
                plugin_by_campaign[key].plugin_id if key in plugin_by_campaign else None
            ),
            evidence_schema=(
                plugin_by_campaign[key].evidence_schema
                if key in plugin_by_campaign
                else "EvidenceLedgerEntry:v1"
            ),
            status=status,
            matched_observation_refs=refs,
            gaps=list(dict.fromkeys(gaps))[:12],
            contract=_contract(key, status=status, gaps=gaps),
        )
        entries.append(entry)
        nodes.append(
            HypothesisDAGNode(
                node_id=campaign_id,
                node_type="campaign",
                ref=key,
                status=status,
                metadata={
                    "validator_id": campaign.get("validator_id"),
                    "surfaces": campaign["surfaces"],
                },
            )
        )
        for ref in refs:
            observation_id = f"observation:{ref}"
            if not any(node.node_id == observation_id for node in nodes):
                nodes.append(
                    HypothesisDAGNode(
                        node_id=observation_id,
                        node_type=(
                            "workflow_observation"
                            if ref in workflow_ref_set
                            else "surface_observation"
                        ),
                        ref=ref,
                        status="observed",
                    )
                )
            edges.append(
                HypothesisDAGEdge(
                    source=observation_id,
                    target=campaign_id,
                    relation="observation_supports_campaign",
                )
            )
        for gap in entry.gaps:
            gap_id = f"gap:{gap}"
            if not any(node.node_id == gap_id for node in nodes):
                nodes.append(
                    HypothesisDAGNode(
                        node_id=gap_id,
                        node_type="coverage_gap",
                        ref=gap,
                        status="open",
                    )
                )
            edges.append(
                HypothesisDAGEdge(
                    source=campaign_id,
                    target=gap_id,
                    relation="campaign_blocked_by_gap",
                )
            )
        all_gaps.extend(entry.gaps)

    summary: dict[str, int] = {}
    for entry in entries:
        summary[entry.status] = summary.get(entry.status, 0) + 1
    result = CampaignPlannerResult(
        target_url=target_url,
        entries=entries,
        nodes=nodes,
        edges=edges,
        coverage_gaps=list(dict.fromkeys(all_gaps))[:200],
        summary=summary,
    )
    return result.model_dump(mode="json")


__all__ = ["build_campaign_plan"]
