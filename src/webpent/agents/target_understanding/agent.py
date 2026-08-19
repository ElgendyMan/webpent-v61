"""Target Understanding node.

This node is deliberately additive.  It consumes structured material already
produced by authentication, crawling, and BAC discovery, then projects a
redacted, deterministic understanding into the existing Mental Model.  It
never performs a new network request and never stores cookies, tokens, or raw
object identifiers.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

from langchain_core.messages import AIMessage

from webpent.models.mental_model import EdgeKind, extract_mental_model_updates
from webpent.models.targets import Target
from webpent.shared.application_intent import infer_application_intent
from webpent.shared.bac_identity_tester import normalise_identity_profiles
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)

_MAX_ENDPOINTS = 500
_MAX_FORMS = 200
_MAX_IDENTITIES = 50
_MAX_OBJECTS = 200
_MAX_WORKFLOWS = 100


def _target_from_state(value: Any) -> Target | None:
    if isinstance(value, Target):
        return value
    if isinstance(value, dict):
        try:
            return Target.model_validate(value)
        except Exception:
            return None
    return None


def _as_url(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return candidate.rstrip("/")


def _iter_records(value: Any) -> Iterable[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return (item for item in value if isinstance(item, dict))


def _endpoint_values(crawled_data: dict[str, Any]) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for key in ("endpoints", "urls", "links", "pages", "resources"):
        raw = crawled_data.get(key)
        if not isinstance(raw, list):
            continue
        for item in raw:
            value = item.get("url") if isinstance(item, dict) else item
            endpoint = _as_url(value)
            if endpoint and endpoint not in seen:
                seen.add(endpoint)
                values.append(endpoint)
            if len(values) >= _MAX_ENDPOINTS:
                return values
    return values


def _normalise_parameter_names(record: dict[str, Any]) -> list[str]:
    raw = record.get("parameter_names") or record.get("parameters") or record.get("data")
    if isinstance(raw, dict):
        raw = list(raw.keys())
    if not isinstance(raw, (list, tuple, set)):
        return []
    return sorted({str(value).strip()[:100] for value in raw if str(value).strip()})[:100]


def _auth_signals(state: PentestState) -> list[str]:
    signals: set[str] = set()
    auth_state = state.get("auth_state") or {}
    if isinstance(auth_state, dict):
        cookies = auth_state.get("cookies") or {}
        if cookies:
            signals.add("session-cookie")
        if auth_state.get("validated"):
            signals.add("validated-auth-state")
        source = auth_state.get("source")
        if source:
            signals.add(f"auth-source:{str(source)[:80]}")
    if state.get("session_cookies"):
        signals.add("session-cookie")
    if state.get("identity_profiles") or state.get("identities"):
        signals.add("multi-identity-context")
    return sorted(signals)[:20]


def _endpoint_details(
    endpoints: list[str],
    forms: list[dict[str, Any]],
    auth_signals: list[str],
) -> list[dict[str, Any]]:
    details: dict[str, dict[str, Any]] = {
        endpoint: {
            "url": endpoint,
            "methods": [],
            "parameter_names": [],
            "auth_signals": list(auth_signals),
            "evidence_refs": ["obs://target-understanding/endpoints"],
        }
        for endpoint in endpoints
    }
    for form in forms[:_MAX_FORMS]:
        action = _as_url(form.get("action") or form.get("url") or form.get("source_url"))
        if not action:
            continue
        row = details.setdefault(
            action,
            {
                "url": action,
                "methods": [],
                "parameter_names": [],
                "auth_signals": list(auth_signals),
                "evidence_refs": ["obs://target-understanding/forms"],
            },
        )
        method = str(form.get("method") or "GET").upper()
        if method not in row["methods"]:
            row["methods"].append(method)
        row["parameter_names"] = sorted(
            set(row["parameter_names"]) | set(_normalise_parameter_names(form))
        )[:100]
        row["form"] = True
        row["evidence_refs"] = ["obs://target-understanding/forms"]
    return list(details.values())[:_MAX_ENDPOINTS]


def _identity_records(state: PentestState) -> list[dict[str, Any]]:
    raw = state.get("identity_profiles") or state.get("identities") or state.get("bac_identities")
    profiles = normalise_identity_profiles(
        raw, fallback_cookies=state.get("session_cookies") or None
    )
    records: list[dict[str, Any]] = []
    for profile in profiles[:_MAX_IDENTITIES]:
        records.append(
            {
                "ref": profile.name,
                "role": profile.role,
                "auth_pattern": "session-cookie" if profile.cookies else "operator-profile",
                "evidence_refs": ["obs://target-understanding/identities"],
            }
        )
    return records


def _object_records(crawled_data: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for key in ("resources", "objects", "records", "pages"):
        for item in _iter_records(crawled_data.get(key)):
            url = _as_url(item.get("url") or item.get("href") or item.get("endpoint"))
            object_id = item.get("object_id") or item.get("id") or item.get("resource_id")
            if not url or object_id is None:
                continue
            record: dict[str, Any] = {
                "type": item.get("type") or item.get("object_type") or "resource",
                "object_id": str(object_id),
                "url": url,
                "evidence_refs": ["obs://target-understanding/objects"],
            }
            owner = item.get("owner_identity") or item.get("owner") or item.get("owner_id")
            if owner is not None:
                record["owner_identity"] = str(owner)
            records.append(record)
            if len(records) >= _MAX_OBJECTS:
                return records
    return records


def _workflow_records(
    forms: list[dict[str, Any]],
    endpoint_details: list[dict[str, Any]],
    identities: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    required_role = next((item.get("role") for item in identities if item.get("role")), None)
    workflows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for form in forms[:_MAX_FORMS]:
        action = _as_url(form.get("action") or form.get("url") or form.get("source_url"))
        if not action:
            continue
        path = urlparse(action).path.strip("/") or "root"
        name = f"form:{path}"[:160]
        if name in seen:
            continue
        seen.add(name)
        workflows.append(
            {
                "name": name,
                "required_role": required_role,
                "steps": [
                    {
                        "method": str(form.get("method") or "GET").upper(),
                        "endpoint": action,
                        "from_state": "observed",
                        "to_state": "submitted"
                        if str(form.get("method") or "GET").upper() == "POST"
                        else "visited",
                        "evidence_refs": ["obs://target-understanding/forms"],
                    }
                ],
                "evidence_refs": ["obs://target-understanding/workflows"],
            }
        )
        if len(workflows) >= _MAX_WORKFLOWS:
            break
    return workflows


def _relations(
    workflows: list[dict[str, Any]], endpoint_details: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    relations: list[dict[str, Any]] = []
    for workflow in workflows:
        workflow_name = workflow.get("name")
        if not workflow_name:
            continue
        for step in workflow.get("steps") or []:
            endpoint = step.get("endpoint")
            if endpoint:
                relations.append(
                    {
                        "kind": EdgeKind.CONTAINS.value,
                        "source": workflow_name,
                        "target": endpoint,
                        "evidence_ref": "obs://target-understanding/workflows",
                    }
                )
    return relations[:_MAX_WORKFLOWS]


def target_understanding_node(state: PentestState) -> dict[str, Any]:
    """Project existing discovery/auth data into a safe target understanding."""
    target = _target_from_state(state.get("target"))
    target_url = target.url if target else None
    crawled_data = state.get("crawled_data") or {}
    if not isinstance(crawled_data, dict):
        crawled_data = {}

    endpoints = _endpoint_values(crawled_data)
    forms = list(_iter_records(crawled_data.get("forms")))[:_MAX_FORMS]
    identities = _identity_records(state)
    objects = _object_records(crawled_data)
    auth_signals = _auth_signals(state)
    details = _endpoint_details(endpoints, forms, auth_signals)
    workflows = _workflow_records(forms, details, identities)
    relations = _relations(workflows, details)
    intent = infer_application_intent(
        target_url=target_url,
        auth_signals=auth_signals,
        identities=identities,
        objects=objects,
        workflows=workflows,
        endpoint_details=details,
    )

    in_scope_endpoints = [
        endpoint for endpoint in endpoints if not target or target.is_in_scope(endpoint)
    ]
    out_of_scope_count = len(endpoints) - len(in_scope_endpoints)
    model_update: dict[str, Any] = {"nodes": {}, "edges": []}
    if target_url:
        try:
            model_update = extract_mental_model_updates(
                discovery_source="target_understanding_node",
                endpoints=in_scope_endpoints,
                endpoint_details=[
                    detail for detail in details if detail.get("url") in in_scope_endpoints
                ],
                identities=identities,
                objects=objects,
                workflows=workflows,
                relations=relations,
                target_url=target_url,
            )
        except Exception as exc:
            logger.warning("Target Understanding projection degraded safely: %s", exc)

    coverage_gaps: list[str] = []
    if not endpoints:
        coverage_gaps.append("no-endpoints")
    if not forms:
        coverage_gaps.append("no-structured-forms")
    if not identities:
        coverage_gaps.append("no-identity-context")
    if not workflows:
        coverage_gaps.append("no-workflow-candidates")

    summary = {
        "schema_version": 1,
        "source": "target_understanding_node",
        "endpoint_count": len(in_scope_endpoints),
        "out_of_scope_endpoint_count": max(0, out_of_scope_count),
        "form_count": len(forms),
        "identity_count": len(identities),
        "object_candidate_count": len(objects),
        "workflow_candidate_count": len(workflows),
        "auth_signals": auth_signals,
        "coverage_gaps": coverage_gaps,
        "mental_model_node_count": len(model_update.get("nodes") or {}),
        "mental_model_edge_count": len(model_update.get("edges") or []),
        "application_intent": intent.get("application_goal"),
        "policy_assumptions": intent.get("policy_assumptions", []),
        "intent_source": intent.get("source"),
        "intent_evidence_refs": intent.get("evidence_refs", []),
    }
    message = (
        "Target Understanding: "
        f"{summary['endpoint_count']} endpoint(s), {summary['form_count']} form(s), "
        f"{summary['identity_count']} identity context(s), "
        f"{summary['workflow_candidate_count']} workflow candidate(s)."
    )
    return {
        "target_understanding": summary,
        "application_intent": intent,
        "policy_assumptions": intent.get("policy_assumptions", []),
        "mental_model": model_update,
        "messages": [AIMessage(content=message)],
        "current_phase": "target_understanding",
    }


__all__ = ["target_understanding_node"]
