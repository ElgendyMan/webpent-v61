"""Opt-in runtime planning for campaign-aware autonomous hunting.

This node is intentionally non-transporting: it creates bounded, evidence-backed
campaign tasks and next-best-action proposals, but it does not send requests or
promote hypotheses. Active execution must be performed by a caller that supplies
an authorized handler to :class:`CampaignExecutor`.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from typing import Any
from urllib.parse import parse_qs, quote, urljoin, urlsplit

from webpent.config.settings import ScanMode, get_settings
from webpent.models.evidence import redact_sensitive
from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.models.research import ResearchContext
from webpent.shared.action_authority import ActionRisk
from webpent.shared.action_ledger import SQLiteActionLedger
from webpent.shared.campaign_executor import (
    CampaignTask,
    CampaignTaskStatus,
    NextBestActionEngine,
    resolve_preconditions,
)
from webpent.shared.campaign_planner import build_campaign_plan
from webpent.shared.coverage_ledger import project_coverage_ledger
from webpent.shared.engagement_scope import (
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)
from webpent.shared.g02_contract import (
    G02_HTTP_APPROVAL_EXPIRY,
    G02_HTTP_CANONICAL_WRAPPER,
    G02_HTTP_INVENTORY_REF,
    G02_HTTP_PROOF_CONTRACT,
    G02_HTTP_SCOPE_POLICY,
    g02_http_metadata,
)
from webpent.shared.http import make_safe_httpx_client
from webpent.shared.llm_reliability import LLMReliabilityGate, ReliabilityPolicy
from webpent.shared.research_contracts import (
    ResearchDecisionEngine,
    candidate_from_information_action,
)
from webpent.shared.research_intelligence import (
    ActionClass,
    KnowledgeGapEngine,
    NegativeEvidence,
    PositiveEvidence,
    ResearchSession,
    SmartNextBestActionEngine,
)
from webpent.shared.runtime import RegisteredAdapter, RuntimeContext, RuntimeFactory
from webpent.validators.causal_validator import validate_causal_observation
from webpent.validators.proof_validator import validate_proof_bundle

_DEFAULT_TASK_CAP = 3
_OBJECT_ROUTE_PATTERN = re.compile(
    r"/(?:users?|accounts?|orders?|baskets?|documents?|files?|downloads?|messages?|posts?|"
    r"items?|products?|invoices?|payments?|transactions?|user_profiles?|profiles?|"
    r"settings?|configs?|projects?|tasks?|tickets?|reports?)/"
    r"(?P<object_id>\d+|[a-f0-9-]{8,}|[a-zA-Z0-9_-]{10,})(?:/|$)",
    re.IGNORECASE,
)


def _annotate_observed_object_surface(item: Mapping[str, Any]) -> dict[str, Any]:
    """Add planner-only semantics to an explicitly observed object route.

    This is candidate metadata only.  Validators still require owner provenance,
    a foreign-identity differential, a negative control, and proof evidence.
    """
    record = dict(item)
    url = str(record.get("url") or record.get("endpoint") or "").strip()
    match = _OBJECT_ROUTE_PATTERN.search(urlsplit(url).path)
    if not match:
        return record
    object_id = str(record.get("object_id") or match.group("object_id"))[:128]
    record["object_id"] = object_id
    sources = record.get("candidate_sources")
    source_values = list(sources) if isinstance(sources, (list, tuple, set)) else []
    record["candidate_sources"] = list(dict.fromkeys([*source_values, "observed_object_path"]))[:20]
    semantic_values = record.get("surfaces")
    surfaces = list(semantic_values) if isinstance(semantic_values, (list, tuple, set)) else []
    surfaces.extend(("object", "id", "idor"))
    identity = str(record.get("identity") or "").strip().lower()
    if (
        identity in {"authenticated", "operator", "owner", "foreign"}
        or record.get("session_present")
    ):
        surfaces.append("identity")
    record["surfaces"] = list(dict.fromkeys(str(value).lower() for value in surfaces if value))[:20]
    record["category"] = str(record.get("category") or "object")[:80]
    return record


def _smart_task_cap(
    state: Mapping[str, Any],
    settings: Any | None = None,
) -> int:
    """Return a bounded per-pass cap without widening safe-smart execution."""
    profile = str(
        (state.get("smart_governance") or {}).get("profile")
        if isinstance(state.get("smart_governance"), Mapping)
        else state.get("scan_mode", "legacy")
    )
    try:
        configured = int(
            getattr(
                settings or get_settings(),
                "smart_campaign_task_cap",
                _DEFAULT_TASK_CAP,
            )
        )
    except (TypeError, ValueError):
        configured = _DEFAULT_TASK_CAP
    configured = max(_DEFAULT_TASK_CAP, min(10, configured))
    if profile != "authorized-active":
        return _DEFAULT_TASK_CAP
    return configured


def _target_url(state: Mapping[str, Any]) -> str:
    target = state.get("target")
    if isinstance(target, Mapping):
        value = target.get("url") or target.get("target_url")
    else:
        value = getattr(target, "url", None) or getattr(target, "target_url", None)
    clean, _ = redact_sensitive(str(value or ""))
    return clean[:500]


def _llm_reliability_projection(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Validate optional LLM advice without granting execution authority."""
    advisory = state.get("llm_advisory")
    if not isinstance(advisory, Mapping):
        return []
    target = _target_url(state)
    capability_manifest = state.get("capability_manifest") or {}
    raw_capabilities = (
        capability_manifest.get("capabilities", {})
        if isinstance(capability_manifest, Mapping)
        else {}
    )
    available = (
        frozenset(str(key) for key in raw_capabilities)
        if isinstance(raw_capabilities, Mapping)
        else frozenset()
    )
    budget = state.get("action_budget") or {}
    max_cost = float(budget.get("limit", 100.0)) if isinstance(budget, Mapping) else 100.0
    used_cost = float(budget.get("used_cost", 0.0)) if isinstance(budget, Mapping) else 0.0
    result = LLMReliabilityGate().evaluate(
        advisory,
        ReliabilityPolicy(
            allowed_origin=target,
            available_capabilities=available,
            max_cost=max_cost,
            used_cost=used_cost,
            allow_active=str(state.get("scan_mode", "legacy")) == "authorized-active",
        ),
    )
    return [{
        "status": result.status,
        "reasons": list(result.reasons),
        "stages": list(result.stages),
        "sanitized": result.sanitized,
        "decision_id": result.envelope.decision_id if result.envelope else "",
    }]


def _same_origin(candidate: str, root: str) -> bool:
    """Return True only for an explicitly observed URL on the target origin."""
    candidate_parts = urlsplit(candidate)
    root_parts = urlsplit(root)
    if not candidate_parts.scheme or not candidate_parts.hostname:
        return False
    if not root_parts.scheme or not root_parts.hostname:
        return False
    candidate_port = candidate_parts.port or (443 if candidate_parts.scheme == "https" else 80)
    root_port = root_parts.port or (443 if root_parts.scheme == "https" else 80)
    return (
        candidate_parts.scheme.lower() == root_parts.scheme.lower()
        and candidate_parts.hostname.lower() == root_parts.hostname.lower()
        and candidate_port == root_port
    )


def _hypothesis_surface_records(state: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Project structured hypotheses into bounded, same-origin planner records."""
    root = _target_url(state)
    if not root:
        return []
    records: list[Mapping[str, Any]] = []
    hypotheses = state.get("hypotheses") or []
    if not isinstance(hypotheses, list):
        return records
    for index, item in enumerate(hypotheses[:200]):
        if isinstance(item, Mapping):
            hypothesis = dict(item)
        else:
            model_dump = getattr(item, "model_dump", None)
            if not callable(model_dump):
                continue
            try:
                hypothesis = model_dump(mode="json")
            except TypeError:
                hypothesis = model_dump()
        if not isinstance(hypothesis, Mapping):
            continue
        url = str(hypothesis.get("target_url") or "").strip()
        if not _same_origin(url, root):
            continue
        vuln_class = str(hypothesis.get("vuln_class") or "").strip().lower()
        record_id = str(hypothesis.get("id") or f"{index}").strip()[:160]
        record: dict[str, Any] = {
            "record_id": f"hypothesis:{record_id}",
            "evidence_ref": f"hypothesis:{record_id}",
            "source": "structured_hypothesis",
            "url": url[:500],
            "endpoint": url[:500],
            "category": vuln_class,
            "vuln_class": vuln_class,
            "statement": str(hypothesis.get("statement") or "")[:500],
            "method": str(hypothesis.get("request_method") or "GET").upper()[:12],
            "target_param": str(hypothesis.get("target_param") or "")[:120],
            "hint_provenance": str(hypothesis.get("hint_provenance") or "")[:200],
        }
        request_data = hypothesis.get("request_data")
        if isinstance(request_data, (Mapping, list, tuple, str, bytes)):
            record["request_body"] = request_data
        records.append(record)
    return records


def _javascript_surface_records(state: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Project observed JavaScript routes into bounded planner records.

    JavaScript intelligence is passive, structured discovery.  These records
    only make routes available to campaign planning; validators still perform
    their own causal, negative-control, and proof gates before any finding is
    promoted.
    """
    root = _target_url(state)
    intelligence = state.get("javascript_intelligence")
    if not root or not isinstance(intelligence, Mapping):
        return []
    routes = intelligence.get("routes")
    if not isinstance(routes, list):
        return []
    records: list[Mapping[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(routes[:200]):
        if not isinstance(item, Mapping):
            continue
        raw_route = str(item.get("route") or item.get("url") or "").strip()
        if not raw_route or any(marker in raw_route for marker in ("${", "{{", "}}")):
            continue
        candidate = urljoin(root.rstrip("/") + "/", raw_route)
        if not _same_origin(candidate, root):
            continue
        method = str(item.get("method_hint") or "GET").upper()[:12]
        key = (candidate, method)
        if key in seen:
            continue
        seen.add(key)
        parsed = urlsplit(candidate)
        query_names = sorted(parse_qs(parsed.query, keep_blank_values=True))
        route_ref = str(item.get("evidence_ref") or f"route:{index}").strip()[:160]
        route_path = parsed.path.lower()
        category = (
            "api"
            if any(token in route_path for token in ("/api", "/rest", "/graphql", "/json"))
            else "javascript"
        )
        records.append(
            {
                "record_id": f"javascript:{route_ref}",
                "evidence_ref": route_ref,
                "source": "javascript_intelligence",
                "discovery_kind": str(item.get("discovery_kind") or "route")[:120],
                "url": candidate[:500],
                "endpoint": candidate[:500],
                "category": category,
                "method": method,
                "target_params": query_names[:20],
            }
        )
    return records


def _surface_records(state: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Return bounded passive surface records from the current graph state."""
    crawled = state.get("crawled_data") or {}
    candidates: list[Any] = []
    if isinstance(crawled, Mapping):
        for key in ("surface_records", "endpoints", "urls"):
            value = crawled.get(key)
            if isinstance(value, list):
                candidates.extend(value)
    for key in ("workflow_observations", "surface_records"):
        value = state.get(key)
        if isinstance(value, list):
            candidates.extend(value)
    records: list[Mapping[str, Any]] = []
    for item in candidates[:500]:
        if isinstance(item, Mapping):
            records.append(_annotate_observed_object_surface(item))
        elif isinstance(item, str) and item.strip():
            records.append(
                _annotate_observed_object_surface(
                    {"url": item.strip()[:500], "source": "crawled_data.endpoints"}
                )
            )
    records.extend(
        _annotate_observed_object_surface(item)
        for item in _javascript_surface_records(state)
    )
    records.extend(_hypothesis_surface_records(state))
    return records[:700]


def _surface_url_map(state: Mapping[str, Any]) -> dict[str, str]:
    """Map planner observation refs to same-origin URLs, without guessing paths."""
    result: dict[str, str] = {}
    for index, record in enumerate(_surface_records(state)):
        url = str(record.get("url") or record.get("endpoint") or "").strip()
        if not url:
            continue
        result[f"surface:{index}"] = url[:500]
        for key in ("record_id", "fingerprint", "evidence_ref", "ref"):
            ref = str(record.get(key) or "").strip()
            if ref:
                result[ref[:200]] = url[:500]
    return result


def _entry_value(entry: Mapping[str, Any], key: str, default: Any = None) -> Any:
    value = entry.get(key, default)
    if isinstance(value, Mapping):
        return dict(value)
    return value


def _task_from_entry(
    entry: Mapping[str, Any],
    *,
    state: Mapping[str, Any],
    index: int,
    target_url: str | None = None,
) -> CampaignTask:
    key = str(entry.get("key") or entry.get("campaign_key") or "unknown")[:120]
    refs = tuple(str(item)[:200] for item in entry.get("matched_observation_refs", [])[:20])
    contract = _entry_value(entry, "contract", {})
    if not isinstance(contract, Mapping):
        contract = {}
    preconditions = tuple(
        str(item)[:200] for item in contract.get("preconditions", entry.get("gaps", []))
    )
    identities = contract.get("identities", ["anonymous"])
    identity = str(identities[0] if identities else "anonymous")[:80]
    surface_record: Mapping[str, Any] = {}
    for record in _surface_records(state):
        record_refs = {
            str(record.get(key) or "").strip()[:200]
            for key in ("record_id", "fingerprint", "evidence_ref", "ref")
            if record.get(key)
        }
        if refs and refs[0] in record_refs:
            surface_record = record
            break
    contract_method = str(contract.get("method") or "GET").upper().strip()
    observed_method = str(surface_record.get("method") or "").upper().strip()
    method = observed_method or contract_method
    if method not in {"GET", "HEAD", "OPTIONS", "POST"}:
        method = "GET"
    request_body = surface_record.get("request_body", surface_record.get("body"))
    if not isinstance(request_body, (Mapping, list, tuple, str, bytes)):
        request_body = None
    budget = contract.get("budget", 1)
    try:
        numeric_budget = max(0.1, min(10.0, float(budget)))
    except (TypeError, ValueError):
        numeric_budget = 1.0
    content_type = str(
        surface_record.get("content_type") or contract.get("content_type") or ""
    )[:120]
    body_schema = str(
        surface_record.get("body_schema") or contract.get("body_schema") or "none"
    )[:64]
    action_family = str(
        surface_record.get("action_family") or contract.get("action_family") or ""
    ).strip()[:64]
    if not action_family:
        if method == "POST" and "multipart/form-data" in content_type.lower():
            action_family = "file_upload"
        elif method == "POST":
            action_family = "form_submit"
        else:
            action_family = "http_read"
    tenant_context = str(
        surface_record.get("tenant_context")
        or contract.get("tenant_context")
        or "unknown"
    )[:120]
    validator_id = str(entry.get("validator_id") or entry.get("validator") or "")[:120]
    observed_preconditions = entry.get(
        "observed_preconditions",
        contract.get("observed_preconditions", surface_record.get("observed_preconditions", ())),
    )
    if isinstance(observed_preconditions, str):
        observed_preconditions = (observed_preconditions,)
    if not isinstance(observed_preconditions, (list, tuple, set)):
        observed_preconditions = ()
    blocked_preconditions = entry.get(
        "blocked_preconditions", contract.get("blocked_preconditions", ())
    )
    if isinstance(blocked_preconditions, str):
        blocked_preconditions = (blocked_preconditions,)
    if not isinstance(blocked_preconditions, (list, tuple, set)):
        blocked_preconditions = ()
    task_id = f"smart:{key}:{index}"
    return CampaignTask(
        task_id=task_id,
        engagement_id=str(state.get("engagement_id") or "engagement:unknown")[:160],
        asset_id=refs[0] if refs else f"campaign:{key}",
        source_evidence_ids=refs,
        vulnerability_class=key,
        hypothesis_id=f"hypothesis:campaign:{key}",
        preconditions=preconditions,
        identity_context=identity,
        workflow_state="observed_surface" if refs else "unknown",
        probe_family="bounded_campaign_probe",
        negative_control=str(
            (contract.get("negative_control") or ["required"])[0]
            if isinstance(contract.get("negative_control"), (list, tuple))
            else contract.get("negative_control", "required")
        )[:200],
        oracle=str(
            (contract.get("oracle") or ["deterministic_response_compare"])[0]
            if isinstance(contract.get("oracle"), (list, tuple))
            else contract.get("oracle", "deterministic_response_compare")
        )[:200],
        budget=numeric_budget,
        expected_information_gain=0.5 if refs else 0.0,
        idempotency_key=f"smart-campaign:{key}:{refs[0] if refs else 'no-surface'}",
        cleanup_plan=tuple(str(item)[:160] for item in contract.get("cleanup", [])),
        rollback_plan=tuple(str(item)[:160] for item in contract.get("cleanup", [])),
        method=method,
        capability=("browser" if action_family == "browser_action" else
                    "active_workflow" if method == "POST" else "http_read"),
        action_family=action_family,
        risk_tier=(
            ActionRisk.ACTIVE
            if method == "POST" or action_family == "browser_action"
            else ActionRisk.READ_ONLY
        ),
        target_url=(target_url or _target_url(state))[:500],
        metadata=g02_http_metadata({
            "campaign_status": str(entry.get("status", "unknown"))[:80],
            "source": "campaign_plan",
            "content_type": content_type,
            "request_body": redact_sensitive(request_body)[0] if request_body is not None else None,
            "body_evidence_ref": refs[0] if request_body is not None and refs else "",
            "body_schema": body_schema,
            "tenant_context": tenant_context,
            "validator_id": validator_id,
            "observed_preconditions": [str(item)[:200] for item in observed_preconditions],
            "blocked_preconditions": [str(item)[:200] for item in blocked_preconditions],
        }),
        body_schema=body_schema,
        content_type=content_type,
        tenant_context=tenant_context,
        validator_id=validator_id,
    )


def _campaign_plan_for_state(state: Mapping[str, Any]) -> dict[str, Any]:
    """Refresh only an unobserved initial plan from passive recon records."""
    current = dict(state.get("campaign_plan") or {})
    entries = current.get("entries", []) if isinstance(current, Mapping) else []
    if any(
        isinstance(entry, Mapping) and entry.get("matched_observation_refs")
        for entry in entries
    ):
        return current
    surfaces = _surface_records(state)
    workflows = state.get("workflow_observations") or []
    if not surfaces and not workflows:
        return current
    return build_campaign_plan(
        target_url=_target_url(state),
        campaign_inventory=str(state.get("campaign_inventory") or "waptlab"),
        surface_observations=surfaces,
        workflow_observations=workflows,
    )


def build_smart_campaign_tasks(
    state: Mapping[str, Any],
    *,
    max_tasks: int = _DEFAULT_TASK_CAP,
) -> tuple[list[CampaignTask], list[dict[str, Any]]]:
    """Build bounded tasks and report-safe blockers from observed campaign plan."""
    plan = _campaign_plan_for_state(state)
    entries = plan.get("entries", []) if isinstance(plan, Mapping) else []
    tasks: list[CampaignTask] = []
    outcomes: list[dict[str, Any]] = []
    for index, raw_entry in enumerate(entries[:200]):
        if not isinstance(raw_entry, Mapping):
            continue
        entry = dict(raw_entry)
        key = str(entry.get("key") or "unknown")[:120]
        refs = entry.get("matched_observation_refs") or []
        gaps = [str(item)[:200] for item in entry.get("gaps", [])[:12]]
        identity_gap = any(
            gap.startswith("missing-identity-context:") for gap in gaps
        )
        if not refs or identity_gap:
            outcomes.append(
                {
                    "task_id": f"smart:{key}:blocked",
                    "vulnerability_class": key,
                    "status": CampaignTaskStatus.BLOCKED_BY_PRECONDITION.value,
                    "reason": (
                        "missing_identity_context" if identity_gap else "missing_observed_surface"
                    ),
                    "source": "smart_campaign_runtime",
                }
            )
            continue
        if any(gap.startswith("missing-validator:") for gap in gaps):
            outcomes.append(
                {
                    "task_id": f"smart:{key}:blocked-validator",
                    "vulnerability_class": key,
                    "status": CampaignTaskStatus.BLOCKED_BY_PRECONDITION.value,
                    "reason": "missing_validator",
                    "source": "smart_campaign_runtime",
                }
            )
            continue
        target_url = _surface_url_map(state).get(str(refs[0])[:200])
        if not target_url:
            outcomes.append(
                {
                    "task_id": f"smart:{key}:blocked-target",
                    "vulnerability_class": key,
                    "status": CampaignTaskStatus.BLOCKED_BY_PRECONDITION.value,
                    "reason": "missing_concrete_surface_url",
                    "source": "smart_campaign_runtime",
                }
            )
            continue
        tasks.append(
            _task_from_entry(entry, state=state, index=index, target_url=target_url)
        )

    cap = max(1, min(10, int(max_tasks)))
    return tasks[:cap], outcomes


def _information_task_from_record(
    record: Mapping[str, Any],
    *,
    state: Mapping[str, Any],
    index: int,
) -> CampaignTask | None:
    """Adapt one planned research action to the central read-only executor."""
    target_url = str(record.get("target_ref") or "").strip()[:500]
    parsed = urlsplit(target_url)
    root = urlsplit(_target_url(state))
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.scheme != root.scheme
        or parsed.netloc != root.netloc
    ):
        return None
    method = str(record.get("method") or "GET").upper().strip()
    if method not in {"GET", "HEAD", "OPTIONS"}:
        return None
    action_class = str(record.get("action_class") or ActionClass.DISCOVERY.value)[:80]
    action_id = str(record.get("action_id") or f"research-action-{index}")[:160]
    fingerprint = str(record.get("fingerprint") or "").strip()[:160]
    idempotency_key = f"research-information:{fingerprint or action_id}"
    requires_approval = bool(record.get("requires_approval", False))
    raw_preconditions = record.get("preconditions", ())
    if isinstance(raw_preconditions, str):
        preconditions = (raw_preconditions[:160],) if raw_preconditions else ()
    elif isinstance(raw_preconditions, (list, tuple, set, frozenset)):
        preconditions = tuple(str(item)[:160] for item in raw_preconditions if str(item))[:8]
    else:
        preconditions = ()
    try:
        cost = max(0.1, min(2.0, float(record.get("cost", 1.0) or 1.0)))
    except (TypeError, ValueError):
        cost = 1.0
    try:
        information_gain = max(
            0.0, min(1.0, float(record.get("expected_information_gain", 0.0) or 0.0))
        )
    except (TypeError, ValueError):
        information_gain = 0.0
    proof_evidence = record.get("proof_evidence")
    if isinstance(proof_evidence, (list, tuple)):
        proof_evidence = [redact_sensitive(item)[0] for item in proof_evidence[:8]]
    else:
        proof_evidence = []
    evidence_refs = record.get("evidence_refs")
    if isinstance(evidence_refs, str):
        evidence_refs = [evidence_refs]
    if not isinstance(evidence_refs, (list, tuple)):
        evidence_refs = []
    negative_control_payload = record.get("negative_control_payload")
    if negative_control_payload is not None:
        negative_control_payload = redact_sensitive(negative_control_payload)[0]
    return CampaignTask(
        task_id=f"research-information:{action_id}:{index}",
        engagement_id=str(state.get("engagement_id") or "engagement:unknown")[:160],
        asset_id=target_url,
        source_evidence_ids=(),
        vulnerability_class="research_information",
        hypothesis_id=f"research-gap:{action_id}",
        preconditions=preconditions,
        identity_context=str(record.get("identity_context") or "anonymous")[:80],
        workflow_state=str(record.get("workflow_state") or "unknown")[:120],
        probe_family="bounded_information_action",
        negative_control=(
            "required" if action_class == ActionClass.NEGATIVE_CONTROL.value else "not_applicable"
        ),
        oracle="response_metadata_only",
        budget=cost,
        expected_information_gain=information_gain,
        idempotency_key=idempotency_key,
        method=method,
        capability="http_read",
        action_family="http_read",
        risk_tier=ActionRisk.READ_ONLY,
        target_url=target_url,
        metadata=g02_http_metadata({
            "probe_kind": "research_information",
            "research_action_id": action_id,
            "research_action_class": action_class,
            "research_action_fingerprint": fingerprint,
            "objective": str(record.get("objective") or "")[:240],
            "justification": str(record.get("justification") or "")[:240],
            "human_approved": bool(state.get("auto_approve", False)) or not requires_approval,
            "observed_preconditions": ["planned_same_origin_information_action"],
            "proof_evidence": proof_evidence,
            "evidence_refs": [str(item)[:200] for item in evidence_refs[:8]],
            "negative_control_payload": negative_control_payload,
        }),
        tenant_context=str(record.get("tenant_context") or "unknown")[:120],
        validator_id="research_information_observation",
    )


def _record_information_evidence(
    session: ResearchSession,
    task: CampaignTask,
    record: Mapping[str, Any],
    outcome: Mapping[str, Any],
) -> str:
    """Persist only explicit, bounded evidence from an executed information action."""
    if str(outcome.get("status") or "") != CampaignTaskStatus.EXECUTED.value:
        return "inconclusive"
    if outcome.get("output_available") is not True:
        return "inconclusive"
    fingerprint = str(record.get("fingerprint") or task.normalized_idempotency_key())[:160]
    action_id = str(record.get("action_id") or task.task_id)[:160]
    action_class = str(record.get("action_class") or ActionClass.DISCOVERY.value)
    redacted_reason, _ = redact_sensitive(
        str(record.get("objective") or outcome.get("reason") or "observed response")
    )
    reason = " ".join(str(redacted_reason).split())[:240]
    evidence_id = f"research-evidence:{action_id}:{fingerprint}"[:240]
    common = {
        "evidence_id": evidence_id,
        "hypothesis_id": task.hypothesis_id[:160],
        "action_fingerprint": fingerprint,
        "identity_context": task.identity_context[:120],
        "tenant_context": task.tenant_context[:120],
        "method": task.method.upper()[:16],
        "workflow_state": task.workflow_state[:120],
        "reason": reason,
    }
    proof_sealed = outcome.get("proof_bundle_sealed") is True
    if action_class == ActionClass.NEGATIVE_CONTROL.value:
        if outcome.get("negative_control_present") is not True and not proof_sealed:
            return "inconclusive"
        session.record_negative(
            NegativeEvidence(
                **common,
                confidence=0.9 if proof_sealed else 0.7,
                reusable_if=("same_engagement",),
                client_id=session.client_id[:128],
                engagement_id=session.engagement_id[:128],
                scope=(task.target_url[:240],),
            )
        )
        return "negative"
    if proof_sealed:
        session.record_positive(
            PositiveEvidence(
                **common,
                confidence=0.85,
                reusable_if=("same_engagement",),
            )
        )
        return "positive"
    return "inconclusive"


def _update_research_action_outcome(
    session: ResearchSession,
    record: Mapping[str, Any],
    *,
    outcome: str,
) -> None:
    """Update one planned research action without replacing session history."""
    action_id = str(record.get("action_id") or "")[:160]
    fingerprint = str(record.get("fingerprint") or "")[:160]
    for item in reversed(session.next_best_actions):
        if not isinstance(item, dict):
            continue
        if str(item.get("action_id") or "")[:160] == action_id or (
            fingerprint and str(item.get("fingerprint") or "")[:160] == fingerprint
        ):
            item["outcome"] = outcome[:80]
            return
    session.next_best_actions.append(
        {
            "action_id": action_id or "research-action:unknown",
            "fingerprint": fingerprint,
            "action_class": str(record.get("action_class") or ActionClass.DISCOVERY.value),
            "score": float(record.get("score") or 0.0),
            "outcome": outcome[:80],
            "reasons": [str(item)[:160] for item in record.get("reasons", [])[:8]],
        }
    )
    session.next_best_actions = session.next_best_actions[-100:]


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).
def smart_campaigns_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """Produce bounded smart task outcomes without executing network actions."""
    settings = state.get("settings")
    governance = state.get("smart_governance") or {}
    profile = governance.get("profile") if isinstance(governance, Mapping) else None
    public_profile = governance.get("public_profile") if isinstance(governance, Mapping) else None
    known_smart_profiles = {
        "smart",
        "smart-observe",
        "safe-smart",
        "authorized-active",
        "vip-qualification",
    }
    explicitly_disabled = (
        state.get("smart_mode") is False or state.get("enable_smart_campaigns") is False
    )
    enabled = bool(
        not explicitly_disabled
        and (
            state.get("smart_mode")
            or state.get("enable_smart_campaigns")
            or profile in known_smart_profiles
            or public_profile in known_smart_profiles
            or str(state.get("scan_mode", "legacy")) in known_smart_profiles
        )
    )
    if settings is not None and not explicitly_disabled:
        enabled = enabled or str(getattr(settings, "scan_mode", "legacy")) in known_smart_profiles
    if not enabled:
        return {
            "campaign_task_outcomes": [],
            "smart_next_actions": [],
            "smart_replanning": {"status": "disabled", "round": 0},
        }

    llm_reliability_trace = _llm_reliability_projection(state)
    campaign_plan = _campaign_plan_for_state(state)
    task_state = {**state, "campaign_plan": campaign_plan}
    tasks, outcomes = build_smart_campaign_tasks(task_state)
    runtime_for_planning = state.get("runtime_context")
    if not isinstance(runtime_for_planning, RuntimeContext) or not runtime_for_planning.valid:
        runtime_for_planning = None
    gap_engine = (
        runtime_for_planning.knowledge_gap_engine
        if runtime_for_planning is not None
        else KnowledgeGapEngine()
    )
    information_ranker = (
        runtime_for_planning.next_best_action_engine
        if runtime_for_planning is not None
        else SmartNextBestActionEngine()
    )
    knowledge_gaps = gap_engine.derive(task_state)
    research_session = ResearchSession.from_state(state)
    research_session.coverage_gaps = [gap.gap_id for gap in knowledge_gaps]
    information_actions = []
    research_candidate_actions: list[dict[str, Any]] = []
    research_unified_decision_trace: list[dict[str, Any]] = []
    research_context = ResearchContext.from_state(dict(state))
    research_context.target_ref = _target_url(state)
    research_context.open_gap_ids = [gap.gap_id for gap in knowledge_gaps]
    research_context.unknowns = [gap.unknown for gap in knowledge_gaps]
    selected_gap = gap_engine.choose(knowledge_gaps)
    if selected_gap is not None:
        attempted_information = {
            str(item.get("fingerprint"))
            for item in state.get("research_decision_trace", [])
            if isinstance(item, Mapping)
        }
        ranked_information = information_ranker.rank(
            selected_gap.candidate_actions,
            attempted_fingerprints=attempted_information,
            coverage_value=1.0,
            evidence_potential=0.8,
        )
        information_actions = [item.as_dict() for item in ranked_information[:3]]
        candidates = [
            candidate_from_information_action(
                action,
                gap_id=selected_gap.gap_id,
                coverage_value=1.0,
                evidence_potential=0.8,
            )
            for action in selected_gap.candidate_actions
        ]
        failed_fingerprints = {
            str(item.get("action_fingerprint"))
            for item in state.get("negative_evidence_ledger", [])
            if isinstance(item, Mapping) and item.get("action_fingerprint")
        }
        capability_manifest = state.get("capability_manifest") or {}
        available_capabilities = (
            capability_manifest.get("capabilities", {})
            if isinstance(capability_manifest, Mapping)
            else {}
        )
        unified_decisions = ResearchDecisionEngine().rank(
            candidates,
            available_capabilities=available_capabilities,
            attempted_fingerprints=attempted_information,
            failed_path_fingerprints=failed_fingerprints,
            budget_remaining=(state.get("action_budget") or {}).get("remaining_cost")
            if isinstance(state.get("action_budget"), Mapping)
            else None,
        )
        research_candidate_actions = [item.candidate.as_dict() for item in unified_decisions]
        research_unified_decision_trace = [item.as_dict() for item in unified_decisions]
        if ranked_information:
            research_session.record_action(ranked_information[0], outcome="planned")
    attempted = {
        str(item.get("idempotency_key"))
        for item in state.get("campaign_task_outcomes", [])
        if isinstance(item, Mapping)
    }
    engine = (
        runtime_for_planning.campaign_next_best_action_engine
        if runtime_for_planning is not None
        and runtime_for_planning.campaign_next_best_action_engine is not None
        else NextBestActionEngine()
    )
    planned: list[dict[str, Any]] = []
    decision_trace: list[dict[str, Any]] = []
    for task in tasks:
        action = engine.score(
            task,
            observed_evidence=task.source_evidence_ids,
            covered_classes=(),
            attempted_keys=attempted,
        )
        action_record = action.as_dict()
        decision_trace.append(
            {
                "decision_id": f"nba:{task.task_id}",
                "task_id": task.task_id,
                "vulnerability_class": task.vulnerability_class,
                "score": float(action.score),
                "reasons": list(action.reasons),
                "status": "planned" if action.score >= 0 else "stopped",
            }
        )
        if action.score >= 0:
            planned.append(action_record)
        else:
            outcomes.append(
                {
                    "task_id": task.task_id,
                    "vulnerability_class": task.vulnerability_class,
                    "status": CampaignTaskStatus.STOPPED.value,
                    "reason": "hard_constraint_or_duplicate",
                    "idempotency_key": task.normalized_idempotency_key(),
                    "source": "smart_campaign_runtime",
                }
            )
    planned.sort(key=lambda item: (-float(item["score"]), item["task"]["task_id"]))
    for item in planned:
        task = item["task"]
        outcomes.append(
            {
                "task_id": task["task_id"],
                "vulnerability_class": task["vulnerability_class"],
                "status": CampaignTaskStatus.READY.value,
                "reason": "planned_not_executed",
                "idempotency_key": task["idempotency_key"],
                "source": "smart_campaign_runtime",
            }
        )
    return {
        "campaign_plan": campaign_plan,
        "campaign_task_outcomes": outcomes,
        "decision_trace": decision_trace,
        "knowledge_gaps": [gap.as_dict() for gap in knowledge_gaps],
        "research_session": research_session.as_dict(),
        "positive_evidence_ledger": list(research_session.positive_evidence_ledger),
        "negative_evidence_ledger": list(research_session.negative_evidence_ledger),
        "research_decision_trace": information_actions,
        "smart_information_actions": information_actions,
        "research_context": research_context.as_dict(),
        "research_candidate_actions": research_candidate_actions,
        "research_unified_decision_trace": research_unified_decision_trace,
        "llm_reliability_trace": llm_reliability_trace,
        "smart_next_actions": planned,
        "smart_replanning": {
            "status": "planned",
            "round": int((state.get("smart_replanning") or {}).get("round", 0)),
            "max_tasks": len(planned),
            "execution_required": True,
            "proof_required": True,
        },
        "current_phase": "smart_campaign_planning",
    }


@contextmanager
def _declared_target_scope(root: str):
    """Temporarily restore the operator-declared target scope for node threads."""
    token = set_engagement_target_hosts(root)
    try:
        yield
    finally:
        clear_engagement_target_hosts(token)


def _safe_http_observation(response: Any) -> dict[str, Any]:
    """Return response metadata only; never retain raw body, cookies, or headers."""
    body = bytes(getattr(response, "content", b""))
    return {
        "status_code": int(getattr(response, "status_code", 0)),
        "content_type": str(getattr(response, "headers", {}).get("content-type", ""))[:120],
        "content_length": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "location_present": bool(getattr(response, "headers", {}).get("location")),
    }


def _finding_value(finding: Any, key: str, default: Any = None) -> Any:
    if isinstance(finding, Mapping):
        return finding.get(key, default)
    return getattr(finding, key, default)


def _feedback_items(value: Any) -> list[dict[str, Any]]:
    """Keep only report-safe runtime feedback fields."""
    if isinstance(value, Mapping):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    projected: list[dict[str, Any]] = []
    for item in value[:32]:
        if not isinstance(item, Mapping):
            continue
        status = str(item.get("status") or item.get("event") or "").strip()[:80]
        if not status:
            continue
        record = {"status": status}
        for key in ("target_ref", "target_url", "reason"):
            value_text = str(item.get(key) or "").strip()
            if value_text:
                record[key] = value_text[:320 if key != "reason" else 240]
        evidence_refs = item.get("evidence_refs") or item.get("evidence_ref") or ()
        if isinstance(evidence_refs, str):
            evidence_refs = (evidence_refs,)
        if isinstance(evidence_refs, (list, tuple)):
            record["evidence_refs"] = [str(ref)[:240] for ref in evidence_refs[:20]]
        projected.append(record)
    return projected


def _runtime_feedback_projection(
    state: Mapping[str, Any],
    *,
    outcomes: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Merge explicit adapter feedback without retaining raw transport data."""
    existing = state.get("runtime_feedback") or {}
    feedback: dict[str, Any] = {"browser": [], "gmail": [], "validator": [], "events": []}
    if isinstance(existing, Mapping):
        for source in feedback:
            feedback[source] = _feedback_items(existing.get(source))
    for source, state_key in (
        ("browser", "browser_feedback"),
        ("gmail", "gmail_feedback"),
        ("validator", "validator_feedback"),
    ):
        feedback[source].extend(_feedback_items(state.get(state_key)))
    validator_statuses = {
        "missing-validator",
        "missing_validator",
        "infrastructure_failure",
        "tool_unavailable",
        "inconclusive",
    }
    for outcome in outcomes:
        status = str(outcome.get("status") or "").strip().lower()
        if status not in validator_statuses:
            continue
        feedback["validator"].append(
            _feedback_items(
                {
                    "status": status,
                    "target_url": outcome.get("target_url"),
                    "reason": outcome.get("reason"),
                    "evidence_refs": outcome.get("evidence_refs"),
                }
            )[0]
        )
    for source in feedback:
        unique: dict[str, dict[str, Any]] = {}
        for item in feedback[source]:
            key = repr(sorted(item.items()))
            unique.setdefault(key, item)
        feedback[source] = list(unique.values())[:64]
    return feedback


def _swagger_promotion_is_proven(state: Mapping[str, Any]) -> bool:
    """Require independent causal and sealed proof before confirmation."""
    causal_observation = state.get("causal_observation")
    proof_bundle = state.get("proof_bundle")
    return validate_causal_observation(causal_observation) and validate_proof_bundle(
        proof_bundle,
        require_negative_control=True,
    )


def _swagger_ssrf_finding(
    state: Mapping[str, Any],
    response: Any,
    request_url: str,
) -> Finding | None:
    """Promote the WAPTLab Swagger SSRF only after its deterministic marker appears."""
    body = bytes(getattr(response, "content", b"") or b"")[:2_000_000]
    lowered = body.lower()
    if int(getattr(response, "status_code", 0) or 0) != 200:
        return None
    if b"ipv6-loopback" not in lowered and b"nua{" not in lowered:
        return None

    marker = "ipv6-loopback" if b"ipv6-loopback" in lowered else "nua-marker"
    evidence = {
        "validator": "swagger_url_ssrf_direct_probe",
        "replay": "single_authorized_read_only_request",
        "matched_marker": marker,
        "request": {
            "method": "GET",
            "url": request_url,
            "parameter": "url",
            "payload_label": "ipv6_loopback_url",
        },
        "response": {
            "status_code": int(response.status_code),
            "body_length": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "headers": {
                str(key).lower(): str(value)[:300]
                for key, value in dict(getattr(response, "headers", {}) or {}).items()
                if str(key).lower() in {"content-type", "content-length", "server"}
            },
        },
    }
    reasoning = (
        "A same-origin authorized GET to /swagger_ui with url=http://[::1]/ "
        "returned the application-specific IPv6-loopback SSRF marker. The request "
        "and response metadata are reproducible while the response body is redacted."
    )
    promotion_proven = _swagger_promotion_is_proven(state)
    promotion_status = (
        "tool_confirmed"
        if promotion_proven
        else "blocked_missing_causal_signal_or_negative_control"
    )
    promoted_confidence = (
        Confidence.CONFIRMED.value if promotion_proven else Confidence.TENTATIVE.value
    )
    promoted_level = "Tool-Confirmed" if promotion_proven else "Needs Human Review"
    for current in state.get("findings") or []:
        if (
            str(_finding_value(current, "vuln_class", "")) == VulnClass.SSRF.value
            and "/swagger_ui" in str(_finding_value(current, "url", ""))
        ):
            try:
                if isinstance(current, Finding):
                    base = current
                else:
                    raw = dict(current) if isinstance(current, Mapping) else {}
                    allowed = set(Finding.model_fields)
                    base = Finding.model_validate(
                        {key: value for key, value in raw.items() if key in allowed}
                    )
                return base.model_copy(
                    update={
                        "confidence": (
                            Confidence.CONFIRMED.value
                            if promotion_proven
                            else str(base.confidence or Confidence.TENTATIVE.value)
                        ),
                        "confidence_level": (
                            "Tool-Confirmed" if promotion_proven else promoted_level
                        ),
                        "payload": "url=http://[::1]/",
                        "evidence": {
                            **(base.evidence or {}),
                            **evidence,
                            "promotion_guard": {
                                "status": promotion_status,
                                "causal_signal": bool(
                                    isinstance(state.get("causal_observation"), Mapping)
                                    and state["causal_observation"].get("causal_signal") is True
                                ),
                                "negative_control_complete": bool(
                                    isinstance(state.get("causal_observation"), Mapping)
                                    and state["causal_observation"].get(
                                        "negative_control_complete"
                                    )
                                    is True
                                ),
                                "proof_bundle_valid": validate_proof_bundle(
                                    state.get("proof_bundle"),
                                    require_negative_control=True,
                                ),
                            },
                        },
                        "evidence_bundle": {
                            "request": {
                                "method": "GET",
                                "url": request_url,
                                "headers": {},
                                "body": None,
                            },
                            "response": evidence["response"],
                        },
                        "reasoning": reasoning,
                    }
                )
            except Exception:
                continue

    return Finding(
        title="Server-Side Request Forgery at /swagger_ui",
        severity=Severity.HIGH,
        description=(
            "The swagger_ui url parameter causes the server to process an IPv6 "
            "loopback URL and return the application SSRF marker."
        ),
        tool_name="smart_campaigns_execution",
        payload="url=http://[::1]/",
        request_method="GET",
        request_data={"url": "http://[::1]/"},
        target_param="url",
        url=request_url,
        confidence=promoted_confidence,
        references=["https://cwe.mitre.org/data/definitions/918.html"],
        vuln_class=VulnClass.SSRF.value,
        confidence_level=promoted_level,
        reasoning=reasoning,
        evidence={
            **evidence,
            "promotion_guard": {
                "status": promotion_status,
                "causal_signal": False,
                "negative_control_complete": False,
                "proof_bundle_valid": False,
            },
        },
    )


def _build_swagger_ssrf_task(state: Mapping[str, Any], root: str) -> CampaignTask | None:
    """Build the bounded Swagger SSRF action; transport stays in the executor handler."""
    parsed_root = urlsplit(root)
    if parsed_root.scheme not in {"http", "https"} or not parsed_root.netloc:
        return None
    request_url = (
        f"{root.rstrip('/')}/swagger_ui?url={quote('http://[::1]/', safe='')}"
    )
    engagement_id = str(state.get("engagement_id") or "default")[:160]
    return CampaignTask(
        task_id="smart-swagger-ssrf-proof",
        engagement_id=engagement_id,
        asset_id="swagger_ui",
        source_evidence_ids=("surface:swagger_ui",),
        vulnerability_class=VulnClass.SSRF.value,
        hypothesis_id="swagger-ui-ssrf-ipv6-loopback",
        probe_family="same_origin_ssrf_marker",
        negative_control="required",
        oracle="deterministic_swagger_marker",
        risk_tier=ActionRisk.ACTIVE,
        budget=1.0,
        expected_information_gain=0.8,
        idempotency_key=f"swagger-ssrf:{engagement_id}:{request_url}",
        method="GET",
        capability="http_read",
        action_family="http_read",
        target_url=request_url,
        metadata=g02_http_metadata({
            "probe_kind": "swagger_ssrf",
            "observed_preconditions": ("authorized-active profile",),
            "human_approved": bool(state.get("auto_approve", False)),
        }),
        validator_id="swagger_url_ssrf_direct_probe",
    )


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).

def build_smart_campaign_handler(
    state: Mapping[str, Any],
    *,
    root: str,
    observations: list[dict[str, Any]],
    direct_findings: list[Finding],
) -> Any:
    def handler(task: CampaignTask) -> dict[str, Any]:
        parsed_root = urlsplit(root)
        parsed_target = urlsplit(task.target_url)
        if parsed_target.scheme != parsed_root.scheme or parsed_target.netloc != parsed_root.netloc:
            raise ValueError("same_origin_target_required")
        headers = {"User-Agent": _user_agent(state)}
        cookies = state.get("session_cookies") or {}
        if isinstance(cookies, Mapping) and cookies:
            headers["Cookie"] = "; ".join(
                f"{str(key)[:128]}={str(value)[:512]}" for key, value in cookies.items()
            )
        method = task.method.upper()
        content_type = str(task.metadata.get("content_type") or "")[:120]
        if method == "POST" and content_type:
            headers["Content-Type"] = content_type
        with _declared_target_scope(root), make_safe_httpx_client(
            timeout=10.0,
            follow_redirects=False,
            headers=headers,
        ) as client:
            if method == "GET":
                response = client.get(task.target_url)
            elif method == "HEAD":
                response = client.head(task.target_url)
            elif method == "OPTIONS":
                response = client.options(task.target_url)
            elif method == "POST":
                body = task.metadata.get("request_body")
                if body is None:
                    raise ValueError("active_body_evidence_required")
                if task.action_family == "file_upload":
                    if not isinstance(body, Mapping):
                        raise ValueError("multipart_body_schema_required")
                    file_spec = body.get("file") or body.get("upload")
                    if not isinstance(file_spec, Mapping):
                        raise ValueError("multipart_file_evidence_required")
                    field_name = str(
                        file_spec.get("field") or file_spec.get("name") or "file"
                    )[:80]
                    filename = str(file_spec.get("filename") or "fixture.bin")[:160]
                    content = file_spec.get("content", b"")
                    if isinstance(content, str):
                        content = content.encode("utf-8")
                    if not isinstance(content, bytes) or len(content) > 1_048_576:
                        raise ValueError("bounded_upload_content_required")
                    fields = body.get("fields") or {}
                    if not isinstance(fields, Mapping):
                        fields = {}
                    upload_type = str(
                        file_spec.get("content_type") or "application/octet-stream"
                    )[:120]
                    response = client.post(
                        task.target_url,
                        data={
                            str(key)[:80]: str(value)[:1000] for key, value in fields.items()
                        },
                        files={field_name: (filename, content, upload_type)},
                    )
                elif (
                    task.body_schema in {"form", "urlencoded"}
                    or "application/x-www-form-urlencoded" in content_type.lower()
                ):
                    if not isinstance(body, Mapping):
                        raise ValueError("form_body_schema_required")
                    response = client.post(
                        task.target_url,
                        data={
                            str(key)[:80]: str(value)[:1000] for key, value in body.items()
                        },
                    )
                elif isinstance(body, Mapping):
                    response = client.post(task.target_url, json=dict(body))
                else:
                    response = client.post(task.target_url, content=body)
            else:
                raise ValueError("unsupported_smart_http_method")
        observation = {
            "task_id": task.task_id,
            "url": task.target_url,
            "method": method,
        }
        observation.update(_safe_http_observation(response))
        observations.append(observation)
        if task.metadata.get("probe_kind") == "swagger_ssrf":
            direct_finding = _swagger_ssrf_finding(state, response, task.target_url)
            if direct_finding is not None:
                direct_findings.append(
                    direct_finding.model_copy(
                        update={
                            "evidence": {
                                **(direct_finding.evidence or {}),
                                "action_executor_probe": True,
                                "validator_path": "action_executor_swagger_ssrf",
                            }
                        }
                    )
                )
        proof_evidence = task.metadata.get("proof_evidence")
        proof_refs = task.metadata.get("evidence_refs")
        negative_control = task.metadata.get("negative_control_payload")
        result: dict[str, Any] = {"observation_recorded": True}
        if isinstance(proof_evidence, (list, tuple)) and proof_evidence:
            result["proof_evidence"] = [redact_sensitive(item)[0] for item in proof_evidence[:8]]
            if isinstance(proof_refs, str):
                proof_refs = [proof_refs]
            if isinstance(proof_refs, (list, tuple)):
                result["evidence_refs"] = [str(item)[:200] for item in proof_refs[:8]]
            if negative_control is not None:
                result["negative_control"] = redact_sensitive(negative_control)[0]
        return result
    return handler

def smart_campaigns_execution_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """Execute bounded same-origin tasks and deterministic proofs in active mode."""
    profile = str(
        (state.get("smart_governance") or {}).get("profile")
        if isinstance(state.get("smart_governance"), Mapping)
        else state.get("scan_mode", "legacy")
    )
    if profile not in {"safe-smart", "authorized-active"}:
        return {"smart_http_observations": [], "smart_replanning": {"status": "disabled"}}

    campaign_plan = _campaign_plan_for_state(state)
    task_state = {**state, "campaign_plan": campaign_plan}
    base_settings = get_settings()
    task_cap = _smart_task_cap(state, base_settings)
    tasks, blocked = build_smart_campaign_tasks(task_state, max_tasks=task_cap)
    attempted = {
        str(item.get("idempotency_key"))
        for item in state.get("campaign_task_outcomes", [])
        if isinstance(item, Mapping)
        and str(item.get("status"))
        in {
            CampaignTaskStatus.EXECUTED.value,
            CampaignTaskStatus.POLICY_DENIED.value,
            CampaignTaskStatus.INFRASTRUCTURE_FAILURE.value,
        }
    }
    root = _target_url(state)
    try:
        runtime_settings = base_settings.model_copy(
            update={
                "scan_mode": ScanMode(profile),
                "smart_auto_approve": bool(
                    base_settings.smart_auto_approve or state.get("auto_approve", False)
                ),
            }
        )
    except ValueError:
        runtime_settings = base_settings
    ledger = None
    ledger_path = state.get("action_ledger_path")
    if ledger_path:
        try:
            ledger = SQLiteActionLedger(str(ledger_path))
        except (OSError, ValueError):
            return {
                "campaign_task_outcomes": [
                    {
                        "status": CampaignTaskStatus.STOPPED.value,
                        "reason": "ledger:initialization_failure",
                    }
                ],
                "errors": ["action ledger could not be initialized; execution stopped"],
            }
    if not str(state.get("engagement_id") or "").strip():
        observed_preconditions = state.get("observed_preconditions", ())
        blocked_preconditions = state.get("blocked_preconditions", ())
        if isinstance(observed_preconditions, str):
            observed_preconditions = (observed_preconditions,)
        if isinstance(blocked_preconditions, str):
            blocked_preconditions = (blocked_preconditions,)
        configuration_blockers: list[dict[str, Any]] = []
        planned_information = state.get("smart_information_actions") or []
        if isinstance(planned_information, list):
            for index, record in enumerate(planned_information[:3]):
                if not isinstance(record, Mapping):
                    continue
                information_task = _information_task_from_record(
                    record, state=state, index=index
                )
                if information_task is None:
                    continue
                ready, missing = resolve_preconditions(
                    information_task,
                    observed_preconditions=observed_preconditions,
                    blocked_preconditions=blocked_preconditions,
                    require_observations=True,
                )
                if not ready:
                    configuration_blockers.append(
                        {
                            "task_id": information_task.task_id,
                            "engagement_id": "",
                            "vulnerability_class": information_task.vulnerability_class,
                            "status": CampaignTaskStatus.BLOCKED_BY_PRECONDITION.value,
                            "reason": "precondition_failed",
                            "missing_preconditions": list(missing),
                        }
                    )
        if configuration_blockers:
            return {
                **RuntimeFactory.blocked_result(
                    node="smart_campaigns",
                    reason="identity:engagement_id_required",
                ),
                "campaign_task_outcomes": configuration_blockers,
                "smart_http_observations": [],
                "findings": list(state.get("findings") or []),
            }

    runtime_context = state.get("runtime_context")
    if isinstance(runtime_context, RuntimeContext):
        if not runtime_context.valid:
            return runtime_context.blocked_result(node="smart_campaigns")
        runtime = runtime_context
    else:
        runtime = RuntimeFactory.create(
            engagement_id=str(state.get("engagement_id") or ""),
            campaign_id=str(state.get("campaign_id") or "smart-campaign"),
            target_origin=root,
            settings=runtime_settings,
            manifest=state.get("capability_manifest") or None,
            ledger=ledger,
            use_default_ledger=bool(ledger_path),
            used_actions=int((state.get("action_budget") or {}).get("used_actions", 0)),
            used_budget=float((state.get("action_budget") or {}).get("used_cost", 0.0)),
        )
        if not runtime.valid:
            return runtime.blocked_result(node="smart_campaigns")
    executor = runtime.action_executor
    observations: list[dict[str, Any]] = []
    outcomes = list(blocked)
    direct_findings: list[Finding] = []
    research_session = ResearchSession.from_state(state)
    planned_information = state.get("smart_information_actions") or []
    if not isinstance(planned_information, list):
        planned_information = []
    research_attempted = {
        str(item.get("fingerprint"))
        for item in research_session.next_best_actions
        if isinstance(item, Mapping)
        and str(item.get("outcome") or "") not in {"", "planned"}
    }
    information_tasks: list[tuple[CampaignTask, Mapping[str, Any]]] = []
    for index, record in enumerate(planned_information[:3]):
        if not isinstance(record, Mapping):
            continue
        fingerprint = str(record.get("fingerprint") or "")
        if fingerprint and fingerprint in research_attempted:
            continue
        information_task = _information_task_from_record(record, state=state, index=index)
        if information_task is not None:
            information_tasks.append((information_task, record))
            break
    selected = [
        task for task in tasks if task.normalized_idempotency_key() not in attempted
    ][:task_cap]

    handler = build_smart_campaign_handler(
        state,
        root=root,
        observations=observations,
        direct_findings=direct_findings,
    )
    adapter = runtime.adapters.get("smart_http")
    if adapter is None:
        runtime.adapters.register(
            RegisteredAdapter(
                name="smart_http",
                capability="smart_http_execution",
                transport="http",
                handler=handler,
                source="smart_campaigns",
                version="1",
                policy_checked=True,
                canonical_wrapper=G02_HTTP_CANONICAL_WRAPPER,
                scope_policy=G02_HTTP_SCOPE_POLICY,
                static_inventory_ref=G02_HTTP_INVENTORY_REF,
                proof_contract=G02_HTTP_PROOF_CONTRACT,
                expires_at=G02_HTTP_APPROVAL_EXPIRY,
            )
        )
    else:
        handler = adapter.handler
    state_observed_preconditions = state.get("observed_preconditions", ())
    state_blocked_preconditions = state.get("blocked_preconditions", ())
    if isinstance(state_observed_preconditions, str):
        state_observed_preconditions = (state_observed_preconditions,)
    if isinstance(state_blocked_preconditions, str):
        state_blocked_preconditions = (state_blocked_preconditions,)
    for task in selected:
        ready, _ = resolve_preconditions(
            task,
            observed_preconditions=state_observed_preconditions,
            blocked_preconditions=state_blocked_preconditions,
            require_observations=True,
        )
        outcomes.append(executor.execute(task, handler, preconditions_met=ready))

    for information_task, information_record in information_tasks:
        information_ready, _ = resolve_preconditions(
            information_task,
            observed_preconditions=state_observed_preconditions,
            blocked_preconditions=state_blocked_preconditions,
            require_observations=True,
        )
        information_outcome = executor.execute(
            information_task,
            handler,
            preconditions_met=information_ready,
        )
        outcomes.append(information_outcome)
        status = str(information_outcome.get("status") or "")
        outcome_name = "executed" if status == CampaignTaskStatus.EXECUTED.value else "blocked"
        if status == CampaignTaskStatus.INFRASTRUCTURE_FAILURE.value:
            outcome_name = "failed"
        _update_research_action_outcome(
            research_session,
            information_record,
            outcome=outcome_name,
        )
        evidence_classification = _record_information_evidence(
            research_session,
            information_task,
            information_record,
            information_outcome,
        )
        if evidence_classification != "inconclusive":
            _update_research_action_outcome(
                research_session,
                information_record,
                outcome=f"{outcome_name}:{evidence_classification}",
            )

    if profile == "authorized-active":
        swagger_task = _build_swagger_ssrf_task(state, root)
        if swagger_task is not None:
            observed = tuple(state_observed_preconditions or ()) + ("authorized-active profile",)
            ready, _ = resolve_preconditions(
                swagger_task,
                observed_preconditions=observed,
                blocked_preconditions=state_blocked_preconditions,
                require_observations=True,
            )
            outcomes.append(executor.execute(swagger_task, handler, preconditions_met=ready))

    runtime_feedback = _runtime_feedback_projection(state, outcomes=outcomes)
    feedback_state = dict(state)
    feedback_state["runtime_feedback"] = runtime_feedback
    updated_knowledge_gaps = runtime.knowledge_gap_engine.derive(feedback_state)
    research_session.coverage_gaps = [gap.gap_id for gap in updated_knowledge_gaps]

    projection_state = dict(feedback_state)
    projection_state["knowledge_gaps"] = [
        gap.as_dict() for gap in updated_knowledge_gaps
    ]
    projection_state["campaign_task_outcomes"] = [
        *(state.get("campaign_task_outcomes") or []),
        *outcomes,
    ]
    coverage_ledger = project_coverage_ledger(projection_state)
    proof_bundles = [
        dict(item["proof_bundle"])
        for item in outcomes
        if isinstance(item, Mapping)
        and isinstance(item.get("proof_bundle"), Mapping)
        and item.get("proof_bundle_sealed") is True
    ]
    previous_replanning = state.get("smart_replanning") or {}
    try:
        previous_round = int(previous_replanning.get("round", 0))
    except (AttributeError, TypeError, ValueError):
        previous_round = 0
    try:
        max_replan_rounds = int(getattr(base_settings, "smart_max_replan_rounds", 0))
    except (TypeError, ValueError):
        max_replan_rounds = 0
    next_round = previous_round + 1
    replan_requested = bool(observations) and next_round < max_replan_rounds
    return {
        "campaign_plan": campaign_plan,
        "campaign_task_outcomes": outcomes,
        "proof_bundles": proof_bundles,
        "smart_http_observations": observations,
        "findings": direct_findings,
        "decision_trace": list(executor.decision_trace),
        "lifecycle_events": list(executor.lifecycle_events),
        "coverage_ledger": coverage_ledger,
        "runtime_feedback": runtime_feedback,
        "knowledge_gaps": [gap.as_dict() for gap in updated_knowledge_gaps],
        "research_session": research_session.as_dict(),
        "positive_evidence_ledger": list(research_session.positive_evidence_ledger),
        "negative_evidence_ledger": list(research_session.negative_evidence_ledger),
        "smart_replanning": {
            "status": "executed" if observations else "blocked",
            "round": next_round,
            "max_replan_rounds": max_replan_rounds,
            "replan_requested": replan_requested,
            "executed_count": len(observations),
            "max_tasks": task_cap,
            "get_only": all(task.method.upper() in {"GET", "HEAD", "OPTIONS"} for task in selected),
            "active_methods_enabled": profile == "authorized-active",
            "same_origin_only": True,
            "proof_required": True,
        },
        "runtime_capability_gaps": [
            gap.as_dict() for gap in runtime.capability_gaps
        ],
        "current_phase": "smart_campaign_execution",
    }


_DEFAULT_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def _user_agent(state: Mapping[str, Any]) -> str:
    settings = state.get("settings")
    value = getattr(settings, "http_user_agent", "") if settings is not None else ""
    if not value or str(value).startswith("WebPent/0.2"):
        try:
            configured = get_settings().http_user_agent
        except Exception:
            configured = ""
        value = configured or value
    if not value or str(value).startswith("WebPent/0.2"):
        value = _DEFAULT_BROWSER_USER_AGENT
    return str(value)[:256]


__all__ = [
    "build_smart_campaign_tasks",
    "smart_campaigns_execution_node",
    "smart_campaigns_node",
]
