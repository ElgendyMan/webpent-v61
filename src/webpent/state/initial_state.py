"""Shared initial-state construction for WebPent engagements.

The CLI and Celery worker are different entry points, but they must start an
engagement with the same state contract.  This module owns the common empty
containers and keeps entry-point-specific values (for example Playwright
availability and stealth mode) explicit.

The factory is intentionally deterministic and does not perform network I/O,
load credentials from disk, or print operator-supplied values.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from webpent.config.settings import (
    ScanMode,
    ScanProfile,
    deployment_requires_proof_bundle,
    get_settings,
    profile_requires_proof_bundle,
    resolve_scan_profile,
)
from webpent.shared.campaign_planner import build_campaign_plan
from webpent.shared.campaigns import (
    build_generic_campaign_ledger,
    build_waptlab_campaign_ledger,
)
from webpent.shared.capability_manifest import build_capability_manifest
from webpent.shared.runtime import RuntimeFactory
from webpent.shared.target_package_context import (
    TargetPackageContext,
    admit_target_package,
)

if TYPE_CHECKING:
    from webpent.models.targets import Target


def _root_goal_nodes() -> dict[str, Any]:
    """Create the engagement root goal without making startup fatal.

    Goal-tree creation is additive.  A failure must not prevent a legacy scan
    from starting; the Rabbit Hole layer already has a bounded fallback for an
    empty goal tree.
    """
    try:
        from webpent.models.goal_tree import create_root_goal

        root = create_root_goal()
        return {root.id: root.model_dump(mode="json")}
    except Exception:
        return {}


def build_initial_state(
    target: Target,
    *,
    thread_id: str | None = None,
    additional_target_origins: list[str] | None = None,
    owner_username: str | None = None,
    client_id: str | None = None,
    engagement_id: str | None = None,
    campaign_id: str | None = None,
    credentials: dict[str, str] | None = None,
    session_cookies: dict[str, str] | None = None,
    session_headers: dict[str, str] | None = None,
    identity_profiles: dict[str, Any] | None = None,
    jwt_weak_secret_candidates: list[str] | None = None,
    jwt_public_key_available: bool = False,
    disclosed_report_corpus: list[Any] | None = None,
    llm_override: bool | None = None,
    custom_payloads: list[str] | None = None,
    report_formats: list[str] | None = None,
    playwright_enabled: bool = True,
    skip_recon: bool = False,
    stealth_mode: bool = False,
    auto_approve: bool = False,
    enable_autonomous_controller: bool = False,
    scan_mode: str | ScanMode | None = None,
    profile: str | ScanProfile | None = None,
    root_goal_nodes: dict[str, Any] | None = None,
    action_ledger_path: str | None = None,
    campaign_inventory: str = "waptlab",
    enable_control_plane: bool = True,
    control_plane_profile_root: str | None = None,
    raw_scope_entries: list[str] | None = None,
    target_package: dict[str, Any] | None = None,
    target_package_context: TargetPackageContext | None = None,
    target_package_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a complete, redaction-safe starting state for one engagement.

    All mutable inputs are copied so the CLI/API caller cannot accidentally
    mutate LangGraph state after invocation.  The function only initializes
    state; authentication, crawling, tools, LLM calls, and PoC execution stay
    in their dedicated graph nodes.
    """
    resolved_engagement_id = str(engagement_id or thread_id or "").strip() or None
    resolved_owner_username = str(owner_username or "").strip() or None
    resolved_client_id = str(client_id or "").strip() or None
    target_url = target.url if hasattr(target, "url") else str(target.get("url", ""))
    if target_package is not None and target_package_context is not None:
        raise ValueError(
            "raw target_package and admitted target_package_context are mutually exclusive"
        )
    admitted_package_context = target_package_context or (
        admit_target_package(target_package) if target_package is not None else None
    )
    binding_projection = dict(target_package_binding or {})
    if admitted_package_context is None and binding_projection:
        raise ValueError("target_package_binding requires an admitted target package context")
    # A raw package remains supported for legacy projection-only callers. It is
    # not an executable package-backed engagement because no lease binding was
    # created. The executable entrypoints pass an already-admitted context and
    # therefore must provide the durable binding below.
    binding_required = target_package_context is not None
    if binding_required and admitted_package_context is not None:
        required_binding = {
            "engagement_id": str(resolved_engagement_id or ""),
            "package_id": admitted_package_context.package_id,
            "package_sha256": admitted_package_context.package_sha256,
            "scope_digest": admitted_package_context.scope_digest,
            "policy_digest": admitted_package_context.policy_digest,
        }
        for key, expected in required_binding.items():
            if str(binding_projection.get(key) or "") != expected:
                raise ValueError(f"target_package_binding_{key}_mismatch")
        if binding_required and not str(binding_projection.get("lease_id") or ""):
            raise ValueError("target_package_binding_lease_missing")
    requested_inventory = str(campaign_inventory or "waptlab").strip().lower()
    if requested_inventory == "auto":
        parsed_target = urlsplit(target_url)
        target_host = (parsed_target.hostname or "").lower()
        resolved_inventory = (
            "waptlab"
            if parsed_target.port == 8000 or target_host in {"waptlab", "waptlab.local"}
            else "generic"
        )
    elif requested_inventory in {"waptlab", "generic"}:
        resolved_inventory = requested_inventory
    else:
        raise ValueError("campaign_inventory must be one of: waptlab, generic, auto")
    settings = get_settings()
    if action_ledger_path:
        settings = settings.model_copy(
            update={"action_ledger_path": Path(action_ledger_path).expanduser()}
        )
    resolved_scan_mode = settings.scan_mode
    if profile is not None:
        resolved_profile, resolved_scan_mode = resolve_scan_profile(profile)
        settings = settings.model_copy(update={"scan_mode": resolved_scan_mode})
    else:
        if scan_mode is not None:
            resolved_scan_mode = ScanMode(str(getattr(scan_mode, "value", scan_mode)))
            settings = settings.model_copy(update={"scan_mode": resolved_scan_mode})
        resolved_profile = {
            ScanMode.LEGACY: ScanProfile.LEGACY,
            ScanMode.SAFE_SMART: ScanProfile.SMART_OBSERVE,
            ScanMode.AUTHORIZED_ACTIVE: ScanProfile.AUTHORIZED_ACTIVE,
        }[resolved_scan_mode]
    vip_proof_required = profile_requires_proof_bundle(resolved_profile)
    deployment_proof_required = deployment_requires_proof_bundle(
        settings.environment_profile
    )
    proof_required = vip_proof_required or deployment_proof_required
    capability_manifest = build_capability_manifest(settings)
    resolved_campaign_id = (
        str(campaign_id or f"{resolved_engagement_id or 'engagement'}:main").strip()
        or "engagement:main"
    )
    runtime_context = RuntimeFactory.create(
        engagement_id=resolved_engagement_id or "",
        campaign_id=resolved_campaign_id,
        target_origin=target_url,
        settings=settings,
        manifest=capability_manifest,
        enable_control_plane=bool(enable_control_plane),
        control_plane_profile_root=control_plane_profile_root,
        raw_scope_entries=list(raw_scope_entries or []),
        target_package=(
            admitted_package_context.as_state()
            if admitted_package_context is not None
            else None
        ),
    )
    scan_mode_value = getattr(resolved_scan_mode, "value", resolved_scan_mode)
    profile_value = getattr(resolved_profile, "value", resolved_profile)
    governance_profile = profile_value if profile is not None else str(scan_mode_value)
    normalized_payloads = [
        str(item).strip()
        for item in list(custom_payloads or [])
        if str(item).strip()
    ]
    normalized_formats = [
        str(item).strip().lower()
        for item in list(report_formats or [])
        if str(item).strip()
    ]
    normalized_origins = [
        str(item).strip()
        for item in list(additional_target_origins or [])
        if str(item).strip()
    ]

    return {
        "target": target,
        "target_package": (
            admitted_package_context.as_state() if admitted_package_context is not None else {}
        ),
        "target_package_status": (
            "ready" if admitted_package_context is not None else "not_provided"
        ),
        "target_package_id": (
            admitted_package_context.package_id if admitted_package_context is not None else None
        ),
        "target_package_sha256": (
            admitted_package_context.package_sha256
            if admitted_package_context is not None
            else None
        ),
        "target_package_scope_digest": (
            admitted_package_context.scope_digest if admitted_package_context is not None else None
        ),
        "target_package_policy_digest": (
            admitted_package_context.policy_digest if admitted_package_context is not None else None
        ),
        "target_package_capability_digest": (
            admitted_package_context.capability_digest
            if admitted_package_context is not None
            else None
        ),
        "target_package_authorization": (
            {
                "expires_at": admitted_package_context.expires_at,
                "revocation_state": admitted_package_context.revocation_state,
                "user_confirmed": True,
            }
            if admitted_package_context is not None
            else {}
        ),
        "target_package_preflight_status": (
            "not_requested" if admitted_package_context is not None else "not_provided"
        ),
        "target_package_capability_matrix": {},
        "target_package_knowledge_gaps": [],
        "target_package_blocked_tasks": [],
        "target_package_binding": binding_projection,
        "additional_target_origins": normalized_origins,
        "messages": [],
        "findings": [],
        "current_phase": "init",
        "hypotheses": [],
        "lessons": [],
        "payloads_to_test": ({"custom": normalized_payloads} if normalized_payloads else {}),
        "custom_payloads": normalized_payloads,
        "crawled_data": {},
        "auth_state": {},
        "optimization_retries": {},
        "errors": [],
        "credentials": dict(credentials or {}),
        "session_cookies": dict(session_cookies or {}),
        "session_headers": dict(session_headers or {}),
        "identity_profiles": dict(identity_profiles or {}),
        "raw_scope_entries": list(raw_scope_entries or []),
        "compiled_scope": {},
        "scope_compile_status": "not_requested",
        "scope_compile_error": "",
        "signup_forms_detected": [],
        "signup_submissions": [],
        "verification_material_events": [],
        "identity_records": {},
        "identity_provisioning_status": "disabled",
        "secret_refs": {
            **(
                {"credentials": f"vault://{resolved_engagement_id}/credentials"}
                if credentials and resolved_engagement_id
                else {}
            ),
            **(
                {"session_cookies": f"vault://{resolved_engagement_id}/session_cookies"}
                if session_cookies and resolved_engagement_id
                else {}
            ),
            **(
                {"identity_profiles": f"vault://{resolved_engagement_id}/identity_profiles"}
                if identity_profiles and resolved_engagement_id
                else {}
            ),
        },
        "bac_observations": [],
        "bac_coverage_gaps": [],
        "relational_evidence": [],
        "authorization_matrix": {},
        "subdomain_takeover_observations": [],
        "subdomain_takeover_coverage_gaps": [],
        "cloud_storage_observations": [],
        "cloud_storage_coverage_gaps": [],
        "jwt_weak_secret_candidates": list(jwt_weak_secret_candidates or []),
        "jwt_public_key_available": bool(jwt_public_key_available),
        "jwt_deep_observations": [],
        "jwt_deep_coverage_gaps": [],
        "disclosed_report_corpus": list(disclosed_report_corpus or []),
        "disclosed_report_advisories": [],
        "advisory_coverage_gaps": [],
        "workflow_observations": [],
        "workflow_coverage_gaps": [],
        "javascript_intelligence": {},
        "js_targeted_tasks": [],
        "surface_security": {},
        "canonical_executions": [],
        "canonical_observations": [],
        "target_understanding": {},
        "target_knowledge": {},
        "attack_graph": {},
        "report_quality_gate": {},
        "memory_summary": {},
        "memory_feedback": [],
        "adaptive_revisit_tasks": {},
        "adaptive_revisit_ledger": {},
        "adaptive_hunt": {},
        "planner_decision": {},
        "planner_gate_audits": [],
        "execution_gate": {},
        "executive_summary": "",
        "risk_score": "",
        "playwright_enabled": bool(playwright_enabled),
        "stealth_mode": bool(stealth_mode),
        "stealth_telemetry": {},
        "llm_enabled_override": llm_override,
        "llm_usage_trace": [],
        "report_formats": normalized_formats,
        "auto_approve": bool(auto_approve),
        "enable_autonomous_controller": bool(enable_autonomous_controller),
        "autonomous_controller_runs": 0,
        "skip_recon": bool(skip_recon),
        "scan_mode": str(scan_mode_value),
        "profile": str(profile_value),
        "capability_manifest": capability_manifest,
        "smart_governance": {
            "profile": str(governance_profile),
            "public_profile": str(profile_value),
            "authority_mode": str(scan_mode_value),
            "fail_closed": True,
            "auto_approve_requested": bool(auto_approve),
            "smart_auto_approve": bool(settings.smart_auto_approve),
            "require_idempotency": bool(
                settings.smart_require_idempotency or proof_required
            ),
            "require_proof_bundle": bool(
                settings.smart_require_proof_bundle or proof_required
            ),
        },
        "action_ledger_path": action_ledger_path,
        "action_budget": {
            "max_actions": int(settings.smart_max_actions),
            "used_actions": 0,
            "max_cost": float(settings.smart_action_budget),
            "used_cost": 0.0,
        },
        "mental_model": {"nodes": {}, "edges": []},
        "goal_tree": {
            "nodes": dict(_root_goal_nodes() if root_goal_nodes is None else root_goal_nodes)
        },
        "decision_log": [],
        "decision_trace": [],
        "lifecycle_events": [],
        "rabbit_hole_ledger": {},
        "coverage_ledger": {},
        "campaign_inventory": resolved_inventory,
        "campaign_id": resolved_campaign_id,
        "runtime_context": runtime_context,
        "runtime_capability_gaps": [
            gap.as_dict() for gap in runtime_context.capability_gaps
        ],
        "control_plane_descriptor": (
            runtime_context.control_plane_runtime.descriptor()
            if runtime_context.control_plane_runtime is not None
            else None
        ),
        "campaign_ledger": (
            build_generic_campaign_ledger()
            if resolved_inventory == "generic"
            else build_waptlab_campaign_ledger()
        ),
        "campaign_plan": build_campaign_plan(
            target_url=target_url,
            campaign_inventory=resolved_inventory,
        ),
        "evidence_ledger": [],
        "positive_evidence_ledger": [],
        "negative_evidence_ledger": [],
        "proof_gap_assessments": [],
        "proof_plan": {},
        "proof_observability": {},
        "proof_outcomes": [],
        "proof_bundles": [],
        "campaign_task_outcomes": [],
        "smart_next_actions": [],
        "smart_http_observations": [],
        "research_round_artifacts": {},
        "recovery_events": [],
        "recovery_state": {
            "status": "not_started",
            "attempts": 0,
            "max_attempts": 2,
            "last_failure_class": "",
        },
        "smart_replanning": {
            "round": 0,
            "max_rounds": int(settings.smart_max_replan_rounds),
            "status": "not_started",
        },
        "rabbit_hole_loop_back_count": 0,
        **({"thread_id": thread_id} if thread_id is not None else {}),
        **(
            {"owner_username": resolved_owner_username}
            if resolved_owner_username
            else {}
        ),
        **({"client_id": resolved_client_id} if resolved_client_id else {}),
        **({"engagement_id": resolved_engagement_id} if resolved_engagement_id else {}),
    }
