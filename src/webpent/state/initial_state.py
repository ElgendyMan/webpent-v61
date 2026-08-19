"""Shared initial-state construction for WebPent engagements.

The CLI and Celery worker are different entry points, but they must start an
engagement with the same state contract.  This module owns the common empty
containers and keeps entry-point-specific values (for example Playwright
availability and stealth mode) explicit.

The factory is intentionally deterministic and does not perform network I/O,
load credentials from disk, or print operator-supplied values.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from webpent.config.settings import ScanMode, ScanProfile, get_settings, resolve_scan_profile
from webpent.shared.campaign_planner import build_campaign_plan
from webpent.shared.campaigns import build_waptlab_campaign_ledger
from webpent.shared.capability_manifest import build_capability_manifest

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
    client_id: str | None = None,
    engagement_id: str | None = None,
    credentials: dict[str, str] | None = None,
    session_cookies: dict[str, str] | None = None,
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
) -> dict[str, Any]:
    """Build a complete, redaction-safe starting state for one engagement.

    All mutable inputs are copied so the CLI/API caller cannot accidentally
    mutate LangGraph state after invocation.  The function only initializes
    state; authentication, crawling, tools, LLM calls, and PoC execution stay
    in their dedicated graph nodes.
    """
    resolved_engagement_id = str(engagement_id or thread_id or "").strip() or None
    resolved_client_id = str(client_id or "").strip() or None
    target_url = target.url if hasattr(target, "url") else str(target.get("url", ""))
    settings = get_settings()
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
    capability_manifest = build_capability_manifest(settings)
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

    return {
        "target": target,
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
        "identity_profiles": dict(identity_profiles or {}),
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
        "report_formats": normalized_formats,
        "auto_approve": bool(auto_approve),
        "enable_autonomous_controller": bool(enable_autonomous_controller),
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
            "require_idempotency": bool(settings.smart_require_idempotency),
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
        "campaign_ledger": build_waptlab_campaign_ledger(),
        "campaign_plan": build_campaign_plan(target_url=target_url),
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
        "smart_replanning": {
            "round": 0,
            "max_rounds": int(settings.smart_max_replan_rounds),
            "status": "not_started",
        },
        "rabbit_hole_loop_back_count": 0,
        **({"thread_id": thread_id} if thread_id is not None else {}),
        **({"client_id": resolved_client_id} if resolved_client_id else {}),
        **({"engagement_id": resolved_engagement_id} if resolved_engagement_id else {}),
    }
