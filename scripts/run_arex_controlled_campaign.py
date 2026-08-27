"""Run one bounded AREX campaign against the purpose-built local IDOR target.

This runner is intentionally finite and in-process.  The scheduler selects a
single GET-only task; CampaignExecutor/ActionAuthority authorize it; the
existing GenericCaseRunner and target adapter own lifecycle transport,
causal-oracle evaluation, and proof verification.  No external target,
credential, callback, mutation, daemon, or persistent polling is used.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from webpent.adapters.controlled_target.adapter import (
    CONTROLLED_IDOR_CASE_ID,
    CONTROLLED_ROUTE_PREFIX,
    CONTROLLED_TARGET_ID,
    build_controlled_idor_registration,
    build_controlled_idor_target,
    build_controlled_target_spec,
)
from webpent.benchmark.research_intelligence import (
    ResearchEvaluationCase,
    evaluate_research_intelligence,
)
from webpent.config.settings import Settings
from webpent.research_engine.autonomous_scheduler import AutonomousScheduler
from webpent.research_engine.campaign_state import CampaignState
from webpent.research_engine.research_budget import ResearchBudget
from webpent.shared.action_authority import ActionAuthority, ActionRisk
from webpent.shared.campaign_executor import (
    CampaignExecutor,
    CampaignTask,
    CampaignTaskStatus,
)
from webpent.shared.generic_case_runner import GenericCaseRunner
from webpent.shared.generic_web_contracts import (
    LifecycleAuthorization,
    LifecycleRunContext,
)
from webpent.shared.security_reasoning_memory import SecurityReasoningMemory

ENGAGEMENT_ID = "arex-controlled-local-idor-engagement-v1"
CAMPAIGN_ID = "arex-controlled-local-idor-campaign-v1"
TASK_ID = "arex-controlled-local-idor-task-v1"
SCOPE_DIGEST = hashlib.sha256(b"controlled-local-loopback-get-only-v1").hexdigest()


def _settings() -> Settings:
    return Settings(
        scan_mode="authorized-active",
        smart_auto_approve=True,
        smart_require_idempotency=True,
        smart_action_budget=3.0,
        smart_max_actions=1,
    )


def _initial_state() -> CampaignState:
    return CampaignState(
        campaign_id=CAMPAIGN_ID,
        target_identity=CONTROLLED_TARGET_ID,
        scope_digest=SCOPE_DIGEST,
        knowledge_model_version="arex-v1",
        current_objectives=("bounded_causal_validation", "evidence_completeness"),
        research_budget=ResearchBudget(
            max_requests=3,
            max_runtime_minutes=5,
            max_browser_actions=0,
            max_depth=1,
            max_hypotheses=1,
        ),
        time_budget=300_000,
        active_hypotheses=(f"{CONTROLLED_IDOR_CASE_ID}:foreign-owner-read",),
    )


def _task(target_origin: str) -> CampaignTask:
    return CampaignTask(
        task_id=TASK_ID,
        engagement_id=ENGAGEMENT_ID,
        asset_id=CONTROLLED_TARGET_ID,
        source_evidence_ids=("controlled-target:declared-id-oracle",),
        vulnerability_class="idor",
        hypothesis_id=f"{CONTROLLED_IDOR_CASE_ID}:foreign-owner-read",
        preconditions=("controlled_target_ready", "loopback_scope_bound"),
        identity_context="synthetic_opaque_identities",
        expected_information_gain=0.9,
        risk_tier=ActionRisk.READ_ONLY,
        target_url=f"{target_origin}{CONTROLLED_ROUTE_PREFIX}",
        method="GET",
        action_family="http_read",
        capability="http_read",
        body_schema="none",
        content_type="",
        budget=3.0,
        metadata={
            "dependencies": (),
            "adapter_name": "controlled_local_idor",
            "observed_preconditions": (
                "controlled_target_ready",
                "loopback_scope_bound",
            ),
        },
    )


def run_campaign() -> dict[str, Any]:
    """Execute and return a redacted, machine-readable campaign report."""
    state = _initial_state()
    memory = SecurityReasoningMemory(
        engagement_id=ENGAGEMENT_ID,
        target_id=CONTROLLED_TARGET_ID,
    )

    with build_controlled_idor_target() as target:
        spec = build_controlled_target_spec(
            target.target_origin,
            engagement_id=ENGAGEMENT_ID,
        )
        target.bind_target_spec(spec)
        registration = build_controlled_idor_registration(target)
        readiness = target.readiness()
        readiness_flags = {
            key: bool(readiness.get(key))
            for key in (
                "preconditions_ready",
                "fixture_ready",
                "identity_model_ready",
                "reset_verified",
                "runtime_digest_verified",
                "network_scope_verified",
            )
        }

        if not all(readiness_flags.values()):
            return {
                "schema_version": "arex-controlled-campaign-v1",
                "campaign_id": CAMPAIGN_ID,
                "engagement_id": ENGAGEMENT_ID,
                "target": target.describe_target(),
                "readiness": readiness_flags,
                "status": "blocked",
                "blocking_reason": "controlled_target_readiness_failed",
                "requests_used": 0,
                "proof_bundle_created": False,
                "official_isolated_p10_runs_authorized": False,
                "qualification_effect": False,
                "real_world_detection_rate_measured": False,
            }

        authorization = LifecycleAuthorization(
            authorized=True,
            engagement_id=ENGAGEMENT_ID,
            allowed_origin=target.target_origin,
            actor="arex-local-bounded-runner",
            satisfied_requirements=(
                "controlled_local_target_authorization",
                "loopback_origin",
                "get_only_causal_validation",
            ),
        )
        run_context = LifecycleRunContext(
            run_id="arex-controlled-local-idor-run-v1",
            target_id=target.target_id,
            case_id=CONTROLLED_IDOR_CASE_ID,
            engagement_id=ENGAGEMENT_ID,
        )
        task = _task(target.target_origin)
        scheduler = AutonomousScheduler(state, max_steps=1)
        decision, planned, route = scheduler.choose(
            [task],
            available_capabilities={"http_read"},
            scope_authorized=True,
            authority_available=True,
            observed_evidence=(),
            observed_preconditions=(
                "controlled_target_ready",
                "loopback_scope_bound",
            ),
        )

        executor = CampaignExecutor(
            ActionAuthority(
                settings=_settings(),
                allowed_origin=target.target_origin,
                manifest={"capabilities": {"http_read": {"available": True}}},
            )
        )
        case_result = None
        execution_record: dict[str, Any] | None = None
        if decision.status == "selected" and planned is not None and route is not None:

            def handler(_task: CampaignTask) -> dict[str, Any]:
                nonlocal case_result
                case_result = GenericCaseRunner.execute_case(
                    registration,
                    target.case_definition(),
                    authorization,
                    run_context,
                )
                return {
                    "handler_status": case_result.status,
                    "handler_reason": case_result.reason,
                    "observation_refs": case_result.observation_refs,
                    "proof_verified": case_result.status == "confirmed",
                }

            execution_record = executor.execute(
                planned.task,
                handler,
                preconditions_met=readiness_flags["preconditions_ready"],
            )
            executor_status = str(execution_record.get("status") or "")
            outcome_status = (
                "completed"
                if executor_status == CampaignTaskStatus.EXECUTED.value
                else "blocked"
                if executor_status
                in {
                    CampaignTaskStatus.BLOCKED_BY_PRECONDITION.value,
                    CampaignTaskStatus.POLICY_DENIED.value,
                    CampaignTaskStatus.CONTEXT_BLOCKED.value,
                }
                else "failed"
            )
            evidence_summary = {
                "scheduler_route": route.route,
                "task_outcome": outcome_status,
                "case_status": str(getattr(case_result, "status", "not_run")),
                "proof_bundle_sealed": str(bool(execution_record.get("proof_bundle_sealed"))),
            }
            state = scheduler.record_task_outcome(
                planned.task.task_id,
                outcome_status,
                evidence_summary=evidence_summary,
            )
            learning_outcome = (
                "supported" if getattr(case_result, "status", "") == "confirmed" else "inconclusive"
            )
            memory.learn_from_outcome(
                hypothesis_id=task.hypothesis_id,
                outcome=learning_outcome,
                rationale=str(getattr(case_result, "reason", "case_not_run")),
                evidence_refs=getattr(case_result, "observation_refs", ()),
                relevance=0.9,
            )
        else:
            state = scheduler.record_task_outcome(
                task.task_id,
                "blocked",
                evidence_summary={
                    "scheduler_status": decision.status,
                    "scheduler_reason": ";".join(decision.reasons),
                },
            )

        case_status = str(getattr(case_result, "status", "not_run"))
        proof_ref = getattr(case_result, "proof_bundle_ref", None)
        benchmark_case = ResearchEvaluationCase(
            case_id=CONTROLLED_IDOR_CASE_ID,
            target_id=CONTROLLED_TARGET_ID,
            hypothesis_generated=decision.status == "selected",
            rank=1 if decision.status == "selected" else None,
            expected_rank=1,
            information_gain=0.9 if decision.status == "selected" else 0.0,
            evidence_quality=1.0 if case_status == "confirmed" else 0.0,
            validation_outcome=(
                case_status
                if case_status in {"confirmed", "inconclusive", "blocked"}
                else "not_run"
            ),
            ground_truth_outcome="confirmed",
            proof_complete=bool(proof_ref),
            requests_used=target.request_count,
        )
        evaluation = evaluate_research_intelligence(
            engagement_id=ENGAGEMENT_ID,
            cases=[benchmark_case],
        )
        final_report = {
            "schema_version": "arex-controlled-campaign-v1",
            "campaign_id": CAMPAIGN_ID,
            "engagement_id": ENGAGEMENT_ID,
            "target": target.describe_target(),
            "readiness": readiness_flags,
            "scheduler": {
                "status": decision.status,
                "task_id": decision.task_id,
                "route": decision.route,
                "reasons": list(decision.reasons),
                "score": decision.score,
            },
            "execution": execution_record,
            "case_result": case_result.as_dict() if case_result is not None else None,
            "campaign_state": state.canonical_dict(),
            "memory": memory.summary(),
            "evaluation": evaluation.model_dump(mode="json"),
            "governance": {
                "controlled_experiment": True,
                "real_world_detection_rate_measured": False,
                "qualification_effect": False,
                "official_isolated_p10_runs_authorized": False,
                "p10_status": "NOT_QUALIFIED",
                "p9_status": "NOT_QUALIFIED",
                "vip_status": "NOT_QUALIFIED",
                "bug_bounty_status": "BLOCKED",
                "human_signoff": False,
            },
            "boundedness": {
                "max_scheduler_steps": 1,
                "max_target_requests": 3,
                "actual_target_requests": target.request_count,
                "external_network": False,
                "credentials": False,
                "state_mutation": False,
                "callbacks": False,
                "shell_execution": False,
                "persistent_service": False,
            },
        }
        return json.loads(json.dumps(final_report, sort_keys=True, default=str))


def main() -> None:
    output = Path("reports/evaluation/arex/controlled_campaign_v1.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    report = run_campaign()
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True))


if __name__ == "__main__":
    main()
