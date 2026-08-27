from __future__ import annotations

from webpent.research_engine.evidence_aware_loop import EvidenceAwareAgentLoop, LoopStatus
from webpent.research_engine.research_budget import BudgetUsage, ResearchBudget
from webpent.research_engine.research_state import ResearchTask


def _task() -> ResearchTask:
    return ResearchTask(
        task_id="task:observe",
        engagement_id="eng",
        target_id="target",
        objective="inspect an already admitted endpoint model",
        required_capability="http_read",
        required_evidence=("baseline", "negative_control"),
        operation="observe",
    )


def test_loop_fails_closed_without_scope_authorization() -> None:
    result = EvidenceAwareAgentLoop().evaluate(
        engagement_id="eng",
        target_id="target",
        tasks=[_task()],
        available_capabilities=["http_read"],
    )
    assert result.status == LoopStatus.BLOCKED
    assert result.stop_reason == "scope_authorization_required"
    assert result.execution_attempted is False
    assert result.finding_promotion_allowed is False


def test_loop_stops_when_capability_is_missing() -> None:
    result = EvidenceAwareAgentLoop().evaluate(
        engagement_id="eng",
        target_id="target",
        tasks=[_task()],
        available_capabilities=["browser_read"],
        scope_authorized=True,
    )
    assert result.status == LoopStatus.BLOCKED
    assert result.stop_reason == "required_capability_unavailable"


def test_loop_waits_for_required_evidence_then_central_verification() -> None:
    loop = EvidenceAwareAgentLoop()
    pending = loop.evaluate(
        engagement_id="eng",
        target_id="target",
        tasks=[_task()],
        available_capabilities=["http_read"],
        evidence_refs=["baseline"],
        required_evidence=["baseline", "negative_control"],
        scope_authorized=True,
    )
    assert pending.status == LoopStatus.READY
    assert pending.missing_evidence == ("negative_control",)

    ready = loop.evaluate(
        engagement_id="eng",
        target_id="target",
        tasks=[_task()],
        available_capabilities=["http_read"],
        evidence_refs=["baseline", "negative_control"],
        required_evidence=["baseline", "negative_control"],
        scope_authorized=True,
    )
    assert ready.status == LoopStatus.EVIDENCE_READY
    assert ready.stop_reason == "central_verification_required"
    assert ready.proof_authority is False


def test_loop_honors_budget_and_authority_mode() -> None:
    exhausted = EvidenceAwareAgentLoop(ResearchBudget(max_requests=1)).evaluate(
        engagement_id="eng",
        target_id="target",
        tasks=[_task()],
        available_capabilities=["http_read"],
        usage=BudgetUsage(requests=1),
        scope_authorized=True,
    )
    assert exhausted.status == LoopStatus.STOPPED
    assert exhausted.stop_reason == "request_budget_exhausted"

    denied_mode = EvidenceAwareAgentLoop().evaluate(
        engagement_id="eng",
        target_id="target",
        tasks=[_task()],
        available_capabilities=["http_read"],
        authority_mode="authorized-active",
        scope_authorized=True,
    )
    assert denied_mode.status == LoopStatus.BLOCKED
    assert denied_mode.stop_reason == "unsupported_authority_mode"
