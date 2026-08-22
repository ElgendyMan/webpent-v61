from __future__ import annotations

from typing import Any

import pytest

from webpent.shared.autonomous_controller import AutonomousController
from webpent.shared.autonomy_contracts import ActionBudgetState, AutonomousCycle, StopDecision
from webpent.shared.campaign_executor import ActionExecutor, CampaignTask


class _AllowAuthority:
    def execute(self, request: Any, handler: Any) -> Any:
        class Decision:
            reasons: tuple[str, ...] = ()
            audit_event: dict[str, Any] = {"decision": "test_allow"}

        class Result:
            status = "executed"
            output = handler(request)
            decision = Decision()

        return Result()


def test_budget_state_is_bounded_and_fail_closed() -> None:
    budget = ActionBudgetState.from_state(
        {
            "limit": -10,
            "spent": 99,
            "iterations_limit": 99,
            "iterations": 99,
            "replans_limit": 99,
            "replans": 99,
        },
        default_iterations=3,
    )
    assert budget.limit == 0
    assert budget.spent == 0
    assert budget.iterations_limit == 10
    assert budget.iterations == 10
    assert budget.replans_limit == 10
    assert budget.replans == 10
    assert budget.can_start_iteration() is False
    assert budget.stop_reason in {"iteration_budget_exhausted", "action_budget_exhausted"}


def test_stop_and_cycle_contracts_are_serializable() -> None:
    decision = StopDecision(True, "negative_control_contradicts_theory", category="evidence")
    cycle = AutonomousCycle(
        cycle_id="engagement:0",
        phase="execute",
        status="blocked",
        selected_tasks=1,
        executed_tasks=0,
        evidence_added=False,
        knowledge_updated=False,
        stop_decision=decision,
    )
    payload = cycle.as_dict()
    assert payload["stop_decision"] == {
        "should_stop": True,
        "reason": "negative_control_contradicts_theory",
        "category": "evidence",
        "safe_to_resume": False,
    }


def test_legacy_budget_resume_preserves_spent_cost_and_actions() -> None:
    budget = ActionBudgetState.from_state(
        {
            "max_cost": 5.0,
            "used_cost": 3.0,
            "max_actions": 4,
            "used_actions": 2,
        }
    )

    assert budget.limit == 5.0
    assert budget.spent == 3.0
    assert budget.iterations_limit == 4
    assert budget.iterations == 2
    assert budget.as_dict()["remaining"] == 2.0


def test_controller_emits_budget_stop_and_redacted_cycle(monkeypatch: pytest.MonkeyPatch) -> None:
    task = CampaignTask(
        task_id="task-1",
        engagement_id="eng-1",
        asset_id="asset-1",
        source_evidence_ids=("e-1",),
        vulnerability_class="test",
        hypothesis_id="hyp-1",
        expected_information_gain=0.9,
        budget=2.0,
        capability="http_read",
        target_url="https://example.invalid/",
    )

    monkeypatch.setattr(
        "webpent.shared.autonomous_controller.smart_campaigns_node",
        lambda state: {"campaign_plan": {}, "smart_replanning": {}},
    )
    monkeypatch.setattr(
        AutonomousController,
        "_planned_tasks",
        staticmethod(lambda state, planning: [task]),
    )

    class FakeExecutor(ActionExecutor):
        def __init__(self) -> None:
            self.lifecycle_events: list[dict[str, Any]] = []

        def execute(
            self,
            task: CampaignTask,
            handler: Any,
            *,
            preconditions_met: bool = True,
        ) -> dict[str, Any]:
            self.lifecycle_events.append({"task_id": task.task_id, "stage": "completed"})
            return {
                "task_id": task.task_id,
                "status": "executed",
                "output_available": True,
                "proof_bundle_sealed": True,
                "negative_control_present": True,
                "evidence_refs": ["ref-1"],
            }

    executor = FakeExecutor()
    result = AutonomousController(action_executor=executor, max_iterations=2).run(
        {
            "engagement_id": "eng-1",
            "action_budget": {"limit": 2, "iterations_limit": 2},
        },
        handler=lambda _task: {"ok": True},
        iterations=2,
    )

    assert result["action_budget"]["spent"] == 2
    assert result["stop_decision"]["should_stop"] is True
    assert result["stop_decision"]["reason"] == "action_budget_exhausted"
    assert result["autonomous_cycle_records"]
    assert result["autonomous_cycle_records"][0]["selected_tasks"] == 1
    assert "target_url" not in result["smart_replanning"]["controller_trace"][0]
    assert "handler" not in result["smart_replanning"]["controller_trace"][0]


def test_controller_does_not_call_handler_when_budget_is_insufficient(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = CampaignTask(
        task_id="expensive-task",
        engagement_id="eng-1",
        asset_id="asset-1",
        source_evidence_ids=("e-1",),
        vulnerability_class="test",
        hypothesis_id="hyp-1",
        expected_information_gain=0.9,
        budget=2.0,
        capability="http_read",
        target_url="https://example.invalid/",
    )
    monkeypatch.setattr(
        "webpent.shared.autonomous_controller.smart_campaigns_node",
        lambda state: {"campaign_plan": {}, "smart_replanning": {}},
    )
    monkeypatch.setattr(
        AutonomousController,
        "_planned_tasks",
        staticmethod(lambda state, planning: [task]),
    )

    class NeverCalledExecutor(ActionExecutor):
        def __init__(self) -> None:
            self.lifecycle_events: list[dict[str, Any]] = []
            self.called = False

        def execute(
            self,
            task: CampaignTask,
            handler: Any,
            *,
            preconditions_met: bool = True,
        ) -> dict[str, Any]:
            self.called = True
            raise AssertionError("executor must not run after budget reservation fails")

    executor = NeverCalledExecutor()
    result = AutonomousController(action_executor=executor).run(
        {"engagement_id": "eng-1", "action_budget": {"limit": 1.0}},
        handler=lambda _task: {"unexpected": True},
        iterations=1,
    )
    assert executor.called is False
    assert result["action_budget"]["spent"] == 0.0
    assert result["stop_decision"]["reason"] == "action_budget_exhausted"


def test_controller_exhausts_replan_budget_on_repeated_infrastructure_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = CampaignTask(
        task_id="failing-task",
        engagement_id="eng-1",
        asset_id="asset-1",
        source_evidence_ids=("e-1",),
        vulnerability_class="test",
        hypothesis_id="hyp-1",
        expected_information_gain=0.9,
        budget=1.0,
        capability="http_read",
        target_url="https://example.invalid/",
    )
    monkeypatch.setattr(
        "webpent.shared.autonomous_controller.smart_campaigns_node",
        lambda state: {"campaign_plan": {}, "smart_replanning": {}},
    )
    monkeypatch.setattr(
        AutonomousController,
        "_planned_tasks",
        staticmethod(lambda state, planning: [task]),
    )

    class FailingExecutor(ActionExecutor):
        def __init__(self) -> None:
            self.lifecycle_events: list[dict[str, Any]] = []

        def execute(
            self,
            task: CampaignTask,
            handler: Any,
            *,
            preconditions_met: bool = True,
        ) -> dict[str, Any]:
            return {
                "task_id": task.task_id,
                "status": "infrastructure_failure",
                "reason": "offline_fixture_failure",
                "output_available": False,
                "proof_bundle_sealed": False,
            }

    result = AutonomousController(action_executor=FailingExecutor(), max_iterations=3).run(
        {
            "engagement_id": "eng-1",
            "action_budget": {"limit": 5.0, "replans_limit": 1},
            "recovery_state": {"attempts": 0, "max_attempts": 3},
        },
        handler=lambda _task: {"ok": True},
        iterations=3,
    )
    assert result["action_budget"]["replans"] == 1
    assert result["stop_decision"]["reason"] == "recovery_budget_exhausted"


def test_negative_control_contradiction_is_an_evidence_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = CampaignTask(
        task_id="control-task",
        engagement_id="eng-1",
        asset_id="asset-1",
        source_evidence_ids=("e-1",),
        vulnerability_class="test",
        hypothesis_id="hyp-1",
        expected_information_gain=0.9,
        budget=1.0,
        capability="http_read",
        target_url="https://example.invalid/",
    )
    monkeypatch.setattr(
        "webpent.shared.autonomous_controller.smart_campaigns_node",
        lambda state: {"campaign_plan": {}, "smart_replanning": {}},
    )
    monkeypatch.setattr(
        AutonomousController,
        "_planned_tasks",
        staticmethod(lambda state, planning: [task]),
    )

    class ContradictionExecutor(ActionExecutor):
        def __init__(self) -> None:
            self.lifecycle_events: list[dict[str, Any]] = []

        def execute(
            self,
            task: CampaignTask,
            handler: Any,
            *,
            preconditions_met: bool = True,
        ) -> dict[str, Any]:
            return {
                "task_id": task.task_id,
                "status": "executed",
                "negative_control_contradicts": True,
                "output_available": True,
                "proof_bundle_sealed": False,
            }

    result = AutonomousController(action_executor=ContradictionExecutor()).run(
        {"engagement_id": "eng-1", "action_budget": {"limit": 5.0}},
        handler=lambda _task: {"ok": True},
        iterations=2,
    )
    assert result["stop_decision"] == {
        "should_stop": True,
        "reason": "negative_control_contradicts_theory",
        "category": "evidence",
        "safe_to_resume": False,
    }
    assert result["autonomous_cycle_records"][0]["executed_tasks"] == 1


def test_resumed_budget_does_not_reset_accumulated_spend() -> None:
    resumed = ActionBudgetState.from_state(
        {
            "limit": 5.0,
            "spent": 4.0,
            "iterations_limit": 3,
            "iterations": 2,
            "replans_limit": 2,
            "replans": 1,
            "status": "replanning",
        }
    )
    assert resumed.spent == 4.0
    assert resumed.iterations == 2
    assert resumed.replans == 1
    assert resumed.reserve(1.0) is True
    assert resumed.reserve(0.1) is False
    assert resumed.stop_reason == "action_budget_exhausted"


def test_controller_requires_injected_runtime_dependencies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "webpent.shared.autonomous_controller.smart_campaigns_node",
        lambda state: {"smart_next_actions": [], "campaign_plan": {}, "smart_replanning": {}},
    )
    with pytest.raises(RuntimeError, match="runtime_dependencies_required"):
        AutonomousController(action_executor=None).run({}, handler=None, iterations=1)
