from __future__ import annotations

import webpent.shared.autonomous_controller as controller_module
from webpent.graph.builder import (
    NODE_AUTONOMOUS_CONTROLLER,
    NODE_RECOVERY,
    NODE_STRATEGIST,
    recovery_node,
    route_after_autonomous_controller,
    route_after_recovery,
)
from webpent.models.research import CandidateAction
from webpent.shared.autonomous_controller import AutonomousController
from webpent.shared.campaign_executor import CampaignTask


class _RecoveryExecutor:
    def __init__(self, *, fail_attempts: int) -> None:
        self.fail_attempts = fail_attempts
        self.calls: list[str] = []
        self.lifecycle_events: list[dict[str, object]] = []

    def execute(self, task, handler, *, preconditions_met=True):
        self.calls.append(task.task_id)
        self.lifecycle_events.append({"task_id": task.task_id, "stage": "planned"})
        if len(self.calls) <= self.fail_attempts:
            return {
                "task_id": task.task_id,
                "status": "infrastructure_failure",
                "reason": "simulated_timeout",
                "error_type": "TimeoutError",
                "output_available": False,
                "proof_bundle_sealed": False,
            }
        handler(task)
        return {
            "task_id": task.task_id,
            "status": "executed",
            "reason": "executed",
            "output_available": True,
            "proof_bundle_sealed": False,
        }


def _task(task_id: str) -> CampaignTask:
    return CampaignTask(
        task_id=task_id,
        engagement_id="engagement-recovery",
        asset_id="asset-1",
        source_evidence_ids=(),
        vulnerability_class="idor",
        hypothesis_id="hypothesis-1",
        expected_information_gain=0.9,
        idempotency_key=f"recovery-{task_id}",
        target_url="https://target.test/profile",
    )


def _patch_planner(monkeypatch, task: CampaignTask) -> None:
    monkeypatch.setattr(
        controller_module,
        "smart_campaigns_node",
        lambda _state: {
            "campaign_plan": {"tasks": [task.as_dict()]},
            "smart_next_actions": [{"task": task.as_dict()}],
            "smart_replanning": {},
            "capability_manifest": {"capabilities": {}},
        },
    )
    monkeypatch.setattr(
        controller_module,
        "build_smart_campaign_tasks",
        lambda _state, max_tasks: ([_task(task.task_id)][:max_tasks], []),
    )


def test_recovery_replans_once_and_completes(monkeypatch) -> None:
    task = _task("timeout-task")
    executor = _RecoveryExecutor(fail_attempts=1)
    _patch_planner(monkeypatch, task)
    result = AutonomousController(action_executor=executor, max_iterations=3).run(
        {
            "engagement_id": task.engagement_id,
            "recovery_state": {"attempts": 0, "max_attempts": 2},
        },
        handler=lambda _task: None,
        iterations=3,
    )

    assert executor.calls == [task.task_id, task.task_id]
    assert [item["status"] for item in result["campaign_task_outcomes"]] == [
        "infrastructure_failure",
        "executed",
    ]
    event = result["recovery_events"][0]
    assert event["failure_class"] == "infrastructure_failure"
    assert event["status"] == "replan_requested"
    assert event["retry_allowed"] is True
    assert result["recovery_state"]["status"] == "completed"
    assert result["recovery_state"]["attempts"] == 1


def _candidate() -> dict[str, object]:
    return CandidateAction(
        action_id="action-retry",
        action_class="read_only",
        objective="retry a bounded read-only action",
        hypothesis_id="hypothesis-retry",
        target_ref="https://target.test/profile",
        idempotency_key="retry-fingerprint",
    ).model_dump(mode="json")


def test_graph_recovery_route_is_bounded_and_pure() -> None:
    state = {
        "research_candidate_actions": [_candidate()],
        "autonomous_controller_runs": 1,
        "smart_replanning": {"max_replan_rounds": 3},
        "recovery_state": {
            "status": "replanning",
            "attempts": 1,
            "max_attempts": 2,
        },
        "recovery_events": [
            {
                "failure_class": "infrastructure_failure",
                "status": "replan_requested",
                "retry_allowed": True,
            }
        ],
    }

    assert route_after_autonomous_controller(state) == NODE_RECOVERY
    next_state = recovery_node(state)
    assert next_state["recovery_state"]["status"] == "retry_ready"
    assert route_after_recovery({**state, **next_state}) == NODE_AUTONOMOUS_CONTROLLER

    exhausted = {
        **state,
        "recovery_state": {**state["recovery_state"], "attempts": 2},
    }
    assert route_after_recovery(exhausted) == NODE_STRATEGIST


def test_graph_recovery_rejects_policy_denial() -> None:
    state = {
        "research_candidate_actions": [_candidate()],
        "autonomous_controller_runs": 1,
        "smart_replanning": {"max_replan_rounds": 3},
        "recovery_state": {"status": "not_started", "attempts": 0, "max_attempts": 2},
        "recovery_events": [
            {
                "failure_class": "policy_denied",
                "status": "replan_requested",
                "retry_allowed": True,
            }
        ],
    }

    assert route_after_autonomous_controller(state) != NODE_RECOVERY


def test_recovery_budget_is_fail_closed(monkeypatch) -> None:
    task = _task("always-timeout")
    executor = _RecoveryExecutor(fail_attempts=10)
    _patch_planner(monkeypatch, task)
    result = AutonomousController(action_executor=executor, max_iterations=3).run(
        {
            "engagement_id": task.engagement_id,
            "recovery_state": {"attempts": 0, "max_attempts": 1},
        },
        handler=lambda _task: None,
        iterations=3,
    )

    assert executor.calls == [task.task_id, task.task_id]
    assert result["recovery_state"]["status"] == "exhausted"
    assert result["recovery_state"]["attempts"] == 1
    assert result["smart_replanning"]["stop_reason"] == "recovery_budget_exhausted"
    assert result["recovery_events"][0]["retry_allowed"] is True
