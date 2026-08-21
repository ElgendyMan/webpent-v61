from __future__ import annotations

import threading

import webpent.shared.autonomous_controller as controller_module
from webpent.shared.autonomous_controller import AutonomousController
from webpent.shared.campaign_executor import CampaignTask


class _FakeExecutor:
    def __init__(self) -> None:
        self.lifecycle_events: list[dict[str, object]] = []
        self.calls: list[str] = []
        self._lock = threading.Lock()

    def execute(self, task, handler, *, preconditions_met=True):
        with self._lock:
            self.calls.append(task.task_id)
            self.lifecycle_events.append({"task_id": task.task_id, "stage": "completed"})
        handler(task)
        return {
            "task_id": task.task_id,
            "status": "executed",
            "reason": "executed",
            "output_available": True,
            "proof_bundle_sealed": False,
        }


def _task(task_id: str, *, parent_task_id: str = "") -> CampaignTask:
    return CampaignTask(
        task_id=task_id,
        engagement_id="engagement-1",
        asset_id=f"asset-{task_id}",
        source_evidence_ids=(),
        vulnerability_class="idor",
        hypothesis_id=f"hypothesis-{task_id}",
        expected_information_gain=0.8,
        idempotency_key=f"key-{task_id}",
        parent_task_id=parent_task_id,
        target_url="https://target.test/profile",
    )


def test_parallel_controller_is_explicit_bounded_and_state_safe(monkeypatch) -> None:
    tasks = [_task("task-a"), _task("task-b"), _task("task-c")]
    executor = _FakeExecutor()
    handled: list[str] = []

    def fake_planner(_state):
        return {
            "campaign_plan": {"tasks": [task.as_dict() for task in tasks]},
            "smart_next_actions": [{"task": task.as_dict()} for task in tasks],
            "smart_replanning": {},
            "capability_manifest": {"capabilities": {}},
        }

    monkeypatch.setattr(controller_module, "smart_campaigns_node", fake_planner)
    monkeypatch.setattr(
        controller_module,
        "build_smart_campaign_tasks",
        lambda _state, max_tasks: (tasks[:max_tasks], []),
    )

    result = AutonomousController(action_executor=executor, max_iterations=1).run(
        {
            "engagement_id": "engagement-1",
            "parallel_execution": {"enabled": True, "max_workers": 2},
        },
        handler=lambda task: handled.append(task.task_id),
    )

    assert len(executor.calls) == 2
    assert set(executor.calls) == {"task-a", "task-b"}
    assert set(handled) == {"task-a", "task-b"}
    assert [item["task_id"] for item in result["campaign_task_outcomes"]] == [
        "task-a",
        "task-b",
    ]
    trace = result["smart_replanning"]["controller_trace"]
    assert len(trace) == 2
    assert all(item["parallel_batch"] is True for item in trace)
    assert all(item["parallel_workers"] == 2 for item in trace)
    assert result["smart_replanning"]["controller_executed"] == 2


def test_parallel_selector_rejects_stateful_or_dependent_tasks() -> None:
    selected = AutonomousController._select_independent_tasks(
        [_task("read-a"), _task("write-a", parent_task_id="read-a"), _task("read-b")],
        8,
    )

    assert [task.task_id for task in selected] == ["read-a", "read-b"]
