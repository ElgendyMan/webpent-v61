from __future__ import annotations

from types import SimpleNamespace

from webpent.shared.action_authority import ActionAuthority
from webpent.shared.autonomous_controller import AutonomousController
from webpent.shared.campaign_executor import ActionExecutor


def _state() -> dict:
    return {
        "smart_mode": True,
        "scan_mode": "safe-smart",
        "engagement_id": "engagement:test-controller",
        "target": {"url": "http://example.test"},
        "campaign_plan": {
            "entries": [
                {
                    "key": "sqli",
                    "matched_observation_refs": ["surface:0"],
                    "contract": {"method": "GET", "oracle": "status_compare"},
                }
            ]
        },
        "crawled_data": {
            "surface_records": [
                {"url": "http://example.test/item", "ref": "surface:0"}
            ]
        },
        "findings": [],
        "hypotheses": [],
        "campaign_task_outcomes": [],
        "research_decision_trace": [],
    }


def test_controller_safe_stops_without_injected_handler() -> None:
    result = AutonomousController().run(_state())

    assert result["smart_replanning"]["status"] == "controller_safe_stopped"
    assert result["smart_replanning"]["controller_trace"][0]["status"] == "safe_stopped"
    assert result["smart_replanning"]["controller_trace"][0]["planned_count"] >= 1


def test_controller_executes_only_through_action_executor() -> None:
    authority = ActionAuthority(
        settings=SimpleNamespace(
            scan_mode="safe-smart",
            smart_auto_approve=False,
            smart_action_budget=10.0,
            smart_max_actions=3,
            smart_require_idempotency=True,
        ),
        allowed_origin="http://example.test",
        manifest={"capabilities": {"http_read": {"available": True}}},
    )
    executor = ActionExecutor(authority)
    calls: list[str] = []

    def handler(task):
        calls.append(task.task_id)
        return {
            "finding_id": "finding:test-controller",
            "proof_evidence": [{"kind": "response", "status_code": 200}],
            "evidence_refs": ["surface:0"],
            "negative_control": {"status": "completed", "matched": False},
        }

    result = AutonomousController(action_executor=executor, max_iterations=2).run(
        _state(), handler=handler, iterations=1
    )

    assert len(calls) == 1
    assert result["smart_replanning"]["status"] == "controller_completed"
    assert result["campaign_task_outcomes"][0]["status"] == "executed"
    assert result["campaign_task_outcomes"][0]["proof_bundle_sealed"] is True
    assert result["lifecycle_events"]


def test_controller_does_not_execute_when_action_executor_is_missing() -> None:
    calls: list[str] = []

    result = AutonomousController().run(_state(), handler=lambda task: calls.append(task.task_id))

    assert calls == []
    assert result["smart_replanning"]["status"] == "controller_safe_stopped"
