from __future__ import annotations

from typing import Any

import pytest

from webpent.models.proof_bundle import build_proof_bundle
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


def test_sealed_target_backed_proof_materializes_causal_edge_and_coverage() -> None:
    task = CampaignTask(
        task_id="next-task",
        engagement_id="eng-1",
        asset_id="asset-1",
        source_evidence_ids=("surface-1",),
        vulnerability_class="idor",
        hypothesis_id="hyp-next",
    )
    bundle = build_proof_bundle(
        engagement_id="eng-1",
        finding_id="finding-1",
        hypothesis_id="hyp-next",
        target_fingerprint="sha256:target-fingerprint",
        evidence=[{"phase": "baseline"}, {"phase": "candidate"}],
        evidence_refs=["proof-ref-1"],
        negative_control={"phase": "negative-control"},
        baseline={"phase": "baseline"},
        request_evidence=[{"method": "GET", "path": "/object/1"}],
        response_evidence=[{"status": 200, "marker": "candidate"}],
        scope_context={"origin": "https://example.invalid"},
        identity_context={"identity": "authorized-test"},
        causal_oracle={
            "requires_target_backed": True,
            "causal_signal": True,
            "negative_control_complete": True,
        },
        target_backed=True,
        negative_control_independent=True,
        validator_id="test-validator",
        validator_version="1",
        replay_metadata={"replayable": True},
        cleanup_status="complete",
    ).seal(actor="test")
    record = {
        "status": "executed",
        "proof_bundle_sealed": True,
        "evidence_refs": ["proof-ref-1"],
        "proof_bundle": bundle.model_dump(mode="json"),
        "causal_next_action_ids": ["next-task"],
        "causal_next_hypothesis_ids": ["hyp-next"],
    }

    edge = AutonomousController._causal_edge_from_record(task, record)
    assert edge is not None
    assert edge["kind"] == "confirmed_finding_leads_to_next_action"
    assert edge["causal_signal"] is True
    assert edge["negative_control_complete"] is True

    ledger = AutonomousController._update_coverage_ledger({}, [task], [record])
    assert ledger["idor"]["attempts"] == 1
    assert ledger["idor"]["proof_confirmed"] is True
    assert ledger["idor"]["proof_bundle_ids"] == [bundle.bundle_id]

    rejected = dict(record)
    rejected["proof_bundle"] = {
        **record["proof_bundle"],
        "negative_control_independent": False,
    }
    assert AutonomousController._causal_edge_from_record(task, rejected) is None


def test_attack_graph_accepts_only_strict_confirmed_causal_edge() -> None:
    from webpent.shared.attack_graph import build_attack_graph

    graph = build_attack_graph(
        findings=[{"id": "finding-1", "title": "finding", "severity": "high"}],
        hypotheses=[{"id": "hyp-next", "title": "next", "priority": "high"}],
        causal_edges=[
            {
                "id": "causal:1",
                "kind": "confirmed_finding_leads_to_next_action",
                "source_id": "finding:finding-1",
                "target_id": "hypothesis:hyp-next",
                "evidence_refs": ["proof-ref-1"],
                "confidence": "target_backed_causal_proof",
                "causal_signal": True,
                "negative_control_complete": True,
                "target_backed": True,
                "proof_bundle_sealed": True,
            }
        ],
    )
    assert any(
        edge["kind"] == "confirmed_finding_leads_to_next_action"
        for edge in graph["edges"]
    )
    assert "proof-ref-1" in graph["edges"][0]["evidence_refs"]

    graph_without_control = build_attack_graph(
        findings=[{"id": "finding-1", "title": "finding", "severity": "high"}],
        hypotheses=[{"id": "hyp-next", "title": "next", "priority": "high"}],
        causal_edges=[
            {
                "kind": "confirmed_finding_leads_to_next_action",
                "source_id": "finding:finding-1",
                "target_id": "hypothesis:hyp-next",
                "evidence_refs": ["proof-ref-1"],
                "causal_signal": True,
                "negative_control_complete": False,
            }
        ],
    )
    assert not any(
        edge["kind"] == "confirmed_finding_leads_to_next_action"
        for edge in graph_without_control["edges"]
    )


def test_controller_consumes_coverage_between_bounded_rounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def make_task(task_id: str, vulnerability_class: str) -> CampaignTask:
        return CampaignTask(
            task_id=task_id,
            engagement_id="eng-coverage",
            asset_id="asset-1",
            source_evidence_ids=(f"e-{task_id}",),
            vulnerability_class=vulnerability_class,
            hypothesis_id=f"hyp-{task_id}",
            expected_information_gain=0.8,
            budget=1.0,
            capability="http_read",
            target_url="https://example.invalid/",
        )

    first_task = make_task("first", "idor")
    second_task = make_task("second", "ssti")
    monkeypatch.setattr(
        "webpent.shared.autonomous_controller.smart_campaigns_node",
        lambda state: {"campaign_plan": {}, "smart_replanning": {}},
    )
    monkeypatch.setattr(
        AutonomousController,
        "_planned_tasks",
        staticmethod(
            lambda state, planning: [
                second_task
                if (state.get("coverage_ledger") or {}).get("idor", {}).get("attempts", 0)
                else first_task
            ]
        ),
    )

    class RecordingExecutor(ActionExecutor):
        def __init__(self) -> None:
            self.lifecycle_events: list[dict[str, Any]] = []
            self.calls: list[str] = []

        def execute(
            self,
            task: CampaignTask,
            handler: Any,
            *,
            preconditions_met: bool = True,
        ) -> dict[str, Any]:
            self.calls.append(task.task_id)
            return {
                "task_id": task.task_id,
                "status": "executed",
                "output_available": True,
                "proof_bundle_sealed": False,
                "evidence_refs": [f"evidence:{task.task_id}"],
            }

    executor = RecordingExecutor()
    result = AutonomousController(action_executor=executor, max_iterations=2).run(
        {"engagement_id": "eng-coverage", "action_budget": {"limit": 5.0}},
        handler=lambda _task: {"ok": True},
        iterations=2,
    )

    assert executor.calls == ["first", "second"]
    assert result["coverage_ledger"]["idor"]["attempts"] == 1
    assert result["coverage_ledger"]["ssti"]["attempts"] == 1
    assert len(result["autonomous_cycle_records"]) == 2


def _ranking_task(
    task_id: str,
    vulnerability_class: str,
    *,
    expected_information_gain: float = 0.8,
) -> CampaignTask:
    return CampaignTask(
        task_id=task_id,
        engagement_id="eng-ranking",
        asset_id="asset-1",
        source_evidence_ids=(f"e-{task_id}",),
        vulnerability_class=vulnerability_class,
        hypothesis_id=f"hyp-{task_id}",
        expected_information_gain=expected_information_gain,
        budget=1.0,
        capability="http_read",
        target_url="https://example.invalid/",
    )


class _RecordingExecutor(ActionExecutor):
    def __init__(self) -> None:
        self.lifecycle_events: list[dict[str, Any]] = []
        self.calls: list[str] = []

    def execute(
        self,
        task: CampaignTask,
        handler: Any,
        *,
        preconditions_met: bool = True,
    ) -> dict[str, Any]:
        self.calls.append(task.task_id)
        return {
            "task_id": task.task_id,
            "engagement_id": task.engagement_id,
            "vulnerability_class": task.vulnerability_class,
            "hypothesis_id": task.hypothesis_id,
            "status": "executed",
            "output_available": True,
            "proof_bundle_sealed": False,
            "evidence_refs": [f"evidence:{task.task_id}"],
        }


def test_causal_edge_changes_next_action(monkeypatch: pytest.MonkeyPatch) -> None:
    first = _ranking_task("first", "idor")
    second = _ranking_task("second", "ssti")
    monkeypatch.setattr(
        "webpent.shared.autonomous_controller.build_smart_campaign_tasks",
        lambda state, max_tasks=10: ([first, second], []),
    )

    def planning(state: dict[str, Any]) -> dict[str, Any]:
        order = ["first", "second"]
        if state.get("causal_edges"):
            order = ["second", "first"]
        return {
            "campaign_plan": {},
            "smart_next_actions": [{"task": {"task_id": item}} for item in order],
            "smart_replanning": {},
        }

    monkeypatch.setattr("webpent.shared.autonomous_controller.smart_campaigns_node", planning)
    baseline_executor = _RecordingExecutor()
    baseline = AutonomousController(action_executor=baseline_executor).run(
        {"engagement_id": "eng-ranking", "action_budget": {"limit": 5.0}},
        handler=lambda _task: {"ok": True},
        iterations=1,
    )
    causal_executor = _RecordingExecutor()
    causal = AutonomousController(action_executor=causal_executor).run(
        {
            "engagement_id": "eng-ranking",
            "action_budget": {"limit": 5.0},
            "causal_edges": [
                {
                    "engagement_id": "eng-ranking",
                    "proof_bundle_sealed": True,
                    "target_backed": True,
                    "evidence_refs": ["proof-ref"],
                    "metadata": {
                        "proof_bundle_sealed": True,
                        "target_backed": True,
                        "target_action_ids": ["second"],
                    },
                }
            ],
        },
        handler=lambda _task: {"ok": True},
        iterations=1,
    )
    assert baseline_executor.calls == ["first"]
    assert causal_executor.calls == ["second"]
    assert baseline["smart_replanning"]["controller_executed"] == 1
    assert causal["smart_replanning"]["controller_executed"] == 1


def test_low_coverage_path_gets_priority_boost(monkeypatch: pytest.MonkeyPatch) -> None:
    low_coverage = _ranking_task("low", "idor", expected_information_gain=0.5)
    higher_base = _ranking_task("base", "ssti", expected_information_gain=0.55)
    monkeypatch.setattr(
        "webpent.shared.autonomous_controller.build_smart_campaign_tasks",
        lambda state, max_tasks=10: ([low_coverage, higher_base], []),
    )
    monkeypatch.setattr(
        "webpent.shared.autonomous_controller.smart_campaigns_node",
        lambda state: {
            "campaign_plan": {},
            "smart_next_actions": [
                {"task": {"task_id": "low"}},
                {"task": {"task_id": "base"}},
            ],
            "smart_replanning": {},
        },
    )
    executor = _RecordingExecutor()
    result = AutonomousController(action_executor=executor).run(
        {
            "engagement_id": "eng-ranking",
            "action_budget": {"limit": 5.0},
            "coverage_ledger": {
                "idor": {"attempts": 0},
                "ssti": {"attempts": 1},
            },
        },
        handler=lambda _task: {"ok": True},
        iterations=1,
    )
    assert executor.calls == ["low"]
    assert result["smart_replanning"]["controller_executed"] == 1
    assert result["smart_replanning"]["controller_trace"][0]["task_id"] == "low"
    assert result["smart_replanning"]["controller_trace"][0]["status"] == "executed"
