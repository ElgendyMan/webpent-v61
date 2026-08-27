import hashlib

from webpent.research_engine.autonomous_scheduler import AutonomousScheduler
from webpent.research_engine.campaign_state import CampaignState
from webpent.research_engine.execution_router import CapabilityAwareRouter
from webpent.research_engine.research_budget import ResearchBudget
from webpent.shared.action_authority import ActionRisk
from webpent.shared.campaign_executor import CampaignTask


def _state(**overrides):
    values = {
        "campaign_id": "campaign-arex-001",
        "target_identity": "controlled-loopback-id-oracle",
        "scope_digest": hashlib.sha256(b"loopback-only").hexdigest(),
        "current_objectives": ("validate controlled authorization behavior",),
    }
    values.update(overrides)
    return CampaignState(**values)


def _task(**overrides):
    values = {
        "task_id": "task-001",
        "engagement_id": "engagement-arex-001",
        "asset_id": "controlled-id-oracle",
        "source_evidence_ids": ("evidence:source",),
        "vulnerability_class": "idor",
        "hypothesis_id": "hypothesis-001",
        "expected_information_gain": 0.6,
        "risk_tier": ActionRisk.READ_ONLY,
        "target_url": "http://127.0.0.1:18080/controlled/resource/1",
    }
    values.update(overrides)
    return CampaignTask(**values)


def _choose(scheduler, tasks, **overrides):
    values = {
        "available_capabilities": {"http_read"},
        "scope_authorized": True,
        "authority_available": True,
    }
    values.update(overrides)
    return scheduler.choose(tasks, **values)


def test_router_allows_only_loopback_read_only_observation():
    router = CapabilityAwareRouter()
    decision = router.route(
        _task(),
        available_capabilities={"http_read"},
        scope_authorized=True,
        authority_available=True,
    )

    assert decision.allowed is True
    assert decision.route == "observation"


def test_router_blocks_external_mutating_body_and_forbidden_capabilities():
    router = CapabilityAwareRouter()
    cases = (
        (_task(target_url="https://example.test/resource"), "target_origin_not_loopback"),
        (_task(method="POST"), "method_not_read_only"),
        (_task(body_schema="json"), "request_body_not_allowed"),
        (_task(capability="credential_use"), "capability_forbidden"),
        (_task(risk_tier=ActionRisk.ACTIVE), "risk_tier_not_bounded"),
    )

    for task, reason in cases:
        decision = router.route(
            task,
            available_capabilities={"http_read", "credential_use"},
            scope_authorized=True,
            authority_available=True,
        )
        assert decision.status == "blocked"
        assert reason in decision.reasons
        assert decision.route == "none"


def test_router_blocks_missing_scope_authority_and_capability():
    decision = CapabilityAwareRouter().route(
        _task(),
        available_capabilities=set(),
        scope_authorized=False,
        authority_available=False,
    )

    assert decision.status == "blocked"
    assert set(decision.reasons) == {
        "scope_not_authorized",
        "action_authority_unavailable",
        "capability_unavailable",
    }


def test_scheduler_selects_highest_gain_routable_task():
    scheduler = AutonomousScheduler(_state())
    low = _task(task_id="low", expected_information_gain=0.1)
    high = _task(task_id="high", expected_information_gain=0.8)

    decision, planned, route = _choose(scheduler, [low, high])

    assert decision.status == "selected"
    assert planned is not None and planned.task.task_id == "high"
    assert route is not None and route.route == "observation"


def test_scheduler_penalizes_duplicate_idempotency_and_prefers_new_path():
    scheduler = AutonomousScheduler(_state())
    duplicate = _task(
        task_id="duplicate", idempotency_key="same-key", expected_information_gain=0.8
    )
    fresh = _task(task_id="fresh", idempotency_key="fresh-key", expected_information_gain=0.7)

    decision, planned, _ = _choose(scheduler, [duplicate, fresh], attempted_keys=("same-key",))

    assert decision.status == "selected"
    assert planned is not None and planned.task.task_id == "fresh"
    assert "duplication_penalty" not in planned.reasons

    duplicate_plan = scheduler.scorer.score(duplicate, attempted_keys=("same-key",))
    assert "duplication_penalty" in duplicate_plan.reasons


def test_scheduler_returns_explicit_blocked_for_unavailable_capability():
    scheduler = AutonomousScheduler(_state())

    decision, planned, route = _choose(
        scheduler,
        [_task()],
        available_capabilities={"offline_analysis"},
    )

    assert decision.status == "blocked"
    assert decision.task_id == "task-001"
    assert planned is None
    assert route is not None and "capability_unavailable" in route.reasons


def test_scheduler_returns_blocked_for_unmet_dependencies_then_selects_after_completion():
    dependent = _task(task_id="dependent", metadata={"dependencies": ["dependency"]})
    scheduler = AutonomousScheduler(_state())

    blocked, planned, _ = _choose(scheduler, [dependent])
    assert blocked.status == "blocked"
    assert "dependencies_unmet:dependency" in blocked.reasons
    assert planned is None

    scheduler.record_task_outcome("dependency", "completed")
    selected, planned, _ = _choose(scheduler, [dependent])
    assert selected.status == "selected"
    assert planned is not None and planned.task.task_id == "dependent"


def test_scheduler_skips_completed_failed_and_blocked_tasks():
    state = _state(
        completed_tasks=("completed",),
        failed_tasks=("failed",),
        blocked_tasks=("blocked",),
    )
    scheduler = AutonomousScheduler(state)
    tasks = [
        _task(task_id="completed"),
        _task(task_id="failed"),
        _task(task_id="blocked"),
        _task(task_id="available"),
    ]

    decision, planned, _ = _choose(scheduler, tasks)

    assert decision.status == "selected"
    assert planned is not None and planned.task.task_id == "available"


def test_scheduler_stops_on_step_and_research_budgets():
    step_limited = AutonomousScheduler(_state(), max_steps=0)
    decision, _, _ = _choose(step_limited, [_task()])
    assert decision.status == "stopped"
    assert decision.reasons == ("step_budget_exhausted",)

    budget_state = _state(research_budget=ResearchBudget(max_requests=1))
    budget_limited = AutonomousScheduler(budget_state)
    first, _, _ = _choose(budget_limited, [_task(task_id="first")])
    assert first.status == "selected"
    budget_limited.record_task_outcome("first", "completed")
    second, _, _ = _choose(budget_limited, [_task(task_id="second")])
    assert second.status == "stopped"
    assert second.reasons == ("research_budget_exhausted",)


def test_record_task_outcome_updates_bucket_evidence_and_lineage():
    scheduler = AutonomousScheduler(_state())
    before = scheduler.state

    after = scheduler.record_task_outcome(
        "task-001",
        "completed",
        evidence_summary={"proof_ref": "proof://sealed/redacted"},
    )

    assert "task-001" in after.completed_tasks
    assert after.evidence_summary["proof_ref"] == "proof://sealed/redacted"
    assert after.lineage.sequence == before.lineage.sequence + 2
    assert after.lineage.parent_snapshot_digest
    assert scheduler.state.snapshot_digest() == after.snapshot_digest()


def test_record_task_outcome_rejects_unknown_status():
    scheduler = AutonomousScheduler(_state())

    try:
        scheduler.record_task_outcome("task-001", "executed")
    except ValueError as exc:
        assert str(exc) == "invalid_campaign_task_status"
    else:
        raise AssertionError("invalid status was accepted")


def test_scope_and_authority_block_prevent_scheduler_selection():
    scheduler = AutonomousScheduler(_state())
    decision, planned, route = _choose(
        scheduler,
        [_task()],
        scope_authorized=False,
        authority_available=False,
    )

    assert decision.status == "blocked"
    assert planned is None
    assert route is not None
    assert "scope_not_authorized" in decision.reasons
    assert "action_authority_unavailable" in decision.reasons


def test_scheduler_is_bounded_to_one_selection_per_call():
    scheduler = AutonomousScheduler(_state())
    tasks = [_task(task_id="a"), _task(task_id="b")]

    first, planned, _ = _choose(scheduler, tasks)
    second, planned_again, _ = _choose(scheduler, tasks)

    assert first.status == "selected"
    assert second.status == "selected"
    assert planned is not None and planned_again is not None
    assert scheduler.steps == 2
    assert planned.task.task_id == planned_again.task.task_id


__all__ = []


# Keep an unused local dependency fixture explicit for readability in dependency tests.
assert _task(task_id="dependency").task_id == "dependency"


def test_router_rejects_ambiguous_localhost_origin():
    decision = CapabilityAwareRouter().route(
        _task(target_url="http://localhost:18080/controlled/resource/1"),
        available_capabilities={"http_read"},
        scope_authorized=True,
        authority_available=True,
    )

    assert decision.status == "blocked"
    assert "target_origin_not_loopback" in decision.reasons
    assert decision.route == "none"
