from __future__ import annotations

from webpent.research.decision_loop import (
    DecisionLoopContext,
    DecisionLoopStatus,
    decide_next_step,
)
from webpent.research.planner import ResearchQueue
from webpent.research_engine.research_state import ResearchTask


def _task(task_id: str, priority: float, operation: str = "validate") -> ResearchTask:
    return ResearchTask(
        task_id=task_id,
        engagement_id="eng:decision",
        target_id="target:recorded",
        objective="Validate a recorded hypothesis",
        reason="explicit recorded evidence",
        priority=priority,
        expected_information_gain=priority,
        cost=0.1,
        required_capability="http_read",
        required_evidence=("oracle", "negative_control", "replay"),
        operation=operation,
    )


def test_selects_highest_utility_unattempted_validation_proposal():
    queue = ResearchQueue((_task("low", 0.2), _task("high", 0.9)))
    result = decide_next_step(
        queue,
        DecisionLoopContext(scope_verified=True, remaining_budget=2),
    )
    assert result.status is DecisionLoopStatus.CONTINUE
    assert result.stage == "validate"
    assert result.selected_task_id == "high"
    assert result.execution_allowed is False
    assert result.mutation_allowed is False
    assert result.qualification_effect is False


def test_skips_attempted_and_non_validation_tasks():
    queue = ResearchQueue(
        (_task("done", 1.0), _task("observe", 0.8, "observe"), _task("next", 0.4))
    )
    result = decide_next_step(
        queue,
        DecisionLoopContext(
            scope_verified=True,
            remaining_budget=1,
            attempted_task_ids=frozenset({"done"}),
        ),
    )
    assert result.status is DecisionLoopStatus.CONTINUE
    assert result.selected_task_id == "next"
    assert result.admissible_count == 1


def test_replans_before_more_validation_when_evidence_is_incomplete():
    queue = ResearchQueue((_task("candidate", 0.8),))
    result = decide_next_step(
        queue,
        DecisionLoopContext(
            scope_verified=True,
            remaining_budget=1,
            available_evidence=frozenset({"oracle"}),
            required_evidence=frozenset({"oracle", "negative_control", "replay"}),
        ),
    )
    assert result.status is DecisionLoopStatus.REPLAN
    assert result.stage == "evidence"
    assert result.selected_task_id is None
    assert result.missing_evidence == ("negative_control", "replay")


def test_replans_for_negative_control_then_replay():
    queue = ResearchQueue((_task("candidate", 0.8),))
    no_control = decide_next_step(
        queue,
        DecisionLoopContext(
            scope_verified=True,
            remaining_budget=1,
            available_evidence=frozenset({"oracle"}),
            required_evidence=frozenset({"oracle"}),
        ),
    )
    assert no_control.status is DecisionLoopStatus.REPLAN
    assert "independent_negative_control_required" in no_control.rationale

    no_replay = decide_next_step(
        queue,
        DecisionLoopContext(
            scope_verified=True,
            remaining_budget=1,
            available_evidence=frozenset({"oracle"}),
            required_evidence=frozenset({"oracle"}),
            negative_control_complete=True,
        ),
    )
    assert no_replay.status is DecisionLoopStatus.REPLAN
    assert no_replay.stage == "replay"


def test_scope_policy_and_budget_fail_closed():
    queue = ResearchQueue((_task("candidate", 0.8),))
    blocked = decide_next_step(queue, DecisionLoopContext(remaining_budget=1))
    assert blocked.status is DecisionLoopStatus.BLOCKED
    assert blocked.stage == "stop"

    policy_blocked = decide_next_step(
        queue,
        DecisionLoopContext(scope_verified=True, policy_allows_proposal=False, remaining_budget=1),
    )
    assert policy_blocked.status is DecisionLoopStatus.BLOCKED

    stopped = decide_next_step(
        queue,
        DecisionLoopContext(scope_verified=True, remaining_budget=0),
    )
    assert stopped.status is DecisionLoopStatus.STOP
    assert stopped.selected_task_id is None


def test_bounded_steps_stop_without_authority():
    queue = ResearchQueue((_task("candidate", 0.8),))
    result = decide_next_step(
        queue,
        DecisionLoopContext(
            scope_verified=True,
            remaining_budget=1,
            max_steps=1,
            completed_steps=1,
        ),
    )
    assert result.status is DecisionLoopStatus.STOP
    assert result.rationale[0] == "bounded_step_limit_reached"
    assert result.execution_allowed is False
