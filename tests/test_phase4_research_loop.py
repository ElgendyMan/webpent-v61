from __future__ import annotations

from webpent.graph.builder import (
    NODE_ACTIVE_RESEARCH,
    NODE_AUTONOMOUS_CONTROLLER,
    NODE_CAUSAL_RESEARCH,
    NODE_KNOWLEDGE_GAP,
    NODE_RECOVERY,
    NODE_SMART_CAMPAIGNS,
    NODE_STRATEGIST,
    route_after_active_research,
    route_after_autonomous_controller,
    route_after_causal_research,
    route_after_research_session,
    route_after_smart_campaigns_execution,
)


def test_research_route_replans_only_within_bounded_rounds() -> None:
    state = {
        "enable_autonomous_controller": False,
        "smart_replanning": {
            "replan_requested": True,
            "round": 1,
            "max_replan_rounds": 3,
        },
    }

    assert route_after_smart_campaigns_execution(state) == NODE_SMART_CAMPAIGNS


def test_research_route_stops_when_round_budget_is_exhausted() -> None:
    state = {
        "enable_autonomous_controller": False,
        "smart_replanning": {
            "replan_requested": True,
            "round": 3,
            "max_replan_rounds": 3,
        },
    }

    assert route_after_smart_campaigns_execution(state) == NODE_STRATEGIST


def test_research_route_stops_without_observation_request() -> None:
    state = {
        "enable_autonomous_controller": False,
        "smart_replanning": {
            "replan_requested": False,
            "round": 1,
            "max_replan_rounds": 3,
        },
    }

    assert route_after_smart_campaigns_execution(state) == NODE_STRATEGIST


def test_controller_route_remains_explicitly_opt_in() -> None:
    state = {
        "enable_autonomous_controller": True,
        "smart_replanning": {
            "replan_requested": True,
            "round": 1,
            "max_replan_rounds": 3,
        },
    }

    assert route_after_smart_campaigns_execution(state) == NODE_AUTONOMOUS_CONTROLLER


def _candidate(action_id: str = "research-1") -> dict[str, str]:
    return {
        "action_id": action_id,
        "target_ref": "https://example.invalid/read-only",
        "objective": "collect bounded response metadata",
        "method": "GET",
        "capability": "http_read",
        "action_class": "observation",
        "idempotency_key": f"idempotency:{action_id}",
        "tenant_context": "tenant:test",
    }


def test_controller_route_enters_recovery_for_retryable_infrastructure_failure() -> None:
    state = {
        "autonomous_controller_runs": 1,
        "smart_replanning": {
            "controller_executed": True,
            "max_replan_rounds": 3,
        },
        "recovery_state": {"attempts": 0, "max_attempts": 2, "status": "retry_ready"},
        "recovery_events": [
            {
                "failure_class": "infrastructure_failure",
                "retry_allowed": True,
                "status": "retry_ready",
            }
        ],
    }

    assert route_after_autonomous_controller(state) == NODE_RECOVERY


def test_controller_route_enters_knowledge_gap_for_unattempted_research() -> None:
    state = {
        "autonomous_controller_runs": 1,
        "smart_next_actions": [],
        "smart_replanning": {
            "controller_executed": True,
            "max_replan_rounds": 3,
        },
        "research_candidate_actions": [_candidate()],
    }

    assert route_after_autonomous_controller(state) == NODE_KNOWLEDGE_GAP


def test_controller_route_stops_at_controller_budget() -> None:
    state = {
        "autonomous_controller_runs": 3,
        "smart_replanning": {
            "controller_executed": True,
            "max_replan_rounds": 3,
        },
        "research_candidate_actions": [_candidate()],
    }

    assert route_after_autonomous_controller(state) == NODE_STRATEGIST


def test_research_session_requires_valid_candidate_and_budget() -> None:
    state = {
        "autonomous_controller_runs": 0,
        "smart_replanning": {"max_replan_rounds": 1},
        "research_candidate_actions": [_candidate()],
    }
    assert route_after_research_session(state) == NODE_ACTIVE_RESEARCH

    state["autonomous_controller_runs"] = 1
    assert route_after_research_session(state) == NODE_STRATEGIST


def test_active_research_requires_observation_before_causal_projection() -> None:
    assert route_after_active_research({}) == NODE_STRATEGIST
    assert (
        route_after_active_research({"research_active_observations": [{"status": "observed"}]})
        == NODE_CAUSAL_RESEARCH
    )


def test_causal_research_reenters_controller_only_with_remaining_candidate() -> None:
    state = {
        "autonomous_controller_runs": 0,
        "smart_replanning": {"max_replan_rounds": 2},
        "research_candidate_actions": [_candidate("research-2")],
    }
    assert route_after_causal_research(state) == NODE_AUTONOMOUS_CONTROLLER

    state["autonomous_controller_runs"] = 2
    assert route_after_causal_research(state) == NODE_STRATEGIST
