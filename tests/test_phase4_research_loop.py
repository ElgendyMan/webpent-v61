from __future__ import annotations

from webpent.graph.builder import (
    NODE_SMART_CAMPAIGNS,
    NODE_STRATEGIST,
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

    assert route_after_smart_campaigns_execution(state) == "autonomous_controller"
