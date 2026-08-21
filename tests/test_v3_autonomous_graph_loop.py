"""Contracts for the graph-owned bounded autonomous controller loop."""

from webpent.graph.builder import (
    NODE_AUTONOMOUS_CONTROLLER,
    NODE_SMART_CAMPAIGNS,
    NODE_STRATEGIST,
    route_after_autonomous_controller,
    route_after_smart_campaigns_execution,
)


def _state(**updates: object) -> dict[str, object]:
    state: dict[str, object] = {
        "enable_autonomous_controller": True,
        "autonomous_controller_runs": 0,
        "smart_next_actions": [],
        "smart_replanning": {
            "max_replan_rounds": 3,
            "controller_executed": False,
        },
    }
    state.update(updates)
    return state


def test_smart_execution_enters_controller_only_with_budget() -> None:
    assert route_after_smart_campaigns_execution(_state()) == NODE_AUTONOMOUS_CONTROLLER
    assert (
        route_after_smart_campaigns_execution(
            _state(autonomous_controller_runs=3)
        )
        == NODE_STRATEGIST
    )


def test_controller_replans_only_after_useful_bounded_work() -> None:
    assert route_after_autonomous_controller(_state()) == NODE_STRATEGIST
    assert (
        route_after_autonomous_controller(
            _state(
                autonomous_controller_runs=1,
                smart_next_actions=[{"action_id": "next"}],
                smart_replanning={
                    "max_replan_rounds": 3,
                    "controller_executed": True,
                },
            )
        )
        == NODE_SMART_CAMPAIGNS
    )
    assert (
        route_after_autonomous_controller(
            _state(
                autonomous_controller_runs=3,
                smart_next_actions=[{"action_id": "next"}],
                smart_replanning={
                    "max_replan_rounds": 3,
                    "controller_executed": True,
                },
            )
        )
        == NODE_STRATEGIST
    )
