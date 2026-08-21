import inspect
from types import SimpleNamespace

from typer.testing import CliRunner

from webpent.cli import app, scan
from webpent.models.goal_tree import (
    GoalTree,
    GoalType,
    count_goal_nodes,
    create_rabbit_hole_branch_goal,
    create_root_goal,
    curiosity_budget_consumed,
    find_root_goal_id,
    increment_budget_consumed,
)
from webpent.shared.action_authority import ActionAuthority
from webpent.shared.autonomous_controller import AutonomousController
from webpent.shared.campaign_executor import ActionExecutor


def _tree_state() -> dict:
    root = create_root_goal(label="engagement_root")
    branch = create_rabbit_hole_branch_goal(
        parent_id=root.id,
        label="rabbit_hole:backup",
        branch_depth=0,
        budget_remaining=2,
    )
    tree = GoalTree(nodes={root.id: root, branch.id: branch})
    return tree.to_dict_for_state(), root.id, branch.id


def test_goaltree_is_canonical_for_root_branch_count_and_budget() -> None:
    state, root_id, branch_id = _tree_state()
    assert find_root_goal_id(state) == root_id
    assert count_goal_nodes(state, GoalType.RABBIT_HOLE_BRANCH) == 1
    assert curiosity_budget_consumed(state) == 0.0

    update = increment_budget_consumed(state, branch_id, delta=1)
    merged = {"nodes": {**state["nodes"], **update["nodes"]}}
    assert curiosity_budget_consumed(merged) == 1.0


def test_controller_stops_when_no_new_evidence_or_state_delta() -> None:
    state = {
        "smart_mode": True,
        "scan_mode": "safe-smart",
        "engagement_id": "engagement:convergence",
        "target": {"url": "http://example.test"},
        "campaign_plan": {
            "entries": [
                {
                    "key": "sqli",
                    "matched_observation_refs": ["surface:0"],
                    "contract": {
                        "method": "GET",
                        "oracle": "status_compare",
                        "preconditions": ["surface observed"],
                        "observed_preconditions": ["surface observed"],
                    },
                }
            ]
        },
        "crawled_data": {"surface_records": [{"url": "http://example.test/item"}]},
        "findings": [],
        "hypotheses": [],
        "campaign_task_outcomes": [],
        "research_decision_trace": [],
        "observed_preconditions": ["surface observed"],
    }
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
    result = AutonomousController(
        action_executor=ActionExecutor(authority), max_iterations=3
    ).run(
        state,
        handler=lambda _task: {"metadata": {"status": "unchanged"}},
        iterations=3,
    )
    assert result["smart_replanning"]["stop_reason"] == "same_action_repeated"
    assert result["smart_replanning"]["controller_trace"][-1]["result"] == "same_action_repeated"


def test_scan_threads_named_identity_profiles_into_initial_state() -> None:
    source = inspect.getsource(scan)
    assert "identity_profiles=identity_profiles" in source
    assert "identity_profiles={}," not in source


def test_status_command_exposes_effective_smart_profile() -> None:
    result = CliRunner().invoke(app, ["status", "--profile", "smart"])
    assert result.exit_code == 0
    assert "Composition profile" in result.stdout
    assert "safe-smart" in result.stdout
    assert "Capability Readiness" in result.stdout


def test_status_command_rejects_unknown_profile() -> None:
    result = CliRunner().invoke(app, ["status", "--profile", "not-a-profile"])
    assert result.exit_code == 2
    assert "unsupported scan profile" in result.output.lower()
