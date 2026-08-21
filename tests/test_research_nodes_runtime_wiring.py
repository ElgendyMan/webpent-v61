from webpent.models.targets import Target
from webpent.shared.research_nodes import next_best_action_node
from webpent.state.initial_state import build_initial_state


def test_next_best_action_uses_runtime_injected_ranker(monkeypatch) -> None:
    state = build_initial_state(
        Target(url="https://target.test"),
        engagement_id="eng-research-nodes",
        campaign_id="campaign-research-nodes",
        auto_approve=True,
        enable_control_plane=True,
    )
    state["smart_information_actions"] = [
        {
            "action_id": "action:owner-context",
            "action_class": "identity_acquisition",
            "objective": "acquire owner context",
            "target_ref": "https://target.test/profile/1",
            "expected_information_gain": 0.8,
            "cost": 1.0,
            "failure_probability": 0.0,
            "scope_risk": 0.0,
            "rate_limit_cost": 0.0,
            "dependency_penalty": 0.0,
            "capability": "http_read",
        }
    ]

    class ForbiddenEngineConstruction:
        def __init__(self) -> None:
            raise AssertionError("research node must use runtime-injected ranker")

    monkeypatch.setattr(
        "webpent.shared.research_nodes.SmartNextBestActionEngine",
        ForbiddenEngineConstruction,
    )

    result = next_best_action_node(state)
    assert result["smart_next_actions"]
    assert result["research_candidate_actions"]
