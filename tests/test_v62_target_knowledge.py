from __future__ import annotations

from webpent.agents.target_understanding.agent import target_understanding_node
from webpent.knowledge.builder import KnowledgeBuilder
from webpent.knowledge.target_knowledge import TargetKnowledgeModel
from webpent.models.targets import Target


def _target() -> Target:
    return Target(url="http://lab.local", in_scope_regex=[r"lab\.local"])


def test_builder_returns_valid_model_from_empty_state() -> None:
    model = KnowledgeBuilder.from_state({}).build()

    assert isinstance(model, TargetKnowledgeModel)
    assert model.engagement_id == "unscoped"
    assert model.nodes == {}
    assert model.edges == []
    assert model.to_dict()["engagement_id"] == "unscoped"


def test_builder_preserves_engagement_scope() -> None:
    model = KnowledgeBuilder.from_state({"engagement_id": "engagement-a"}).build()

    assert model.engagement_id == "engagement-a"
    assert KnowledgeBuilder.from_state({"engagement_id": "engagement-b"}).build().engagement_id == (
        "engagement-b"
    )


def test_builder_fails_closed_for_missing_or_malformed_state() -> None:
    empty_model = KnowledgeBuilder.from_state(None).build()
    malformed_model = KnowledgeBuilder.from_state({"mental_model": "not-a-dict"}).build()

    assert empty_model.engagement_id == "unscoped"
    assert malformed_model.engagement_id == "unscoped"
    assert malformed_model.nodes == {}
    assert malformed_model.edges == []


def test_target_understanding_returns_target_knowledge_projection() -> None:
    result = target_understanding_node(
        {
            "target": _target(),
            "engagement_id": "waptlab-main",
            "crawled_data": {"endpoints": ["http://lab.local/login"]},
        }  # type: ignore[arg-type]
    )

    projection = result["target_knowledge"]
    assert projection["engagement_id"] == "waptlab-main"
    assert projection["schema_version"] == 1
    assert any(node["kind"] == "endpoint" for node in projection["nodes"].values())

    brain = result["target_brain"]
    assert brain["engagement_id"] == "waptlab-main"
    assert brain["endpoint_count"] == 1
    assert brain["coverage_gaps"] == [
        "no_authorization_profiles",
        "no_workflow_observations",
        "no_data_flow_observations",
    ]
    assert brain["knowledge"]["engagement_id"] == "waptlab-main"
    assert "finding" not in repr(brain)


def test_target_understanding_target_brain_fails_closed_for_malformed_state() -> None:
    result = target_understanding_node(
        {
            "engagement_id": "malformed-state",
            "mental_model": "not-a-dict",
            "crawled_data": "not-a-dict",
            "session_cookies": {"session": "secret-cookie"},
        }  # type: ignore[arg-type]
    )

    brain = result["target_brain"]
    assert brain["engagement_id"] == "malformed-state"
    assert brain["endpoint_count"] == 0
    assert brain["knowledge"]["nodes"] == {}
    assert "secret-cookie" not in repr(brain)

