from __future__ import annotations

from datetime import UTC, datetime

from webpent.attack_graph import AttackGraphEngine
from webpent.knowledge.model_v2 import build_target_knowledge_v2
from webpent.research import HypothesisGenerator, ResearchPlanner

NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)


def _model():
    observations = [
        {
            "observation_id": "obs:1",
            "source": "fixture",
            "observed_at": NOW,
            "confidence": 1.0,
            "evidence_refs": ["evidence:1"],
        }
    ]
    entities = [
        {
            "kind": "identity",
            "canonical_key": "identity:opaque",
            "source_observation": "obs:1",
            "confidence": 1.0,
            "evidence_refs": ["evidence:1"],
        },
        {
            "kind": "endpoint",
            "canonical_key": "GET /objects/{id}",
            "source_observation": "obs:1",
            "confidence": 0.9,
            "evidence_refs": ["evidence:1"],
        },
        {
            "kind": "resource",
            "canonical_key": "resource:opaque",
            "source_observation": "obs:1",
            "confidence": 0.9,
            "evidence_refs": ["evidence:1"],
        },
    ]
    first = build_target_knowledge_v2(
        engagement_id="eng", target_id="target", observations=observations, entities=entities
    )
    ids = {entity.canonical_key: entity.entity_id for entity in first.entities.values()}
    return build_target_knowledge_v2(
        engagement_id="eng",
        target_id="target",
        observations=observations,
        entities=entities,
        relations=[
            {
                "relation": "exposes",
                "source_entity": ids["identity:opaque"],
                "target_entity": ids["GET /objects/{id}"],
                "source_observation": "obs:1",
                "confidence": 0.9,
                "evidence_refs": ["evidence:1"],
            },
            {
                "relation": "can_access",
                "source_entity": ids["GET /objects/{id}"],
                "target_entity": ids["resource:opaque"],
                "source_observation": "obs:1",
                "confidence": 0.8,
                "evidence_refs": ["evidence:1"],
            },
        ],
    )


def test_hypothesis_generation_is_deterministic_and_explainable() -> None:
    model = _model()
    graph = AttackGraphEngine().build(model)
    generator = HypothesisGenerator()

    first = [item.model_dump(mode="json") for item in generator.generate(model, graph)]
    second = [item.model_dump(mode="json") for item in generator.generate(model, graph)]

    assert first == second
    assert first
    hypothesis = first[0]
    assert hypothesis["vuln_class"] == "idor"
    assert hypothesis["affected_asset"] == "GET /objects/{id}"
    assert hypothesis["reasoning_chain"]
    assert hypothesis["required_capability"] == "http_read"
    assert all("body" not in key.lower() for key in hypothesis)


def test_planner_selects_highest_value_task_and_never_authorizes_execution() -> None:
    model = _model()
    graph = AttackGraphEngine().build(model)
    hypotheses = HypothesisGenerator().generate(model, graph)
    planner = ResearchPlanner()

    queue = planner.build_queue(
        hypotheses,
        engagement_id="eng",
        target_id="target",
        available_capabilities={"http_read"},
    )
    decision = planner.decide(queue)

    assert queue.tasks
    assert queue.next_task().task_id == decision.selected_task_id
    assert decision.status == "planned"
    assert decision.authoritative is False
    assert decision.execution_allowed is False


def test_planner_filters_unavailable_capability_and_completed_task() -> None:
    model = _model()
    graph = AttackGraphEngine().build(model)
    hypothesis = HypothesisGenerator().generate(model, graph)[0]
    planner = ResearchPlanner()
    task_id = planner.task_id(hypothesis, engagement_id="eng", target_id="target")

    assert (
        planner.build_queue(
            hypothesis and [hypothesis],
            engagement_id="eng",
            target_id="target",
            available_capabilities=set(),
        ).tasks
        == ()
    )
    assert (
        planner.build_queue(
            [hypothesis],
            engagement_id="eng",
            target_id="target",
            available_capabilities={"http_read"},
            completed_task_ids={task_id},
        ).tasks
        == ()
    )
