from __future__ import annotations

from datetime import UTC, datetime

from webpent.attack_graph import AttackGraphEngine, VulnerabilityChainReasoner
from webpent.knowledge.model_v2 import build_target_knowledge_v2

NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)


def _knowledge():
    observations = [
        {
            "observation_id": "obs:fixture",
            "source": "controlled_fixture",
            "observed_at": NOW,
            "confidence": 1.0,
            "evidence_refs": ["trace:fixture"],
        }
    ]
    entities = [
        {
            "kind": "user",
            "canonical_key": "user:opaque",
            "source_observation": "obs:fixture",
            "confidence": 1.0,
        },
        {
            "kind": "endpoint",
            "canonical_key": "GET /objects/{id}",
            "source_observation": "obs:fixture",
            "confidence": 1.0,
        },
        {
            "kind": "resource",
            "canonical_key": "resource:opaque",
            "source_observation": "obs:fixture",
            "confidence": 1.0,
        },
        {
            "kind": "permission",
            "canonical_key": "ownership-check",
            "source_observation": "obs:fixture",
            "confidence": 0.8,
        },
    ]
    model = build_target_knowledge_v2(
        engagement_id="engagement-a",
        target_id="target-a",
        observations=observations,
        entities=entities,
        relations=[],
    )
    entity = {item.canonical_key: item.entity_id for item in model.entities.values()}
    return build_target_knowledge_v2(
        engagement_id="engagement-a",
        target_id="target-a",
        observations=observations,
        entities=entities,
        relations=[
            {
                "relation": "exposes",
                "source_entity": entity["user:opaque"],
                "target_entity": entity["GET /objects/{id}"],
                "source_observation": "obs:fixture",
                "confidence": 0.9,
                "evidence_refs": ["trace:1"],
            },
            {
                "relation": "can_access",
                "source_entity": entity["GET /objects/{id}"],
                "target_entity": entity["resource:opaque"],
                "source_observation": "obs:fixture",
                "confidence": 0.8,
                "evidence_refs": ["trace:2"],
            },
            {
                "relation": "depends_on",
                "source_entity": entity["GET /objects/{id}"],
                "target_entity": entity["ownership-check"],
                "source_observation": "obs:fixture",
                "confidence": 0.7,
                "evidence_refs": ["trace:3"],
            },
        ],
    )


def test_attack_graph_engine_builds_typed_consistent_graph() -> None:
    graph = AttackGraphEngine().build(_knowledge())

    assert graph.version == "2"
    assert not graph.consistency_errors
    assert {str(node.kind) for node in graph.nodes.values()} >= {
        "identity",
        "endpoint",
        "resource",
        "permission",
    }
    assert all(edge.evidence_refs for edge in graph.edges)
    assert graph.recommended_path_ids


def test_attack_graph_engine_is_deterministic() -> None:
    engine = AttackGraphEngine()
    first = engine.build(_knowledge()).model_dump(mode="json")
    second = engine.build(_knowledge()).model_dump(mode="json")

    assert first == second


def test_chain_reasoner_returns_potential_not_confirmed_chain() -> None:
    graph = AttackGraphEngine().build(_knowledge())
    chains = VulnerabilityChainReasoner(max_hops=3).derive(graph)

    assert chains
    assert all(chain.status == "potential" for chain in chains)
    assert all(chain.validation_required for chain in chains)
    assert all(chain.eligible_for_validation for chain in chains)
    assert not any(chain.status == "confirmed" for chain in chains)


def test_chain_reasoner_fails_closed_on_graph_consistency_errors() -> None:
    graph = (
        AttackGraphEngine()
        .build(_knowledge())
        .model_copy(update={"consistency_errors": ["relation_evidence_missing:bad"]})
    )

    assert VulnerabilityChainReasoner().derive(graph) == ()
