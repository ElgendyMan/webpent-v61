from __future__ import annotations

from datetime import UTC, datetime

import pytest

from webpent.knowledge.model_v2 import (
    KnowledgeEntityKind,
    KnowledgeLifecycle,
    TargetKnowledgeV2,
    build_target_knowledge_v2,
    upgrade_legacy_knowledge,
)
from webpent.knowledge.target_knowledge import KnowledgeNode, TargetKnowledgeModel

OBSERVED_AT = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)


def _model() -> TargetKnowledgeV2:
    observations = [
        {
            "observation_id": "obs:surface",
            "source": "controlled_surface_fixture",
            "observed_at": OBSERVED_AT,
            "confidence": 0.9,
            "evidence_refs": ["trace:surface"],
            "facts": {"method": "GET", "authorization": "must-not-persist"},
        }
    ]
    entities = [
        {
            "kind": kind.value,
            "canonical_key": f"{kind.value}:sample",
            "source_observation": "obs:surface",
            "confidence": 0.8,
            "observed_at": OBSERVED_AT,
            "lifecycle": KnowledgeLifecycle.OBSERVED,
            "metadata": {"name": kind.value, "cookie": "must-not-persist"},
        }
        for kind in KnowledgeEntityKind
    ]
    return build_target_knowledge_v2(
        engagement_id="engagement-a",
        target_id="target-a",
        observations=observations,
        entities=entities,
    )


def test_v2_contains_required_entity_vocabulary_and_lineage() -> None:
    model = _model()

    assert model.schema_version == 2
    assert {entity.kind for entity in model.entities.values()} == set(KnowledgeEntityKind)
    assert all(entity.source_observation == "obs:surface" for entity in model.entities.values())
    assert all(entity.observed_at == OBSERVED_AT for entity in model.entities.values())
    assert all(
        entity.lifecycle == KnowledgeLifecycle.OBSERVED for entity in model.entities.values()
    )
    assert all(entity.confidence == 0.8 for entity in model.entities.values())
    assert all(entity.entity_id.startswith("entity:") for entity in model.entities.values())


def test_v2_is_deterministic_and_redacted() -> None:
    first = _model()
    second = _model()

    assert first.content_hash() == second.content_hash()
    payload = str(first.as_dict())
    assert "must-not-persist" not in payload
    assert first.entities_of_kind(KnowledgeEntityKind.RESOURCE)


def test_v2_rejects_missing_lineage() -> None:
    with pytest.raises(ValueError, match="source_observation_missing"):
        build_target_knowledge_v2(
            engagement_id="engagement-a",
            target_id="target-a",
            observations=[],
            entities=[
                {
                    "kind": "resource",
                    "canonical_key": "resource:1",
                    "source_observation": "obs:missing",
                }
            ],
        )


def test_v2_upgrade_preserves_legacy_entities() -> None:
    legacy = TargetKnowledgeModel(
        engagement_id="engagement-a",
        nodes={
            "node:1": KnowledgeNode(
                node_id="node:1",
                kind="object",
                canonical_key="object:1",
                confidence=0.7,
                evidence_refs=["evidence:1"],
                metadata={"owner": "opaque"},
            )
        },
    )

    upgraded = upgrade_legacy_knowledge(legacy, target_id="target-a")

    assert upgraded.schema_version == 2
    assert upgraded.engagement_id == "engagement-a"
    assert upgraded.target_id == "target-a"
    assert upgraded.entities["node:1"].canonical_key == "object:1"
    assert upgraded.entities["node:1"].source_observation == "legacy:node:1"
    assert upgraded.observations["legacy:node:1"].evidence_refs == ("evidence:1",)


def test_v2_snapshot_round_trip_is_canonical_and_validated() -> None:
    model = build_target_knowledge_v2(
        engagement_id="engagement-snapshot",
        target_id="target-snapshot",
        observations=[
            {
                "observation_id": "obs-1",
                "source": "controlled",
                "facts": {"Authorization": "Bearer should-not-persist", "route": "/safe"},
            }
        ],
        entities=[
            {
                "kind": "resource",
                "canonical_key": "invoice",
                "source_observation": "obs-1",
                "metadata": {"owner": "synthetic-owner"},
            }
        ],
    )
    snapshot = model.to_snapshot_json()
    restored = TargetKnowledgeV2.from_snapshot_json(snapshot)
    assert restored.content_hash() == model.content_hash()
    assert snapshot == restored.to_snapshot_json()
    assert "should-not-persist" not in snapshot


def test_v2_snapshot_restore_rejects_invalid_or_wrong_schema() -> None:
    with pytest.raises(ValueError, match="knowledge_snapshot_invalid_json"):
        TargetKnowledgeV2.from_snapshot_json("not-json")
    with pytest.raises(ValueError, match="knowledge_snapshot_schema_mismatch"):
        TargetKnowledgeV2.from_snapshot_json('{"schema_version": 1}')
