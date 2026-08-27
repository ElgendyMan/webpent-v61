from datetime import UTC, datetime

import pytest

from webpent.asros.world_model import (
    BehaviorObservation,
    BehaviorStatus,
    BusinessIntent,
    EvidenceLineage,
    Freshness,
    InvariantKind,
    SecurityInvariant,
    SecurityWorldModel,
)
from webpent.knowledge.model_v2 import TargetKnowledgeV2


def _lineage(*refs: str) -> EvidenceLineage:
    return EvidenceLineage(
        source="controlled_observation",
        evidence_refs=refs,
        confidence=0.8,
        freshness=Freshness.FRESH,
        observed_at=datetime(2026, 8, 27, tzinfo=UTC),
    )


def _knowledge() -> TargetKnowledgeV2:
    return TargetKnowledgeV2(
        engagement_id="eng-asros",
        target_id="controlled-loopback",
        observations={
            "obs-1": {
                "observation_id": "obs-1",
                "source": "controlled_target",
                "confidence": 0.8,
                "evidence_refs": ("obs-ref-1",),
            }
        },
    )


def test_world_model_represents_intent_invariant_and_behavior_with_lineage():
    model = SecurityWorldModel.from_target_knowledge(
        _knowledge(),
        business_intents=(
            BusinessIntent(
                intent_id="intent-owner-read",
                goal="Owner reads the owned resource",
                workflow="resource-read",
                transaction="read-resource",
                ownership_rules=("requester owns resource",),
                trust_assumptions=("identity is stable",),
                lineage=_lineage("intent-ref"),
            ),
        ),
        invariants=(
            SecurityInvariant(
                invariant_id="inv-owner-boundary",
                statement="A requester cannot access another owner's resource",
                kind=InvariantKind.OWNERSHIP,
                subject="requester",
                protected_resource="resource-42",
                forbidden_conditions=("requester is not owner",),
                lineage=_lineage("invariant-ref"),
            ),
        ),
        behaviours=(
            BehaviorObservation(
                behavior_id="behavior-owner",
                subject="resource-42",
                expected="owner receives the resource",
                observed="owner receives the resource",
                status=BehaviorStatus.EXPECTED,
                lineage=_lineage("owner-ref"),
            ),
        ),
    )

    assert model.authoritative is False
    assert model.execution_capability is False
    assert model.content_hash() == model.content_hash()
    assessment = model.invariant_assessment("inv-owner-boundary")
    assert assessment.result == "supported"
    assert assessment.requires_causal_validation is True
    assert assessment.evidence_refs == ("owner-ref",)


def test_world_model_marks_deviation_as_disputed_not_confirmed():
    model = SecurityWorldModel.from_target_knowledge(
        _knowledge(),
        invariants=(
            SecurityInvariant(
                invariant_id="inv-role",
                statement="A low privilege requester cannot cross the role boundary",
                kind=InvariantKind.ROLE_BOUNDARY,
                subject="low-role",
                protected_resource="admin-resource",
                lineage=_lineage("inv-ref"),
            ),
        ),
        behaviours=(
            BehaviorObservation(
                behavior_id="behavior-role",
                subject="admin-resource",
                expected="request is denied",
                observed="request returned an observation",
                status=BehaviorStatus.DEVIATION,
                deviation="observed outcome differs from expectation",
                lineage=_lineage("deviation-ref"),
            ),
        ),
    )

    assessment = model.invariant_assessment("inv-role")
    assert assessment.result == "disputed"
    assert assessment.requires_causal_validation is True
    assert model.authoritative is False


def test_world_model_rejects_missing_lineage_and_duplicate_ids():
    with pytest.raises(ValueError, match="lineage_evidence_required"):
        EvidenceLineage(source="unit", evidence_refs=())

    with pytest.raises(ValueError, match="duplicate_world_model_invariant_id"):
        SecurityWorldModel.from_target_knowledge(
            _knowledge(),
            invariants=(
                SecurityInvariant(
                    invariant_id="duplicate",
                    statement="The invariant has a bounded statement",
                    kind=InvariantKind.WORKFLOW,
                    subject="subject",
                    protected_resource="resource",
                    lineage=_lineage("a"),
                ),
                SecurityInvariant(
                    invariant_id="duplicate",
                    statement="The second invariant must be rejected",
                    kind=InvariantKind.WORKFLOW,
                    subject="subject",
                    protected_resource="resource",
                    lineage=_lineage("b"),
                ),
            ),
        )


def test_world_model_cannot_be_authoritative_or_execute():
    with pytest.raises(ValueError, match="world_model_cannot_grant_authority"):
        SecurityWorldModel(
            engagement_id="eng",
            target_id="target",
            knowledge_hash="a" * 64,
            authoritative=True,
        )

    with pytest.raises(ValueError, match="behavior_deviation_observation_required"):
        BehaviorObservation(
            behavior_id="bad",
            subject="resource",
            expected="denied",
            status=BehaviorStatus.DEVIATION,
            lineage=_lineage("ref"),
        )
