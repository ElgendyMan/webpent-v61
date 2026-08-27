from __future__ import annotations

import pytest

from webpent.asros.world_model import (
    BusinessIntent,
    EvidenceLineage,
    InvariantKind,
    SecurityInvariant,
    SecurityWorldModel,
)
from webpent.avde import (
    AttackPathExplorer,
    AutonomousValidationStrategy,
    BehavioralSurfaceDiscovery,
    CompetitionLoop,
    DiscoveryHypothesisEngine,
    SecurityInvariantMiner,
    SeniorReasoningReviewer,
)


def lineage(ref: str = "fixture://observation/1") -> EvidenceLineage:
    return EvidenceLineage(source="controlled-fixture", evidence_refs=(ref,), confidence=0.8)


def world() -> SecurityWorldModel:
    return SecurityWorldModel(
        engagement_id="eng-1",
        target_id="target-1",
        knowledge_hash="a" * 64,
        business_intents=(
            BusinessIntent(
                intent_id="intent-1",
                goal="read an owned record",
                workflow="record-read",
                lineage=lineage("fixture://intent/1"),
            ),
        ),
        invariants=(
            SecurityInvariant(
                invariant_id="inv-1",
                statement="A subject can read only an owned record.",
                kind=InvariantKind.OWNERSHIP,
                subject="synthetic-subject",
                protected_resource="record/1",
                forbidden_conditions=("different-owner",),
                lineage=lineage(),
            ),
        ),
    )


def test_discovery_is_deterministic_and_deduplicates_prior_ids() -> None:
    engine = DiscoveryHypothesisEngine()
    first = engine.generate(
        world(), attack_graph=({"asset": "record/1", "required_capability": "analysis"},)
    )
    second = engine.generate(
        world(), attack_graph=({"asset": "record/1", "required_capability": "analysis"},)
    )
    assert first == second
    assert first[0].hypothesis_id == engine.generate(world(), prior_hypotheses=())[0].hypothesis_id
    assert first[0].vulnerability_class == "broken_access_control"
    assert first[0].reasoning_chain[-1].startswith("candidate/control comparison")
    assert engine.generate(world(), prior_hypotheses=first) == ()
    assert "token" not in " ".join(first[0].source_refs).lower()
    assert first[0].status.value == "generated"


def test_discovery_requires_world_model_and_does_not_execute() -> None:
    with pytest.raises(TypeError, match="security_world_model_required"):
        DiscoveryHypothesisEngine().generate({})  # type: ignore[arg-type]
    assert not hasattr(DiscoveryHypothesisEngine(), "request")


def test_explorer_and_strategy_rank_and_block_without_capability() -> None:
    explorer = AttackPathExplorer()
    paths = explorer.explore(
        (
            {
                "kind": "ownership",
                "steps": ["candidate", "control"],
                "impact": 0.9,
                "confidence": 0.9,
                "validation_cost": 8,
                "required_capability": "oracle",
            },
            {
                "kind": "trust_boundary",
                "steps": ["reach"],
                "impact": 0.4,
                "confidence": 0.5,
                "validation_cost": 2,
                "required_capability": "analysis",
            },
        ),
        target_id="target-1",
        available_capabilities=("oracle", "analysis"),
    )
    assert paths[0].expected_security_value >= paths[1].expected_security_value
    hypothesis = DiscoveryHypothesisEngine().generate(world())[0]
    plan = AutonomousValidationStrategy().choose(
        hypothesis, (path for path in paths), available_capabilities=("oracle",), max_cost=20
    )
    assert plan.decision == "selected"
    blocked = AutonomousValidationStrategy().choose(
        hypothesis, (path for path in paths), available_capabilities=("missing",)
    )
    assert blocked.decision == "blocked"
    assert blocked.risk == "blocked"


def test_behavior_groups_redacts_and_miner_requires_contrast() -> None:
    discovery = BehavioralSurfaceDiscovery()
    surfaces = discovery.discover(
        (
            {
                "asset": "record/1",
                "role": "owner",
                "subject": "s1",
                "source_refs": ("fixture://a",),
            },
            {
                "asset": "record/1",
                "role": "other",
                "subject": "s2",
                "source_refs": ("authorization=fixture-marker",),
            },
            {
                "asset": "record/2",
                "role": "owner",
                "subject": "s1",
                "source_refs": ("fixture://b",),
            },
        )
    )
    assert len(surfaces) == 2
    record_one = next(item for item in surfaces if item.asset == "record/1")
    assert record_one.stability < 1
    assert all("secret" not in ref for ref in record_one.source_refs)
    mined = SecurityInvariantMiner().mine(surfaces, world())
    assert len(mined) == 1
    assert mined[0].requires_negative_control is True
    assert "record/1" in mined[0].affected_entities
    assert mined[0].validation_method.startswith("candidate/control comparison")
    assert mined[0].source_refs
    empty_world = SecurityWorldModel(
        engagement_id="eng-1",
        target_id="target-1",
        knowledge_hash="b" * 64,
        business_intents=(),
        invariants=(),
    )
    assert SecurityInvariantMiner().mine(surfaces, empty_world) == ()


def test_review_and_competition_are_advisory() -> None:
    hypothesis = DiscoveryHypothesisEngine().generate(world())[0]
    path = AttackPathExplorer().explore(
        (
            {
                "steps": ["candidate", "control"],
                "required_capability": "analysis",
                "validation_cost": 4,
            },
        ),
        target_id="target-1",
        available_capabilities=("analysis",),
    )[0]
    plan = AutonomousValidationStrategy().choose(
        hypothesis, [path], available_capabilities=("analysis",)
    )
    review = SeniorReasoningReviewer().review(hypothesis, plan)
    assert review.creates_finding is False
    assert review.human_signoff is False
    round_ = CompetitionLoop().run([hypothesis], budget=10)
    assert round_.winner_id == hypothesis.hypothesis_id
    assert round_.advisory_only is True
    assert round_.round_id == CompetitionLoop().run([hypothesis], budget=10).round_id
    empty_round = CompetitionLoop().run([hypothesis], budget=0)
    assert empty_round.winner_id is None
    assert empty_round.advisory_only is True
    blocked_plan = AutonomousValidationStrategy().choose(
        hypothesis, [path], available_capabilities=("missing",)
    )
    assert SeniorReasoningReviewer().review(hypothesis, blocked_plan).decision.value == "block"
    with pytest.raises(ValueError, match="hypothesis_plan_mismatch"):
        SeniorReasoningReviewer().review(
            hypothesis,
            plan.model_copy(update={"hypothesis_id": "b" * 64}),
        )
