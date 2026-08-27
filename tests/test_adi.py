import pytest

from webpent.adi import (
    ADIIntelligenceEngine,
    FailureIntelligence,
    HistoricalEvidence,
    ResearchSurfaceSignal,
)
from webpent.asros.quality_controller import PostExecutionReview, QualityReviewStatus
from webpent.asros.world_model import (
    BusinessIntent,
    EvidenceLineage,
    InvariantKind,
    SecurityInvariant,
    SecurityWorldModel,
)


def lineage(ref: str = "fixture://adi/1") -> EvidenceLineage:
    return EvidenceLineage(source="controlled-fixture", evidence_refs=(ref,), confidence=0.8)


def world() -> SecurityWorldModel:
    return SecurityWorldModel(
        engagement_id="adi-eng-1",
        target_id="adi-target-1",
        knowledge_hash="c" * 64,
        business_intents=(
            BusinessIntent(
                intent_id="adi-intent-1",
                goal="read an owned record",
                workflow="record-read",
                lineage=lineage("fixture://adi/intent"),
            ),
        ),
        invariants=(
            SecurityInvariant(
                invariant_id="adi-inv-1",
                statement="A subject can read only an owned record.",
                kind=InvariantKind.OWNERSHIP,
                subject="synthetic-subject",
                protected_resource="record/1",
                forbidden_conditions=("different-owner",),
                lineage=lineage(),
            ),
        ),
    )


def test_failure_intelligence_is_scoped_and_deduplicated() -> None:
    memory = FailureIntelligence()
    record = memory.learn(
        engagement_id="eng-1",
        target_id="target-1",
        hypothesis_id="h-1",
        affected_asset="record/1",
        outcome="blocked",
        reason="precondition unavailable",
        evidence_refs=("fixture://failure/1",),
    )
    assert record is not None
    duplicate = memory.learn(
        engagement_id="eng-1",
        target_id="target-1",
        hypothesis_id="h-1",
        affected_asset="record/1",
        outcome="blocked",
        reason="precondition unavailable",
        evidence_refs=("fixture://failure/1",),
    )
    assert duplicate == record
    assert len(memory.records(engagement_id="eng-1", target_id="target-1")) == 1
    assert memory.records(engagement_id="other", target_id="target-1") == ()
    assert memory.records_for_other_scope(engagement_id="other", target_id="target-1")
    assert (
        memory.learn(
            engagement_id="eng-1",
            target_id="target-1",
            hypothesis_id="h-1",
            affected_asset="record/1",
            outcome="evidence",
            reason="successful evidence",
        )
        is None
    )


def test_adi_run_is_deterministic_and_uses_existing_advisory_components() -> None:
    history = (
        HistoricalEvidence(
            evidence_id="e-1",
            engagement_id="adi-eng-1",
            target_id="adi-target-1",
            asset="record/1",
            outcome="evidence",
            evidence_refs=("fixture://evidence/1",),
            information_gain=0.8,
            confidence=0.9,
        ),
    )
    memory = FailureIntelligence()
    first = ADIIntelligenceEngine(failure_intelligence=memory).run_advisory(
        world(),
        observations=({"asset": "record/1", "status": "deviation"},),
        attack_graph=(
            {
                "kind": "ownership",
                "asset": "record/1",
                "steps": ("candidate", "control"),
                "impact": 0.9,
                "confidence": 0.9,
                "validation_cost": 4,
                "required_capability": "analysis",
            },
        ),
        signals=(
            ResearchSurfaceSignal(
                asset="record/1",
                business_impact=0.9,
                source_refs=("fixture://surface/run",),
            ),
        ),
        historical_evidence=history,
        available_capabilities=("analysis",),
    )
    second = ADIIntelligenceEngine(failure_intelligence=memory).run_advisory(
        world(),
        observations=({"asset": "record/1", "status": "deviation"},),
        attack_graph=(
            {
                "kind": "ownership",
                "asset": "record/1",
                "steps": ("candidate", "control"),
                "impact": 0.9,
                "confidence": 0.9,
                "validation_cost": 4,
                "required_capability": "analysis",
            },
        ),
        signals=(
            ResearchSurfaceSignal(
                asset="record/1",
                business_impact=0.9,
                source_refs=("fixture://surface/run",),
            ),
        ),
        historical_evidence=history,
        available_capabilities=("analysis",),
    )
    assert first == second
    hypotheses, plans, decisions, research_map = first
    assert len(hypotheses) == len(plans) == len(decisions) == 1
    assert plans[0].decision == "selected"
    assert decisions[0].execution_delegated is True
    assert decisions[0].advisory_only is True
    assert research_map.nodes[0].historical_success_rate == 1.0
    assert research_map.nodes[0].source_refs == (
        "fixture://adi/1",
        "fixture://surface/run",
    )
    assert research_map.changes_policy is False
    assert research_map.executes_transport is False


def test_adi_research_map_uses_signal_and_failure_penalty() -> None:
    memory = FailureIntelligence()
    memory.learn(
        engagement_id="adi-eng-1",
        target_id="adi-target-1",
        hypothesis_id="h-1",
        affected_asset="record/1",
        outcome="failed",
        reason="no usable observation",
    )
    research_map = ADIIntelligenceEngine(failure_intelligence=memory).build_research_map(
        world(),
        signals=(
            ResearchSurfaceSignal(
                asset="record/1",
                business_impact=1.0,
                source_refs=("fixture://surface/1",),
            ),
        ),
    )
    assert research_map.nodes[0].repeated_failure_count == 1
    assert research_map.nodes[0].priority_score < 0.5
    assert research_map.nodes[0].source_refs == (
        "fixture://adi/1",
        "fixture://surface/1",
    )
    assert research_map.observation_sequence == 0


def test_confidence_review_is_not_approval() -> None:
    post = PostExecutionReview(
        status=QualityReviewStatus.ACCEPTED_FOR_REVIEW,
        hypothesis_id="h-adi-1",
        evidence_quality_score=0.9,
        evidence_refs=("fixture://proof/1",),
        causal_proof_present=True,
        negative_control_present=True,
        proof_sealed=True,
        proof_replayable=True,
    )
    report = ADIIntelligenceEngine.confidence_review(
        post_review=post,
        security_boundary_exists=True,
        alternative_explanation_considered=True,
        impact_demonstrated=True,
    )
    assert report.status == "accepted_for_review"
    assert report.confidence == 0.9
    assert report.can_create_confirmed_finding is False
    assert report.can_override_oracle is False
    assert report.can_override_policy is False

    blocked = PostExecutionReview(
        status=QualityReviewStatus.INSUFFICIENT,
        hypothesis_id="h-adi-1",
        evidence_quality_score=0.2,
    )
    blocked_report = ADIIntelligenceEngine.confidence_review(
        post_review=blocked,
        security_boundary_exists=False,
        alternative_explanation_considered=False,
        impact_demonstrated=False,
    )
    assert blocked_report.status == "insufficient"
    assert blocked_report.confidence == 0.0


def test_adi_rejects_non_review_inputs() -> None:
    with pytest.raises(TypeError, match="security_world_model_required"):
        ADIIntelligenceEngine().build_research_map({})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unsupported_failure_outcome"):
        FailureIntelligence().learn(
            engagement_id="e",
            target_id="t",
            hypothesis_id="h",
            affected_asset="a",
            outcome="unsupported",  # type: ignore[arg-type]
            reason="invalid",
        )
