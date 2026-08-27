from __future__ import annotations

import pytest

from webpent.abhie_v6 import (
    ABHIEV6Core,
    AgentResearchState,
    AttackChainIntelligenceV6,
    DeepDiscoveryEngineV6,
    DifferentialAnalysisV6,
    InvariantReasoningSystemV6,
    OutcomeKind,
    ResearchAgentCoreV6,
    ResearchCreativityEngineV6,
    ResearchIntelligenceScorecard,
    ResearchLearningV4,
    V6Status,
)
from webpent.abhip.contracts import IntelligenceNode, TargetIntelligenceGraph
from webpent.asros.world_model import (
    BehaviorObservation,
    BehaviorStatus,
    EvidenceLineage,
    InvariantKind,
    SecurityInvariant,
    SecurityWorldModel,
)


def _graph() -> TargetIntelligenceGraph:
    return TargetIntelligenceGraph(
        engagement_id="eng-v6",
        target_id="target-v6",
        knowledge_hash="0123456789abcdef",
        nodes=(
            IntelligenceNode(
                node_id="resource-1",
                kind="resource",
                label="object",
                evidence_source="offline-record",
                confidence=0.8,
                lifecycle_state="observed",
                validation_status="pending",
                evidence_refs=("ev:resource-1",),
            ),
            IntelligenceNode(
                node_id="workflow-1",
                kind="workflow",
                label="read workflow",
                evidence_source="offline-record",
                confidence=0.7,
                lifecycle_state="observed",
                validation_status="pending",
                evidence_refs=("ev:workflow-1",),
            ),
        ),
        coverage_gaps=("ownership", "authorization"),
    )


def _world_model() -> SecurityWorldModel:
    invariant_lineage = EvidenceLineage(
        source="offline-invariant-fixture",
        evidence_refs=("ev:invariant-1",),
        confidence=0.8,
    )
    behavior_lineage = EvidenceLineage(
        source="offline-behavior-fixture",
        evidence_refs=("ev:behavior-1",),
        confidence=0.8,
    )
    invariant = SecurityInvariant(
        invariant_id="inv-ownership",
        statement="Foreign identities cannot read an owned resource.",
        kind=InvariantKind.OWNERSHIP,
        subject="foreign-identity",
        protected_resource="resource-1",
        forbidden_conditions=("foreign identity reads owned resource",),
        lineage=invariant_lineage,
    )
    behavior = BehaviorObservation(
        behavior_id="behavior-1",
        subject="resource-1",
        expected="foreign identity is denied",
        observed="foreign identity was allowed in recorded fixture",
        status=BehaviorStatus.DEVIATION,
        deviation="recorded access differs from the invariant",
        lineage=behavior_lineage,
    )
    return SecurityWorldModel(
        engagement_id="eng-v6",
        target_id="target-v6",
        knowledge_hash="0123456789abcdef",
        invariants=(invariant,),
        behaviours=(behavior,),
    )


def test_agent_core_is_bounded_deterministic_and_non_executing() -> None:
    graph = _graph()
    agent = ResearchAgentCoreV6(max_decisions=1)
    first = agent.plan(graph=graph, evidence_state={"ownership": 0})
    second = agent.plan(graph=graph, evidence_state={"ownership": 0})
    assert first == second
    assert len(first) == 1
    assert first[0].risk == 0.0
    assert first[0].execution_requested is False
    assert first[0].finding_created is False
    state = agent.build_state(graph=graph, decisions=first, stop_reason="bounded")
    assert state.digest() == state.digest()
    assert not state.execution_attempted
    assert not state.finding_created


def test_deep_discovery_is_evidence_linked_and_fail_closed() -> None:
    candidates = DeepDiscoveryEngineV6().discover(graph=_graph())
    assert {item.violated_assumption for item in candidates} == {
        "Security must preserve authorization",
        "Security must preserve ownership",
    }
    assert all(item.source_refs for item in candidates)
    assert all(item.status == V6Status.ADVISORY for item in candidates)
    assert all(not item.confirmed and not item.finding_created for item in candidates)


def test_invariant_reasoning_reports_disputed_and_requires_causal_validation() -> None:
    results = InvariantReasoningSystemV6().assess(world_model=_world_model())
    assert len(results) == 1
    assert results[0].result.value == "disputed"
    assert results[0].source_evidence == ("ev:behavior-1",)
    assert results[0].confidence == 0.7
    assert results[0].causal_validation_required


def test_attack_chain_has_dependencies_and_no_promotion() -> None:
    graph = _graph()
    candidates = DeepDiscoveryEngineV6().discover(graph=graph)
    invariants = InvariantReasoningSystemV6().assess(world_model=_world_model())
    chains = AttackChainIntelligenceV6().generate(
        graph=graph,
        candidates=candidates,
        invariants=invariants,
    )
    assert chains
    assert all(chain.dependencies for chain in chains)
    assert all(not chain.causally_confirmed for chain in chains)
    assert all(not chain.finding_created for chain in chains)


def test_creativity_and_differential_are_ranked_but_not_verdicts() -> None:
    candidate = DeepDiscoveryEngineV6().discover(graph=_graph())[0]
    directions = ResearchCreativityEngineV6().explore(
        candidate=candidate,
        evidence_refs=("ev:z", "ev:a", "ev:z"),
    )
    assert tuple(item.rank for item in directions) == (1, 2, 3)
    assert all(item.evidence_refs == ("ev:a", "ev:z") for item in directions)
    report = DifferentialAnalysisV6().compare(
        comparison_id="cmp-1",
        left={"identity": "owner", "role": "reader"},
        right={"identity": "foreign", "role": "reader"},
        evidence_refs=("ev:2", "ev:1"),
    )
    identity = next(item for item in report if item.dimension == "identity")
    assert identity.signal
    assert identity.evidence_refs == ("ev:1", "ev:2")
    assert all(not item.promotion_eligible for item in report)


def test_learning_is_scoped_redacted_and_advisory() -> None:
    first = ResearchLearningV4(engagement_id="eng-v6", target_id="target-a")
    second = ResearchLearningV4(engagement_id="eng-v6", target_id="target-b")
    lesson = first.learn(
        lesson_id="lesson-a",
        situation="blocked path",
        decision="stop before execution",
        outcome=OutcomeKind.BLOCKED_CAPABILITY,
        future_recommendation="require approved evidence",
        evidence_refs=("Authorization: Bearer raw-secret",),
    )
    assert lesson is not None
    assert lesson.advisory_only
    assert first.summary()["target_isolated"] is True
    second_items = second.summary()["items"]
    assert all(not entries for entries in second_items.values())
    assert "raw-secret" not in str(first.memory.records)


def test_architect_review_delegates_central_gate_and_blocks_missing_proof() -> None:
    result = ABHIEV6Core().architect.review(
        engagement_id="eng-v6",
        target_id="target-v6",
        subject_id="hyp-1",
        hypothesis={
            "id": "hyp-1",
            "reason": "ownership assumption",
            "affected_asset": "resource-1",
            "evidence_refs": ("ev:1",),
            "attack_plan": ("record control pair",),
        },
        argument_chain={"steps": ("observe", "compare")},
        evidence_refs=("ev:1",),
        observation_count=0,
        claim="possible authorization difference",
    )
    assert result.status == V6Status.BLOCKED
    assert result.central_post_status in {"blocked", "insufficient"}
    assert result.qualification_approved is False
    assert result.oracle_overridden is False
    assert result.finding_created is False


def test_core_integration_is_zero_request_and_no_finding() -> None:
    result = ABHIEV6Core().run(
        graph=_graph(),
        world_model=_world_model(),
        evidence_state={"ownership": 1},
        left_context={"identity": "owner"},
        right_context={"identity": "foreign"},
        evidence_refs=("ev:core",),
    )
    assert result.requests_sent == 0
    assert not result.mutations_performed
    assert not result.finding_created
    assert result.candidates
    assert result.invariants
    assert result.chains
    assert result.creative_directions
    assert result.differentials
    assert result.architect_review.status == V6Status.BLOCKED
    assert result.state.stop_reason.startswith("advisory lifecycle")


def test_authority_flags_fail_closed() -> None:
    with pytest.raises(ValueError, match="scorecard_cannot_approve_qualification"):
        ResearchIntelligenceScorecard(
            engagement_id="eng-v6",
            target_id="target-v6",
            qualification_approved=True,
        )
    with pytest.raises(ValueError, match="agent_state_cannot_execute"):
        AgentResearchState(
            engagement_id="eng-v6",
            target_id="target-v6",
            execution_attempted=True,
        )
