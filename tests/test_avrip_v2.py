from __future__ import annotations

from datetime import UTC, datetime

import pytest

from webpent.asros.adaptive_strategy import ResearchDirection
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
from webpent.avrip.assumptions import (
    AssumptionKind,
    SecurityAssumptionDiscoveryEngine,
)
from webpent.avrip.core import AVRIPCoreV2
from webpent.avrip.cross_domain import (
    CrossDomainAttackReasoner,
    SecurityDomain,
)
from webpent.avrip.evidence import (
    EvidenceIntelligenceV2,
    EvidenceItem,
    EvidencePolarity,
)
from webpent.avrip.intent import ApplicationIntentV2
from webpent.avrip.memory import AutonomousResearchMemoryV2
from webpent.avrip.optimizer import (
    ResearchStrategyOptimizerV2,
    StrategyObservation,
    StrategyOutcome,
)
from webpent.avrip.reasoning import (
    DeepVulnerabilityReasoner,
    ReasoningStepKind,
)
from webpent.avrip.review import SeniorResearchReviewerV2
from webpent.knowledge.model_v2 import (
    KnowledgeEntity,
    KnowledgeEntityKind,
    KnowledgeObservation,
    KnowledgeRelation,
    TargetKnowledgeV2,
)
from webpent.models.attack_graph import (
    AttackGraph,
    AttackGraphEdge,
    AttackGraphNode,
    AttackGraphNodeKind,
)

SCOPE = {"engagement_id": "eng-1", "target_id": "target-1"}


def _lineage(*refs: str, confidence: float = 0.8) -> EvidenceLineage:
    return EvidenceLineage(
        source="offline.fixture",
        evidence_refs=refs or ("fixture:observation-1",),
        confidence=confidence,
        freshness=Freshness.FRESH,
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _world() -> SecurityWorldModel:
    lineage = _lineage("obs:ownership")
    return SecurityWorldModel(
        **SCOPE,
        knowledge_hash="a" * 64,
        business_intents=(
            BusinessIntent(
                intent_id="intent:orders",
                goal="Complete an order workflow safely",
                workflow="order-flow",
                transaction="order",
                state_transitions=("cart -> checkout", "checkout -> paid"),
                ownership_rules=("Only the owner may modify the order",),
                trust_assumptions=("Role boundary is enforced",),
                lineage=lineage,
            ),
        ),
        invariants=(
            SecurityInvariant(
                invariant_id="invariant:owner-read",
                statement="Only the owner may read the order resource.",
                kind=InvariantKind.OWNERSHIP,
                subject="user",
                protected_resource="order",
                allowed_conditions=("owner",),
                forbidden_conditions=("other-user",),
                lineage=lineage,
            ),
        ),
        behaviours=(
            BehaviorObservation(
                behavior_id="behavior:order",
                subject="order",
                expected="Owner can read an order.",
                observed="Owner can read an order.",
                status=BehaviorStatus.EXPECTED,
                lineage=lineage,
            ),
        ),
    )


def _knowledge() -> TargetKnowledgeV2:
    entities = {}
    for entity_id, kind in (
        ("identity:user", KnowledgeEntityKind.IDENTITY),
        ("resource:order", KnowledgeEntityKind.RESOURCE),
        ("workflow:order", KnowledgeEntityKind.WORKFLOW),
        ("permission:read", KnowledgeEntityKind.PERMISSION),
    ):
        entities[entity_id] = KnowledgeEntity(
            entity_id=entity_id,
            kind=kind,
            canonical_key=entity_id,
            source_observation="knowledge:obs",
            confidence=0.8,
            evidence_refs=(f"evidence:{entity_id}",),
        )
    return TargetKnowledgeV2(
        **SCOPE,
        entities=entities,
        observations={
            "knowledge:obs": KnowledgeObservation(
                observation_id="knowledge:obs",
                source="offline.fixture",
                evidence_refs=("obs:knowledge",),
                confidence=0.8,
            ),
        },
        relations=(
            KnowledgeRelation(
                relation_id="relation:owner",
                relation="owner resource",
                source_entity="identity:user",
                target_entity="resource:order",
                source_observation="knowledge:obs",
                confidence=0.8,
                evidence_refs=("evidence:relation",),
            ),
            KnowledgeRelation(
                relation_id="relation:state",
                relation="state transition",
                source_entity="workflow:order",
                target_entity="resource:order",
                source_observation="knowledge:obs",
                confidence=0.8,
                evidence_refs=("evidence:state",),
            ),
        ),
    )


def _attack_graph() -> AttackGraph:
    specs = (
        ("graph:identity", AttackGraphNodeKind.IDENTITY),
        ("graph:resource", AttackGraphNodeKind.RESOURCE),
        ("graph:workflow", AttackGraphNodeKind.WORKFLOW),
        ("graph:permission", AttackGraphNodeKind.PERMISSION),
        ("graph:state", AttackGraphNodeKind.STATE),
    )
    nodes = {
        node_id: AttackGraphNode(
            id=node_id,
            kind=kind,
            label=node_id,
            source_refs=(f"obs:{node_id}",),
        )
        for node_id, kind in specs
    }
    return AttackGraph(
        nodes=nodes,
        edges=(
            AttackGraphEdge(
                id="edge:identity-resource",
                kind="relates",
                source_id="graph:identity",
                target_id="graph:resource",
                evidence_refs=["obs:edge"],
            ),
        ),
    )


def test_intent_and_assumptions_are_deterministic_and_advisory() -> None:
    world = _world()
    first = ApplicationIntentV2.from_world_model(world)
    second = ApplicationIntentV2.from_world_model(world)
    assert first.content_hash() == second.content_hash()
    assert first.execution_capability is False
    report = SecurityAssumptionDiscoveryEngine().discover(world_model=world, intent=first)
    assert report.assumptions
    assert any(item.kind == AssumptionKind.OWNERSHIP for item in report.assumptions)
    assert all(item.advisory_only for item in report.assumptions)
    assert all("causal_oracle" in item.missing_evidence for item in report.assumptions)


def test_deep_reasoning_has_ordered_chain_and_scope_guard() -> None:
    world = _world()
    assumptions = SecurityAssumptionDiscoveryEngine().discover(world_model=world).assumptions
    report = DeepVulnerabilityReasoner().reason(
        world_model=world,
        assumptions=assumptions,
        knowledge=_knowledge(),
        attack_graph=_attack_graph(),
        memory_hints=("prior blocked path",),
    )
    assert report.hypotheses
    hypothesis = report.hypotheses[0]
    assert tuple(step.kind for step in hypothesis.reasoning_chain) == (
        ReasoningStepKind.OBSERVATION,
        ReasoningStepKind.CONTEXT,
        ReasoningStepKind.ASSUMPTION,
        ReasoningStepKind.HYPOTHESIS,
        ReasoningStepKind.VALIDATION,
    )
    assert hypothesis.advisory_only is True
    assert hypothesis.status in {"potential", "blocked"}
    assert "memory hint" in hypothesis.reasoning_chain[1].statement

    mismatched = _knowledge().model_copy(update={"target_id": "other-target"})
    with pytest.raises(ValueError, match="scope_mismatch"):
        DeepVulnerabilityReasoner().reason(
            world_model=world,
            assumptions=assumptions,
            knowledge=mismatched,
        )


def test_cross_domain_reasoning_requires_all_five_domains() -> None:
    knowledge = _knowledge()
    graph = _attack_graph()
    report = CrossDomainAttackReasoner().reason(
        knowledge=knowledge,
        attack_graph=graph,
    )
    assert report.paths
    assert report.paths[0].domains == tuple(SecurityDomain)
    assert report.paths[0].hypothesis_status == "potential"
    assert report.paths[0].advisory_only is True
    assert "causal_oracle" in report.paths[0].missing_evidence

    incomplete = AttackGraph(
        nodes={"only:identity": _attack_graph().nodes["graph:identity"]}
    )
    blocked = CrossDomainAttackReasoner().reason(
        knowledge=TargetKnowledgeV2(engagement_id="e2", target_id="t2"),
        attack_graph=incomplete,
    )
    assert not blocked.paths
    assert blocked.blocked_reasons


def test_evidence_intelligence_is_tri_state_and_fail_closed() -> None:
    engine = EvidenceIntelligenceV2()
    empty = engine.assess(hypothesis_id="h1", items=())
    assert empty.interpretation == "insufficient"
    assert "causal_signal" in empty.missing_requirements
    items = (
        EvidenceItem(
            evidence_id="e1",
            hypothesis_id="h1",
            source_ref="source:1",
            description="Candidate observation",
            polarity=EvidencePolarity.SUPPORTS,
            confidence=0.9,
            causal_signal=True,
        ),
        EvidenceItem(
            evidence_id="e2",
            hypothesis_id="h1",
            source_ref="source:1",
            description="Independent contradiction",
            polarity=EvidencePolarity.CONTRADICTS,
            confidence=0.7,
            independent_control=True,
        ),
    )
    mixed = engine.assess(hypothesis_id="h1", items=items)
    assert mixed.interpretation == "mixed"
    assert mixed.conflicts
    assert "sealed_proof_bundle" in mixed.missing_requirements
    with pytest.raises(ValueError, match="scope_mismatch"):
        engine.assess(
            hypothesis_id="h1",
            items=(items[0].model_copy(update={"hypothesis_id": "h2"}),),
        )


def test_optimizer_is_scoped_deterministic_and_deprioritizes_blocked_strategy() -> None:
    observation = StrategyObservation(
        **SCOPE,
        strategy_id="strategy:ownership",
        direction=ResearchDirection.RELATIONSHIP,
        outcome=StrategyOutcome.BLOCKED,
        cost=80.0,
        evidence_quality=0.1,
        reason="missing causal control",
    )
    optimizer = ResearchStrategyOptimizerV2()
    report = optimizer.optimize(
        **SCOPE,
        current_direction=ResearchDirection.RELATIONSHIP,
        observations=(observation,),
        candidate_strategies=(
            ("strategy:ownership", ResearchDirection.RELATIONSHIP),
            ("strategy:workflow", ResearchDirection.WORKFLOW),
        ),
    )
    repeat = optimizer.optimize(
        **SCOPE,
        current_direction=ResearchDirection.RELATIONSHIP,
        observations=(observation,),
        candidate_strategies=(
            ("strategy:ownership", ResearchDirection.RELATIONSHIP),
            ("strategy:workflow", ResearchDirection.WORKFLOW),
        ),
    )
    assert report.deterministic_basis_hash == repeat.deterministic_basis_hash
    assert report.learned_observation_count == 1
    assert report.advisory_only is True
    assert all(item.priority < 1.0 for item in report.priorities)
    with pytest.raises(ValueError, match="scope_mismatch"):
        optimizer.optimize(
            **SCOPE,
            current_direction=ResearchDirection.RELATIONSHIP,
            observations=(observation.model_copy(update={"target_id": "other"}),),
        )


def test_memory_delegates_to_scoped_store_and_redacts_secrets() -> None:
    memory = AutonomousResearchMemoryV2(**SCOPE)
    lesson = memory.remember_lesson(
        category="failed_path",
        summary="Candidate path was blocked; Authorization: Bearer abcdef must not persist.",
        outcome="blocked",
        evidence_refs=("obs:1",),
    )
    assert lesson is not None
    assert "abcdef" not in lesson.summary
    assert "[REDACTED]" in lesson.summary
    assert memory.snapshot().isolated is True
    assert memory.snapshot().authoritative is False
    assert memory.retrieve("blocked")
    with pytest.raises(ValueError, match="unsupported_researcher"):
        memory.remember_lesson(
            category="untrusted-category",
            summary="invalid category",
            outcome="blocked",
        )
    other = AutonomousResearchMemoryV2(engagement_id="eng-2", target_id="target-1")
    assert not other.retrieve("blocked")


def test_core_composition_is_offline_advisory_and_review_stays_insufficient() -> None:
    report = AVRIPCoreV2().analyze(
        world_model=_world(),
        knowledge=_knowledge(),
        attack_graph=_attack_graph(),
        current_direction=ResearchDirection.RELATIONSHIP,
        memory_lessons=(
            (
                "environment_limitation",
                "No causal lab is available",
                "blocked",
                ("obs:limit",),
            ),
        ),
    )
    assert report.intent.engagement_id == SCOPE["engagement_id"]
    assert report.reasoning.hypotheses
    assert report.cross_domain.paths
    assert all(item.interpretation == "insufficient" for item in report.evidence_assessments)
    assert all(item.disposition == "insufficient" for item in report.reviews)
    assert report.requests_emitted is False
    assert report.findings_created == 0
    assert report.qualification_effect is False
    assert report.advisory_only is True
    assert report.memory.isolated is True


def test_senior_review_never_promotes_without_central_review_and_complete_proof() -> None:
    world = _world()
    assumptions = SecurityAssumptionDiscoveryEngine().discover(world_model=world).assumptions
    hypothesis = DeepVulnerabilityReasoner().reason(
        world_model=world,
        assumptions=assumptions,
    ).hypotheses[0]
    evidence = EvidenceIntelligenceV2().assess(
        hypothesis_id=hypothesis.hypothesis_id,
        items=(),
    )
    assessment = SeniorResearchReviewerV2().assess(
        hypothesis=hypothesis,
        evidence=evidence,
        alternative_explanations=("Reachability alone is not causal proof",),
        central_review_passed=True,
    )
    assert assessment.disposition == "insufficient"
    assert assessment.creates_finding is False
    assert assessment.grants_signoff is False
    assert assessment.changes_qualification is False
    assert assessment.execution_capability is False
