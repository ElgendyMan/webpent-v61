from __future__ import annotations

import json

import pytest

from webpent.abhie import (
    ABHIECoreV4,
    AttackChainIntelligence,
    BoundaryCrossing,
    Disposition,
    EvidenceAssessment,
    EvidenceRef,
    EvidenceState,
    ExpertHypothesisEngine,
    ExpertStrategySelector,
    Hypothesis,
    Lifecycle,
    ReflectionMemory,
    ResearchBrainState,
    ResearchBrainStateStore,
    ResearchStrategyDecision,
    SecurityAssumption,
    SecurityBoundaryMapper,
    SeniorResearchReviewer,
)
from webpent.abhie.brain import ResearchBrainBuilder
from webpent.abhie.contracts import BrainObservation
from webpent.abhie.discovery import UnknownVulnerabilityDiscoveryEngine


def _observation(
    observation_id: str = "obs-1",
    *,
    asset: str = "resource-1",
    domain: str = "resource",
    evidence_refs: tuple[str, ...] = (),
) -> BrainObservation:
    return BrainObservation(
        observation_id=observation_id,
        target_ref="target-a",
        asset=asset,
        domain=domain,
        statement="recorded observation",
        evidence_refs=evidence_refs,
        confidence=0.7,
    )


def _assumption() -> SecurityAssumption:
    return SecurityAssumption(
        assumption_id="assumption-1",
        statement="owner boundary should hold",
        domain="authorization",
        affected_assets=("resource-1",),
        risk=0.7,
        source_refs=("evidence-1",),
        falsifiers=("candidate/control difference",),
    )


def test_brain_state_is_deterministic_scoped_and_restorable() -> None:
    evidence = EvidenceRef("evidence-1", "recorded", EvidenceState.PRESENT)
    builder = ResearchBrainBuilder()
    state = builder.build(
        target_ref="target-a",
        engagement_ref="eng-a",
        knowledge={
            "entities": {
                "entity-key": {"name": "catalog", "kind": "resource"}
            }
        },
        attack_graph={
            "nodes": {
                "node-key": {"node_id": "route-1", "kind": "endpoint"}
            }
        },
        invariants=({"name": "owner boundary", "domain": "authorization"},),
        evidence=(evidence,),
        history=("b", "a", "a"),
    )

    assert [item.asset for item in state.known] == ["route-1", "catalog"]
    restored = ResearchBrainState.restore(state.snapshot())
    assert restored == state
    assert restored.evidence[0].state is EvidenceState.PRESENT
    assert restored.digest() == state.digest()
    assert json.loads(state.snapshot())["version"] == "abhie-v4"
    with pytest.raises(ValueError, match="unsupported brain state version"):
        ResearchBrainState.restore(state.snapshot().replace("abhie-v4", "old"))

    store = ResearchBrainStateStore()
    store.put(state)
    other = ResearchBrainState("target-b", "eng-a")
    store.put(other)
    assert store.get("target-a", "eng-a") == state
    assert store.get("target-b", "eng-a") == other
    assert store.get("target-a", "eng-b") is None
    with pytest.raises(KeyError):
        store.snapshot("target-a", "eng-b")


def test_discovery_emits_five_unknown_directions_without_claiming_findings() -> None:
    state = ResearchBrainState(
        target_ref="target-a",
        engagement_ref="eng-a",
        known=(_observation(),),
        risky_assumptions=(_assumption(),),
    )
    directions = UnknownVulnerabilityDiscoveryEngine().discover(state)
    assert len(directions) == 5
    assert {item.category for item in directions} == {
        "unexpected_trust_relationship",
        "missing_authorization_boundary",
        "incorrect_workflow_assumption",
        "inconsistent_state_transition",
        "data_ownership_mistake",
    }
    assert all(item.validation_strategy for item in directions)
    assert all("causal oracle" in " ".join(item.validation_strategy) for item in directions)
    assert not any(hasattr(item, "finding_id") for item in directions)


def test_boundary_mapper_is_deterministic_and_marks_dangerous_crossings() -> None:
    mapper = SecurityBoundaryMapper()
    kwargs = {
        "target_ref": "target-a",
        "users": ({"id": "u1", "label": "requester"},),
        "roles": ({"id": "r1", "label": "admin role"},),
        "resources": ({"id": "resource-1", "label": "tenant record"},),
        "actions": ({"id": "a1", "label": "read"},),
        "workflows": ({"id": "w1", "label": "checkout"},),
        "states": ({"id": "s1", "label": "approved"},),
    }
    graph = mapper.map(**kwargs)
    assert graph == mapper.map(**kwargs)
    assert graph.digest
    assert any(item.source_node == "role:r1" for item in graph.crossings)
    assert mapper.dangerous_crossings(graph)
    empty = mapper.map(target_ref="empty")
    assert {node.kind for node in empty.nodes} == {"user", "resource"}


def test_competing_hypotheses_include_benign_alternative_and_are_advisory() -> None:
    crossing = BoundaryCrossing(
        "cross-1",
        "role:r1",
        "resource:resource-1",
        "role may access resource boundary",
        "admin can cross",
    )
    competition = ExpertHypothesisEngine().generate(
        observation_id="obs-1",
        assumptions=(_assumption(),),
        crossings=(crossing,),
        assets=("resource-1",),
    )
    assert len(competition.candidates) == 3
    assert any(item.hypothesis_id.endswith("-benign") for item in competition.candidates)
    assert competition.winner_id
    prioritized = ExpertHypothesisEngine().prioritize(competition)
    winner = next(
        item
        for item in prioritized.candidates
        if item.hypothesis_id == prioritized.winner_id
    )
    assert winner.lifecycle is Lifecycle.PRIORITIZED
    assert "causal" in " ".join(competition.rationale)


def test_strategy_selection_is_deterministic_and_blocks_unsafe_capabilities() -> None:
    decision = ExpertStrategySelector().select(
        hypothesis_id="h-1", available_capabilities=("recorded", "read-only")
    )
    assert isinstance(decision, ResearchStrategyDecision)
    assert decision.delegated_only is True
    assert decision.selected_strategy_id == "h-1:read-only-local"
    blocked = next(
        item
        for item in decision.candidates
        if item.strategy_id.endswith("state-changing")
    )
    assert blocked.eligible is False
    assert blocked.blocked_reasons
    assert all("mutation" in reason or "credential" in reason for reason in blocked.blocked_reasons)


def test_reflection_is_scoped_versioned_and_redacted() -> None:
    memory = ReflectionMemory()
    lesson_a = memory.record(
        target_ref="target-a",
        engagement_ref="eng-a",
        failed=("Authorization: Bearer bearer-secret",),
        next_changes=("keep read-only",),
    )
    memory.record(target_ref="target-b", engagement_ref="eng-a", worked=("other",))
    assert lesson_a.version == "1"
    assert memory.for_scope(target_ref="target-a", engagement_ref="eng-a") == (lesson_a,)
    assert memory.for_scope(target_ref="target-a", engagement_ref="eng-b") == ()
    assert "bearer-secret" not in str(memory.snapshot())
    brain = ResearchBrainState("target-a", "eng-a", research_history=("existing",))
    applied = memory.apply_to_brain(brain)
    assert lesson_a.lesson_id in applied.research_history
    assert applied.target_ref == brain.target_ref


def test_attack_chain_requires_evidence_and_never_promotes() -> None:
    left = Hypothesis(
        "h-left",
        "left",
        "why",
        ("ev-left",),
        ("missing",),
        ("benign",),
        ("validate",),
        ("asset",),
        confidence=0.8,
    )
    right = Hypothesis(
        "h-right",
        "right",
        "why",
        ("ev-right",),
        ("missing",),
        ("benign",),
        ("validate",),
        ("asset",),
        confidence=0.6,
    )
    chain = AttackChainIntelligence().build((right, left))[0]
    assert chain.evidence_dependencies == ("ev-left", "ev-right")
    assert chain.disposition is Disposition.ADVISORY
    assert "negative control" in " ".join(chain.validation_requirements)
    no_evidence = Hypothesis(
        "h-empty", "empty", "why", (), (), (), (), ("asset",), confidence=0.9
    )
    assert AttackChainIntelligence().build((left, no_evidence)) == ()


def test_reviewer_is_fail_closed_and_has_no_authority() -> None:
    winner = Hypothesis(
        "h-1", "statement", "why", (), ("causal",), (), ("validate",), ("asset",), confidence=0.5
    )
    evidence = EvidenceAssessment(
        EvidenceState.PRESENT,
        EvidenceState.PRESENT,
        EvidenceState.PRESENT,
        EvidenceState.PRESENT,
        1.0,
    )
    review = SeniorResearchReviewer().review(
        target_ref="target-a",
        hypothesis=winner,
        evidence=evidence,
        real_boundary=True,
        failed_assumption=True,
        impact_demonstrated=True,
    )
    assert review.disposition is Disposition.ADVISORY
    assert review.no_finding_created is True
    assert review.no_governance_override is True
    blocked = SeniorResearchReviewer().review(
        target_ref="target-a",
        hypothesis=winner,
        evidence=EvidenceAssessment(
            EvidenceState.MISSING,
            EvidenceState.MISSING,
            EvidenceState.MISSING,
            EvidenceState.MISSING,
            0.0,
        ),
        real_boundary=False,
        failed_assumption=False,
        impact_demonstrated=False,
    )
    assert blocked.disposition is Disposition.INSUFFICIENT
    assert blocked.no_finding_created is True


def test_core_is_deterministic_advisory_and_sends_zero_requests() -> None:
    brain = ResearchBrainState(
        target_ref="target-a",
        engagement_ref="eng-a",
        risky_assumptions=(_assumption(),),
    )
    observation = _observation(domain="user", asset="requester")
    result = ABHIECoreV4().run(brain=brain, observations=(observation,))
    repeat = ABHIECoreV4().run(brain=brain, observations=(observation,))
    assert result["requests"] == 0
    assert result["executed"] is False
    assert result["finding_created"] is False
    assert result["evidence"].strong_enough_for_confirmation is False
    assert result["review"].no_governance_override is True
    assert result["boundary_graph"] == repeat["boundary_graph"]
    assert result["competition"] == repeat["competition"]
    assert result["discovery_directions"]
    assert all(item.disposition is Disposition.ADVISORY for item in result["chains"])
