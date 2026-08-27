from webpent.asros.reasoning import (
    ArgumentStep,
    ArgumentStepKind,
    ResearchArgumentChain,
    ResearchReasoningEngine,
)
from webpent.asros.world_model import (
    EvidenceLineage,
    InvariantKind,
    SecurityInvariant,
    SecurityWorldModel,
)
from webpent.intelligence.contracts import ResearchHypothesis
from webpent.knowledge.model_v2 import TargetKnowledgeV2
from webpent.models.findings import VulnClass


def _world() -> SecurityWorldModel:
    knowledge = TargetKnowledgeV2(
        engagement_id="eng-reasoning",
        target_id="target-loopback",
        observations={
            "obs": {
                "observation_id": "obs",
                "source": "controlled",
                "confidence": 0.9,
                "evidence_refs": ("obs-ref",),
            }
        },
    )
    return SecurityWorldModel.from_target_knowledge(
        knowledge,
        invariants=(
            SecurityInvariant(
                invariant_id="inv-owner",
                statement="A requester cannot access another owner's resource",
                kind=InvariantKind.OWNERSHIP,
                subject="requester",
                protected_resource="resource-42",
                lineage=EvidenceLineage(
                    source="controlled", evidence_refs=("inv-ref",), confidence=0.9
                ),
            ),
        ),
    )


def _hypothesis() -> ResearchHypothesis:
    return ResearchHypothesis(
        target_url="http://127.0.0.1:3000/resource/42",
        reason="Authorization boundary may not enforce resource ownership",
        evidence_needed=("owner control", "non-owner control"),
        attack_plan=("compare owner and non-owner responses", "require causal oracle"),
        vuln_class=VulnClass.IDOR,
        affected_asset="resource-42",
        evidence_refs=("hyp-ref",),
    )


def test_reasoning_engine_builds_deterministic_four_step_chain():
    engine = ResearchReasoningEngine()
    chain = engine.build_argument_chain(
        world_model=_world(),
        hypothesis=_hypothesis(),
        observation="Object identifier is exposed at /resource?id=42&token=should-not-leak",
        assumption_tested="ownership enforcement is the security boundary",
        memory_hints=("previous owner/non-owner comparison was low value",),
    )

    assert [step.kind for step in chain.steps] == [
        ArgumentStepKind.OBSERVATION,
        ArgumentStepKind.REASONING,
        ArgumentStepKind.HYPOTHESIS,
        ArgumentStepKind.VALIDATION,
    ]
    assert chain.validation_required is True
    assert chain.status == "potential"
    statements = " ".join(step.statement.lower() for step in chain.steps)
    assert "should-not-leak" not in statements
    assert "[redacted]" in statements
    assert chain.content_hash() == chain.content_hash()
    assert chain.evidence_refs


def test_reasoning_decision_is_bounded_and_delegates_execution():
    engine = ResearchReasoningEngine()
    chain = engine.build_argument_chain(
        world_model=_world(),
        hypothesis=_hypothesis(),
        observation="Object identifier is exposed",
        assumption_tested="ownership enforcement is the security boundary",
    )
    decision = engine.decide(chain, prior_failures=3)

    assert decision.action == "validate_hypothesis"
    assert decision.blocked is False
    assert decision.required_capability == "http_read"
    assert decision.execution_delegated is True
    assert decision.expected_gain < 0.75


def test_argument_chain_rejects_wrong_order_and_self_validation():
    common = {
        "chain_id": "chain-1",
        "target_id": "target",
        "hypothesis_id": "hypothesis",
        "why_it_matters": "reason",
        "assumption_tested": "assumption",
        "evidence_refs": ("ref",),
        "cheapest_validation_path": ("compare controls",),
    }
    steps = tuple(
        ArgumentStep(step_id=str(index), kind=kind, statement="statement")
        for index, kind in enumerate(
            (
                ArgumentStepKind.REASONING,
                ArgumentStepKind.OBSERVATION,
                ArgumentStepKind.HYPOTHESIS,
                ArgumentStepKind.VALIDATION,
            )
        )
    )
    try:
        ResearchArgumentChain(steps=steps, **common)
    except ValueError as exc:
        assert "argument_chain_order_invalid" in str(exc)
    else:
        raise AssertionError("wrong argument order was accepted")

    valid_steps = tuple(
        ArgumentStep(step_id=str(index), kind=kind, statement="statement")
        for index, kind in enumerate(
            (
                ArgumentStepKind.OBSERVATION,
                ArgumentStepKind.REASONING,
                ArgumentStepKind.HYPOTHESIS,
                ArgumentStepKind.VALIDATION,
            )
        )
    )
    try:
        ResearchArgumentChain(steps=valid_steps, status="validated", **common)
    except ValueError as exc:
        assert "argument_chain_cannot_self_validate" in str(exc)
    else:
        raise AssertionError("self-validating chain was accepted")
