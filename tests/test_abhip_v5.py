from __future__ import annotations

import pytest

from webpent.abhip import (
    AutonomousResearchLoopV3,
    AutonomousResearchMemoryV3,
    AutonomousSecurityReviewerV3,
    DifferentialDimension,
    DifferentialReasoningEngine,
    ExpertVulnerabilityReasoningEngine,
    IntelligenceNode,
    LoopPhase,
    ResearchLesson,
    SecurityQuestion,
    TargetIntelligenceGraph,
)


def _graph(*, engagement_id: str = "eng-1", target_id: str = "target-1") -> TargetIntelligenceGraph:
    return TargetIntelligenceGraph(
        engagement_id=engagement_id,
        target_id=target_id,
        knowledge_hash="knowledge-hash",
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
        ),
        coverage_gaps=("ownership", "authorization"),
    )


def _question() -> SecurityQuestion:
    return SecurityQuestion(
        question_id="question-1",
        question="Can another identity access this object?",
        affected_assets=("resource-1",),
        security_assumption="Ownership boundary is enforced.",
        expected_evidence=("owner-control-pair",),
        validation_strategy=("causal-oracle",),
        priority=0.9,
    )


def test_differential_reasoning_is_explicit_and_fail_closed() -> None:
    engine = DifferentialReasoningEngine()
    blocked = engine.compare(
        engagement_id="eng-1",
        target_id="target-1",
        dimension=DifferentialDimension.IDENTITY,
        left_context="owner",
        right_context="foreign",
        left_observation={"status": "success", "response": {"allowed": True}},
        right_observation={"status": "success", "response": {"allowed": False}},
        observation_source="recorded-fixture",
        reasoning="Compare owner and foreign identity contexts.",
        possible_security_impact="Object authorization may differ.",
        validation_requirement="Require central causal oracle and negative control.",
    )
    assert blocked.blocked_reasons == (
        "negative_control_required",
        "replayability_required",
    )
    assert not blocked.comparisons[0].differential_signal
    assert not blocked.promotion_eligible

    ready = engine.compare(
        engagement_id="eng-1",
        target_id="target-1",
        dimension=DifferentialDimension.ROLE,
        left_context="role-a",
        right_context="role-b",
        left_observation={"status": "success", "response": {"allowed": True}},
        right_observation={"status": "success", "response": {"allowed": False}},
        observation_source="recorded-fixture",
        reasoning="Compare role contexts.",
        possible_security_impact="Role boundary may differ.",
        validation_requirement="Verify with independent negative control.",
        negative_control_complete=True,
        replayable=True,
    )
    assert ready.observation_count == 2
    assert ready.comparisons[0].differential_signal


def test_differential_reasoning_rejects_secret_shaped_input() -> None:
    report = DifferentialReasoningEngine().compare(
        engagement_id="eng-1",
        target_id="target-1",
        dimension=DifferentialDimension.STATE,
        left_context="before",
        right_context="after",
        left_observation={"headers": "Authorization: Bearer raw-secret"},
        right_observation={"response": {"state": "same"}},
        observation_source="recorded-fixture",
        reasoning="State comparison.",
        possible_security_impact="Unknown.",
        validation_requirement="Require a state oracle.",
        negative_control_complete=True,
        replayable=True,
    )
    assert "valueerror" in report.blocked_reasons
    assert report.observation_count == 0
    assert not report.comparisons[0].differential_signal


def test_research_loop_is_bounded_non_repeating_and_non_executing() -> None:
    loop = AutonomousResearchLoopV3(max_cycles=4)
    result = loop.run(
        graph=_graph(),
        questions=(_question(),),
        attempted_action_ids=("question-1",),
        failed_paths=("path-unavailable",),
    )
    phases = tuple(event.phase for event in result.checkpoint.events)
    assert phases == (
        LoopPhase.OBSERVE,
        LoopPhase.UNDERSTAND,
        LoopPhase.QUESTION,
        LoopPhase.HYPOTHESIS,
        LoopPhase.EXPERIMENT,
        LoopPhase.EVIDENCE,
        LoopPhase.EVALUATE,
        LoopPhase.LEARN,
    )
    assert result.repeated_paths_skipped == ("question-1",)
    assert result.checkpoint.stop_reason == "execution_boundary_closed"
    assert not result.execution_attempted
    assert not result.findings_created
    assert not result.promotion_eligible


def test_reasoning_and_reviewer_remain_advisory_and_fail_closed() -> None:
    report = ExpertVulnerabilityReasoningEngine().analyze(
        hypothesis_id="hyp-1",
        security_boundary="resource ownership",
        attacker_capability="foreign synthetic identity",
        required_conditions=("recorded owner/control pair",),
        impact="possible unauthorized object access",
        alternative_explanations=("fixture routing difference",),
        evidence_refs=("ev:left", "ev:right"),
        causal_oracle_present=False,
        validation_requirements=("central oracle", "replayable proof"),
    )
    assert report.disposition == "advisory_with_alternatives"
    assert report.evidence_strength == 0.5
    assert not report.finding_created

    assessment = AutonomousSecurityReviewerV3().review(report)
    assert assessment.status == "blocked"
    assert "causal_oracle_missing" in assessment.evidence_challenges
    assert "sealed_proof_bundle_missing" in assessment.reproducibility_challenges
    assert not assessment.qualification_approved
    assert not assessment.finding_created


def test_memory_v3_is_target_engagement_scoped_and_redacted() -> None:
    first = AutonomousResearchMemoryV3(engagement_id="eng-1", target_id="target-1")
    second = AutonomousResearchMemoryV3(engagement_id="eng-1", target_id="target-2")
    lesson = first.remember(
        lesson_id="lesson-1",
        category="failed_path",
        summary="Authorization: Bearer raw-secret must never be retained.",
        evidence_refs=("ev:1",),
        rationale="blocked by missing oracle",
    )
    assert isinstance(lesson, ResearchLesson)
    assert lesson.version == "abhip-memory-v3"
    assert first.scope != second.scope
    assert len(first.records) >= 1
    assert len(second.records) == 0
    assert "raw-secret" not in first.records[0].content
    assert first.summary()["target_isolated"] is True
    assert first.summary()["authoritative"] is False


def test_advisory_contracts_reject_authority_flags() -> None:
    with pytest.raises(ValueError, match="assessment_cannot_grant_authority"):
        from webpent.abhip.contracts import AutonomousSecurityAssessment

        AutonomousSecurityAssessment(
            engagement_id="eng-1",
            target_id="target-1",
            hypothesis_id="hyp-1",
            validity_challenges=(),
            evidence_challenges=(),
            impact_challenges=(),
            reasoning_challenges=(),
            reproducibility_challenges=(),
            status="ready",
            qualification_approved=True,
        )
