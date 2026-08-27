from __future__ import annotations

import pytest

from webpent.vabhfil_v8 import (
    AutonomousHypothesisEvolutionV8,
    AutonomousResearchExecutiveV8,
    AutonomousResearchMemoryIntelligenceV8,
    AutonomousResearchQualityEvaluatorV8,
    ExpertFalsePositiveDefenseV8,
    ExpertSecurityReasoningModelV8,
    VABHFILV8Core,
    VIPArchitectureReadinessReviewerV8,
    VIPControlledBenchmarkV7,
)
from webpent.vabhfil_v8.contracts import (
    ExecutiveResearchDecisionV8,
    HypothesisDisposition,
    ResearchConfidenceReportV8,
    V8Status,
)


def test_executive_decision_contains_reasoning_and_fail_closed_controls() -> None:
    decision = AutonomousResearchExecutiveV8().decide(
        engagement_id="e1",
        target_id="t1",
        coverage={"coverage_gaps": ("ownership invariant",)},
    )
    assert decision.investigation_priority == "medium"
    assert decision.reasoning_chain
    assert decision.evidence_requirements
    assert decision.risk == 0.0
    assert not decision.execution_requested
    assert not decision.finding_created


def test_reasoning_model_emits_complete_chain_for_each_assumption() -> None:
    model = {
        "security_assumptions": ("role controls object access", "workflow state is enforced"),
        "trust_relationships": ("user to resource boundary",),
        "sensitive_workflows": ("approval workflow",),
    }
    investigations = ExpertSecurityReasoningModelV8().investigate(
        engagement_id="e1", target_id="t1", mental_model=model
    )
    assert len(investigations) == 2
    assert all(
        item.security_question and item.evidence_needed and item.validation_approach
        for item in investigations
    )
    assert all(not item.confirmation_claimed for item in investigations)


def test_strategy_adapts_after_failure_and_graph_stays_unconfirmed() -> None:
    result = VABHFILV8Core().run(
        engagement_id="e1",
        target_id="t1",
        mental_model={"security_assumptions": ("owner check",), "protected_assets": ("record",)},
        attack_graph={"identities": ("requester",), "permissions": ("read",), "actions": ("view",)},
        previous_failures=("insufficient evidence",),
    )
    assert result.strategy.mode.value == "alternative_hypothesis_testing"
    assert result.graph_update.added_nodes
    assert not result.graph_update.confirmation_claimed
    assert result.requests_sent == 0
    assert not result.finding_created


def test_hypothesis_evolution_preserves_history_and_rejects_conflict() -> None:
    investigation = ExpertSecurityReasoningModelV8().investigate(
        engagement_id="e1", target_id="t1", assumptions=("role check",)
    )
    manager = AutonomousHypothesisEvolutionV8()
    hypotheses = manager.create(investigation)
    updated = manager.compare(
        hypotheses,
        conflicting_evidence={hypotheses[0].hypothesis_id: ("intended behavior observed",)},
    )
    assert len(updated[0].confidence_history) == 2
    assert updated[0].disposition in (
        HypothesisDisposition.REJECTED,
        HypothesisDisposition.INCONCLUSIVE,
    )
    assert not updated[0].confirmation_claimed


def test_false_positive_defense_reports_missing_evidence_without_override() -> None:
    report = ExpertFalsePositiveDefenseV8().assess(
        subject_id="h1",
        intended_behavior_possible=True,
        attacker_capability_realistic=False,
        impact_proven=False,
        alternative_explanations=("configuration",),
        reproducible_by_another_researcher=False,
    )
    assert report.disposition == HypothesisDisposition.INCONCLUSIVE
    assert report.missing_evidence
    assert not report.oracle_overridden
    assert not report.confirmation_created


def test_memory_is_scoped_and_redacts_sensitive_values() -> None:
    memory = AutonomousResearchMemoryIntelligenceV8()
    lesson = memory.learn(
        engagement_id="e1",
        target_id="t1",
        pattern="auth token=secret-value",
        failed_approaches=("cookie=abc",),
        validation_lesson="do not persist password=pw",
    )
    assert lesson.redacted
    assert "secret-value" not in lesson.pattern
    assert "abc" not in lesson.failed_approaches[0]
    assert len(memory.for_scope(engagement_id="e1", target_id="t1")) == 1
    assert not memory.for_scope(engagement_id="e2", target_id="t1")


def test_benchmark_registers_six_blocked_cases_reproducibly() -> None:
    benchmark = VIPControlledBenchmarkV7()
    first = benchmark.run()
    second = benchmark.run()
    assert first == second
    assert first["registered_scenario_count"] == 6
    assert first["blocked_case_count"] == 6
    assert first["scorable_case_count"] == 0
    assert first["requests_sent"] == 0
    assert all(case["disposition"] == "blocked" for case in first["cases"])


def test_quality_score_is_null_without_valid_ground_truth() -> None:
    benchmark = VIPControlledBenchmarkV7().run()
    score = AutonomousResearchQualityEvaluatorV8().score(
        engagement_id="e1", target_id="t1", benchmark=benchmark, investigation_count=6
    )
    assert score.autonomy is None
    assert score.reasoning_depth is None
    assert score.real_world_detection_rate is None
    assert score.requests_sent == 0


def test_readiness_review_cannot_grant_vip_or_open_p10() -> None:
    benchmark = VIPControlledBenchmarkV7().run()
    score = AutonomousResearchQualityEvaluatorV8().score(
        engagement_id="e1", target_id="t1", benchmark=benchmark
    )
    review = VIPArchitectureReadinessReviewerV8().review(
        engagement_id="e1", target_id="t1", score=score, benchmark=benchmark
    )
    assert review.status == V8Status.BLOCKED
    assert not review.vip_approved
    assert not review.p10_opened
    assert not review.qualification_gates_modified


def test_core_digest_and_authority_flags_are_stable() -> None:
    result = VABHFILV8Core().run(
        engagement_id="e1", target_id="t1", coverage={"coverage_gaps": ("missing oracle",)}
    )
    assert result.digest() == result.digest()
    assert result.requests_sent == 0
    assert not result.mutations_performed
    assert not result.finding_created
    assert not result.qualification_approved


def test_contracts_reject_execution_and_confirmation_claims() -> None:
    with pytest.raises(ValueError, match="cannot_execute"):
        ExecutiveResearchDecisionV8(
            decision_id="d",
            direction="research",
            investigation_priority="low",
            reasoning_chain=("reason",),
            confidence=0.1,
            expected_value=0.1,
            uncertainty=0.9,
            cost=0.1,
            risk=0.0,
            evidence_requirements=("oracle",),
            strategy_change="none",
            stop_decision="stop",
            execution_requested=True,
        )
    with pytest.raises(ValueError, match="cannot_override"):
        ResearchConfidenceReportV8(
            report_id="r",
            subject_id="s",
            intended_behavior_possible=False,
            attacker_capability_realistic=True,
            impact_proven=True,
            alternative_explanations=(),
            reproducible_by_another_researcher=True,
            missing_evidence=(),
            confidence=1.0,
            oracle_overridden=True,
        )
