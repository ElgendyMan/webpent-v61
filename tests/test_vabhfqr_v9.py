from __future__ import annotations

import pytest

from webpent.vabhfqr_v9 import (
    AutonomousResearchLoopV9,
    EvidenceDisposition,
    EvidenceIntelligenceV9,
    ResearchStateV9,
    V9AnalyticsReview,
    V9Status,
    VABHFQRV9Core,
    VIPBenchmarkSuiteV9,
)


def test_core_builds_architecture_questions_and_zero_request_result() -> None:
    result = VABHFQRV9Core().run(
        engagement_id="eng-1",
        target_id="target-recorded",
        recorded_state={
            "purpose": "recorded service",
            "critical_assets": ["asset-a"],
            "trust_boundaries": ["boundary-a"],
            "workflows": ["workflow-a"],
            "assumptions": ["role separation"],
            "invariants": ["owner access"],
            "privilege_model": ["owner", "requester"],
        },
    )
    assert result.requests_sent == 0
    assert result.finding_created is False
    assert result.architecture_map.critical_assets == ("asset-a",)
    assert (
        result.experiments[0].selected_action == "offline evidence review and causal-oracle design"
    )
    assert result.hypotheses[0].confidence_history == (0.20,)
    assert all(item.disposition is EvidenceDisposition.BLOCKED for item in result.evidence)


def test_closed_loop_state_snapshot_restore_and_recovery() -> None:
    loop = AutonomousResearchLoopV9()
    result, state = loop.run(engagement_id="eng-2", target_id="target-2")
    assert result.loop_steps[0].completed is True
    assert state.cycle == 1
    restored = ResearchStateV9.restore(state.snapshot())
    recovered = loop.recover(restored, "missing causal oracle")
    assert recovered.failures == ("missing causal oracle",)
    assert set(recovered.completed_stages) == {"observe", "understand", "reason", "plan"}


def test_experiment_plan_is_advisory_and_never_execution() -> None:
    result = VABHFQRV9Core().run(engagement_id="eng-3", target_id="target-3")
    assert all(not experiment.execution_requested for experiment in result.experiments)
    with pytest.raises(ValueError, match="experiment_plan_cannot_execute"):
        from webpent.vabhfqr_v9.contracts import ResearchExperimentPlanV9

        ResearchExperimentPlanV9(
            experiment_id="bad",
            question="q",
            selected_action="a",
            expected_information_gain=0.1,
            uncertainty_reduction=0.1,
            evidence_value=0.1,
            estimated_cost=0.1,
            risk=0.0,
            available_capability="none",
            preconditions=("p",),
            success_criteria=("s",),
            stop_conditions=("stop",),
            execution_requested=True,
        )


def test_evidence_requires_causal_sealed_replayable_package() -> None:
    intelligence = EvidenceIntelligenceV9()
    blocked = intelligence.assess(subject_id="h-1")
    assert blocked.disposition is EvidenceDisposition.BLOCKED
    confirmed = intelligence.assess(
        subject_id="h-1",
        observation_refs=("obs-candidate", "obs-control"),
        causal_oracle="candidate differs from intended behavior and control",
        proof_bundle_ref="pb-redacted",
        seal_verified=True,
        replay_verified=True,
    )
    assert confirmed.disposition is EvidenceDisposition.CONFIRMED
    assert intelligence.verify_replay(confirmed, "replay-digest") is True


def test_benchmark_has_eight_classes_and_blocks_missing_evidence() -> None:
    suite = VIPBenchmarkSuiteV9.from_recorded_state()
    summary = suite.summary()
    assert summary["registered_classes"] == 8
    assert summary["blocked_case_count"] == 8
    assert summary["scorable_case_count"] == 0
    assert summary["requests_sent"] == 0
    assert summary["qualification_claim"] is False


def test_analytics_separates_engineering_and_qualification_metrics() -> None:
    suite = VIPBenchmarkSuiteV9.from_recorded_state()
    score = V9AnalyticsReview().score(engagement_id="eng-4", target_id="t-4", suite=suite)
    review = V9AnalyticsReview().readiness(engagement_id="eng-4", target_id="t-4", suite=suite)
    assert score.engineering_metrics["transport_safety"] == 1.0
    assert score.qualification_metrics["f1"] is None
    assert review.status is V9Status.BLOCKED
    assert review.vip_approved is False
    assert review.p10_opened is False


def test_memory_isolation_is_explicit() -> None:
    first = VABHFQRV9Core().run(engagement_id="eng-a", target_id="target-a")
    second = VABHFQRV9Core().run(engagement_id="eng-b", target_id="target-b")
    assert first.memory_snapshot.target_id != second.memory_snapshot.target_id
    assert first.memory_snapshot.engagement_id != second.memory_snapshot.engagement_id
    assert first.memory_snapshot.version == "vabh-fqr-v9"


def test_invalid_authority_flags_fail_closed() -> None:
    with pytest.raises(ValueError, match="readiness_cannot_grant_authority"):
        from webpent.vabhfqr_v9.contracts import VIPReadinessAssessmentV9

        VIPReadinessAssessmentV9(
            engagement_id="e",
            target_id="t",
            architecture_maturity="x",
            autonomy="x",
            discovery_intelligence="x",
            evidence_pipeline="x",
            benchmark_quality="x",
            operational_reliability="x",
            limitations=(),
            blockers=(),
            vip_approved=True,
        )


def test_result_digest_is_stable_for_same_recorded_state() -> None:
    core = VABHFQRV9Core()
    one = core.run(
        engagement_id="eng-d",
        target_id="target-d",
        recorded_state={"assumptions": ["a"]},
    )
    two = core.run(
        engagement_id="eng-d",
        target_id="target-d",
        recorded_state={"assumptions": ["a"]},
    )
    assert one.digest() == two.digest()
    assert one.digest()


def test_previous_failures_change_next_reasoning_without_transport() -> None:
    result = VABHFQRV9Core().run(
        engagement_id="eng-f",
        target_id="target-f",
        previous_failures=("precondition blocked",),
    )
    assert "adapted" in result.loop_steps[0].rationale
    assert result.memory_snapshot.failed_experiments == ("precondition blocked",)
    assert result.requests_sent == 0
