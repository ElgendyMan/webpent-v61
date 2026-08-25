from webpent.shared.behavior_scenarios import BehaviorScenarioResult, ScenarioStatus
from webpent.shared.evaluation import (
    ObservabilityRecorder,
    QualificationScorecard,
    evaluate_behavior_results,
)


def _result(
    status: ScenarioStatus = ScenarioStatus.PASS, forbidden: tuple[str, ...] = ()
) -> BehaviorScenarioResult:
    return BehaviorScenarioResult(
        scenario_id="s1",
        version="1",
        status=status,
        expected_behavior=("safe",),
        actual_behavior=("safe",),
        forbidden_actions=("bad",),
        observed_forbidden_actions=forbidden,
        policy_decisions=(),
        redacted_trace=(),
    )


def test_behavior_evaluation_is_offline_and_counts_unsafe_events() -> None:
    evaluation = evaluate_behavior_results(
        (_result(), _result(ScenarioStatus.INCONCLUSIVE, ("bad",)))
    )
    assert evaluation.total == 2
    assert evaluation.passed == 1
    assert evaluation.unsafe_events == 1
    assert not evaluation.safe


def test_observability_is_bounded_and_redacted() -> None:
    recorder = ObservabilityRecorder(max_events=1)
    recorder.emit(
        "decision", run_id="r1", engagement_id="e1", password="fixture"
    )
    recorder.emit("second", token="fixture-token-value-456")
    snapshot = recorder.snapshot()
    assert len(snapshot) == 1
    assert "fixture-token-value-456" not in repr(snapshot)


def test_scorecard_never_claims_qualification_without_live_evidence() -> None:
    behavior = evaluate_behavior_results((_result(),))
    scorecard = QualificationScorecard.build(
        revision="abc123", behavior=behavior, full_regression_passed=True
    )
    assert scorecard.qualification_status == "blocked"
    assert "live:three_independent_runs_required" in scorecard.blockers
    assert not scorecard.as_dict().get("live_qualification_passed")
    payload = scorecard.as_dict()
    assert payload["readiness_score"] < 100
    assert payload["readiness_status"] == "below-threshold"
    assert len(payload["dimensions"]) == 8
    assert len(payload["integrity_signature"]) == 64
    assert payload["operator_signature_required"] is True


def test_scorecard_integrity_seal_is_deterministic_for_same_inputs() -> None:
    behavior = evaluate_behavior_results((_result(),))
    first = QualificationScorecard.build(
        revision="abc123", behavior=behavior, full_regression_passed=True
    )
    second = QualificationScorecard.build(
        revision="abc123", behavior=behavior, full_regression_passed=True
    )
    assert first.integrity_signature == second.integrity_signature
    assert first.qualification_status == "blocked"


def test_promotion_state_requires_successive_evidence_gates() -> None:
    behavior = evaluate_behavior_results((_result(),))

    engineering = QualificationScorecard.build(
        revision="abc123", behavior=behavior, full_regression_passed=True
    )
    assert engineering.promotion_state == "ENGINEERING_READY"

    evidence = QualificationScorecard.build(
        revision="abc123",
        behavior=behavior,
        full_regression_passed=True,
        evidence_ready=True,
    )
    assert evidence.promotion_state == "EVIDENCE_READY"

    benchmark = QualificationScorecard.build(
        revision="abc123",
        behavior=behavior,
        full_regression_passed=True,
        evidence_ready=True,
        live_qualification_runs=3,
        live_qualification_passed=True,
    )
    assert benchmark.promotion_state == "BENCHMARK_QUALIFIED"

    distributed = QualificationScorecard.build(
        revision="abc123",
        behavior=behavior,
        full_regression_passed=True,
        evidence_ready=True,
        live_qualification_runs=3,
        live_qualification_passed=True,
        distributed_qualification_passed=True,
    )
    assert distributed.promotion_state == "DISTRIBUTED_QUALIFIED"

    vip = QualificationScorecard.build(
        revision="abc123",
        behavior=behavior,
        full_regression_passed=True,
        evidence_ready=True,
        live_qualification_runs=3,
        live_qualification_passed=True,
        distributed_qualification_passed=True,
        release_artifacts_consistent=True,
        independent_review_approved=True,
    )
    assert vip.promotion_state == "VIP_QUALIFIED"
    assert vip.qualification_status == "qualified"


def test_promotion_state_never_skips_live_benchmark_or_distributed_gate() -> None:
    behavior = evaluate_behavior_results((_result(),))
    scorecard = QualificationScorecard.build(
        revision="abc123",
        behavior=behavior,
        full_regression_passed=True,
        evidence_ready=True,
        live_qualification_runs=3,
        live_qualification_passed=False,
        distributed_qualification_passed=True,
        release_artifacts_consistent=True,
        independent_review_approved=True,
    )
    assert scorecard.promotion_state == "EVIDENCE_READY"
    assert scorecard.promotion_state != "VIP_QUALIFIED"
    assert scorecard.qualification_status == "blocked"


def test_promotion_state_is_serialized_and_integrity_bound() -> None:
    behavior = evaluate_behavior_results((_result(),))
    scorecard = QualificationScorecard.build(
        revision="abc123",
        behavior=behavior,
        full_regression_passed=True,
        evidence_ready=True,
    )
    payload = scorecard.as_dict()
    assert payload["promotion_state"] == "EVIDENCE_READY"
    assert payload["evidence_ready"] is True
    assert len(payload["integrity_signature"]) == 64
    assert {
        "NOT_READY",
        "ENGINEERING_READY",
        "EVIDENCE_READY",
        "BENCHMARK_QUALIFIED",
        "DISTRIBUTED_QUALIFIED",
        "VIP_QUALIFIED",
    } >= {payload["promotion_state"]}


# End of appended promotion-state contract tests.
