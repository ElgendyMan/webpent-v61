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
        "decision", run_id="r1", engagement_id="e1", password="fixture-password-value-123"
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
