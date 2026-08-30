from webpent.irta.metrics import CaseOutcome, IrtaBenchmark, measure_learning, score_outcomes


def test_benchmark_builds_ten_independent_targets_and_adversarial_tiers():
    result = IrtaBenchmark().build(tuple(range(10)))
    assert result.targets == 10
    assert result.cases == 160
    assert len(result.tiers) == 40
    assert result.score.evaluated == 0
    assert result.score.blocked == 40


def test_learning_measurement_reports_recall_delta_without_inventing_cases():
    baseline = score_outcomes(
        (CaseOutcome("a", True, "confirmed"), CaseOutcome("b", True, "clean"))
    )
    later = score_outcomes(
        (
            CaseOutcome("a", True, "confirmed"),
            CaseOutcome("b", True, "confirmed"),
            CaseOutcome("c", True, "confirmed"),
        )
    )
    measurement = measure_learning(baseline, later)
    assert measurement.baseline_cases == 2
    assert measurement.later_cases == 3
    assert measurement.recall_delta > 0
