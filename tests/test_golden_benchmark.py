from __future__ import annotations

import pytest

from webpent.benchmark.golden import (
    default_golden_cases,
    run_golden_benchmark,
)
from webpent.benchmark.metrics import evaluate


def test_metrics_distinguish_false_discovery_from_false_positive_rate() -> None:
    report = evaluate(
        ["idor", "known-negative"],
        ["idor"],
        negative_case_ids=["known-negative", "unseen-negative"],
    )

    assert report.false_discovery_rate == pytest.approx(0.5)
    assert report.false_positive_rate == pytest.approx(0.5)


def test_fpr_is_unknown_without_declared_negative_universe() -> None:
    report = evaluate(["idor", "unknown"], ["idor"])

    assert report.false_discovery_rate == pytest.approx(0.5)
    assert report.false_positive_rate == 0.0
    assert report.negative_case_count == 0


def test_default_golden_benchmark_is_deterministic_and_non_live() -> None:
    result = run_golden_benchmark()
    payload = result.as_dict()

    assert payload["fixture_type"] == "offline-contract-golden"
    assert payload["live_findings_claimed"] is False
    assert len(payload["cases"]) == 2

    complete = result.cases[0].evaluate()
    assert complete.precision == 1.0
    assert complete.recall == 1.0
    assert complete.evidence_quality == 1.0
    assert complete.reproducibility == 1.0

    incomplete = result.cases[1].evaluate()
    assert incomplete.precision == 0.5
    assert incomplete.recall == 0.5
    assert incomplete.false_discovery_rate == 0.5
    assert incomplete.false_positive_rate == 0.5
    assert incomplete.evidence_quality == 0.5
    assert incomplete.reproducibility == pytest.approx(2 / 3)


def test_golden_case_ids_are_unique() -> None:
    cases = default_golden_cases()
    assert len({case.case_id for case in cases}) == len(cases)
