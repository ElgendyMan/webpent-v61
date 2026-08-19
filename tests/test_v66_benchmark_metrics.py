from __future__ import annotations

import pytest

from webpent.benchmark.metrics import evaluate


def test_benchmark_metrics_are_explicit_and_reproducible() -> None:
    report = evaluate(
        ["idor", "xss", "false-positive"],
        ["idor", "xss", "sqli"],
        evidence_complete={"idor": True, "xss": True, "false-positive": False},
        tested_surface_count=8,
        total_surface_count=10,
        independent_runs=[
            ["idor", "xss", "false-positive"],
            ["idor", "xss", "false-positive"],
        ],
    )
    assert report.true_positive_count == 2
    assert report.false_positive_count == 1
    assert report.missed_count == 1
    assert report.precision == 2 / 3
    assert report.recall == 2 / 3
    assert report.false_positive_rate == 1 / 3
    assert report.evidence_quality == pytest.approx(2 / 3, abs=1e-6)
    assert report.coverage == 0.8
    assert report.reproducibility == 1.0


def test_benchmark_empty_denominators_fail_closed_to_zero() -> None:
    report = evaluate([], [], tested_surface_count=3, total_surface_count=0)
    assert report.precision == 0.0
    assert report.recall == 0.0
    assert report.false_positive_rate == 0.0
    assert report.coverage == 0.0
    assert report.reproducibility == 0.0
