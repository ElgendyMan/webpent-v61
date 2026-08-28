from __future__ import annotations

from webpent.dcvu import (
    AutonomousDcvCampaign,
    attach_metrics,
    build_default_fixtures,
    build_ground_truth_registry,
)


def test_metrics_are_computed_per_target() -> None:
    fixtures = build_default_fixtures()
    registry = build_ground_truth_registry(fixtures)
    run, _ = AutonomousDcvCampaign().run(fixtures, registry)
    attach_metrics(run)
    assert len(run.metrics) == 3
    assert all(metric.attempted_cases == 6 for metric in run.metrics)
    assert all(metric.scored_cases == 6 for metric in run.metrics)
    assert all(metric.false_positive == 0 for metric in run.metrics)
    assert all(metric.false_negative == 0 for metric in run.metrics)
    assert all(metric.precision == 1.0 for metric in run.metrics)
    assert all(metric.recall == 1.0 for metric in run.metrics)
    assert all(metric.f1 == 1.0 for metric in run.metrics)
    assert all(metric.proof_completeness == 1.0 for metric in run.metrics)
    assert all(metric.scoring_eligible for metric in run.metrics)


def test_metrics_are_not_official_qualification() -> None:
    fixtures = build_default_fixtures()
    registry = build_ground_truth_registry(fixtures)
    run, _ = AutonomousDcvCampaign().run(fixtures, registry)
    attach_metrics(run)
    assert run.governance["official_isolated_p10_runs_authorized"] is False
    assert run.governance["qualification_effect"] is False
