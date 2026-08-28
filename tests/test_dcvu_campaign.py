from __future__ import annotations

from webpent.dcvu import (
    AutonomousDcvCampaign,
    build_default_fixtures,
    build_ground_truth_registry,
)


def test_campaign_runs_same_loop_over_three_targets() -> None:
    fixtures = build_default_fixtures()
    registry = build_ground_truth_registry(fixtures)
    run, traces = AutonomousDcvCampaign().run(fixtures, registry)
    assert run.run_id == "dcvu-v1-local-campaign"
    assert len(run.targets) == 3
    assert len(run.cases) == 18
    assert len(run.evaluations) == 18
    assert len(traces) == 3
    assert all(trace.discovered_surface_count == 6 for trace in traces)
    assert all(not trace.execution_events for trace in traces)
    assert all(flag is False for flag in run.governance.values())


def test_campaign_is_deterministic() -> None:
    fixtures = build_default_fixtures()
    registry = build_ground_truth_registry(fixtures)
    first, first_trace = AutonomousDcvCampaign().run(fixtures, registry)
    second, second_trace = AutonomousDcvCampaign().run(fixtures, registry)
    assert [item.verdict for item in first.evaluations] == [
        item.verdict for item in second.evaluations
    ]
    assert first_trace == second_trace
