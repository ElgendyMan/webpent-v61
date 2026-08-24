import pytest

from webpent.benchmark import measure_vip_v2, qualify_vip_v2
from webpent.benchmark.qualification import (
    GroundTruthCase,
    QualificationFixture,
    QualificationRun,
)

_FIXTURE = QualificationFixture(
    fixture_id="fixture-1",
    target_ref="offline://fixture-1",
    ground_truth=(
        GroundTruthCase(case_id="case-a", category="xss"),
        GroundTruthCase(case_id="case-b", category="idor"),
        GroundTruthCase(case_id="case-negative", category="sqli", expected=False),
    ),
)


def _runner(fixture: QualificationFixture, repetition: int) -> QualificationRun:
    return QualificationRun(
        run_id=f"{fixture.fixture_id}:run:{repetition}",
        target_ref=fixture.target_ref,
        evidence_artifact="artifact:offline",
        candidate_case_ids=("case-a", "case-b", "case-negative"),
        confirmed_case_ids=("case-a",),
        proof_case_ids=("case-a",),
        replay_case_ids=("case-a",),
        canonical_outcomes=(
            ("case-a", "confirmed"),
            ("case-b", "candidate"),
            ("case-negative", "candidate"),
        ),
    )


def test_vip_v2_requires_three_repetitions() -> None:
    with pytest.raises(ValueError, match="vip_v2_requires_at_least_three_repetitions"):
        qualify_vip_v2([_FIXTURE], _runner, repetitions=2)


def test_vip_v2_measures_supplied_runs_without_inference() -> None:
    result = qualify_vip_v2([_FIXTURE], _runner)
    metrics = measure_vip_v2(
        result,
        expected_case_ids=("case-a", "case-b"),
        negative_case_ids=("case-negative",),
        evidence_complete={"case-a": True, "case-b": False, "case-negative": False},
        tested_surface_count=2,
        total_surface_count=4,
    )

    assert result.reproducible is True
    assert len(result.matrix.runs) == 3
    assert metrics.independent_run_count == 3
    assert metrics.benchmark.true_positive_count == 2
    assert metrics.benchmark.false_positive_count == 1
    assert metrics.benchmark.missed_count == 0
    assert metrics.benchmark.false_positive_rate == 1.0
    assert metrics.benchmark.coverage == 0.5
    assert metrics.proof_rate == 1.0
    assert metrics.replay_success_rate == 1.0


def test_vip_v2_does_not_mark_live_qualification() -> None:
    result = qualify_vip_v2([_FIXTURE], _runner)
    assert result.matrix.summary()["live_qualification_proven"] is False
