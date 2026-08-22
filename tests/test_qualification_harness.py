from __future__ import annotations

import pytest

from webpent.benchmark.qualification import (
    GroundTruthCase,
    QualificationFixture,
    QualificationRun,
    run_offline_qualification,
)


@pytest.fixture
def fixture() -> QualificationFixture:
    return QualificationFixture(
        fixture_id="offline-idor-fixture",
        target_ref="fixture://idor",
        ground_truth=(
            GroundTruthCase("case-a", "idor"),
            GroundTruthCase("case-b", "workflow"),
        ),
        scenario={"mode": "deterministic", "note": "api_key=not-retained"},
    )


def test_offline_harness_is_reproducible_and_separates_discovery_from_confirmation(
    fixture: QualificationFixture,
) -> None:
    def runner(current: QualificationFixture, repetition: int) -> QualificationRun:
        assert current.fixture_id == fixture.fixture_id
        return QualificationRun(
            run_id=f"{current.fixture_id}:run:{repetition}",
            target_ref=current.target_ref,
            evidence_artifact="evidence://offline/fixture",
            candidate_case_ids=("case-a", "case-b", "case-fp"),
            confirmed_case_ids=("case-a",),
            proof_case_ids=("case-a", "case-b"),
            replay_case_ids=("case-a", "case-b"),
            reviewed_case_ids=("case-a", "case-b"),
            unauthorized_attempts=0,
            out_of_scope_attempts=0,
            budget_spent=2.0,
            budget_limit=4.0,
            stop_reason="information_gain_below_threshold",
        )

    result = run_offline_qualification([fixture], runner, repetitions=3)
    summary = result.matrix.summary()

    assert result.reproducible is True
    assert len(result.run_digests) == 3
    assert summary["candidate_cases"] == 3
    assert summary["confirmed_expected_cases"] == 1
    assert summary["candidate_false_positives"] == 1
    assert summary["candidate_false_negative_cases"] == 0
    assert summary["proof_replay_agreement_rate"] == 1.0
    assert summary["unauthorized_attempts"] == 0
    assert summary["out_of_scope_attempts"] == 0
    assert summary["budget_spent"] == 6.0
    assert summary["stop_reasons"] == ["information_gain_below_threshold"]


def test_offline_harness_detects_non_reproducible_canonical_outcomes(
    fixture: QualificationFixture,
) -> None:
    def runner(current: QualificationFixture, repetition: int) -> QualificationRun:
        outcome = "positive" if repetition == 1 else "inconclusive"
        return QualificationRun(
            run_id=f"{current.fixture_id}:run:{repetition}",
            target_ref=current.target_ref,
            evidence_artifact="evidence://offline/fixture",
            candidate_case_ids=("case-a",),
            canonical_outcomes=(("case-a", outcome),),
            unauthorized_attempts=1 if repetition == 2 else 0,
            out_of_scope_attempts=2 if repetition == 2 else 0,
            budget_spent=1.0,
            budget_limit=1.0,
            stop_reason="budget_exhausted",
        )

    result = run_offline_qualification([fixture], runner, repetitions=2)

    assert result.reproducible is False
    assert result.matrix.summary()["unauthorized_attempts"] == 1
    assert result.matrix.summary()["out_of_scope_attempts"] == 2


def test_harness_rejects_bad_runner_and_invalid_repetition_count(
    fixture: QualificationFixture,
) -> None:
    with pytest.raises(ValueError, match="between 2 and 20"):
        run_offline_qualification(
            [fixture],
            lambda _fixture, _run: QualificationRun("x", "t", "e"),
            repetitions=1,
        )
    with pytest.raises(TypeError, match="QualificationRun"):
        run_offline_qualification(
            [fixture],
            lambda _fixture, _run: {"status": "bad"},  # type: ignore[arg-type]
            repetitions=2,
        )



def test_qualification_serialization_redacts_fixture_and_run_values(
    fixture: QualificationFixture,
) -> None:
    run = QualificationRun(
        run_id="run-secret=api_key=raw",
        target_ref="fixture://safe",
        evidence_artifact="evidence://safe",
        candidate_case_ids=("case-a",),
        canonical_outcomes=(("case-a", "api_key=raw-secret"),),
    )
    rendered = repr({"fixture": fixture.as_dict(), "run": run.as_dict()})

    assert "not-retained" not in rendered
    assert "raw-secret" not in rendered
    assert "[REDACTED]" in rendered
