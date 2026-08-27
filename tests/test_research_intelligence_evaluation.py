from __future__ import annotations

from webpent.benchmark.research_intelligence import (
    ResearchEvaluationCase,
    evaluate_research_intelligence,
)


def test_internal_evaluation_is_deterministic_and_lab_scoped() -> None:
    cases = [
        ResearchEvaluationCase(
            case_id="idor-1",
            target_id="controlled-a",
            hypothesis_generated=True,
            rank=1,
            expected_rank=1,
            information_gain=0.9,
            evidence_quality=1.0,
            validation_outcome="confirmed",
            ground_truth_outcome="confirmed",
            proof_complete=True,
            requests_used=3,
        ),
        ResearchEvaluationCase(
            case_id="blocked-1",
            target_id="controlled-a",
            hypothesis_generated=True,
            rank=2,
            expected_rank=2,
            information_gain=0.4,
            evidence_quality=0.5,
            validation_outcome="blocked",
            ground_truth_outcome="blocked",
            proof_complete=False,
            requests_used=0,
        ),
    ]
    first = evaluate_research_intelligence(engagement_id="eng", cases=cases)
    second = evaluate_research_intelligence(engagement_id="eng", cases=list(reversed(cases)))

    assert first == second
    assert first.case_count == 2
    assert first.target_ids == ("controlled-a",)
    assert first.hypothesis_quality == 1.0
    assert first.validation_accuracy == 1.0
    assert first.proof_completeness == 0.5
    assert first.controlled_experiment is True
    assert first.real_world_detection_rate_measured is False
    assert first.qualification_effect is False


def test_evaluation_does_not_convert_missing_ground_truth_into_accuracy() -> None:
    report = evaluate_research_intelligence(
        engagement_id="eng",
        cases=[
            ResearchEvaluationCase(
                case_id="observation-only",
                target_id="target",
                validation_outcome="confirmed",
                evidence_quality=0.4,
            )
        ],
    )
    assert report.validation_accuracy is None
    assert report.real_world_detection_rate_measured is False
