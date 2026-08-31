from dataclasses import asdict

import pytest

from webpent.irta.v3 import (
    BlindEvaluationBoundary,
    CaseOutcome,
    GroundTruthCase,
)


def _boundary() -> BlindEvaluationBoundary:
    boundary = BlindEvaluationBoundary("target-alpha", "digest-alpha", "campaign-1")
    boundary.register_owner_case(
        GroundTruthCase(
            "case-1", "authorization", "object-route", CaseOutcome.CONFIRMED, "oracle-1"
        )
    )
    boundary.register_owner_case(
        GroundTruthCase("case-2", "authorization", "profile-route", CaseOutcome.CLEAN, "oracle-2")
    )
    return boundary


def test_detector_view_contains_no_truth_or_route_answer() -> None:
    view = _boundary().detector_view()
    public = asdict(view)
    assert public == {
        "target_id": "target-alpha",
        "runtime_digest": "digest-alpha",
        "campaign_id": "campaign-1",
        "network_scope": "loopback-only",
    }
    assert "vulnerability_class" not in public
    assert "expected_outcome" not in public
    assert "oracle_id" not in public


def test_owner_evaluates_observations_separately_from_detector_view() -> None:
    boundary = _boundary()
    observation = boundary.accept_observation("case-1", 200, "json-object", "redacted-body")
    assert observation.evidence_digest
    assert boundary.owner_evaluate((observation,)) == {"case-1": CaseOutcome.CONFIRMED}


def test_unknown_case_is_fail_closed_and_not_recorded() -> None:
    boundary = _boundary()
    with pytest.raises(ValueError, match="unknown case"):
        boundary.accept_observation("not-registered", 200, "json", "body")


def test_sensitive_or_external_route_reference_is_rejected() -> None:
    boundary = BlindEvaluationBoundary("target-alpha", "digest-alpha", "campaign-1")
    with pytest.raises(ValueError, match="unsafe"):
        boundary.register_owner_case(
            GroundTruthCase(
                "case-x",
                "authorization",
                "https://example.invalid",
                CaseOutcome.CONFIRMED,
                "oracle",

            )
        )
