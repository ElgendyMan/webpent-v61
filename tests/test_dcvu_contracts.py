from __future__ import annotations

import pytest

from webpent.dcvu import (
    CaseDisposition,
    DcvRun,
    GroundTruthRecord,
    TargetProfile,
    VulnerabilityCase,
)


def _target() -> TargetProfile:
    return TargetProfile(
        target_id="fixture-a",
        version="1.0.0",
        source_digest="sha256:fixture-a-v1",
        semantic_family="authorization_fixture",
    )


def _case(**overrides: object) -> VulnerabilityCase:
    payload: dict[str, object] = {
        "case_id": "fixture-a.idor.v1",
        "target_id": "fixture-a",
        "vulnerability_class": "idor_bola",
        "title": "owner binding",
        "oracle_id": "oracle.owner_binding.v1",
        "negative_control_id": "control.same_owner.v1",
    }
    payload.update(overrides)
    return VulnerabilityCase(**payload)


def test_accepted_case_requires_oracle_and_negative_control() -> None:
    with pytest.raises(ValueError, match="causal oracle"):
        _case(oracle_id="").validate()
    with pytest.raises(ValueError, match="negative control"):
        _case(negative_control_id="").validate()


def test_credentials_login_and_mutation_cases_fail_closed() -> None:
    with pytest.raises(ValueError, match="credentials"):
        _case(requires_credentials=True).validate()
    with pytest.raises(ValueError, match="credentials"):
        _case(requires_login=True).validate()
    with pytest.raises(ValueError, match="credentials"):
        _case(requires_mutation=True).validate()


def test_non_accepted_case_can_record_reason_without_being_scored() -> None:
    case = _case(
        disposition=CaseDisposition.BLOCKED,
        oracle_id="",
        negative_control_id="",
    )
    case.validate()
    assert case.disposition is CaseDisposition.BLOCKED


def test_ground_truth_requires_independent_review_and_digest() -> None:
    record = GroundTruthRecord(
        case=_case(),
        exists=True,
        location_fingerprint="fixture-a:resource-owner-binding",
        expected_impact="cross-owner read",
        source_evidence_digest="sha256:ground-truth-a",
        independent_review_id="review-dcvu-a-001",
    )
    record.validate()


def test_run_invariants_disable_side_effects_and_qualification() -> None:
    run = DcvRun(run_id="dcvu-v1-contracts", targets=[_target()], cases=[_case()])
    run.validate()
    assert run.governance["official_isolated_p10_runs_authorized"] is False
    assert run.governance["qualification_effect"] is False


def test_target_profile_rejects_credentials_or_mutation() -> None:
    with pytest.raises(ValueError, match="credentials and mutation"):
        TargetProfile(
            target_id="fixture-a",
            version="1.0.0",
            source_digest="sha256:fixture-a-v1",
            semantic_family="authorization_fixture",
            credentials_enabled=True,
        ).validate()
