from webpent.validation import (
    validate_identity_differential,
    validate_state_diff,
)


def test_identity_403_vs_200_is_candidate_only() -> None:
    result = validate_identity_differential(
        {
            "engagement_id": "eng-1",
            "target_id": "target-1",
            "identity_ref": "identity-owner",
            "status_code": 403,
            "evidence_refs": ["owner:response"],
        },
        {
            "engagement_id": "eng-1",
            "target_id": "target-1",
            "identity_ref": "identity-foreign",
            "status_code": 200,
            "evidence_refs": ["foreign:response"],
        },
    )

    assert result.differential_signal is True
    assert result.status == "candidate_validation_required"
    assert result.promotion_eligible is False
    assert "central_sealed_replayable_proof_bundle" in result.required_validation


def test_identity_cross_engagement_is_rejected_fail_closed() -> None:
    result = validate_identity_differential(
        {
            "engagement_id": "eng-1",
            "target_id": "target-1",
            "identity_ref": "identity-owner",
            "status_code": 403,
        },
        {
            "engagement_id": "eng-2",
            "target_id": "target-1",
            "identity_ref": "identity-foreign",
            "status_code": 200,
        },
    )

    assert result.differential_signal is False
    assert result.reason == "engagement_id_mismatch"
    assert result.promotion_eligible is False


def test_state_diff_requires_evidence_refs_and_never_promotes() -> None:
    missing_refs = validate_state_diff(
        {"state_fingerprint": "state-a"},
        {"state_fingerprint": "state-b"},
    )
    valid = validate_state_diff(
        {"state_fingerprint": "state-a", "evidence_refs": ["state:before"]},
        {"state_fingerprint": "state-b", "evidence_refs": ["state:after"]},
    )

    assert missing_refs.differential_signal is True
    assert missing_refs.valid is False
    assert valid.valid is True
    assert valid.status == "candidate_state_difference"
    assert valid.promotion_eligible is False
