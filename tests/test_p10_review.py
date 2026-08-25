from __future__ import annotations

import json
from pathlib import Path

from webpent.benchmark.p10_review import validate_mapping_review

_ROOT = Path(__file__).parents[1]

MAPPING_HASH = "sha256:mapping"
ORACLE_HASH = "sha256:oracle"
CASES = ["case-1", "case-2"]
OOS = ["case-oos"]
EXCLUSIONS = [
    "live_precision_recall",
    "p10_qualification",
    "vip_qualification",
    "http_200_as_finding",
    "blocked_inventory_rows_as_tp",
]


def _review(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "reviewer_id": "independent-reviewer:grok-p10-mapping",
        "reviewer_type": "external_mapping_reviewer_non_human_identifier",
        "approval_scope": "case_mapping_and_safety_posture_only",
        "approved": True,
        "full_p10_qualification_approved": False,
        "mapping_hash": MAPPING_HASH,
        "oracle_contract_hash": ORACLE_HASH,
        "approved_case_count": 2,
        "approved_class_count": 2,
        "approved_case_ids": CASES,
        "out_of_scope_confirmed": OOS,
        "explicitly_not_approving": EXCLUSIONS,
        "results_seen_by_reviewer": False,
    }
    value.update(overrides)
    return value


def _validate(review: dict[str, object]) -> dict[str, object]:
    return validate_mapping_review(
        review,
        expected_mapping_hash=MAPPING_HASH,
        expected_oracle_contract_hash=ORACLE_HASH,
        expected_case_ids=CASES,
        expected_class_count=2,
        expected_out_of_scope_case_ids=OOS,
    )


def test_valid_mapping_review_passes_without_full_qualification() -> None:
    result = _validate(_review())

    assert result == {
        "valid": True,
        "mapping_approved": True,
        "full_p10_qualification_approved": False,
        "blocking_reasons": [],
    }


def test_hash_mismatch_fails_closed() -> None:
    result = _validate(_review(mapping_hash="sha256:wrong"))

    assert result["valid"] is False
    assert "mapping_review_hash_mismatch" in result["blocking_reasons"]


def test_simulation_reviewer_cannot_approve_mapping() -> None:
    result = _validate(_review(reviewer_id="simulation:fixture"))

    assert result["valid"] is False
    assert "simulation_reviewer_cannot_approve_mapping" in result["blocking_reasons"]


def test_reviewer_type_must_be_explicitly_non_human_mapping_reviewer() -> None:
    result = _validate(_review(reviewer_type="human"))

    assert result["valid"] is False
    assert "mapping_review_reviewer_type_invalid" in result["blocking_reasons"]


def test_missing_approved_case_ids_fails_closed() -> None:
    result = _validate(_review(approved_case_ids=[]))

    assert result["valid"] is False
    assert "mapping_review_case_ids_mismatch" in result["blocking_reasons"]


def test_missing_explicit_exclusion_fails_closed() -> None:
    result = _validate(_review(explicitly_not_approving=EXCLUSIONS[:-1]))

    assert result["valid"] is False
    assert "mapping_review_explicit_exclusions_missing" in result["blocking_reasons"]


def test_full_qualification_claim_is_rejected() -> None:
    result = _validate(_review(full_p10_qualification_approved=True))

    assert result["valid"] is False
    assert "mapping_review_cannot_claim_full_p10_qualification" in result["blocking_reasons"]


def test_committed_ground_truth_records_mapping_only_review() -> None:
    document = json.loads(
        (_ROOT / "docs/juice_shop_p10_ground_truth_v1.json").read_text(
            encoding="utf-8"
        )
    )
    cases = document["cases"]
    review = document["independence"]["mapping_review"]
    result = validate_mapping_review(
        review,
        expected_mapping_hash=(
            "sha256:602b2411df9b259911b1ae0757e5e26fabdc86b928fb5b43b040750182762ad5"
        ),
        expected_oracle_contract_hash=(
            "sha256:63977f8451f0709abff5671d1ac24943abe35b0bb0a4f399791e2c1f66aeb71c"
        ),
        expected_case_ids=[
            case["case_id"] for case in cases if case["mapping_status"] == "approved"
        ],
        expected_class_count=6,
        expected_out_of_scope_case_ids=review["out_of_scope_confirmed"],
    )

    assert result["valid"] is True
    assert document["independence"]["reviewer_approval"] is False
    assert document["independence"]["full_p10_qualification_approved"] is False
    assert document["status"] == "mapping_approved_oracles_frozen_pending_full_runs"
    assert (
        document["independence"]["review_status"]
        == "mapping_approved_pending_oracle_freeze_and_full_runs"
    )
