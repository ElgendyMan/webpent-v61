"""Fail-closed boundary check for non-human AI review imports.

This validator records technical review evidence without allowing an imported
review to become a human signoff, an Official P10 authorization, or a
qualification decision.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"json_object_required:{path}")
    return value


def validate(review_path: Path, governance_path: Path) -> list[str]:
    errors: list[str] = []
    review = load(review_path)
    governance = load(governance_path)

    if review.get("record_type") != "external_review_bundle_metadata_only":
        errors.append("review_import_must_be_metadata_only")
    if review.get("raw_archive_imported") is not False:
        errors.append("raw_archive_must_not_be_imported")
    if review.get("reviewer_type") != "independent_non_human_attributable_reviewer":
        errors.append("reviewer_type_must_be_non_human_attributable")
    if review.get("reviewer_identity_is_human") is not False:
        errors.append("human_identity_must_not_be_claimed")
    if review.get("human_independent_signoff_obtained") is not False:
        errors.append("human_signoff_must_remain_false")

    for item in review.get("reviews", []):
        if not isinstance(item, dict):
            errors.append("review_entry_must_be_object")
            continue
        if item.get("human_independent_signoff_obtained") is not False:
            errors.append(f"human_signoff_must_remain_false:{item.get('decision_id')}")
        if item.get("official_isolated_p10_runs_authorized") is not False:
            errors.append(f"official_run_gate_must_remain_false:{item.get('decision_id')}")
        if item.get("reviewed_case_count") != 3 or item.get("reviewed_class_count") != 3:
            errors.append(f"review_snapshot_counts_unexpected:{item.get('decision_id')}")
        if item.get("reviewed_non_scoring_count") != 8:
            errors.append(f"review_snapshot_non_scoring_count_unexpected:{item.get('decision_id')}")

    effects = review.get("import_effect", {})
    for field in (
        "governance_packet_modified",
        "human_signoff_changed",
        "official_run_gate_changed",
        "qualification_changed",
        "scoring_set_changed",
    ):
        if effects.get(field) is not False:
            errors.append(f"import_effect_must_be_false:{field}")

    authority = governance.get("decision_authority", {})
    if authority.get("status") != "pending_independent_governance_signoff":
        errors.append("current_governance_must_remain_pending")
    if authority.get("independent_reviewer_id") is not None:
        errors.append("current_human_reviewer_must_not_be_fabricated")
    if governance.get("run_gate", {}).get("official_isolated_p10_runs_authorized") is not False:
        errors.append("current_official_run_gate_must_remain_false")
    qualification = governance.get("qualification", {})
    for name in ("p10", "p9", "vip"):
        if qualification.get(name) != "NOT_QUALIFIED":
            errors.append(f"current_{name}_must_remain_not_qualified")

    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--review",
        type=Path,
        default=PROJECT_ROOT / "docs/reviews/juice_shop_ai_technical_review_import_v1.json",
    )
    parser.add_argument(
        "--governance",
        type=Path,
        default=PROJECT_ROOT / "docs/juice_shop_governance_decision_v1.json",
    )
    args = parser.parse_args()
    errors = validate(args.review, args.governance)
    print(json.dumps({"passed": not errors, "errors": errors}, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
