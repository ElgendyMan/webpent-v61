#!/usr/bin/env python3
"""Fail-closed validation for the Juice Shop P10 expansion plan.

This validates a planning artifact only. It never promotes a candidate, edits
frozen ground truth, or authorizes official P10 execution.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

DEFAULT_PLAN = Path("docs/juice_shop_p10_expansion_plan_v1.json")
REQUIRED_CURRENT_CASES = {
    "juice.error_handling.v1",
    "juice.exposed_metrics.v1",
    "juice.local_xss.v1",
}
EXPECTED_NON_SCORING = {
    "juice.access_log_disclosure.v1": "implemented_pending_governance_confirmation",
    "juice.directory_listing.v1": "blocked",
    "juice.forgotten_backup.v1": "blocked",
    "juice.misplaced_signature_file.v1": "blocked",
    "juice.privacy_policy_proof.v1": "out_of_scope",
    "juice.public_scoreboard_route.v1": "out_of_scope",
    "juice.security_policy.v1": "out_of_scope",
    "juice.well_known_security_policy.v1": "out_of_scope",
}


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", nargs="?", type=Path, default=DEFAULT_PLAN)
    args = parser.parse_args()

    try:
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot_read_plan:{exc}")

    if plan.get("status") != "draft_pending_independent_review":
        fail("plan_must_remain_draft_pending_independent_review")

    gate = plan.get("current_gate", {})
    if gate.get("governance_status") != "PENDING_INDEPENDENT_GOVERNANCE_SIGNOFF":
        fail("governance_status_not_pending")
    if gate.get("official_isolated_p10_runs_authorized") is not False:
        fail("official_runs_must_remain_unauthorized")
    if gate.get("p10_status") != "NOT_QUALIFIED":
        fail("p10_must_remain_not_qualified")

    thresholds = plan.get("thresholds", {})
    minimum_cases = thresholds.get("minimum_approved_cases")
    minimum_classes = thresholds.get("minimum_approved_classes")
    minimum_runs = thresholds.get("minimum_isolated_runs")
    if (minimum_cases, minimum_classes, minimum_runs) != (10, 6, 3):
        fail("official_thresholds_mismatch")

    current = plan.get("current_oracle_approved_set", {})
    current_cases = set(current.get("case_ids", []))
    current_classes = set(current.get("class_names", []))
    if current_cases != REQUIRED_CURRENT_CASES:
        fail("current_oracle_case_set_mismatch")
    if current.get("case_count") != len(current_cases) or current.get("case_count") != 3:
        fail("current_case_count_mismatch")
    if current.get("class_count") != len(current_classes) or current.get("class_count") != 3:
        fail("current_class_count_mismatch")

    gap = plan.get("gap", {})
    if gap.get("additional_cases_required") != minimum_cases - current.get("case_count", 0):
        fail("additional_case_gap_mismatch")
    if gap.get("additional_classes_required") != minimum_classes - current.get("class_count", 0):
        fail("additional_class_gap_mismatch")

    dispositions = plan.get("case_disposition_plan", [])
    actual = {
        entry.get("registry_case_id"): entry.get("current_disposition")
        for entry in dispositions
    }
    if actual != EXPECTED_NON_SCORING:
        fail("non_scoring_case_disposition_mismatch")
    if any(entry.get("counts_now") is not False for entry in dispositions):
        fail("non_scoring_case_cannot_count_now")

    candidates = plan.get("new_candidate_tracks", [])
    if not candidates:
        fail("candidate_tracks_missing")
    if any(candidate.get("counts_now") is not False for candidate in candidates):
        fail("candidate_cannot_count_now")
    candidate_keys = {candidate.get("candidate_key") for candidate in candidates}
    if None in candidate_keys:
        fail("candidate_key_missing")

    prohibited = plan.get("prohibited_shortcuts", [])
    required_phrases = ("frozen ground truth", "blocked", "official isolated P10")
    if not all(
        any(phrase.lower() in item.lower() for item in prohibited)
        for phrase in required_phrases
    ):
        fail("prohibited_shortcuts_incomplete")

    print(
        "PASS: expansion plan is fail-closed; "
        f"current={current.get('case_count')}/{current.get('class_count')}, "
        f"gap={gap.get('additional_cases_required')}/{gap.get('additional_classes_required')}, "
        f"non_scoring={len(dispositions)}, candidates={len(candidates)}, "
        "official_runs=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
