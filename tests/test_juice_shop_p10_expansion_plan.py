from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parents[1]
PLAN = ROOT / "docs" / "juice_shop_p10_expansion_plan_v1.json"


def test_expansion_plan_remains_fail_closed() -> None:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))

    assert plan["status"] == "draft_pending_independent_review"
    assert plan["current_gate"]["governance_status"] == (
        "PENDING_INDEPENDENT_GOVERNANCE_SIGNOFF"
    )
    assert plan["current_gate"]["official_isolated_p10_runs_authorized"] is False
    assert plan["current_gate"]["p10_status"] == "NOT_QUALIFIED"

    current = plan["current_oracle_approved_set"]
    assert current["case_count"] == 3
    assert current["class_count"] == 3
    assert plan["gap"]["additional_cases_required"] == 7
    assert plan["gap"]["additional_classes_required"] == 3

    dispositions = plan["case_disposition_plan"]
    assert len(dispositions) == 8
    assert all(entry["counts_now"] is False for entry in dispositions)
    assert sum(entry["current_disposition"] == "blocked" for entry in dispositions) == 3
    assert sum(entry["current_disposition"] == "out_of_scope" for entry in dispositions) == 4
    assert sum(
        entry["current_disposition"]
        == "implemented_pending_governance_confirmation"
        for entry in dispositions
    ) == 1


def test_expansion_candidates_cannot_count_as_approved() -> None:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))

    candidates = plan["new_candidate_tracks"]
    assert len(candidates) == 4
    assert all(candidate["counts_now"] is False for candidate in candidates)
    assert not any(
        candidate["status"] in {"approved", "oracle_approved"}
        for candidate in candidates
    )
