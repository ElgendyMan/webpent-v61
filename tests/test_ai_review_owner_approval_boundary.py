from __future__ import annotations

import json
from pathlib import Path

from scripts.check_ai_review_owner_approval_boundary import validate

ROOT = Path(__file__).parents[1]
REVIEW = ROOT / "docs/reviews/juice_shop_ai_technical_review_import_v1.json"
GOVERNANCE = ROOT / "docs/juice_shop_governance_decision_v1.json"


def test_non_human_review_import_is_metadata_only_and_fail_closed() -> None:
    errors = validate(REVIEW, GOVERNANCE)
    assert errors == []


def test_non_human_review_cannot_flip_gated_state(tmp_path: Path) -> None:
    review = json.loads(REVIEW.read_text(encoding="utf-8"))
    review["human_independent_signoff_obtained"] = True
    review["reviews"][0]["official_isolated_p10_runs_authorized"] = True
    review["import_effect"]["qualification_changed"] = True
    path = tmp_path / "tampered-review.json"
    path.write_text(json.dumps(review), encoding="utf-8")

    errors = validate(path, GOVERNANCE)

    assert "human_signoff_must_remain_false" in errors
    assert "official_run_gate_must_remain_false:juice-shop-independent-review-20260827-01" in errors
    assert "import_effect_must_be_false:qualification_changed" in errors
