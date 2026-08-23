import json
from pathlib import Path

SCORECARD = Path(__file__).parents[1] / "docs" / "v75_maturity_scorecard.json"


def test_v75_scorecard_is_deterministic_and_fail_closed():
    data = json.loads(SCORECARD.read_text(encoding="utf-8"))
    components = data["components"]
    assert sum(item["weight"] for item in components) == data["maximum_points"]
    assert sum(item["verified_points"] for item in components) == data["verified_score_points"]
    assert all(item["verified_points"] <= item["weight"] for item in components)
    assert data["current_maturity_verdict"] == "target_reached_as_engineering_maturity_only"
    assert data["vip_qualification"]["status"] == "NOT_QUALIFIED"
    assert data["vip_qualification"]["strict_confirmed"] == 0
    assert data["vip_qualification"]["proof_bundles"] == 0
    assert data["score_integrity"]["candidate_or_inventory_counted_as_finding"] is False
    assert data["score_integrity"]["gates_lowered"] is False
