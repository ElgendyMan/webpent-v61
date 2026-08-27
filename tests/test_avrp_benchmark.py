from __future__ import annotations

import json
from pathlib import Path

from benchmarks.avrp_multiclass_controlled import (
    SCENARIO_CLASSES,
    build_scenario_inventory,
    compute_research_quality_metrics,
    evaluate_recorded_artifact,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "reports/evaluation/asros/asros_advanced_controlled_benchmark_v1.json"


def test_avrp_inventory_has_five_scenarios_and_preserves_blocked_truth() -> None:
    source = json.loads(SOURCE.read_text(encoding="utf-8"))
    cases = source["evaluation"]["cases"]
    inventory = build_scenario_inventory(cases)
    assert tuple(item["vulnerability_class"] for item in inventory) == SCENARIO_CLASSES
    assert sum(item["status"] == "scorable" for item in inventory) == 1
    assert inventory[0]["scorable_case_ids"] == ("controlled.idor.owner_resource.v1",)
    assert all(
        item["included_in_scoring"] is False
        for item in inventory
        if item["vulnerability_class"] != "idor"
    )
    assert all(item["source_cases"] for item in inventory if item["status"] == "scorable")
    assert all(
        "causal evidence" in item["blocked_reason"]
        for item in inventory
        if item["status"] == "blocked"
    )


def test_avrp_metrics_are_bounded_and_do_not_claim_detection_rate() -> None:
    source = json.loads(SOURCE.read_text(encoding="utf-8"))
    cases = source["evaluation"]["cases"]
    inventory = build_scenario_inventory(cases)
    metrics = compute_research_quality_metrics(cases, inventory)
    assert metrics["registered_scenario_count"] == 5
    assert metrics["scorable_case_count"] == 1
    assert metrics["blocked_scenario_count"] == 4
    assert metrics["scorable_class_count"] == 1
    assert metrics["evidence_completeness"] == 1.0
    assert metrics["production_precision"] is None
    assert metrics["production_recall"] is None
    assert metrics["real_world_detection_rate_measured"] is False


def test_avrp_runner_is_offline_and_governance_closed(tmp_path: Path) -> None:
    output = tmp_path / "avrp.json"
    artifact = evaluate_recorded_artifact(SOURCE)
    output.write_text(json.dumps(artifact), encoding="utf-8")
    assert artifact["benchmark_scope"]["requests_sent_by_this_runner"] == 0
    assert artifact["benchmark_scope"]["synthetic_observations_created"] is False
    assert artifact["benchmark_scope"]["synthetic_proof_bundles_created"] is False
    assert artifact["detection_metrics"]["precision"] is None
    assert artifact["governance"] == {
        "official_isolated_p10_runs_authorized": False,
        "p10_status": "NOT_QUALIFIED",
        "p9_status": "NOT_QUALIFIED",
        "vip_status": "NOT_QUALIFIED",
        "bug_bounty_status": "BLOCKED",
        "human_signoff": False,
        "qualification_effect": False,
    }
    assert output.exists()
