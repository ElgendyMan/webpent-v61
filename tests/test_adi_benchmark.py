from __future__ import annotations

from benchmarks.adi_multistep_controlled import (
    ADI_CHAIN_CONTRACTS,
    build_chain_inventory,
    compute_adi_efficiency_metrics,
)

RECORDED_IDOR = {
    "case_id": "recorded-idor",
    "vulnerability_class": "idor",
    "validation_outcome": "confirmed",
    "ground_truth_outcome": "confirmed",
    "ground_truth_source": "recorded-fixture",
    "hypothesis_generated": True,
    "proof_complete": True,
}


def test_three_adi_chain_contracts_are_present_without_execution() -> None:
    assert tuple(item.scenario_id for item in ADI_CHAIN_CONTRACTS) == (
        "idor_chain",
        "privilege_boundary_chain",
        "business_workflow_chain",
    )
    assert all(item.execution_status == "not_executed" for item in ADI_CHAIN_CONTRACTS)


def test_incomplete_recorded_case_does_not_become_scorable_chain() -> None:
    inventory = build_chain_inventory((RECORDED_IDOR,))
    by_id = {item["scenario_id"]: item for item in inventory}
    assert by_id["idor_chain"]["status"] == "blocked"
    assert by_id["idor_chain"]["scorable_case_ids"] == ()
    assert by_id["privilege_boundary_chain"]["status"] == "blocked"
    assert by_id["business_workflow_chain"]["status"] == "blocked"


def test_efficiency_metrics_do_not_invent_unavailable_adi_measurements() -> None:
    inventory = build_chain_inventory((RECORDED_IDOR,))
    metrics = compute_adi_efficiency_metrics((RECORDED_IDOR,), inventory)
    assert metrics["average_useful_hypothesis_ratio"] is None
    assert metrics["investigation_depth"] is None
    assert metrics["evidence_completeness"] is None
    assert metrics["blocked_capability_detection_accuracy"] is None
    assert metrics["duplicate_hypothesis_reduction"] == 1.0
    assert metrics["production_precision"] is None
    assert metrics["production_recall"] is None
    assert metrics["real_world_detection_rate_measured"] is False
