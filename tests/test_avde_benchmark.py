from __future__ import annotations

from scripts.run_avde_controlled_benchmark import evaluate


def test_benchmark_is_offline_and_excludes_blocked_cases() -> None:
    result = evaluate(
        {
            "schema_version": "source-v1",
            "evaluation": {
                "evidence_quality": 0.25,
                "cases": [
                    {
                        "case_id": "c1",
                        "target_id": "local-1",
                        "vulnerability_class": "idor",
                        "validation_outcome": "confirmed",
                        "ground_truth_outcome": "confirmed",
                        "ground_truth_source": "recorded-fixture",
                        "proof_complete": True,
                        "hypothesis_generated": True,
                        "evidence_quality": 1.0,
                        "rank": 1,
                        "requests_used": 2,
                    },
                    {
                        "case_id": "c2",
                        "target_id": "local-1",
                        "vulnerability_class": "privilege_escalation",
                        "validation_outcome": "blocked",
                        "ground_truth_outcome": None,
                        "proof_complete": False,
                    },
                ],
            },
        }
    )
    metrics = result["metrics"]
    assert result["benchmark_scope"]["requests_sent_by_this_runner"] == 0
    assert metrics["scorable_classes"] == ["broken_access_control"]
    assert metrics["scorable_case_count"] == 1
    assert metrics["blocked_or_inconclusive_case_count"] == 1
    assert result["case_disposition"]["blocked_excluded_from_tp_fp_fn"] is True
    assert result["case_disposition"]["synthetic_proof_bundles_created"] is False
    assert result["governance"]["qualification_effect"] is False
    assert len(result["class_inventory"]) == 6
    assert sum(item["status"] == "scorable" for item in result["class_inventory"]) == 1
    assert all(
        item["included_in_scoring"] is False
        for item in result["class_inventory"]
        if item["class_id"] != "broken_access_control"
    )
    assert result["metrics"]["production_precision"] is None
    assert result["metrics"]["production_recall"] is None
    assert result["claims"]["production_precision_recall_calculated"] is False


def test_multiclass_contracts_are_advisory_and_have_no_execution_surface() -> None:
    from benchmarks.avde_multiclass_controlled import CONTROLLED_CLASS_CONTRACTS

    assert len(CONTROLLED_CLASS_CONTRACTS) == 6
    assert all(
        contract.allowed_methods == ("GET", "HEAD") for contract in CONTROLLED_CLASS_CONTRACTS
    )
    assert all(
        contract.execution_status == "not_executed" for contract in CONTROLLED_CLASS_CONTRACTS
    )
