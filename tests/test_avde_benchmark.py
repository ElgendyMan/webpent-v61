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
