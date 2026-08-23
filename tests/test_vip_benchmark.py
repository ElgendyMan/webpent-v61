from __future__ import annotations

import json
from pathlib import Path

from benchmarks.metrics import (
    compare_runs,
    compute_metrics,
    is_confirmed_with_required_controls,
    summarize_run,
)

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / "benchmarks" / "vip_v1"


def _read(name: str) -> dict:
    return json.loads((BENCHMARK / name).read_text(encoding="utf-8"))


def test_versioned_manifest_is_fail_closed_and_reproducible():
    manifest = _read("manifest.json")
    assert manifest["schema_version"] == 1
    assert manifest["metric_contract"]["confirmed_only"] is True
    assert set(manifest["metric_contract"]["required_confirmation_fields"]) == {
        "causal_signal",
        "negative_control_complete",
        "proof_bundle_sealed",
    }
    assert manifest["safety"]["modifies_target"] is False
    assert manifest["safety"]["requires_explicit_authorization"] is True


def test_expected_catalog_contains_twenty_evidence_contracts():
    expected = _read("expected_findings.json")["entries"]
    assert len(expected) == 20
    assert len({entry["key"] for entry in expected}) == 20
    assert all(entry["evidence_required"] for entry in expected)
    assert all(entry["negative_control_required"] for entry in expected)


def test_e2e_scenarios_cover_required_research_paths():
    scenarios = _read("scenarios.json")["scenarios"]
    assert {scenario["id"] for scenario in scenarios} == {"A", "B", "C", "D", "E"}
    assert all(scenario["required_artifacts"] for scenario in scenarios)
    assert all(scenario["success"] for scenario in scenarios)


def test_confirmation_requires_causal_control_and_sealed_proof():
    accepted = {
        "key": "header_sqli",
        "status": "confirmed",
        "causal_signal": True,
        "negative_control_complete": True,
        "proof_bundle_sealed": True,
    }
    for field in ("causal_signal", "negative_control_complete", "proof_bundle_sealed"):
        rejected = {**accepted, field: False}
        assert is_confirmed_with_required_controls(rejected) is False
    assert is_confirmed_with_required_controls(accepted) is True


def test_summarize_run_does_not_count_unproven_confirmed_status():
    summary = summarize_run(
        {
            "case_id": "unproven-confirmed",
            "findings": [
                {
                    "key": "header_sqli",
                    "status": "confirmed",
                    "causal_signal": False,
                    "negative_control_complete": False,
                    "proof_bundle_sealed": False,
                }
            ],
        },
        ground_truth=[{"key": "header_sqli"}],
    )

    assert summary["confirmed"] == 0
    assert summary["confirmed_unverified"] == 1
    assert summary["proof_bundle_coverage"] is None
    assert summary["replay_success_rate"] is None
    assert summary["true_positives"] == 0
    assert summary["false_positives"] == 0
    assert summary["ground_truth_positive_count"] == 1


def test_compare_runs_preserves_gated_repeatability_only():
    result = compare_runs(
        [
            {
                "case_id": "r1",
                "comparison_group": "same-fixture",
                "findings": [
                    {
                        "key": "header_sqli",
                        "status": "confirmed",
                        "causal_signal": False,
                        "negative_control_complete": False,
                        "proof_bundle_sealed": False,
                    }
                ],
            },
            {
                "case_id": "r2",
                "comparison_group": "same-fixture",
                "findings": [
                    {
                        "key": "header_sqli",
                        "status": "confirmed",
                        "causal_signal": True,
                        "negative_control_complete": True,
                        "proof_bundle_sealed": True,
                    }
                ],
            },
        ],
        ground_truth=[{"key": "header_sqli"}],
    )

    assert result["runs"][0]["confirmed"] == 0
    assert result["runs"][1]["confirmed"] == 1
    assert result["repeatability"]["same-fixture"] == 0.0


def test_metrics_use_set_semantics_and_confirmed_findings_only():
    expected = [{"key": "a"}, {"key": "b"}, {"key": "c"}]
    observed = [
        {
            "key": "a",
            "status": "confirmed",
            "causal_signal": True,
            "negative_control_complete": True,
            "proof_bundle_sealed": True,
        },
        {
            "key": "a",
            "status": "confirmed",
            "causal_signal": True,
            "negative_control_complete": True,
            "proof_bundle_sealed": True,
        },
        {
            "key": "b",
            "status": "candidate",
            "causal_signal": True,
            "negative_control_complete": True,
            "proof_bundle_sealed": True,
        },
        {
            "key": "x",
            "status": "confirmed",
            "causal_signal": True,
            "negative_control_complete": True,
            "proof_bundle_sealed": True,
        },
    ]
    metrics = compute_metrics(expected, observed)
    assert metrics.true_positives == 1
    assert metrics.false_positives == 1
    assert metrics.false_negatives == 2
    assert metrics.precision == 0.5
    assert metrics.recall == 1 / 3
    assert round(metrics.f1, 6) == round(0.4, 6)
