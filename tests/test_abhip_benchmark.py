"""Regression tests for the offline ABHIP v5 controlled benchmark."""

from __future__ import annotations

import hashlib
from pathlib import Path

from benchmarks.abhip_v4_controlled import CLASSES, build_report
from benchmarks.abhip_v4_metrics import score_report

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "reports/evaluation/asros/asros_advanced_controlled_benchmark_v1.json"
PREVIOUS = ROOT / "reports/evaluation/abhie/abhie_v4_controlled_benchmark.json"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_benchmark_registers_six_classes_and_only_recorded_idor_is_scorable() -> None:
    before = _digest(SOURCE)
    report = build_report(SOURCE)
    after = _digest(SOURCE)

    assert tuple(report["registered_classes"]) == CLASSES
    assert len(report["classes"]) == 6
    assert [item["class"] for item in report["classes"] if item["scorable"]] == ["idor"]
    assert report["recorded_complete_case_ids"] == ["controlled.idor.owner_resource.v1"]
    assert before == after


def test_benchmark_readiness_contract_is_target_neutral_and_fail_closed() -> None:
    report = build_report(SOURCE)
    required = {
        "hidden security assumptions",
        "multiple possible research paths",
        "autonomous decision requirement",
        "causal oracle result",
        "sealed ProofBundle",
        "replay verification",
    }
    blocked = [item for item in report["classes"] if item["status"] == "BLOCKED"]

    assert len(blocked) == 5
    assert all(item["scorable"] is False for item in blocked)
    assert all(item["readiness_contract"]["target_neutral"] for item in report["classes"])
    assert all(
        required.issubset(item["readiness_contract"]["required_semantics"])
        for item in report["classes"]
    )
    assert all(item["readiness_contract"]["runner_must_not_execute"] for item in report["classes"])


def test_benchmark_is_offline_and_production_metrics_are_unavailable() -> None:
    report = build_report(SOURCE)
    metrics = report["metrics"]

    assert report["execution"] == {
        "offline": True,
        "runner_creates_observations": False,
        "requests_sent": 0,
        "credentials_used": False,
        "mutations_performed": False,
        "external_targets_contacted": False,
    }
    assert metrics["precision"] is None
    assert metrics["recall"] is None
    assert metrics["f1"] is None
    assert metrics["production_detection_rate"] is None
    assert metrics["valid_ground_truth"] is False
    assert report["governance"]["official_isolated_p10_runs_authorized"] is False
    assert report["governance"]["vip_status"] == "NOT_QUALIFIED"


def test_internal_metrics_compare_against_real_previous_artifact() -> None:
    report = build_report(SOURCE)
    previous = __import__("json").loads(PREVIOUS.read_text(encoding="utf-8"))
    scored = score_report(report, previous_report=previous)

    assert scored["quality_claim"] == "recorded_research_capability_coverage_only"
    assert scored["readiness_coverage"] == 0.166667
    assert scored["recorded_scorable_case_count"] == 1
    assert scored["previous_version_comparison"]["status"] == "RECORDED_ARTIFACT_COMPARISON"
    assert scored["previous_version_comparison"]["scorable_case_count_delta"] == 0
    assert scored["previous_version_comparison"]["evidence_completeness_delta"] == 0.0
    assert scored["production_metrics_available"] is False
