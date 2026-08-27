from __future__ import annotations

import hashlib
import json
from pathlib import Path

from benchmarks.abhie_v6_controlled import CLASSES, build_report
from benchmarks.abhie_v6_scorecard import score_report

SOURCE = Path("reports/evaluation/asros/asros_advanced_controlled_benchmark_v1.json")


def test_v6_benchmark_registers_six_classes_and_is_fail_closed() -> None:
    before = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    report = build_report(SOURCE)
    after = hashlib.sha256(SOURCE.read_bytes()).hexdigest()

    assert report["registered_classes"] == list(CLASSES)
    assert len(report["classes"]) == 6
    assert report["execution"] == {
        "offline": True,
        "runner_creates_observations": False,
        "requests_sent": 0,
        "credentials_used": False,
        "mutations_performed": False,
        "external_targets_contacted": False,
    }
    assert report["metrics"]["registered_class_count"] == 6
    assert report["metrics"]["scorable_class_count"] == 0
    assert report["metrics"]["blocked_class_count"] == 6
    assert report["metrics"]["recorded_scorable_case_count"] == 0
    assert report["recorded_complete_case_ids"] == []
    assert report["metrics"]["precision"] is None
    assert report["metrics"]["recall"] is None
    assert report["metrics"]["f1"] is None
    assert report["metrics"]["real_world_detection_rate"] is None
    assert report["benchmark_quality"]["hardcoded_detection"] is False
    assert before == after

    for category in report["classes"]:
        assert category["readiness_contract"]["target_neutral"] is True
        assert category["readiness_contract"]["missing_evidence_is_blocking"] is True
        assert category["readiness_contract"]["runner_must_not_execute"] is True
        assert category["scorable"] is False
        assert category["status"] == "BLOCKED"
        for candidate in category["blocked_candidates"]:
            assert candidate["missing_requirements"]


def test_v6_scorecard_preserves_blocked_and_governance_state(tmp_path: Path) -> None:
    benchmark_path = tmp_path / "benchmark.json"
    benchmark_path.write_text(
        json.dumps(build_report(SOURCE), sort_keys=True), encoding="utf-8"
    )
    scorecard = score_report(benchmark_path)

    assert scorecard["registered_classes"] == 6
    assert scorecard["scorable_classes"] == 0
    assert scorecard["blocked_classes"] == 6
    assert scorecard["scorable_cases"] == 0
    assert scorecard["production_detection"]["available"] is False
    assert scorecard["production_detection"]["precision"] is None
    assert scorecard["production_detection"]["recall"] is None
    assert scorecard["production_detection"]["f1"] is None
    assert scorecard["interpretation"]["blocked_excluded_from_metrics"] is True
    assert scorecard["interpretation"]["missing_evidence_is_not_false_negative"] is True
    assert scorecard["interpretation"]["qualification_effect"] is False
    assert scorecard["governance"]["official_isolated_p10_runs_authorized"] is False
    assert scorecard["governance"]["vip_status"] == "NOT_QUALIFIED"
