from __future__ import annotations

from pathlib import Path

from benchmarks.abhie_v4_controlled import CLASSES, build_report

SOURCE = Path("reports/evaluation/asros/asros_advanced_controlled_benchmark_v1.json")


def test_abhie_benchmark_is_truthful_six_class_offline_report() -> None:
    report = build_report(SOURCE)
    assert tuple(report["registered_classes"]) == CLASSES
    assert len(report["classes"]) == 6
    assert report["execution"] == {
        "offline": True,
        "requests_sent": 0,
        "credentials_used": False,
        "mutations_performed": False,
        "external_targets_contacted": False,
        "runner_creates_observations": False,
    }
    scorable = [item for item in report["classes"] if item["scorable"]]
    assert [item["class"] for item in scorable] == ["idor"]
    assert scorable[0]["case_count"] == 1
    assert scorable[0]["cases"][0]["case_id"] == "controlled.idor.owner_resource.v1"
    blocked = [item for item in report["classes"] if item["status"] == "BLOCKED"]
    assert {item["class"] for item in blocked} == set(CLASSES) - {"idor"}
    assert all(item["case_count"] == 0 for item in blocked)
    assert all(item["readiness_contract"]["target_neutral"] for item in report["classes"])

    score = report["quality_score"]
    assert score["scorable_class_count"] == 1
    assert score["blocked_class_count"] == 5
    assert score["recorded_scorable_case_count"] == 1
    assert score["production_metrics_available"] is False
    assert score["precision"] is None
    assert score["recall"] is None
    assert score["f1"] is None
    assert score["real_world_detection_rate"] is None
    assert report["governance"]["official_isolated_p10_runs_authorized"] is False
    assert report["governance"]["qualification_effect"] is False
    assert report["governance"]["vip_status"] == "NOT_QUALIFIED"


def test_abhie_benchmark_does_not_promote_blocked_or_incomplete_cases(tmp_path: Path) -> None:
    source = tmp_path / "incomplete.json"
    source.write_text(
        '{"evaluation":{"cases":[{"case_id":"x","vulnerability_class":"tenant_isolation",'
        '"validation_outcome":"confirmed","ground_truth_outcome":"confirmed",'
        '"proof_complete":true,"ground_truth_source":"source",'
        '"hypothesis_generated":true,"requests_used":0}]},'
        '"provenance":{"source_proof_bundle_ref_recorded":"ref"}}',
        encoding="utf-8",
    )
    report = build_report(source)
    tenant = next(item for item in report["classes"] if item["class"] == "tenant_isolation")
    assert tenant["status"] == "BLOCKED"
    assert tenant["scorable"] is False
    assert tenant["case_count"] == 0
