from pathlib import Path

from scripts.run_asros_advanced_controlled_benchmark import build_benchmark

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "reports/evaluation/arex/controlled_campaign_v1.json"


def test_advanced_benchmark_is_multiclass_but_only_scores_recorded_causal_case():
    result = build_benchmark(SOURCE)
    evaluation = result["evaluation"]

    assert result["registered_vulnerability_classes"] == [
        "idor",
        "privilege_escalation",
        "business_logic",
        "information_disclosure",
    ]
    assert result["scorable_vulnerability_classes"] == ["idor"]
    assert set(result["blocked_vulnerability_classes"]) == {
        "privilege_escalation",
        "business_logic",
        "information_disclosure",
    }
    assert evaluation["case_count"] == 4
    assert evaluation["validation_accuracy"] == 1.0
    assert evaluation["unnecessary_exploration_reduction"] == 1.0
    assert evaluation["real_world_detection_rate_measured"] is False
    assert evaluation["qualification_effect"] is False


def test_advanced_benchmark_is_deterministic_and_fail_closed():
    first = build_benchmark(SOURCE)
    second = build_benchmark(SOURCE)

    assert first == second
    assert first["benchmark_scope"]["requests_sent_by_this_runner"] == 0
    assert first["governance"]["official_isolated_p10_runs_authorized"] is False
    assert first["governance"]["vip_status"] == "NOT_QUALIFIED"
    assert "excluded from TP/FN/clean scoring" in first["blocked_reason"]
