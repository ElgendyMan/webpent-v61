from pathlib import Path

from benchmarks.avrip_deep_controlled import evaluate_recorded_artifact

SOURCE = Path("reports/evaluation/asros/asros_advanced_controlled_benchmark_v1.json")


def test_avrip_benchmark_is_offline_and_preserves_governance() -> None:
    artifact = evaluate_recorded_artifact(SOURCE)
    scope = artifact["benchmark_scope"]
    governance = artifact["governance"]

    assert scope["requests_sent_by_this_runner"] == 0
    assert scope["external_network"] is False
    assert scope["credentials"] is False
    assert scope["state_mutation"] is False
    assert scope["synthetic_observations_created"] is False
    assert scope["synthetic_proof_bundles_created"] is False
    assert governance["official_isolated_p10_runs_authorized"] is False
    assert governance["p10_status"] == "NOT_QUALIFIED"
    assert governance["p9_status"] == "NOT_QUALIFIED"
    assert governance["vip_status"] == "NOT_QUALIFIED"
    assert governance["bug_bounty_status"] == "BLOCKED"
    assert governance["human_signoff"] is False
    assert governance["qualification_effect"] is False


def test_avrip_benchmark_has_five_classes_and_only_recorded_idor_is_scorable() -> None:
    artifact = evaluate_recorded_artifact(SOURCE)
    assert artifact["registered_vulnerability_classes"] == [
        "idor",
        "privilege_escalation",
        "business_logic_authorization_failure",
        "information_disclosure",
        "authentication_boundary_issue",
    ]
    assert len(artifact["recorded_scorable_case_ids"]) == 1
    assert artifact["recorded_scorable_case_ids"][0] == "controlled.idor.owner_resource.v1"
    inventory = artifact["scenario_inventory"]
    assert sum(item["status"] == "scorable" for item in inventory) == 1
    assert sum(item["status"] == "blocked" for item in inventory) == 4
    for item in inventory:
        if item["status"] == "blocked":
            assert item["included_in_scoring"] is False
            assert item["blocked_reason"]


def test_avrip_benchmark_keeps_unavailable_intelligence_and_detection_metrics_null() -> None:
    artifact = evaluate_recorded_artifact(SOURCE)
    intelligence = artifact["research_intelligence_metrics"]
    detection = artifact["detection_metrics"]

    assert intelligence["metric_scope"] == "recorded_controlled_evidence_only"
    assert intelligence["complete_recorded_case_count"] == 1
    assert intelligence["intent_projection_coverage"] is None
    assert intelligence["security_assumption_coverage"] is None
    assert intelligence["deep_reasoning_quality"] is None
    assert intelligence["cross_domain_join_quality"] is None
    assert intelligence["strategy_adaptation_quality"] is None
    assert intelligence["reason_unavailable"]
    assert detection["precision"] is None
    assert detection["recall"] is None
    assert detection["f1"] is None
    assert detection["reason"]
