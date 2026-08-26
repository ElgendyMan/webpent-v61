from __future__ import annotations

from webpent.benchmark.waptlab_campaign_profile import build_waptlab_campaign_profile
from webpent.shared.campaign_planner import build_campaign_plan


def test_planner_materializes_all_campaign_contracts_without_claiming_tested() -> None:
    plan = build_campaign_plan(
        target_url="http://fixture.local",
        campaign_inventory="waptlab",
        campaign_profile=build_waptlab_campaign_profile(),
    )

    assert len(plan["entries"]) == 20
    assert plan["summary"]["not_observed"] == 18
    assert plan["summary"]["missing-validator"] == 2
    assert all(entry["status"] != "tested" for entry in plan["entries"])
    assert all(entry["contract"]["budget"] >= 0 for entry in plan["entries"])
    assert all(entry["plugin_id"].startswith("campaign:") for entry in plan["entries"])
    assert all(entry["evidence_schema"] == "EvidenceLedgerEntry:v1" for entry in plan["entries"])
    assert all(entry["contract"]["preconditions"] for entry in plan["entries"])
    assert all(not entry["contract"]["observed_preconditions"] for entry in plan["entries"])
    assert all(entry["contract"]["actions"] for entry in plan["entries"])
    assert all(entry["contract"]["oracle"] for entry in plan["entries"])


def test_planner_links_surface_workflow_and_explicit_gaps_in_dag() -> None:
    plan = build_campaign_plan(
        target_url="http://fixture.local",
        campaign_inventory="waptlab",
        campaign_profile=build_waptlab_campaign_profile(),
        observed_campaigns={"header_sqli"},
        blocked_by={"tenant_context_switching": "blocked-by-auth"},
        surface_observations=[
            {"category": "headers", "fingerprint": "surface-headers-1"},
        ],
        workflow_observations=[
            {
                "fingerprint": "workflow-identity-1",
                "intent_tags": ["identity", "download"],
            },
        ],
        explicit_gaps=["missing-negative-control:fixture"],
    )

    by_key = {entry["key"]: entry for entry in plan["entries"]}
    assert by_key["header_sqli"]["status"] == "tested"
    assert by_key["header_sqli"]["matched_observation_refs"] == ["surface-headers-1"]
    assert (
        by_key["header_sqli"]["contract"]["observed_preconditions"]
        == by_key["header_sqli"]["contract"]["preconditions"]
    )
    assert by_key["tenant_context_switching"]["status"] == "blocked-by-auth"
    assert "blocked-by-auth:tenant_context_switching" in by_key["tenant_context_switching"]["gaps"]
    assert "missing-negative-control:fixture" in plan["coverage_gaps"]

    node_types = {node["node_type"] for node in plan["nodes"]}
    assert "campaign" in node_types
    assert "surface_observation" in node_types
    assert "workflow_observation" in node_types
    assert "coverage_gap" in node_types
    assert any(edge["relation"] == "observation_supports_campaign" for edge in plan["edges"])
    assert any(edge["relation"] == "campaign_blocked_by_gap" for edge in plan["edges"])


def test_planner_redacts_secret_like_metadata() -> None:
    plan = build_campaign_plan(
        target_url="http://fixture.local",
        surface_observations=[
            {
                "category": "profile",
                "fingerprint": "surface-profile-1",
                "authorization": "Bearer very-secret-token",
            }
        ],
        explicit_gaps=["token=do-not-persist"],
    )

    rendered = str(plan)
    assert "very-secret-token" not in rendered
    assert "do-not-persist" not in rendered


def test_planner_supports_generic_surface_inventory_without_waptlab_entries() -> None:
    plan = build_campaign_plan(
        target_url="http://juice-shop.local",
        campaign_inventory="generic",
        surface_observations=[
            {"category": "api", "endpoint": "/rest/user/whoami", "fingerprint": "api-1"},
            {"category": "query", "endpoint": "/search?q=test", "fingerprint": "query-1"},
        ],
    )

    keys = {entry["key"] for entry in plan["entries"]}
    assert len(plan["entries"]) == 10
    assert "header_sqli" not in keys
    assert {"api_issue", "sqli_param"}.issubset(keys)
    assert all(entry["validator_id"] for entry in plan["entries"])
    assert all(entry["plugin_id"].startswith("campaign:") for entry in plan["entries"])
    assert "campaign:header_sqli" not in {entry["plugin_id"] for entry in plan["entries"]}
    assert all(entry["contract"]["preconditions"] for entry in plan["entries"])
    by_key = {entry["key"]: entry for entry in plan["entries"]}
    assert by_key["api_issue"]["matched_observation_refs"] == ["api-1"]
    assert by_key["sqli_param"]["matched_observation_refs"] == ["query-1"]
    assert (
        by_key["api_issue"]["contract"]["observed_preconditions"]
        == by_key["api_issue"]["contract"]["preconditions"]
    )
    assert (
        by_key["sqli_param"]["contract"]["observed_preconditions"]
        == by_key["sqli_param"]["contract"]["preconditions"]
    )
    assert all(entry["status"] != "tested" for entry in plan["entries"])


def test_explicit_waptlab_inventory_keeps_legacy_matrix() -> None:
    plan = build_campaign_plan(
        target_url="http://127.0.0.1:8000",
        campaign_inventory="waptlab",
        campaign_profile=build_waptlab_campaign_profile(),
    )

    assert len(plan["entries"]) == 20
    assert plan["entries"][0]["key"] == "header_sqli"
    assert plan["entries"][0]["plugin_id"] == "campaign:header_sqli"
    assert plan["summary"]["missing-validator"] == 2


def test_auto_inventory_never_guesses_waptlab_from_url() -> None:
    for target_url in (
        "http://127.0.0.1:8000",
        "http://waptlab.local",
        "https://arbitrary-target.example:8000",
    ):
        plan = build_campaign_plan(target_url=target_url, campaign_inventory="auto")

        assert len(plan["entries"]) == 10
        assert plan["entries"][0]["key"] == "xss_reflected"
        assert plan["summary"].get("missing-validator", 0) == 0


def test_auto_inventory_selects_generic_for_any_non_explicit_target() -> None:
    plan = build_campaign_plan(
        target_url="http://127.0.0.1:3000",
        campaign_inventory="auto",
    )

    assert len(plan["entries"]) == 10
    assert plan["entries"][0]["key"] == "xss_reflected"
    assert plan["summary"].get("missing-validator", 0) == 0


def test_auto_inventory_is_target_agnostic_across_unrelated_origins_and_ports() -> None:
    origins = (
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
        "http://localhost:8080/app",
        "https://shop.example.test:9443",
        "https://api.example.test:443/v1",
        "http://192.0.2.44:18080",
    )

    plans = [
        build_campaign_plan(target_url=origin, campaign_inventory="auto") for origin in origins
    ]

    assert all(len(plan["entries"]) == 10 for plan in plans)
    assert all(plan["entries"][0]["key"] == "xss_reflected" for plan in plans)
    assert all(plan["summary"].get("missing-validator", 0) == 0 for plan in plans)
    assert all("header_sqli" not in {entry["key"] for entry in plan["entries"]} for plan in plans)


def test_unknown_campaign_inventory_fails_closed_independent_of_target_url() -> None:
    for target_url in ("http://127.0.0.1:8000", "https://arbitrary.example:9443"):
        try:
            build_campaign_plan(target_url=target_url, campaign_inventory="lab-name-from-host")
        except ValueError as exc:
            assert "campaign_inventory" in str(exc)
        else:
            raise AssertionError("unknown campaign inventory must fail closed")
