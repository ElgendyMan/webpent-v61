from __future__ import annotations

from webpent.shared.campaign_planner import build_campaign_plan


def test_planner_materializes_all_campaign_contracts_without_claiming_tested() -> None:
    plan = build_campaign_plan(target_url="http://fixture.local")

    assert len(plan["entries"]) == 20
    assert plan["summary"]["not_observed"] == 13
    assert plan["summary"]["missing-validator"] == 7
    assert all(entry["status"] != "tested" for entry in plan["entries"])
    assert all(entry["contract"]["budget"] >= 0 for entry in plan["entries"])
    assert all(entry["plugin_id"].startswith("campaign:") for entry in plan["entries"])
    assert all(entry["evidence_schema"] == "EvidenceLedgerEntry:v1" for entry in plan["entries"])
    assert all(entry["contract"]["preconditions"] for entry in plan["entries"])
    assert all(entry["contract"]["actions"] for entry in plan["entries"])
    assert all(entry["contract"]["oracle"] for entry in plan["entries"])


def test_planner_links_surface_workflow_and_explicit_gaps_in_dag() -> None:
    plan = build_campaign_plan(
        target_url="http://fixture.local",
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
