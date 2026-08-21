from __future__ import annotations

from webpent.agents.access_control import agent as access_agent
from webpent.models.targets import Target
from webpent.shared.bac_identity_tester import (
    IdentityProfile,
    assess_access_control,
    build_relational_evidence,
    normalise_identity_profiles,
    sanitise_probe_result,
)


def test_identity_profiles_normalise_legacy_session_without_claiming_two_users():
    profiles = normalise_identity_profiles({}, fallback_cookies={"session": "secret"})
    assert len(profiles) == 1
    assert profiles[0].name == "session-1"
    assert profiles[0].cookies == {"session": "secret"}
    assert "secret" not in repr(profiles[0].public_metadata)


def test_assessment_requires_explicit_owner_for_tool_confirmation():
    rows = [
        sanitise_probe_result(
            profile=IdentityProfile(name="alice", role="user"),
            url="http://lab.local/orders/1001",
            status_code=200,
            content_length=42,
        ),
        sanitise_probe_result(
            profile=IdentityProfile(name="bob", role="user"),
            url="http://lab.local/orders/1001",
            status_code=200,
            content_length=42,
        ),
    ]
    result = assess_access_control(rows)
    assert result["status"] == "needs_review"
    assert result["confidence_level"] == "Needs Human Review"


def test_assessment_confirms_only_with_foreign_denied_negative_control():
    rows = [
        sanitise_probe_result(
            profile=IdentityProfile(name="alice", role="user"),
            url="http://lab.local/orders/1001",
            status_code=200,
            content_length=42,
        ),
        sanitise_probe_result(
            profile=IdentityProfile(name="bob", role="user"),
            url="http://lab.local/orders/1001",
            status_code=200,
            content_length=42,
        ),
        sanitise_probe_result(
            profile=IdentityProfile(name="charlie", role="user"),
            url="http://lab.local/orders/1001",
            status_code=403,
            content_length=0,
        ),
    ]
    result = assess_access_control(rows, owner_identity="alice")
    assert result["status"] == "confirmed"
    assert result["confidence_level"] == "Tool-Confirmed"
    edges = build_relational_evidence(rows, owner_identity="alice", object_id="1001")
    assert edges and edges[0]["differential"] is False
    assert "session" not in str(edges)


def test_access_control_node_emits_confirmed_finding_only_with_owner_metadata(monkeypatch):
    target = Target(url="http://lab.local")
    monkeypatch.setattr(
        access_agent,
        "_probe_url",
        lambda url, cookies=None, timeout=10.0, headers=None: (
            (200, 123)
            if cookies and cookies.get("session") in {"alice-secret", "bob-secret"}
            else (403, 0)
        ),
    )
    state = {
        "target": target,
        "engagement_id": "bac-test-engagement",
        "findings": [],
        "crawled_data": {
            "endpoints": [
                {
                    "url": "http://lab.local/orders/1001",
                    "owner_identity": "alice",
                    "object_id": "1001",
                }
            ]
        },
        "identity_profiles": {
            "alice": {"role": "user", "cookies": {"session": "alice-secret"}},
            "bob": {"role": "user", "cookies": {"session": "bob-secret"}},
            "charlie": {"role": "user", "cookies": {"session": "charlie-secret"}},
        },
    }
    result = access_agent.access_control_node(state)
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding.confidence_level == "Tool-Confirmed"
    assert finding.vuln_class == "idor"
    assert finding.evidence_bundle is not None
    assert finding.evidence_bundle["bundle_id"]
    assert finding.evidence["owner_identity"] == "alice"
    assert "alice-secret" not in str(finding.evidence)
    assert "bob-secret" not in str(finding.evidence)
    assert result["relational_evidence"]


def test_access_control_node_records_coverage_gap_with_one_identity(monkeypatch):
    target = Target(url="http://lab.local")
    monkeypatch.setattr(access_agent, "_probe_url", lambda *args, **kwargs: (200, 80))
    result = access_agent.access_control_node(
        {
            "target": target,
            "findings": [],
            "crawled_data": {"urls": ["http://lab.local/orders/1001"]},
            "identity_profiles": {"alice": {"cookies": {"session": "secret"}}},
        }
    )
    assert result["findings"] == []
    assert result["bac_coverage_gaps"]
    assert result["bac_coverage_gaps"][0]["status"] == "coverage_gap"
    assert "secret" not in str(result)
