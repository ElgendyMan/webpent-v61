from __future__ import annotations

from webpent.graph.builder import (
    END,
    NODE_SCOPE_REVIEW,
    NODE_WAF_DETECTOR,
    route_after_scope_enforcer,
    route_after_scope_review,
)
from webpent.models.findings import Finding, Severity, VulnClass
from webpent.shared.kev import enrich_finding_with_kev
from webpent.shared.llm_reliability import llm_budget_allows
from webpent.shared.scope_drift import detect_scope_drift


def test_scope_drift_requires_human_approval() -> None:
    event = detect_scope_drift(
        ["https://app.test/users", "https://api.test/users"],
        "https://app.test",
    )
    assert event["detected"] is True
    assert event["requires_human_approval"] is True
    assert event["out_of_scope_origins"] == ["https://api.test"]


def test_scope_drift_routes_to_explicit_review_and_stops_without_approval() -> None:
    assert route_after_scope_enforcer({"scope_drift_detected": True}) == NODE_SCOPE_REVIEW
    assert route_after_scope_review({"scope_drift_approved": False}) == END
    assert route_after_scope_review({"scope_drift_approved": True}) == NODE_WAF_DETECTOR


def test_same_origin_has_no_scope_drift() -> None:
    event = detect_scope_drift(["https://app.test/users"], "https://app.test")
    assert event["detected"] is False
    assert event["requires_human_approval"] is False


def test_llm_budget_exhaustion_is_fail_closed() -> None:
    allowed, reason = llm_budget_allows(
        {"limit": 1.0, "used_cost": 1.0, "remaining_cost": 0.0}
    )
    assert allowed is False
    assert reason == "budget:llm_exhausted"


def test_legacy_budget_state_remains_backward_compatible() -> None:
    assert llm_budget_allows(None)[0] is True


def test_kev_context_is_advisory_only() -> None:
    finding = Finding(
        title="Known issue",
        severity=Severity.HIGH,
        description="Affects CVE-2024-12345.",
        tool_name="test",
        url="https://target.test",
        vuln_class=VulnClass.XSS,
    )
    enriched = enrich_finding_with_kev(finding, ["CVE-2024-12345"])
    assert enriched.severity == finding.severity
    assert enriched.confidence == "firm"
    assert enriched.confidence_level == finding.confidence_level
    assert enriched.evidence["kev_context"]["confidence_adjustment"]["to"] == "firm"
    assert enriched.evidence["kev_context"]["advisory_only"] is True
    assert enriched.evidence["kev_context"]["does_not_confirm"] is True
