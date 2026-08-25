from datetime import datetime, timezone

from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.shared.finding_aggregation import (
    aggregate_findings,
    default_engagement_id,
    finding_fingerprint,
)


def _finding(
    *,
    title: str,
    url: str,
    vuln_class: VulnClass,
    confidence: Confidence = Confidence.TENTATIVE,
    confidence_level: str = "Pending",
    created_at: datetime,
    evidence: dict | None = None,
    tool_name: str = "test",
) -> Finding:
    return Finding(
        title=title,
        severity=Severity.HIGH,
        description="regression finding",
        tool_name=tool_name,
        url=url,
        vuln_class=vuln_class,
        confidence=confidence,
        confidence_level=confidence_level,
        created_at=created_at,
        evidence=evidence,
    )


def test_aggregate_findings_keeps_distinct_findings_from_multiple_runs() -> None:
    first = _finding(
        title="IDOR on invoice",
        url="https://target.test/invoices/1",
        vuln_class=VulnClass.IDOR,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    second = _finding(
        title="Stored XSS on comments",
        url="https://target.test/comments",
        vuln_class=VulnClass.XSS,
        created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )

    merged = aggregate_findings([first, second])

    assert len(merged) == 2
    assert {item.title for item in merged} == {first.title, second.title}


def test_aggregate_findings_does_not_replace_confirmed_with_new_candidate() -> None:
    confirmed = _finding(
        title="SQL injection",
        url="https://target.test/search?q=1",
        vuln_class=VulnClass.SQLI,
        confidence=Confidence.CONFIRMED,
        confidence_level="Tool-Confirmed",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    candidate = _finding(
        title="SQL injection",
        url="https://target.test/search?q=2",
        vuln_class=VulnClass.SQLI,
        created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )

    merged = aggregate_findings([confirmed, candidate])

    assert len(merged) == 1
    assert merged[0].confidence_level == "Tool-Confirmed"
    assert merged[0].id == confirmed.id


def test_evidence_quality_outweighs_weak_tool_label_during_merge() -> None:
    weak_tool = _finding(
        title="Access control issue",
        url="https://target.test/object/1",
        vuln_class=VulnClass.IDOR,
        confidence=Confidence.CONFIRMED,
        confidence_level="Tool-Confirmed",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    supported = _finding(
        title="Access control issue",
        url="https://target.test/object/1",
        vuln_class=VulnClass.IDOR,
        confidence_level="AI-Assessed",
        created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        evidence={"reproduction": {"steps_to_reproduce": ["repeat the request"]}},
    )

    merged = aggregate_findings([weak_tool, supported])

    assert len(merged) == 1
    assert merged[0].id == supported.id
    assert merged[0].confidence_level == "AI-Assessed"


def test_idor_endpoint_fingerprint_merges_hypothesis_and_bac_titles() -> None:
    historical_pending = _finding(
        title="Potential IDOR at download endpoint",
        url="https://target.test/v1/crm/download/1",
        vuln_class=VulnClass.IDOR,
        confidence_level="Pending",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    current_verified = _finding(
        title="IDOR: Unauthorized access to /v1/crm/download/1",
        url="https://target.test/v1/crm/download/1",
        vuln_class=VulnClass.IDOR,
        confidence=Confidence.CONFIRMED,
        confidence_level="Tool-Confirmed",
        evidence={
            "causal_signal": True,
            "negative_control_complete": True,
            "proof_bundle": {"sealed": True, "replay_status": "passed"},
        },
        created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )

    merged = aggregate_findings([historical_pending, current_verified])

    assert len(merged) == 1
    assert merged[0].id == current_verified.id
    assert merged[0].confidence_level == "Tool-Confirmed"


def test_idor_hypothesis_merges_with_role_aware_access_control_finding() -> None:
    historical_pending = _finding(
        title="Potential IDOR at download endpoint",
        url="https://target.test/v1/crm/download/1",
        vuln_class=VulnClass.IDOR,
        confidence_level="Pending",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    current_verified = _finding(
        title="IDOR: Unauthorized access to /v1/crm/download/1",
        url="https://target.test/v1/crm/download/1",
        vuln_class=VulnClass.AUTH_BYPASS,
        confidence=Confidence.CONFIRMED,
        confidence_level="Tool-Confirmed",
        tool_name="access_control_mapper",
        evidence={
            "causal_signal": True,
            "negative_control_complete": True,
            "proof_bundle": {"sealed": True, "replay_status": "passed"},
        },
        created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )

    merged = aggregate_findings([historical_pending, current_verified])

    assert len(merged) == 1
    assert merged[0].id == current_verified.id


def test_current_richer_idor_record_wins_equal_strength_tie() -> None:
    historical = _finding(
        title="IDOR: Unauthorized access to /v1/crm/download/1",
        url="https://target.test/v1/crm/download/1",
        vuln_class=VulnClass.AUTH_BYPASS,
        confidence=Confidence.CONFIRMED,
        confidence_level="Tool-Confirmed",
        tool_name="access_control_mapper",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    current = _finding(
        title="IDOR: Unauthorized access to /v1/crm/download/1",
        url="https://target.test/v1/crm/download/1",
        vuln_class=VulnClass.AUTH_BYPASS,
        confidence=Confidence.CONFIRMED,
        confidence_level="Tool-Confirmed",
        tool_name="access_control_mapper",
        created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        evidence={
            "causal_signal": True,
            "negative_control_complete": True,
            "reproduction": {"steps_to_reproduce": ["replay the request"]},
        },
    ).model_copy(
        update={
            "evidence_bundle": {"sealed": True},
            "business_impact": "Cross-identity access was reproduced.",
            "cvss_score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        }
    )

    merged = aggregate_findings([historical, current])

    assert len(merged) == 1
    assert merged[0].id == current.id
    assert merged[0].business_impact == current.business_impact


def test_generic_auth_bypass_does_not_share_idor_endpoint_fingerprint() -> None:
    idor = _finding(
        title="IDOR: Unauthorized access to /v1/crm/download/1",
        url="https://target.test/v1/crm/download/1",
        vuln_class=VulnClass.AUTH_BYPASS,
        tool_name="access_control_mapper",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    auth_bypass = _finding(
        title="Authentication bypass via missing session check",
        url="https://target.test/v1/crm/download/1",
        vuln_class=VulnClass.AUTH_BYPASS,
        created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )

    merged = aggregate_findings([idor, auth_bypass])

    assert len(merged) == 2


def test_fingerprint_and_default_scope_are_deterministic() -> None:
    first = _finding(
        title="Open redirect",
        url="https://target.test/redirect/?next=https%3A%2F%2Fexample.test",
        vuln_class=VulnClass.OPEN_REDIRECT,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    second = first.model_copy(update={"url": "HTTPS://TARGET.TEST/redirect?next=https://example.test"})

    assert finding_fingerprint(first) == finding_fingerprint(second)
    assert default_engagement_id(first.url, "client-a") == default_engagement_id(
        first.url,
        "client-a",
    )
    assert default_engagement_id(first.url, "client-a") != default_engagement_id(
        first.url,
        "client-b",
    )
