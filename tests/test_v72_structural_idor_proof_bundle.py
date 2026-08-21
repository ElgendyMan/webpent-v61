from webpent.agents.validator import structural_checks
from webpent.models.findings import Finding, Severity


def test_confirmed_idor_persists_sealed_proof_bundle_as_dict(monkeypatch) -> None:
    calls = []

    def fake_fetch(url, *, cookies=None, target_scope=()):
        calls.append((url, dict(cookies or {}), tuple(target_scope)))
        if cookies == {"sid": "owner"}:
            return 200, "same protected profile", {}
        if cookies == {"sid": "foreign"}:
            return 200, "same protected profile", {}
        return 403, "denied", {}

    monkeypatch.setattr(
        structural_checks,
        "_fetch_page_scoped_with_rate_limit_retry",
        fake_fetch,
    )
    finding = Finding(
        title="Potential IDOR",
        severity=Severity.MEDIUM,
        description="Candidate object-level authorization issue.",
        tool_name="test",
        url="http://127.0.0.1:8000/user_profile/1",
    )
    profiles = {
        "owner": {"role": "owner", "cookies": {"sid": "owner"}},
        "foreign": {"role": "user", "cookies": {"sid": "foreign"}},
    }

    result = structural_checks.validate_idor(
        finding,
        identity_profiles=profiles,
        engagement_id="engagement-test",
        target_scope=("http://127.0.0.1:8000",),
    )

    assert result.confidence_level == "Tool-Confirmed"
    assert isinstance(result.evidence_bundle, dict)
    assert result.evidence_bundle["sealed"] is True
    assert result.evidence["proof_bundle"] == result.evidence_bundle
    assert isinstance(result.evidence["relational_edges"], list)
    assert len(calls) == 4
    assert all(call[2] == ("http://127.0.0.1:8000",) for call in calls)
