from webpent.agents.validator import structural_checks
from webpent.models.findings import Finding


def _finding() -> Finding:
    return Finding(
        title="Cross-account object access",
        severity="high",
        description="Authenticated object endpoint may be readable by another identity.",
        tool_name="validator",
        url="http://127.0.0.1:8000/orders/1001",
        vuln_class="idor",
    )


def test_idor_validator_replays_inside_declared_loopback_scope_and_builds_proof(monkeypatch):
    calls = []

    def fake_fetch(url, *, cookies=None, target_scope=()):
        calls.append((url, cookies, target_scope))
        sid = (cookies or {}).get("session")
        if sid in {"alice", "bob"}:
            return 200, '{"id":1001,"owner":"alice"}', {"content-type": "application/json"}
        return 403, "", {"location": "/login"}

    monkeypatch.setattr(structural_checks, "_fetch_page_scoped", fake_fetch)
    result = structural_checks.validate_idor(
        _finding(),
        cookies={"session": "alice"},
        identity_profiles={
            "alice": {"role": "owner", "cookies": {"session": "alice"}},
            "bob": {"role": "user", "cookies": {"session": "bob"}},
        },
        engagement_id="idor-test",
        target_scope=("http://127.0.0.1:8000",),
    )

    assert result.confidence_level == "Tool-Confirmed"
    assert result.evidence_bundle
    assert result.evidence["proof_bundle"]["negative_control_digest"]
    assert len(calls) == 4
    assert all(call[2] == ("http://127.0.0.1:8000",) for call in calls)
    assert all("alice" not in str(call[1]) or call[1] == {"session": "alice"} for call in calls)


def test_idor_validator_retries_transient_owner_throttle(monkeypatch):
    calls = []

    def fake_fetch(url, *, cookies=None, target_scope=()):
        calls.append((cookies, target_scope))
        sid = (cookies or {}).get("session")
        if sid == "alice" and sum(1 for item in calls if item[0] == {"session": "alice"}) == 1:
            return 429, "Please wait 1 seconds before continuing.", {}
        if sid in {"alice", "bob"}:
            return 200, '{"id":1001,"owner":"alice"}', {"content-type": "application/json"}
        return 403, "", {"location": "/login"}

    monkeypatch.setattr(structural_checks, "_fetch_page_scoped", fake_fetch)
    monkeypatch.setattr(structural_checks.time, "sleep", lambda _seconds: None)
    result = structural_checks.validate_idor(
        _finding(),
        identity_profiles={
            "alice": {"role": "owner", "cookies": {"session": "alice"}},
            "bob": {"role": "user", "cookies": {"session": "bob"}},
        },
        engagement_id="idor-retry-test",
        target_scope=("http://127.0.0.1:8000",),
    )

    assert result.confidence_level == "Tool-Confirmed"
    assert result.evidence_bundle
    assert sum(1 for item in calls if item[0] == {"session": "alice"}) == 2
    assert all(item[1] == ("http://127.0.0.1:8000",) for item in calls)


def test_idor_validator_stays_fail_closed_without_denied_negative_control(monkeypatch):
    def fake_fetch(url, *, cookies=None, target_scope=()):
        sid = (cookies or {}).get("session")
        if sid in {"alice", "bob"}:
            return 200, "same object", {}
        return 200, "same object", {}

    monkeypatch.setattr(structural_checks, "_fetch_page_scoped", fake_fetch)
    result = structural_checks.validate_idor(
        _finding(),
        identity_profiles={
            "alice": {"role": "owner", "cookies": {"session": "alice"}},
            "bob": {"role": "user", "cookies": {"session": "bob"}},
        },
        engagement_id="idor-test",
        target_scope=("http://127.0.0.1:8000",),
    )

    assert result.confidence_level == "Needs Human Review"
    assert result.evidence_bundle is None
    assert "proof_bundle" not in (result.evidence or {})
    assert result.evidence["negative_control_complete"] is False
