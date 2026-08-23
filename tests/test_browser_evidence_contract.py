from webpent.agents.validator.agent import _browser_render_metadata


def test_browser_render_metadata_is_redacted_and_deterministic():
    metadata = _browser_render_metadata(
        used_playwright=True,
        html_content="<form><input name='amount'></form>",
        auth_cookies=[{"name": "session", "value": "secret"}],
        samesite_detected=False,
    )

    assert metadata["engine"] == "playwright-chromium"
    assert metadata["js_executed"] is True
    assert metadata["content_length"] > 0
    assert len(metadata["content_sha256"]) == 64
    assert metadata["auth_cookie_count"] == 1
    assert metadata["samesite_detected"] is False
    assert "secret" not in str(metadata)
    assert "<form>" not in str(metadata)


def test_static_fallback_metadata_is_explicit():
    metadata = _browser_render_metadata(
        used_playwright=False,
        html_content="<html></html>",
        auth_cookies=None,
        samesite_detected=True,
    )

    assert metadata["engine"] == "httpx-static"
    assert metadata["js_executed"] is False
    assert metadata["auth_cookie_count"] == 0
    assert metadata["samesite_detected"] is True


def test_csrf_validator_records_browser_metadata_without_confirmation(monkeypatch):
    from uuid import uuid4

    from webpent.agents.validator import agent as validator_agent
    from webpent.models.findings import Confidence, Finding

    finding = Finding(
        id=uuid4(),
        title="csrf finding",
        url="http://127.0.0.1:8000/csrf",
        vuln_class="csrf",
        severity="high",
        confidence=Confidence.TENTATIVE.value,
        confidence_level="Pending",
        description="test",
        tool_name="test",
    )
    monkeypatch.setattr(
        validator_agent,
        "_fetch_html_via_playwright",
        lambda _url, _cookies: "<form method='post'></form>",
    )
    monkeypatch.setattr(
        validator_agent,
        "_verify_csrf_structurally",
        lambda _url, _html: (True, "missing token"),
    )
    monkeypatch.setattr(
        validator_agent,
        "_persist_finding_incrementally",
        lambda updated, thread_id=None: True,
    )

    updated = validator_agent._validate_csrf(
        finding,
        playwright_enabled=True,
        auth_state={"cookies": [{"name": "session", "value": "secret"}]},
    )

    assert updated.confidence_level == "Needs Human Review"
    assert updated.evidence["browser_render"]["engine"] == "playwright-chromium"
    assert updated.evidence["browser_render"]["auth_cookie_count"] == 1
    assert "secret" not in str(updated.evidence)
    assert "<form>" not in str(updated.evidence)
