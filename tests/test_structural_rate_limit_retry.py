from __future__ import annotations

from webpent.agents.validator import structural_checks


def test_rate_limit_retry_uses_bounded_waptlab_ttl_when_retry_after_missing(monkeypatch):
    calls: list[tuple[str, dict[str, str] | None, tuple[str, ...]]] = []
    sleeps: list[float] = []
    responses = [
        (429, "periodic request detected", {}),
        (200, "owner profile", {"content-type": "text/html"}),
    ]

    def fake_fetch(url, *, cookies=None, target_scope=()):
        calls.append((url, cookies, target_scope))
        return responses.pop(0)

    monkeypatch.setattr(structural_checks, "_fetch_page_scoped", fake_fetch)
    monkeypatch.setattr(structural_checks.time, "sleep", sleeps.append)

    result = structural_checks._fetch_page_scoped_with_rate_limit_retry(
        "http://127.0.0.1:8000/user_profile/1",
        cookies={"session": "redacted"},
        target_scope=("http://127.0.0.1:8000",),
    )

    assert result[0] == 200
    assert len(calls) == 2
    assert sleeps == [15.5]
    assert calls[0][2] == ("http://127.0.0.1:8000",)
    assert calls[0][1] == {"session": "redacted"}


def test_rate_limit_retry_keeps_short_budget_for_transient_5xx(monkeypatch):
    sleeps: list[float] = []
    responses = [
        (503, "temporarily unavailable", {}),
        (200, "ok", {}),
    ]

    monkeypatch.setattr(
        structural_checks,
        "_fetch_page_scoped",
        lambda *args, **kwargs: responses.pop(0),
    )
    monkeypatch.setattr(structural_checks.time, "sleep", sleeps.append)

    result = structural_checks._fetch_page_scoped_with_rate_limit_retry(
        "http://127.0.0.1:8000/health",
        target_scope=("http://127.0.0.1:8000",),
    )

    assert result[0] == 200
    assert sleeps == [4.5]


def test_rate_limit_retry_preserves_original_response_if_retry_transport_fails(monkeypatch):
    sleeps: list[float] = []
    responses = [(429, "periodic request detected", {}), None]

    monkeypatch.setattr(
        structural_checks,
        "_fetch_page_scoped",
        lambda *args, **kwargs: responses.pop(0),
    )
    monkeypatch.setattr(structural_checks.time, "sleep", sleeps.append)

    result = structural_checks._fetch_page_scoped_with_rate_limit_retry(
        "http://127.0.0.1:8000/user_profile/1",
        target_scope=("http://127.0.0.1:8000",),
    )

    assert result == (429, "periodic request detected", {})
    assert sleeps == [15.5]
