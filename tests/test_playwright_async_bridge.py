"""Regression tests for the validator's sync-Playwright/asyncio bridge."""

import asyncio

from webpent.agents.validator import agent as validator_agent


def test_playwright_bridge_runs_sync_worker_inside_asyncio(monkeypatch):
    calls: list[tuple[str, object]] = []

    def fake_sync_fetch(url, auth_cookies=None):
        calls.append((url, auth_cookies))
        return "<html data-rendered='true'></html>"

    monkeypatch.setattr(validator_agent, "_fetch_html_via_playwright_sync", fake_sync_fetch)

    async def invoke_from_graph_loop():
        return validator_agent._fetch_html_via_playwright(
            "http://127.0.0.1:8000", [{"name": "sid", "value": "redacted"}]
        )

    result = asyncio.run(invoke_from_graph_loop())

    assert result == "<html data-rendered='true'></html>"
    assert calls == [("http://127.0.0.1:8000", [{"name": "sid", "value": "redacted"}])]


def test_playwright_bridge_fails_closed_when_worker_raises(monkeypatch):
    def failing_sync_fetch(_url, _auth_cookies=None):
        raise RuntimeError("browser unavailable")

    monkeypatch.setattr(validator_agent, "_fetch_html_via_playwright_sync", failing_sync_fetch)

    async def invoke_from_graph_loop():
        return validator_agent._fetch_html_via_playwright("http://127.0.0.1:8000")

    assert asyncio.run(invoke_from_graph_loop()) is None



def test_auth_login_bridge_runs_sync_worker_inside_asyncio(monkeypatch):
    from webpent.agents.authentication import agent as auth_agent

    calls: list[tuple[str, str, str, object]] = []

    def fake_sync_login(url, username, password, additional_target_origins=None):
        calls.append((url, username, password, additional_target_origins))
        return {"session": "redacted"}

    monkeypatch.setattr(auth_agent, "_perform_login_sync", fake_sync_login)

    async def invoke_from_graph_loop():
        return auth_agent._perform_login(
            "http://127.0.0.1:8000",
            "operator@example.test",
            "test-password",
            ["http://127.0.0.1:8000"],
        )

    result = asyncio.run(invoke_from_graph_loop())

    assert result == {"session": "redacted"}
    assert calls == [
        (
            "http://127.0.0.1:8000",
            "operator@example.test",
            "test-password",
            ["http://127.0.0.1:8000"],
        )
    ]


def test_auth_login_bridge_fails_closed_when_worker_raises(monkeypatch):
    from webpent.agents.authentication import agent as auth_agent

    def failing_sync_login(_url, _username, _password, _additional_target_origins=None):
        raise RuntimeError("browser unavailable")

    monkeypatch.setattr(auth_agent, "_perform_login_sync", failing_sync_login)

    async def invoke_from_graph_loop():
        return auth_agent._perform_login(
            "http://127.0.0.1:8000", "operator@example.test", "test-password"
        )

    assert asyncio.run(invoke_from_graph_loop()) == {}
