from __future__ import annotations

from types import SimpleNamespace

from webpent.agents.access_control import agent as access_control_agent
from webpent.agents.authentication import agent as auth_agent
from webpent.agents.validator import structural_checks
from webpent.shared import engagement_scope
from webpent.shared import http as http_module


class _StructuralFakeClient:
    def __init__(self, captured: dict[str, object]) -> None:
        self.captured = captured

    def __enter__(self) -> _StructuralFakeClient:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def get(self, _url: str, *, headers: dict[str, str]):
        self.captured["headers"] = headers
        return SimpleNamespace(status_code=200, text="<main>ok</main>", headers={})


class _RequestFakeClient:
    def __enter__(self) -> _RequestFakeClient:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def request(self, _method: str, _url: str, *, headers: dict[str, str]):
        assert str(headers["User-Agent"]).startswith("Mozilla/5.0")
        return SimpleNamespace(status_code=200, content=b"ok")


class _FakeClient:
    def __init__(self, captured: dict[str, object]) -> None:
        self.captured = captured

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def get(self, _url: str, *, cookies: dict[str, str], headers: dict[str, str]):
        self.captured["cookies"] = cookies
        self.captured["headers"] = headers
        return SimpleNamespace(status_code=200, text="<main>authenticated</main>", headers={})


def test_session_validation_uses_browser_ua_for_default_project_ua(monkeypatch) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        http_module,
        "make_safe_httpx_client",
        lambda **_kwargs: _FakeClient(captured),
    )

    valid, _reason = auth_agent._validate_session_cookies(
        "http://127.0.0.1:8000/",
        {"session": "opaque"},
    )

    assert valid is True
    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert str(headers["User-Agent"]).startswith("Mozilla/5.0")
    assert headers["Accept-Language"] == "en-US,en;q=0.9"
    assert "gzip" in str(headers["Accept-Encoding"])


def test_structural_fetch_uses_browser_headers_with_cookies(monkeypatch) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        http_module,
        "make_safe_httpx_client",
        lambda **_kwargs: _StructuralFakeClient(captured),
    )

    result = structural_checks._fetch_page(
        "http://127.0.0.1:8000/user_profile/1",
        cookies={"laravel_session": "opaque"},
    )

    assert result is not None
    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert str(headers["User-Agent"]).startswith("Mozilla/5.0")
    assert headers["Accept-Language"] == "en-US,en;q=0.9"
    assert "laravel_session=opaque" in str(headers["Cookie"])


def test_bac_probe_scopes_and_restores_engagement_hosts(monkeypatch) -> None:
    monkeypatch.setattr(
        http_module,
        "make_safe_httpx_client",
        lambda **_kwargs: _RequestFakeClient(),
    )
    before = engagement_scope.get_engagement_target_hosts()

    status, content_length = access_control_agent._probe_url(
        "http://127.0.0.1:8000/user_profile/1",
        target_scope=("http://127.0.0.1:8000",),
    )

    assert (status, content_length) == (200, 2)
    assert engagement_scope.get_engagement_target_hosts() == before
