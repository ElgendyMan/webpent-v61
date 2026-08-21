from __future__ import annotations

from dataclasses import dataclass

from webpent.agents.api_testing.agent import _probe_jwt_alg_none


@dataclass
class _Response:
    status_code: int
    text: str
    headers: dict[str, str]

    @property
    def content(self) -> bytes:
        return self.text.encode()


class _Client:
    def __init__(self, responses: list[_Response]) -> None:
        self._responses = iter(responses)

    def __enter__(self) -> _Client:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def get(self, _url: str, **_kwargs: object) -> _Response:
        return next(self._responses)


def test_jwt_probe_skips_spa_shell_and_reaches_later_api_path(monkeypatch) -> None:
    import webpent.shared.http as http_module

    shell = _Response(
        200,
        "<!doctype html><html><head><base href=\"/\"></head><body><app-root></app-root>",
        {"content-type": "text/html; charset=UTF-8"},
    )
    baseline_json = _Response(
        200,
        '{"user":{}}',
        {"content-type": "application/json"},
    )
    api_response = _Response(
        200,
        '{"user":{"id":1,"email":"redacted@example.test"}}',
        {"content-type": "application/json"},
    )
    clients = iter([_Client([shell, shell]), _Client([baseline_json, api_response])])

    def _client_factory(**_kwargs: object) -> _Client:
        return next(clients)

    monkeypatch.setattr(http_module, "make_safe_httpx_client", _client_factory)

    findings = _probe_jwt_alg_none("http://127.0.0.1:3000")

    assert len(findings) == 1
    assert findings[0].url.endswith("/api/v1/user")


def test_jwt_probe_does_not_report_only_spa_shells(monkeypatch) -> None:
    import webpent.shared.http as http_module

    shell = _Response(
        200,
        "<!doctype html><html><head><base href=\"/\"></head><body><app-root></app-root>",
        {"content-type": "text/html"},
    )
    monkeypatch.setattr(
        http_module,
        "make_safe_httpx_client",
        lambda **_kwargs: _Client([shell, shell]),
    )

    assert _probe_jwt_alg_none("http://127.0.0.1:3000") == []
