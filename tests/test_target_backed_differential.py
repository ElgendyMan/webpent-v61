from __future__ import annotations

from dataclasses import dataclass


@dataclass
class _Response:
    status_code: int
    text: str
    headers: dict[str, str]


class _Client:
    def __init__(self, responses, calls):
        self._responses = iter(responses)
        self._calls = calls

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, url, *, headers=None, cookies=None):
        self._calls.append(
            {"url": url, "headers": dict(headers or {}), "cookies": dict(cookies or {})}
        )
        return next(self._responses)


def test_baseline_differential_replay_has_independent_negative_control(monkeypatch):
    from webpent.shared import grounding

    calls = []
    responses = [
        _Response(200, "<html>clean</html>", {"content-type": "text/html"}),
        _Response(200, "<html>payload reflected</html>", {"content-type": "text/html"}),
        _Response(200, "<html>clean</html>", {"content-type": "text/html"}),
    ]

    response_iter = iter(responses)

    def factory(**_kwargs):
        return _Client(response_iter, calls)

    monkeypatch.setattr("webpent.shared.http.make_safe_httpx_client", factory)
    result = grounding.baseline_differential_test(
        "http://127.0.0.1:8000/search?q=clean",
        payload_url="http://127.0.0.1:8000/search?q=%3Csvg%3E",
        request_headers={"User-Agent": "WebPent-Test"},
        request_cookies={"session": "secret-value"},
    )

    assert result.is_false_positive is False
    assert result.negative_control_status == 200
    assert result.negative_control_length == len("<html>clean</html>")
    assert result.baseline_request_digest
    assert result.payload_request_digest
    assert result.negative_control_request_digest
    assert result.target_fingerprint
    digests = {
        result.baseline_request_digest,
        result.payload_request_digest,
        result.negative_control_request_digest,
    }
    assert len(digests) == 3
    assert len(calls) == 3
    assert all(call["cookies"] == {"session": "secret-value"} for call in calls)
    assert "secret-value" not in repr(result)


def test_negative_control_failure_fails_closed(monkeypatch):
    from webpent.shared import grounding

    calls = []
    responses = [
        _Response(200, "clean", {}),
        _Response(200, "payload", {}),
    ]

    response_iter = iter(responses)

    def factory(**_kwargs):
        return _Client(response_iter, calls)

    monkeypatch.setattr("webpent.shared.http.make_safe_httpx_client", factory)
    result = grounding.baseline_differential_test(
        "http://127.0.0.1:8000/",
        payload_url="http://127.0.0.1:8000/?q=x",
    )

    assert result.is_false_positive is False
    assert "Negative control fetch failed" in result.reason
    assert len(calls) == 3
