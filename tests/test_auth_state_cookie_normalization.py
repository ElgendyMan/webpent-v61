from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.agents.execution_sandbox.agent import (  # noqa: E402
    _inject_cookies,
    _normalise_auth_state_cookies,
)


class _Context:
    def __init__(self) -> None:
        self.calls: list[list[dict[str, object]]] = []

    def add_cookies(self, cookies: list[dict[str, object]]) -> None:
        self.calls.append(cookies)


def test_bare_auth_state_cookie_gets_target_scope() -> None:
    cookies = _normalise_auth_state_cookies(
        [{"name": "sid", "value": "redacted-value"}],
        "http://127.0.0.1:3000/#/login",
    )

    assert cookies == [
        {
            "name": "sid",
            "value": "redacted-value",
            "domain": "127.0.0.1",
            "path": "/",
        }
    ]


def test_same_host_playwright_record_preserves_safe_attributes() -> None:
    cookies = _normalise_auth_state_cookies(
        [
            {
                "name": "sid",
                "value": "v",
                "domain": ".example.test",
                "path": "/app",
                "httpOnly": True,
                "secure": False,
                "sameSite": "Lax",
            }
        ],
        "https://example.test/app/login",
    )

    assert cookies == [
        {
            "name": "sid",
            "value": "v",
            "domain": ".example.test",
            "path": "/app",
            "httpOnly": True,
            "secure": False,
            "sameSite": "Lax",
        }
    ]


def test_cross_origin_and_malformed_records_are_rejected_fail_closed() -> None:
    cookies = _normalise_auth_state_cookies(
        [
            {"name": "other", "value": "v", "domain": "evil.test"},
            {"name": "url-other", "value": "v", "url": "https://evil.test/"},
            {"name": "missing-value"},
            {"name": "bad", "value": "line\nfeed"},
            "not-a-cookie-record",
        ],
        "https://example.test/",
    )

    assert cookies == []


def test_inject_cookies_is_disabled_for_execution() -> None:
    context = _Context()

    _inject_cookies(
        context,
        "http://127.0.0.1:3000/#/search",
        {"cookies": [{"name": "sid", "value": "v"}]},
    )

    assert context.calls == []


def test_invalid_auth_state_does_not_call_playwright() -> None:
    context = _Context()

    _inject_cookies(
        context,
        "https://example.test/",
        {"cookies": [{"name": "sid", "value": "v", "domain": "evil.test"}]},
    )

    assert context.calls == []
