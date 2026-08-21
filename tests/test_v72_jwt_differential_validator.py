from __future__ import annotations

from dataclasses import dataclass

from webpent.agents.validator.structural_checks import validate_auth_bypass
from webpent.models.findings import Finding, Severity, VulnClass
from webpent.models.proof_bundle import validate_proof_bundle


@dataclass
class _Response:
    status_code: int
    text: str


class _Client:
    def __init__(self, responses: list[_Response]) -> None:
        self._responses = iter(responses)

    def __enter__(self) -> _Client:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def get(self, _url: str, **_kwargs: object) -> _Response:
        return next(self._responses)


def _finding() -> Finding:
    return Finding(
        title="Potential unsigned JWT acceptance",
        severity=Severity.HIGH,
        description="An active alg=none JWT probe returned authenticated content.",
        tool_name="api_testing_agent",
        payload="Authorization: Bearer <alg=none-token>",
        url="http://127.0.0.1:3000/rest/user/whoami",
        vuln_class=VulnClass.AUTH_BYPASS,
    )


def test_jwt_differential_requires_rejected_baseline_and_control(monkeypatch) -> None:
    import webpent.shared.http as http_module

    client = _Client(
        [
            _Response(401, "unauthorized"),
            _Response(200, "authenticated-user-content" * 20),
            _Response(401, "unauthorized"),
        ]
    )
    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **_kwargs: client)

    result = validate_auth_bypass(_finding(), engagement_id="juice-test")

    assert result.confidence_level == "Tool-Confirmed"
    assert result.evidence_bundle is not None
    assert result.evidence is not None
    proof = result.evidence["proof_bundle"]
    assert validate_proof_bundle(proof, require_negative_control=True)


def test_jwt_differential_fails_closed_when_control_is_not_rejected(monkeypatch) -> None:
    import webpent.shared.http as http_module

    client = _Client(
        [
            _Response(401, "unauthorized"),
            _Response(200, "authenticated-user-content" * 20),
            _Response(200, "same-public-content" * 20),
        ]
    )
    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **_kwargs: client)

    result = validate_auth_bypass(_finding(), engagement_id="juice-test")

    assert result.confidence_level == "Needs Human Review"
    assert result.evidence_bundle is None
    assert result.evidence is not None
    assert "proof_bundle" not in result.evidence


def test_jwt_spa_fallback_with_identical_bodies_stays_unconfirmed(monkeypatch) -> None:
    import webpent.shared.http as http_module

    client = _Client(
        [
            _Response(200, "same SPA shell" * 200),
            _Response(200, "same SPA shell" * 200),
            _Response(200, "same SPA shell" * 200),
        ]
    )
    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **_kwargs: client)

    result = validate_auth_bypass(_finding(), engagement_id="juice-test")

    assert result.confidence_level == "Needs Human Review"
    assert result.evidence_bundle is None
    assert result.evidence is not None
    assert "proof_bundle" not in result.evidence


def test_non_jwt_auth_bypass_keeps_observation_only(monkeypatch) -> None:
    import webpent.agents.validator.structural_checks as checks

    monkeypatch.setattr(
        checks,
        "_fetch_page",
        lambda _url, cookies=None: (
            (200, "content" * 30, {}) if cookies else (200, "public" * 30, {})
        ),
    )
    finding = _finding().model_copy(update={"payload": "ordinary auth probe"})

    result = validate_auth_bypass(finding, cookies={"sid": "redacted"})

    assert result.confidence_level == "Needs Human Review"
    assert result.evidence_bundle is None


def test_jwt_probe_marker_routes_base64_token_to_differential(monkeypatch) -> None:
    import webpent.shared.http as http_module

    client = _Client(
        [
            _Response(401, "unauthorized"),
            _Response(200, "authenticated-user-content" * 20),
            _Response(401, "unauthorized"),
        ]
    )
    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **_kwargs: client)
    finding = _finding().model_copy(
        update={
            "title": "JWT token accepted at endpoint",
            "description": "The probe used a base64-encoded unsigned token.",
            "payload": "Authorization: Bearer eyJhbGciOiJub25lIn0...",
            "evidence": {"jwt_probe": "alg=none"},
        }
    )

    result = validate_auth_bypass(finding, engagement_id="juice-test")

    assert result.confidence_level == "Tool-Confirmed"
    assert result.evidence_bundle is not None


class _ProbeClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def __enter__(self) -> _ProbeClient:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def get(self, _url: str, **kwargs: object) -> _Response:
        self.calls.append(dict(kwargs.get("headers") or {}))
        return _Response(200, '{"user":{}}')


def test_jwt_probe_does_not_promote_valid_session_cookie(monkeypatch) -> None:
    import webpent.agents.api_testing.agent as api_agent
    import webpent.shared.http as http_module

    client = _ProbeClient()
    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **_kwargs: client)

    findings = api_agent._probe_jwt_alg_none(
        "http://127.0.0.1:3000",
        cookies={"token": "valid-session-token"},
        auth_headers={"Authorization": "Bearer valid-session-token"},
    )

    assert findings == []
    assert client.calls
    assert all("Cookie" not in headers for headers in client.calls)
    assert all(
        not any(str(name).lower() == "x-auth-token" for name in headers)
        for headers in client.calls
    )
