from __future__ import annotations

import pytest

from webpent.config.settings import EnvironmentProfile, ScanMode, Settings
from webpent.shared.action_authority import (
    ActionAuthority,
    ActionRequest,
    ActionRisk,
    ActionStatus,
)


def _manifest(*capabilities: str) -> dict[str, object]:
    return {
        "capabilities": {
            name: {"available": True, "status": "available"}
            for name in capabilities
        },
        "fail_closed": True,
    }


def _request(**overrides: object) -> ActionRequest:
    values: dict[str, object] = {
        "task_id": "phase-a-task",
        "engagement_id": "phase-a-engagement",
        "target_url": "https://example.test/path",
        "capability": "http_read",
        "action_family": "http_read",
        "idempotency_key": "phase-a-idem",
    }
    values.update(overrides)
    return ActionRequest(**values)


def test_non_lab_profile_requires_authentication() -> None:
    with pytest.raises(ValueError, match="requires auth_enabled=True"):
        Settings(
            environment_profile=EnvironmentProfile.STAGING,
            auth_enabled=False,
        )


def test_strict_profile_security_posture_requires_explicit_controls(monkeypatch) -> None:
    from types import SimpleNamespace

    from webpent.config import settings as settings_module
    from webpent.shared import preflight

    monkeypatch.setattr(
        settings_module,
        "get_settings",
        lambda: SimpleNamespace(
            environment_profile=EnvironmentProfile.PRODUCTION,
            auth_enabled=True,
            cors_origins=["*"],
            rate_limit_enabled=False,
        ),
        raising=False,
    )
    posture = preflight._profile_security_posture()
    assert posture["status"].startswith("FAIL")
    assert "CORS origins must be explicit" in posture["failures"]
    assert "rate limiting is disabled" in posture["failures"]


def test_lab_profile_preserves_local_security_compatibility(monkeypatch) -> None:
    from types import SimpleNamespace

    from webpent.config import settings as settings_module
    from webpent.shared import preflight

    monkeypatch.setattr(
        settings_module,
        "get_settings",
        lambda: SimpleNamespace(
            environment_profile=EnvironmentProfile.LAB,
            auth_enabled=False,
            cors_origins=["*"],
            rate_limit_enabled=False,
        ),
        raising=False,
    )
    posture = preflight._profile_security_posture()
    assert posture["status"].startswith("ok")


def test_dns_resolution_failure_is_not_treated_as_safe(monkeypatch) -> None:
    import webpent.shared.http as http

    def fail_resolution(*_args, **_kwargs):
        raise OSError("simulated resolver outage")

    monkeypatch.setattr(http.socket, "getaddrinfo", fail_resolution)

    assert http._is_blocked_host("unresolvable.example.test") is True


def test_unavailable_capability_is_not_treated_as_clean() -> None:
    authority = ActionAuthority(
        settings=Settings(scan_mode=ScanMode.SAFE_SMART),
        allowed_origin="https://example.test",
        manifest=_manifest(),
    )

    decision = authority.authorize(_request(capability="graphql_mutation"))

    assert decision.status is ActionStatus.POLICY_DENIED
    assert "capability:graphql_mutation:unavailable" in decision.reasons


def test_out_of_scope_redirect_like_target_is_denied_before_handler() -> None:
    authority = ActionAuthority(
        settings=Settings(scan_mode=ScanMode.SAFE_SMART),
        allowed_origin="https://example.test",
        manifest=_manifest("http_read"),
    )
    calls: list[str] = []

    result = authority.execute(
        _request(target_url="https://redirected.example.test/private"),
        lambda request: calls.append(request.task_id),
    )

    assert result.status is ActionStatus.POLICY_DENIED
    assert calls == []
    assert "scope:target_origin_mismatch" in result.decision.reasons


def test_destructive_never_becomes_authorized_from_auto_approval() -> None:
    authority = ActionAuthority(
        settings=Settings(
            scan_mode=ScanMode.AUTHORIZED_ACTIVE,
            smart_auto_approve=True,
        ),
        allowed_origin="https://example.test",
        manifest=_manifest("http_read"),
    )

    decision = authority.authorize(
        _request(
            method="DELETE",
            action_family="form_submit",
            risk=ActionRisk.DESTRUCTIVE,
            human_approved=True,
        )
    )

    assert decision.status is ActionStatus.POLICY_DENIED
    assert "policy:destructive_actions_are_not_autonomous" in decision.reasons
