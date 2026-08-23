from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from webpent.config.settings import ScanMode, Settings
from webpent.shared.action_authority import (
    ActionAuthority,
    ActionRequest,
    ActionRisk,
    ActionStatus,
)
from webpent.shared.package_scope import AuthorizationContext, ScopeCompiler


def _manifest(*capabilities: str) -> dict[str, Any]:
    return {
        "capabilities": {
            name: {"available": True, "status": "available"}
            for name in capabilities
        },
        "fail_closed": True,
    }


def _request(**overrides: Any) -> ActionRequest:
    values: dict[str, Any] = {
        "task_id": "task-1",
        "engagement_id": "engagement-1",
        "target_url": "https://example.com/path",
        "capability": "http_read",
        "action_family": "http_read",
        "idempotency_key": "idem-1",
    }
    values.update(overrides)
    return ActionRequest(**values)


def _package(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "status": "ready",
        "package_id": "pkg-1",
        "package_sha256": "digest-1",
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "revocation_state": "active",
    }
    values.update(overrides)
    return values


def _compiler() -> ScopeCompiler:
    return ScopeCompiler(
        AuthorizationContext(
            package_id="pkg-1",
            package_sha256="digest-1",
            scope_digest="scope-1",
            policy_digest="policy-1",
            scope_status="ready",
            scope_rules=(
                {
                    "rule_id": "include-example",
                    "action": "include",
                    "asset_type": "url",
                    "host": "example.com",
                    "scheme": "https",
                    "port": 443,
                    "path": "/",
                },
            ),
            policy_constraints={},
            expires_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            revocation_state="active",
        )
    )


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"target_url": "https://outside.example/path"}, "scope:target_origin_mismatch"),
        ({"capability": "missing_capability"}, "capability:missing_capability:unavailable"),
        ({"idempotency_key": ""}, "idempotency:key_required"),
        ({"risk": ActionRisk.DESTRUCTIVE}, "policy:destructive_actions_are_not_autonomous"),
        ({"task_id": ""}, "identity:task_and_engagement_required"),
    ],
)
def test_denied_policy_never_invokes_handler(
    overrides: dict[str, Any], reason: str
) -> None:
    authority = ActionAuthority(
        settings=Settings(scan_mode=ScanMode.SAFE_SMART),
        allowed_origin="https://example.com",
        manifest=_manifest("http_read"),
    )
    calls: list[str] = []

    result = authority.execute(
        _request(**overrides), lambda request: calls.append(request.task_id)
    )

    assert result.status is ActionStatus.POLICY_DENIED
    assert reason in result.decision.reasons
    assert calls == []


def test_package_scope_and_digest_are_mandatory_for_package_actions() -> None:
    authority = ActionAuthority(
        settings=Settings(scan_mode=ScanMode.SAFE_SMART),
        allowed_origin="https://example.com",
        manifest=_manifest("http_read"),
        target_package=_package(),
        scope_compiler=_compiler(),
    )

    missing_metadata = authority.authorize(_request())
    wrong_digest = authority.authorize(
        _request(
            metadata={
                "target_package_id": "pkg-1",
                "target_package_sha256": "wrong",
            }
        )
    )

    assert missing_metadata.status is ActionStatus.POLICY_DENIED
    assert "package:package_id_mismatch" in missing_metadata.reasons
    assert "package:digest_mismatch" in missing_metadata.reasons
    assert wrong_digest.status is ActionStatus.POLICY_DENIED
    assert "package:digest_mismatch" in wrong_digest.reasons


def test_revoked_or_expired_package_is_denied_even_on_in_scope_url() -> None:
    for package in (
        _package(revocation_state="revoked"),
        _package(expires_at=(datetime.now(UTC) - timedelta(seconds=1)).isoformat()),
    ):
        authority = ActionAuthority(
            settings=Settings(scan_mode=ScanMode.SAFE_SMART),
            allowed_origin="https://example.com",
            manifest=_manifest("http_read"),
            target_package=package,
            scope_compiler=_compiler(),
        )

        decision = authority.authorize(
            _request(
                metadata={
                    "target_package_id": "pkg-1",
                    "target_package_sha256": "digest-1",
                }
            )
        )

        assert decision.status is ActionStatus.POLICY_DENIED
        assert any(reason.startswith("package:") for reason in decision.reasons)


def test_scope_denial_is_independent_of_allowed_origin() -> None:
    authority = ActionAuthority(
        settings=Settings(scan_mode=ScanMode.SAFE_SMART),
        allowed_origin="https://example.com",
        manifest=_manifest("http_read"),
        target_package=_package(),
        scope_compiler=_compiler(),
    )

    decision = authority.authorize(
        _request(
            target_url="https://outside.example/path",
            metadata={
                "target_package_id": "pkg-1",
                "target_package_sha256": "digest-1",
            },
        )
    )

    assert decision.status is ActionStatus.POLICY_DENIED
    assert any(reason.startswith("scope:") for reason in decision.reasons)


def test_audit_event_is_bounded_and_does_not_copy_metadata() -> None:
    authority = ActionAuthority(
        settings=Settings(scan_mode=ScanMode.SAFE_SMART),
        allowed_origin="https://example.com",
        manifest=_manifest("http_read"),
    )
    request = _request(
        target_url="https://example.com/path?secret=must-not-leak",
        metadata={"raw_body": "must-not-leak", "cookie": "must-not-leak"},
    )

    decision = authority.authorize(request)

    assert "target_url" not in decision.audit_event
    assert "metadata" not in decision.audit_event
    assert "must-not-leak" not in repr(decision.audit_event)
    assert len(decision.audit_event["task_id"]) <= 128
