from __future__ import annotations

from pathlib import Path

from webpent.config.settings import ScanMode, Settings
from webpent.shared.action_authority import (
    ActionAuthority,
    ActionRequest,
    ActionRisk,
    ActionStatus,
)
from webpent.shared.action_ledger import SQLiteActionLedger


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
        "task_id": "task-1",
        "engagement_id": "engagement-1",
        "target_url": "https://example.test/path",
        "capability": "http_read",
        "action_family": "http_read",
        "idempotency_key": "idem-1",
    }
    values.update(overrides)
    return ActionRequest(**values)


def test_read_only_action_is_authorized_in_safe_smart() -> None:
    settings = Settings(scan_mode=ScanMode.SAFE_SMART)
    authority = ActionAuthority(
        settings=settings,
        allowed_origin="https://example.test",
        manifest=_manifest("http_read"),
    )

    decision = authority.authorize(_request())

    assert decision.status is ActionStatus.AUTHORIZED
    assert decision.reasons == ()


def test_scope_mismatch_is_fail_closed() -> None:
    authority = ActionAuthority(
        settings=Settings(scan_mode=ScanMode.SAFE_SMART),
        allowed_origin="https://example.test",
        manifest=_manifest("http_read"),
    )

    decision = authority.authorize(
        _request(target_url="https://other.example.test/path")
    )

    assert decision.status is ActionStatus.POLICY_DENIED
    assert "scope:target_origin_mismatch" in decision.reasons


def test_destructive_action_is_denied_even_when_auto_approved() -> None:
    settings = Settings(
        scan_mode=ScanMode.AUTHORIZED_ACTIVE,
        smart_auto_approve=True,
    )
    authority = ActionAuthority(
        settings=settings,
        allowed_origin="https://example.test",
        manifest=_manifest("http_read"),
    )

    decision = authority.authorize(
        _request(
            method="POST",
            action_family="form_submit",
            capability="http_read",
            risk=ActionRisk.DESTRUCTIVE,
            human_approved=True,
        )
    )

    assert decision.status is ActionStatus.POLICY_DENIED
    assert "policy:destructive_actions_are_not_autonomous" in decision.reasons


def test_active_action_requires_authorized_active_and_approval() -> None:
    safe_authority = ActionAuthority(
        settings=Settings(scan_mode=ScanMode.SAFE_SMART),
        allowed_origin="https://example.test",
        manifest=_manifest("http_read"),
    )
    safe_decision = safe_authority.authorize(
        _request(
            method="POST",
            action_family="form_submit",
            risk=ActionRisk.ACTIVE,
            human_approved=True,
        )
    )
    assert safe_decision.status is ActionStatus.POLICY_DENIED
    assert "policy:active_method_requires_authorized_active_profile" in safe_decision.reasons

    active_authority = ActionAuthority(
        settings=Settings(scan_mode=ScanMode.AUTHORIZED_ACTIVE),
        allowed_origin="https://example.test",
        manifest=_manifest("http_read"),
    )
    blocked_decision = active_authority.authorize(
        _request(
            method="POST",
            action_family="form_submit",
            risk=ActionRisk.ACTIVE,
        )
    )
    assert blocked_decision.status is ActionStatus.POLICY_DENIED
    assert "approval:active_action_not_approved" in blocked_decision.reasons

    approved_decision = active_authority.authorize(
        _request(
            method="POST",
            action_family="form_submit",
            risk=ActionRisk.ACTIVE,
            human_approved=True,
        )
    )
    assert approved_decision.status is ActionStatus.AUTHORIZED


def test_handler_failure_is_typed_and_called_once() -> None:
    authority = ActionAuthority(
        settings=Settings(scan_mode=ScanMode.SAFE_SMART),
        allowed_origin="https://example.test",
        manifest=_manifest("http_read"),
    )
    calls: list[str] = []

    def failing_handler(request: ActionRequest) -> None:
        calls.append(request.task_id)
        raise RuntimeError("simulated transport failure")

    result = authority.execute(_request(), failing_handler)

    assert result.status is ActionStatus.INFRASTRUCTURE_FAILURE
    assert calls == ["task-1"]
    assert any(
        reason.startswith("handler:infrastructure_failure:RuntimeError")
        for reason in result.decision.reasons
    )


def test_ledger_rejects_duplicate_idempotency_key(tmp_path: Path) -> None:
    ledger = SQLiteActionLedger(tmp_path / "actions.sqlite3")
    authority = ActionAuthority(
        settings=Settings(scan_mode=ScanMode.SAFE_SMART),
        allowed_origin="https://example.test",
        manifest=_manifest("http_read"),
        ledger=ledger,
    )
    calls: list[str] = []

    def handler(request: ActionRequest) -> str:
        calls.append(request.idempotency_key)
        return "ok"

    first = authority.execute(_request(), handler)
    second = authority.execute(_request(), handler)

    assert first.status is ActionStatus.EXECUTED
    assert second.status is ActionStatus.POLICY_DENIED
    assert "idempotency:duplicate_reservation" in second.decision.reasons
    assert calls == ["idem-1"]
    assert ledger.snapshot("engagement-1") == {
        "engagement_id": "engagement-1",
        "used_actions": 1,
        "used_budget": 1.0,
    }
