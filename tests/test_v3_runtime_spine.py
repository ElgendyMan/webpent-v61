from __future__ import annotations

from pathlib import Path

import pytest

from webpent.config.settings import Settings
from webpent.shared.autonomous_controller import autonomous_controller_node
from webpent.shared.runtime import (
    AdapterRegistry,
    RegisteredAdapter,
    RuntimeConfigurationError,
    RuntimeEventSink,
    RuntimeFactory,
)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        action_ledger_path=tmp_path / "actions.sqlite3",
        scan_mode="safe-smart",
        smart_auto_approve=False,
        smart_require_idempotency=True,
    )


def _manifest() -> dict:
    return {
        "profile": "test",
        "fail_closed": True,
        "capabilities": {
            "http_read": {"available": True, "status": "available"},
        },
        "blockers": [],
    }


def test_runtime_factory_injects_one_central_spine(tmp_path: Path) -> None:
    context = RuntimeFactory.create(
        engagement_id="engagement:test-runtime",
        campaign_id="campaign:test-runtime",
        target_origin="http://example.test",
        settings=_settings(tmp_path),
        manifest=_manifest(),
    )

    assert context.require_valid() is context
    assert context.action_executor.authority is context.action_authority
    assert context.scope_matcher.allows("http://example.test/item")
    assert context.capabilities.available("http_read") is True
    diagnostics = context.diagnostics()
    assert diagnostics["valid"] is True
    assert diagnostics["event_count"] == 1
    assert diagnostics["adapters"] == []


def test_runtime_factory_returns_structured_blocker_for_invalid_context(
    tmp_path: Path,
) -> None:
    context = RuntimeFactory.create(
        engagement_id="",
        campaign_id="",
        target_origin="not-a-url",
        settings=_settings(tmp_path),
        manifest=_manifest(),
    )

    assert context.valid is False
    with pytest.raises(RuntimeConfigurationError):
        context.require_valid()
    result = context.blocked_result(node="surface_discovery")
    assert result["status"] == "blocked_by_configuration"
    assert result["clean"] is False
    assert "engagement_id_required" in result["reason"]
    assert context.event_sink.snapshot()[-1].event_type == (
        "runtime.blocked_by_configuration"
    )


def test_runtime_event_sink_redacts_sensitive_payloads() -> None:
    sink = RuntimeEventSink()
    event = sink.emit(
        "test.secret",
        engagement_id="engagement:test",
        campaign_id="campaign:test",
        payload={"password": "do-not-store", "cookie": "session-secret"},
    )

    serialized = repr(event.payload)
    assert "do-not-store" not in serialized
    assert "session-secret" not in serialized


def test_adapter_registry_requires_policy_checked_manifest() -> None:
    registry = AdapterRegistry()
    adapter = RegisteredAdapter(
        name="native-http",
        capability="http_read",
        transport="http",
        handler=lambda request: request,
    )
    with pytest.raises(RuntimeConfigurationError, match="policy_checked"):
        registry.register(adapter)

    registry.register(
        RegisteredAdapter(
            name="native-http",
            capability="http_read",
            transport="http",
            handler=lambda request: request,
            policy_checked=True,
            version="test-1",
        )
    )
    assert registry.available("native-http") is True
    assert registry.manifest()[0]["policy_checked"] is True


def test_autonomous_controller_node_blocks_without_runtime_context() -> None:
    result = autonomous_controller_node({"engagement_id": "engagement:test"})

    assert result["status"] == "blocked_by_configuration"
    assert result["reason"] == "runtime_context_required"


def test_runtime_factory_rejects_invalid_target_without_raw_transport(
    tmp_path: Path,
) -> None:
    context = RuntimeFactory.create(
        engagement_id="engagement:test-runtime",
        campaign_id="campaign:test-runtime",
        target_origin="file:///etc/passwd",
        settings=_settings(tmp_path),
        manifest=_manifest(),
    )

    assert context.valid is False
    assert context.adapters.manifest() == []
    assert context.diagnostics()["configuration_errors"]
