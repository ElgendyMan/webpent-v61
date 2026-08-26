from __future__ import annotations

from pathlib import Path

import pytest

from webpent.config.settings import Settings
from webpent.graph.checkpoints import _redact_channel
from webpent.models.targets import Target
from webpent.shared.autonomous_controller import autonomous_controller_node
from webpent.shared.control_plane import EngagementScope
from webpent.shared.runtime import (
    AdapterRegistry,
    RegisteredAdapter,
    RuntimeConfigurationError,
    RuntimeEventSink,
    RuntimeFactory,
)
from webpent.shared.semantic_observations import SemanticProfileRegistry
from webpent.shared.target_adapters import (
    RegisteredTargetAdapter,
    TargetAdapterRegistry,
    TargetCaseBinding,
)
from webpent.state.initial_state import build_initial_state


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


class _RuntimeTargetAdapter:
    target_id = "runtime-test-target"
    target_origin = "http://example.test"
    semantic_profiles = SemanticProfileRegistry(
        {"runtime.directory.v1": {"rule": "directory_listing", "promotable": False}}
    )

    def workflow_ids(self) -> tuple[str, ...]:
        return ("runtime-navigate-v1",)

    def workflow_executors(self) -> dict[str, object]:
        return {}

    def case_ids(self) -> tuple[str, ...]:
        return ("runtime.case.v1",)

    def case(self, case_id: str) -> TargetCaseBinding | None:
        if case_id != "runtime.case.v1":
            return None
        return TargetCaseBinding(
            case_id=case_id,
            operation="navigate",
            path="/",
            oracle_id="runtime.oracle.v1",
            workflow_id="runtime-navigate-v1",
            semantic_profile="runtime.directory.v1",
        )

    def semantic_profile_for_case(self, case_id: str) -> str | None:
        return "runtime.directory.v1" if case_id == "runtime.case.v1" else None

    def accepts_origin(self, origin: str) -> bool:
        return origin == self.target_origin


def _runtime_target_registry() -> TargetAdapterRegistry:
    registry = TargetAdapterRegistry()
    registry.register(
        RegisteredTargetAdapter(
            adapter=_RuntimeTargetAdapter(),
            source="tests",
            version="1",
            policy_ref="test-policy",
            proof_contract="test-proof-contract",
        )
    )
    return registry


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


def test_runtime_factory_injects_optional_identity_agent_without_checkpoint_leak(
    tmp_path: Path,
) -> None:
    agent = object()
    context = RuntimeFactory.create(
        engagement_id="engagement:identity-runtime",
        campaign_id="campaign:identity-runtime",
        target_origin="https://example.test",
        settings=_settings(tmp_path),
        manifest=_manifest(),
        identity_provisioning_agent=agent,
        enable_control_plane=True,
    )

    assert context.identity_provisioning_agent is agent
    assert isinstance(context.engagement_scope, EngagementScope)
    descriptor = RuntimeFactory.descriptor(context)
    assert "identity_provisioning_agent" not in descriptor
    assert "engagement_scope" not in descriptor


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


def test_initial_state_injects_and_checkpoint_roundtrips_runtime_context(
    tmp_path: Path,
) -> None:
    state = build_initial_state(
        Target(url="http://example.test"),
        thread_id="engagement:initial-state",
        engagement_id="engagement:initial-state",
        profile="smart-observe",
        action_ledger_path=str(tmp_path / "initial-state.sqlite3"),
    )

    context = state["runtime_context"]
    assert context.valid is True
    assert context.engagement_id == "engagement:initial-state"
    assert state["campaign_id"] == "engagement:initial-state:main"
    safe_descriptor = _redact_channel("runtime_context", context)
    assert isinstance(safe_descriptor, dict)
    assert "action_executor" not in safe_descriptor
    restored = RuntimeFactory.from_descriptor(safe_descriptor)
    assert restored is not None
    assert restored.valid is True
    assert restored.target_origin == "http://example.test"
    assert restored.action_executor.authority is restored.action_authority


def test_initial_state_defaults_to_target_neutral_inventory_even_on_lab_port(
    tmp_path: Path,
) -> None:
    state = build_initial_state(
        Target(url="http://127.0.0.1:8000"),
        thread_id="engagement:generic-default",
        engagement_id="engagement:generic-default",
        profile="smart-observe",
        action_ledger_path=str(tmp_path / "generic-default.sqlite3"),
    )

    assert state["campaign_inventory"] == "generic"
    assert len(state["campaign_plan"]["entries"]) == 10


def test_initial_state_keeps_explicit_waptlab_compatibility_inventory(
    tmp_path: Path,
) -> None:
    state = build_initial_state(
        Target(url="http://127.0.0.1:8000"),
        thread_id="engagement:explicit-waptlab",
        engagement_id="engagement:explicit-waptlab",
        profile="smart-observe",
        campaign_inventory="waptlab",
        action_ledger_path=str(tmp_path / "explicit-waptlab.sqlite3"),
    )

    assert state["campaign_inventory"] == "waptlab"
    assert len(state["campaign_plan"]["entries"]) == 20


def test_target_aware_runtime_roundtrip_requires_explicit_registry(
    tmp_path: Path,
) -> None:
    target_registry = _runtime_target_registry()
    context = RuntimeFactory.create(
        engagement_id="engagement:target-runtime",
        campaign_id="campaign:target-runtime",
        target_origin="http://example.test",
        settings=_settings(tmp_path),
        manifest=_manifest(),
        target_adapter_registry=target_registry,
    )

    assert context.valid is True
    assert context.target_adapter_registration is not None
    assert context.target_adapter_registration.target_id == "runtime-test-target"
    descriptor = RuntimeFactory.descriptor(context)
    assert descriptor["target_adapter"]["target_id"] == "runtime-test-target"
    assert "adapter" not in repr(descriptor["target_adapter"])
    assert RuntimeFactory.from_descriptor(descriptor) is None

    restored = RuntimeFactory.from_descriptor(
        descriptor,
        target_adapter_registry=target_registry,
    )
    assert restored is not None
    assert restored.valid is True
    assert restored.target_adapter_registration is not None
    assert restored.target_adapter_registration.target_id == "runtime-test-target"


def test_initial_state_fails_closed_when_target_workflow_provider_raises(
    tmp_path: Path,
) -> None:
    class _BootstrapFailingAdapter(_RuntimeTargetAdapter):
        executor_calls = 0

        def workflow_executors(self) -> dict[str, object]:
            self.executor_calls += 1
            if self.executor_calls >= 3:
                raise RuntimeError("workflow provider unavailable during bootstrap")
            return {}

    target_registry = TargetAdapterRegistry()
    target_registry.register(
        RegisteredTargetAdapter(
            adapter=_BootstrapFailingAdapter(),
            source="tests",
            version="1",
            policy_ref="test-policy",
            proof_contract="test-proof-contract",
        )
    )

    state = build_initial_state(
        Target(url="http://example.test"),
        thread_id="engagement:bootstrap-failure",
        engagement_id="engagement:bootstrap-failure",
        profile="smart-observe",
        action_ledger_path=str(tmp_path / "bootstrap-failure.sqlite3"),
        target_adapter_registry=target_registry,
    )

    context = state["runtime_context"]
    assert context.valid is False
    assert context.control_plane_browser_adapter is None
    assert any(
        item.startswith("target_adapter:registration_unavailable:")
        for item in context.configuration_errors
    )


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
