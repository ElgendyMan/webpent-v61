from __future__ import annotations

import pytest

from webpent.config.settings import ScanMode, Settings
from webpent.shared.control_plane_runtime import BrowserActionAdapter
from webpent.shared.runtime import (
    CONTROL_PLANE_BROWSER_ADAPTER_NAME,
    CONTROL_PLANE_BROWSER_INVENTORY_REF,
    CONTROL_PLANE_BROWSER_PROOF_CONTRACT,
    AdapterRegistry,
    RuntimeConfigurationError,
    RuntimeFactory,
    register_control_plane_browser_adapter,
)


def _settings() -> Settings:
    return Settings(scan_mode=ScanMode.SAFE_SMART)


def _browser_adapter() -> BrowserActionAdapter:
    return BrowserActionAdapter(lambda _request: {"dom_digest": "sha256:" + "a" * 64})


def test_control_plane_bootstrap_alone_keeps_adapter_gap() -> None:
    context = RuntimeFactory.create(
        engagement_id="eng-browser-gap",
        campaign_id="campaign-browser-gap",
        target_origin="https://example.test",
        settings=_settings(),
        use_default_ledger=False,
        enable_control_plane=True,
    )

    assert context.control_plane_runtime is not None
    assert context.adapters.get(CONTROL_PLANE_BROWSER_ADAPTER_NAME) is None
    assert any(gap.component == "adapters" for gap in context.current_capability_gaps())


def test_valid_injected_browser_adapter_clears_only_adapter_gap() -> None:
    context = RuntimeFactory.create(
        engagement_id="eng-browser-ready",
        campaign_id="campaign-browser-ready",
        target_origin="https://example.test",
        settings=_settings(),
        use_default_ledger=False,
        enable_control_plane=True,
        control_plane_browser_adapter=_browser_adapter(),
    )

    registered = context.adapters.get(CONTROL_PLANE_BROWSER_ADAPTER_NAME)
    assert registered is not None
    assert registered.capability == "browser_action"
    assert registered.transport == "injected_browser_handler"
    assert registered.static_inventory_ref == CONTROL_PLANE_BROWSER_INVENTORY_REF
    assert registered.proof_contract == CONTROL_PLANE_BROWSER_PROOF_CONTRACT
    assert context.adapters.validate_for_execution(
        CONTROL_PLANE_BROWSER_ADAPTER_NAME
    ) == (True, ())
    assert all(gap.component != "adapters" for gap in context.current_capability_gaps())

    descriptor = RuntimeFactory.descriptor(context)
    assert "handler" not in repr(descriptor)
    assert "browser_action" not in repr(descriptor)
    assert descriptor["control_plane_enabled"] is True


def test_browser_registration_rejects_raw_callable() -> None:
    with pytest.raises(RuntimeConfigurationError, match="typed_adapter_required"):
        register_control_plane_browser_adapter(
            AdapterRegistry(),
            lambda _request: {"status": 200},
        )


def test_browser_registration_rejects_duplicate_and_expired_metadata() -> None:
    registry = AdapterRegistry()
    register_control_plane_browser_adapter(
        registry,
        _browser_adapter(),
        expires_at="2099-01-01",
    )
    with pytest.raises(RuntimeConfigurationError, match="duplicate_registration"):
        register_control_plane_browser_adapter(registry, _browser_adapter())

    expired = AdapterRegistry()
    with pytest.raises(RuntimeConfigurationError, match="approval_expired"):
        register_control_plane_browser_adapter(
            expired,
            _browser_adapter(),
            expires_at="2000-01-01",
        )


def test_registered_adapter_expiry_is_not_hardcoded_to_old_g02_date() -> None:
    registry = AdapterRegistry()
    register_control_plane_browser_adapter(
        registry,
        _browser_adapter(),
        expires_at="2099-01-01T00:00:00Z",
    )
    valid, errors = registry.validate_for_execution(CONTROL_PLANE_BROWSER_ADAPTER_NAME)
    assert valid is True
    assert errors == ()

    invalid = registry.get(CONTROL_PLANE_BROWSER_ADAPTER_NAME)
    assert invalid is not None
    assert invalid.g02_errors() == ()
