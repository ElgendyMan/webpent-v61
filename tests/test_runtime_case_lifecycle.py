from __future__ import annotations

from pathlib import Path

import httpx
import pytest

import webpent.adapters.generic_web.adapter as generic_adapter_module
from webpent.adapters.generic_web.adapter import GenericWebAdapter, build_generic_web_registration
from webpent.config.settings import Settings
from webpent.shared.generic_web_contracts import LifecycleAuthorization
from webpent.shared.runtime import RuntimeFactory
from webpent.shared.target_adapters import TargetAdapterRegistry


@pytest.fixture(autouse=True)
def _safe_client_with_injected_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    def factory(**kwargs: object) -> httpx.Client:
        return httpx.Client(**kwargs)

    monkeypatch.setattr(generic_adapter_module, "make_safe_httpx_client", factory)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        action_ledger_path=tmp_path / "actions.sqlite3",
        scan_mode="safe-smart",
        smart_auto_approve=False,
        smart_require_idempotency=True,
    )


def _manifest() -> dict[str, object]:
    return {
        "profile": "test",
        "fail_closed": True,
        "capabilities": {
            "http_read": {"available": True, "status": "available"},
        },
        "blockers": [],
    }


def _authorization() -> LifecycleAuthorization:
    return LifecycleAuthorization(
        authorized=True,
        engagement_id="engagement:case-runtime",
        allowed_origin="http://case-runtime.test",
        satisfied_requirements=("operator_declared_authorization",),
    )


def test_runtime_context_executes_registered_case_through_lifecycle_runner(
    tmp_path: Path,
) -> None:
    adapter = GenericWebAdapter(
        "http://case-runtime.test",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                headers={"content-type": "text/html"},
                content="<html><title>Runtime fixture</title></html>",
                request=request,
            )
        ),
    )
    registration = build_generic_web_registration(adapter)
    registry = TargetAdapterRegistry()
    registry.register(registration)
    runtime = RuntimeFactory.create(
        engagement_id="engagement:case-runtime",
        campaign_id="campaign:case-runtime",
        target_origin="http://case-runtime.test",
        settings=_settings(tmp_path),
        manifest=_manifest(),
        target_adapter_registry=registry,
    )

    result = runtime.execute_registered_case(
        adapter.case_definition(),
        _authorization(),
        run_id="runtime-case-run-001",
    )

    assert result.status == "needs_profile"
    assert result.proof_bundle_ref is None
    assert result.observation_refs


def test_runtime_context_fails_closed_without_injected_registration(tmp_path: Path) -> None:
    adapter = GenericWebAdapter("http://case-runtime.test")
    runtime = RuntimeFactory.create(
        engagement_id="engagement:case-runtime",
        campaign_id="campaign:case-runtime",
        target_origin="http://case-runtime.test",
        settings=_settings(tmp_path),
        manifest=_manifest(),
    )

    result = runtime.execute_registered_case(
        adapter.case_definition(),
        _authorization(),
        run_id="runtime-case-run-002",
    )

    assert result.status == "blocked"
    assert result.reason == "target_adapter_registration_missing"
