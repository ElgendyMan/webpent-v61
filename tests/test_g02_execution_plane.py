from webpent.config.settings import ScanMode, Settings
from webpent.shared.action_authority import ActionAuthority
from webpent.shared.campaign_executor import ActionExecutor, CampaignTask, CampaignTaskStatus
from webpent.shared.runtime import AdapterRegistry, RegisteredAdapter


def _settings() -> Settings:
    return Settings(
        scan_mode=ScanMode.SAFE_SMART,
        smart_require_idempotency=True,
        smart_action_budget=10.0,
        smart_max_actions=5,
    )


def _task(**metadata: str) -> CampaignTask:
    return CampaignTask(
        task_id="g02-task-1",
        engagement_id="g02-engagement-1",
        asset_id="asset-1",
        source_evidence_ids=("surface-1",),
        vulnerability_class="idor",
        hypothesis_id="hypothesis-1",
        target_url="http://example.test/object/1",
        idempotency_key="g02-task-1-key",
        metadata=metadata,
    )


def _registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    registry.register(
        RegisteredAdapter(
            name="native-http",
            capability="http_read",
            transport="http",
            handler=lambda request: request,
            policy_checked=True,
            version="test-1",
            canonical_wrapper="webpent.shared.http.make_safe_httpx_client",
            scope_policy="same-origin",
            static_inventory_ref="docs/direct_io_inventory.json#native-http",
            proof_contract="response-causal-negative-control-proof-bundle",
            expires_at="2026-11-19",
        )
    )
    return registry


def test_g02_execution_requires_registered_adapter_and_preserves_proof_contract():
    registry = _registry()
    authority = ActionAuthority(
        settings=_settings(),
        allowed_origin="http://example.test",
        manifest={"capabilities": {"http_read": {"available": True}}},
        adapter_registry=registry,
        require_g02=True,
    )
    executor = ActionExecutor(authority)
    called = False

    def handler(_task: CampaignTask) -> dict[str, object]:
        nonlocal called
        called = True
        return {
            "finding_id": "finding-g02-1",
            "proof_evidence": [{"causal_signal": "changed"}],
            "evidence_refs": ["execution:g02-1"],
            "negative_control": {"causal_signal": "unchanged"},
        }

    record = executor.execute(
        _task(
            adapter_name="native-http",
            g02_inventory_ref="docs/direct_io_inventory.json#native-http",
            g02_proof_contract="response-causal-negative-control-proof-bundle",
        ),
        handler,
    )

    assert called is True
    assert record["status"] == CampaignTaskStatus.EXECUTED.value
    assert record["proof_bundle_sealed"] is True
    assert record["g02_execution"]["adapter_name"] == "native-http"
    assert record["g02_execution"]["proof_required"] is True
    assert "sealed_proof_bundle" in record["g02_execution"]["confirmation_requires"]


def test_g02_execution_blocks_missing_adapter_before_handler():
    registry = _registry()
    authority = ActionAuthority(
        settings=_settings(),
        allowed_origin="http://example.test",
        manifest={"capabilities": {"http_read": {"available": True}}},
        adapter_registry=registry,
        require_g02=True,
    )
    executor = ActionExecutor(authority)
    called = False

    def handler(_task: CampaignTask) -> dict[str, object]:
        nonlocal called
        called = True
        return {"proof_evidence": [{"unexpected": True}]}

    record = executor.execute(_task(adapter_name="not-registered"), handler)

    assert called is False
    assert record["status"] == CampaignTaskStatus.POLICY_DENIED.value
    assert "g02:adapter:not-registered:not_registered" in record["reason"]
    assert record["proof_bundle"] is None
    assert record["proof_bundle_sealed"] is False


def test_g02_execution_blocks_registered_adapter_without_metadata():
    registry = _registry()
    authority = ActionAuthority(
        settings=_settings(),
        allowed_origin="http://example.test",
        manifest={"capabilities": {"http_read": {"available": True}}},
        adapter_registry=registry,
        require_g02=True,
    )
    executor = ActionExecutor(authority)

    record = executor.execute(
        _task(adapter_name="native-http"),
        lambda _task: {"proof_evidence": [{"unexpected": True}]},
    )

    assert record["status"] == CampaignTaskStatus.POLICY_DENIED.value
    assert "g02:request:g02_inventory_ref:required" in record["reason"]
    assert "g02:request:g02_proof_contract:required" in record["reason"]
    assert record["proof_bundle"] is None


def test_g02_production_callers_use_the_canonical_http_contract():
    from pathlib import Path

    from webpent.shared.g02_contract import (
        G02_HTTP_APPROVAL_EXPIRY,
        G02_HTTP_CANONICAL_WRAPPER,
        G02_HTTP_INVENTORY_REF,
        G02_HTTP_PROOF_CONTRACT,
        G02_HTTP_SCOPE_POLICY,
    )

    project_root = Path(__file__).resolve().parents[1]
    required_symbols = (
        "G02_HTTP_CANONICAL_WRAPPER",
        "G02_HTTP_SCOPE_POLICY",
        "G02_HTTP_INVENTORY_REF",
        "G02_HTTP_PROOF_CONTRACT",
        "G02_HTTP_APPROVAL_EXPIRY",
    )
    for relative in (
        "src/webpent/graph/builder.py",
        "src/webpent/shared/autonomous_controller.py",
    ):
        source = (project_root / relative).read_text(encoding="utf-8")
        assert "RegisteredAdapter(" in source
        for symbol in required_symbols:
            assert symbol in source
    assert G02_HTTP_CANONICAL_WRAPPER
    assert G02_HTTP_SCOPE_POLICY
    assert G02_HTTP_INVENTORY_REF
    assert G02_HTTP_PROOF_CONTRACT
    assert G02_HTTP_APPROVAL_EXPIRY


def test_g02_metadata_helper_preserves_caller_fields_without_downgrading_contract():
    from webpent.shared.g02_contract import (
        G02_HTTP_INVENTORY_REF,
        G02_HTTP_PROOF_CONTRACT,
        g02_http_metadata,
    )

    metadata = g02_http_metadata({"probe_kind": "active_research"})
    assert metadata["probe_kind"] == "active_research"
    assert metadata["g02_inventory_ref"] == G02_HTTP_INVENTORY_REF
    assert metadata["g02_proof_contract"] == G02_HTTP_PROOF_CONTRACT

    overridden = g02_http_metadata(
        {
            "g02_inventory_ref": "untrusted-ref",
            "g02_proof_contract": "untrusted-contract",
        }
    )
    assert overridden["g02_inventory_ref"] == G02_HTTP_INVENTORY_REF
    assert overridden["g02_proof_contract"] == G02_HTTP_PROOF_CONTRACT
