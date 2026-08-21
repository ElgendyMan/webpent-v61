from webpent.config.settings import ScanMode, Settings
from webpent.models.targets import Target
from webpent.reporter.export import build_report_data
from webpent.shared.runtime import (
    AdapterRegistry,
    RegisteredAdapter,
    RuntimeFactory,
)
from webpent.state.initial_state import build_initial_state


def _settings() -> Settings:
    return Settings(scan_mode=ScanMode.SAFE_SMART)


def test_runtime_surfaces_missing_dependencies_as_typed_gaps() -> None:
    context = RuntimeFactory.create(
        engagement_id="engagement-gap",
        campaign_id="campaign-gap",
        target_origin="http://example.test",
        settings=_settings(),
        use_default_ledger=False,
    )

    components = {gap.component for gap in context.capability_gaps}
    assert {
        "identity_tenant_object_graph",
        "workflow_state_machine",
        "replay_engine",
        "adapters",
    } <= components

    result = context.require_capability(
        "workflow_state_machine",
        node="workflow_replay",
    )
    assert result["status"] == "blocked_by_configuration"
    assert result["clean"] is False
    assert result["capability_gaps"]
    assert any(
        gap["component"] == "workflow_state_machine"
        for gap in result["capability_gaps"]
    )


def test_runtime_descriptor_and_diagnostics_preserve_gap_metadata() -> None:
    context = RuntimeFactory.create(
        engagement_id="engagement-gap",
        campaign_id="campaign-gap",
        target_origin="http://example.test",
        settings=_settings(),
        use_default_ledger=False,
    )

    diagnostics = context.diagnostics()
    descriptor = RuntimeFactory.descriptor(context)
    assert diagnostics["capability_gaps"]
    assert descriptor["capability_gaps"] == diagnostics["capability_gaps"]
    assert all("handler" not in gap for gap in descriptor["capability_gaps"])


def test_runtime_has_no_gap_when_explicit_dependencies_are_registered() -> None:
    adapters = AdapterRegistry()
    adapters.register(
        RegisteredAdapter(
            name="http-fixture",
            capability="http_read",
            transport="fixture",
            handler=lambda **_kwargs: {"status": 200},
            policy_checked=True,
        )
    )
    context = RuntimeFactory.create(
        engagement_id="engagement-ready",
        campaign_id="campaign-ready",
        target_origin="http://example.test",
        settings=_settings(),
        use_default_ledger=False,
        adapters=adapters,
        identity_tenant_object_graph=object(),
        workflow_state_machine=object(),
        replay_engine=object(),
    )

    assert context.capability_gaps == ()
    available = context.require_capability("replay_engine", node="replay")
    assert available["status"] == "capability_available"
    assert available["clean"] is False


def test_initial_state_projects_runtime_capability_gaps() -> None:
    state = build_initial_state(
        Target(url="https://example.test"),
        engagement_id="engagement-gap",
        campaign_id="campaign-gap",
        scan_mode=ScanMode.SAFE_SMART,
    )

    gaps = state["runtime_capability_gaps"]
    assert gaps
    assert all(isinstance(item, dict) for item in gaps)
    assert {item["component"] for item in gaps} == {"adapters"}
    assert state["control_plane_descriptor"]["engagement_id"] == "engagement-gap"
    assert state["runtime_context"].diagnostics()["capability_gaps"] == gaps


def test_runtime_control_plane_wiring_is_descriptor_safe() -> None:
    context = RuntimeFactory.create(
        engagement_id="engagement-control",
        campaign_id="campaign-control",
        target_origin="https://example.test",
        settings=_settings(),
        use_default_ledger=False,
        enable_control_plane=True,
    )

    assert context.control_plane_runtime is not None
    assert not {
        "identity_tenant_object_graph",
        "workflow_state_machine",
        "replay_engine",
    } & {gap.component for gap in context.capability_gaps}
    descriptor = RuntimeFactory.descriptor(context)
    assert descriptor["control_plane_enabled"] is True
    assert "handler" not in repr(descriptor)
    restored = RuntimeFactory.from_descriptor(descriptor)
    assert restored is not None
    assert restored.control_plane_runtime is not None


def test_initial_state_can_keep_legacy_gap_mode() -> None:
    state = build_initial_state(
        Target(url="https://example.test"),
        engagement_id="engagement-legacy",
        campaign_id="campaign-legacy",
        scan_mode=ScanMode.SAFE_SMART,
        enable_control_plane=False,
    )

    assert state["control_plane_descriptor"] is None
    assert {
        item["component"] for item in state["runtime_capability_gaps"]
    } >= {
        "identity_tenant_object_graph",
        "workflow_state_machine",
        "replay_engine",
    }


def test_report_surfaces_runtime_capability_gaps() -> None:
    report = build_report_data(
        "https://example.test",
        [],
        runtime_capability_gaps=[
            {
                "component": "workflow_state_machine",
                "status": "missing",
                "reason": "not_registered",
            }
        ],
    )

    assert report["runtime_capability_gaps"] == [
        {
            "component": "workflow_state_machine",
            "status": "missing",
            "reason": "not_registered",
        }
    ]


def test_capability_gap_projection_is_not_clean() -> None:
    context = RuntimeFactory.create(
        engagement_id="engagement-gap",
        campaign_id="campaign-gap",
        target_origin="https://example.test",
        settings=_settings(),
        use_default_ledger=False,
    )

    blocked = context.require_capability("replay_engine", node="replay")
    assert blocked["clean"] is False
    assert blocked["status"] == "blocked_by_configuration"
    assert blocked["capability_gaps"]
