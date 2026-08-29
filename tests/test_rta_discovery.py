from webpent.rta.contracts import RtaScope
from webpent.rta.discovery import discover_loopback_target
from webpent.rta.harness import create_target_app, default_target_configs
from webpent.rta.local_server import serve_loopback


def test_discovery_maps_routes_parameters_and_auth_without_raw_bodies() -> None:
    config = default_target_configs()[0]
    scope = RtaScope(campaign_id="rta-discovery-test")

    with serve_loopback(create_target_app(config)) as base_url:
        snapshot = discover_loopback_target(
            base_url,
            config.target_id,
            "sha256:runtime-test",
            scope,
        )

    assert snapshot.source == "loopback_http"
    assert {surface.path_template for surface in snapshot.surfaces} >= {
        "/api/documents/{document_id}",
        "/api/tenant/{tenant_id}/documents/{document_id}",
        "/api/workflows/{workflow_id}/preview",
    }
    document_surface = next(
        surface
        for surface in snapshot.surfaces
        if "documents/{document_id}" in surface.path_template
    )
    assert document_surface.parameters == ("document_id",)
    assert document_surface.auth_required is True
    assert all(observation.redacted for observation in snapshot.observations)
    assert all(observation.request.state_changing is False for observation in snapshot.observations)


def test_discovery_rejects_non_loopback_base_url() -> None:
    config = default_target_configs()[0]
    scope = RtaScope(campaign_id="rta-discovery-test")

    try:
        discover_loopback_target(
            "http://example.test",
            config.target_id,
            "sha256:runtime-test",
            scope,
        )
    except ValueError as exc:
        assert "loopback" in str(exc)
    else:
        raise AssertionError("external discovery target must be rejected")
