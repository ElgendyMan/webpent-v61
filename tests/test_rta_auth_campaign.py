import pytest

from webpent.rta.auth_campaign import (
    RtaAuthProfiles,
    build_permission_graph,
    run_authenticated_read_campaign,
)
from webpent.rta.contracts import RtaScope, SyntheticAuthContext
from webpent.rta.harness import create_target_app, default_target_configs
from webpent.rta.local_server import serve_loopback


def _profiles() -> RtaAuthProfiles:
    return RtaAuthProfiles(
        contexts=(
            SyntheticAuthContext(
                "user-a",
                "viewer",
                "tenant-a",
                "synthetic:user-a",
                ("document:read", "order:read"),
            ),
            SyntheticAuthContext(
                "admin",
                "admin",
                "tenant-a",
                "synthetic:admin",
                ("document:read", "admin:read"),
            ),
        )
    )


def test_authenticated_campaign_collects_permission_graph_and_read_only_http() -> None:
    config = default_target_configs()[0]
    scope = RtaScope(campaign_id="rta-auth-test")
    paths = ("/api/me", "/api/admin/privilege-preview", "/api/documents/doc-a-2")

    with serve_loopback(create_target_app(config)) as base_url:
        graph, observations = run_authenticated_read_campaign(base_url, scope, _profiles(), paths)

    assert set(graph.roles) == {"admin", "viewer"}
    assert set(graph.tenants) == {"tenant-a"}
    assert len(observations) == len(paths) * 2
    assert all(observation.redacted for observation in observations)
    assert all(observation.request.method == "GET" for observation in observations)
    assert all(not observation.request.state_changing for observation in observations)
    assert any(observation.status_code == 403 for observation in observations)
    assert any(observation.status_code == 200 for observation in observations)


def test_campaign_rejects_non_synthetic_session() -> None:
    profiles = RtaAuthProfiles(contexts=(SyntheticAuthContext("u", "viewer", "t", "real:session"),))
    with pytest.raises(ValueError, match="synthetic"):
        build_permission_graph(profiles)


def test_campaign_rejects_query_paths() -> None:
    config = default_target_configs()[0]
    scope = RtaScope(campaign_id="rta-auth-test")
    with (
        serve_loopback(create_target_app(config)) as base_url,
        pytest.raises(ValueError, match="query-free"),
    ):
        run_authenticated_read_campaign(base_url, scope, _profiles(), ("/api/me?x=1",))
