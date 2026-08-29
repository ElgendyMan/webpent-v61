from __future__ import annotations

import httpx

from webpent.rta import create_target_app, default_target_configs, serve_loopback


def test_three_realistic_targets_serve_real_loopback_http() -> None:
    for config in default_target_configs():
        app = create_target_app(config)
        with (
            serve_loopback(app) as base_url,
            httpx.Client(base_url=base_url, timeout=3.0) as client,
        ):
            index = client.get("/")
            assert index.status_code == 200
            surface_map = client.get("/api/openapi-lite")
            assert surface_map.status_code == 200
            assert surface_map.json()["runtime_digest"].startswith("sha256:")
            unauthenticated = client.get("/api/me")
            assert unauthenticated.status_code == 401
            me = client.get("/api/me", headers={"X-Synthetic-Session": "synthetic:user-a"})
            assert me.status_code == 200
            assert me.json()["tenant_id"] == "tenant-a"


def test_http_observations_expose_causal_auth_and_business_signals() -> None:
    config = default_target_configs()[0]
    app = create_target_app(config)
    with serve_loopback(app) as base_url, httpx.Client(base_url=base_url, timeout=3.0) as client:
        owned = client.get(
            "/api/documents/doc-a-1",
            headers={"X-Synthetic-Session": "synthetic:user-a"},
        )
        cross_owner = client.get(
            "/api/documents/doc-a-2",
            headers={"X-Synthetic-Session": "synthetic:user-a"},
        )
        cross_tenant = client.get(
            "/api/tenant/tenant-b/documents/doc-b-1",
            headers={"X-Synthetic-Session": "synthetic:user-a"},
        )
        privileged_route = client.get(
            "/api/admin/reports",
            headers={"X-Synthetic-Session": "synthetic:user-a"},
        )
        workflow = client.get(
            "/api/workflows/wf-a-1/preview",
            headers={"X-Synthetic-Session": "synthetic:user-a"},
        )
        order = client.get(
            "/api/orders/order-a-1/summary",
            headers={"X-Synthetic-Session": "synthetic:user-a"},
        )

    assert owned.status_code == 200
    assert cross_owner.status_code == 200
    assert cross_tenant.status_code == 200
    assert privileged_route.status_code == 200
    assert workflow.status_code == 200
    assert order.status_code == 200
    assert order.json()["discount"] == 90
