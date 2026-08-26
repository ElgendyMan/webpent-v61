from __future__ import annotations

import json

import httpx
import pytest

import webpent.adapters.generic_web.adapter as generic_adapter_module
from webpent.adapters.generic_web.adapter import (
    GENERIC_WEB_CASE_ID,
    GenericWebAdapter,
    build_generic_web_registration,
)
from webpent.shared.generic_web_contracts import (
    CaseDefinition,
    CaseResult,
    DiscoveryLimits,
)
from webpent.shared.target_adapters import TargetAdapterRegistry
from webpent.shared.workflow_contracts import (
    AUTHORIZED_API_READ,
    AUTHORIZED_API_REQUEST,
    BROWSER_DOM_OBSERVATION,
    BROWSER_OBSERVATION,
    SAME_ORIGIN_RESOURCE_OBSERVATION,
    canonical_workflow_id,
)


@pytest.fixture(autouse=True)
def _safe_client_with_injected_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    def factory(**kwargs: object) -> httpx.Client:
        return httpx.Client(**kwargs)

    monkeypatch.setattr(generic_adapter_module, "make_safe_httpx_client", factory)


def _transport_for_routes(
    routes: dict[str, httpx.Response], calls: list[str]
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        response = routes.get(request.url.path)
        if response is None:
            return httpx.Response(404, request=request)
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            content=response.content,
            request=request,
        )

    return httpx.MockTransport(handler)


def test_generic_adapter_discovers_html_spa_and_openapi_without_raw_evidence() -> None:
    calls: list[str] = []
    routes = {
        "/": httpx.Response(
            200,
            headers={"content-type": "text/html"},
            content=(
                '<!doctype html><title>Catalog</title><a href="/about">About</a>'
                '<a href="/logout">Logout</a><a href="https://evil.test/x">Off</a>'
                '<script src="/app.js"></script><form action="/search" method="GET">'
                '<input name="q" value="redacted"></form>'
            ),
        ),
        "/about": httpx.Response(
            200,
            headers={"content-type": "text/html"},
            content="<html><body>About</body></html>",
        ),
        "/app.js": httpx.Response(
            200,
            headers={"content-type": "application/javascript"},
            content="fetch('/api/catalog')",
        ),
        "/openapi.json": httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=json.dumps(
                {"openapi": "3.0.0", "paths": {"/api/catalog": {}, "/api/items": {}}}
            ),
        ),
    }
    adapter = GenericWebAdapter(
        "http://target.test",
        transport=_transport_for_routes(routes, calls),
        limits=DiscoveryLimits(rate_limit_per_second=100, max_pages=10, max_depth=2),
    )

    result = adapter.discover()

    assert result["target_classification"] == "hybrid"
    assert result["raw_response_bodies_saved"] is False
    assert result["credentials_or_cookies_saved"] is False
    assert "/logout" not in " ".join(calls)
    assert all("evil.test" not in item for item in calls)
    assert any("cross_origin_resource_filtered" in gap for gap in result["coverage_gaps"])
    assert any("state_changing_get_filtered" in gap for gap in result["coverage_gaps"])
    assert any(item["classification"] == "api" for item in result["observations"])
    assert any(item["api_route_count"] == 2 for item in result["observations"])
    capabilities = {item["capability_id"]: item for item in result["capabilities"]}
    assert capabilities["authorized_api_read"]["status"] == "needs_profile"
    assert capabilities["browser_dom_observation"]["status"] == "observation_only"
    assert capabilities["state_changing_execution"]["status"] == "unsupported"


def test_generic_adapter_second_shape_is_unknown_and_fails_closed_on_redirect() -> None:
    calls: list[str] = []
    routes = {
        "/": httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            content="opaque response with no structured web surface",
        ),
        "/redirect": httpx.Response(
            302,
            headers={"location": "https://evil.test/internal"},
            content=b"redirect",
        ),
    }
    adapter = GenericWebAdapter(
        "https://second.test",
        transport=_transport_for_routes(routes, calls),
        limits=DiscoveryLimits(rate_limit_per_second=100, max_pages=2, max_depth=1),
    )

    result = adapter.discover("https://second.test/redirect")

    assert result["target_classification"] == "unknown"
    assert result["observations"] == []
    assert result["redirects_blocked"] == 1
    assert "cross_origin_redirect_filtered" in result["coverage_gaps"]
    assert all("evil.test" not in item for item in calls)


def test_generic_adapter_registry_swaps_distinct_target_instances_without_guessing() -> None:
    first = GenericWebAdapter(
        "http://shape-one.test",
        target_id="fixture_shape_one",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                headers={"content-type": "text/html"},
                content="<html><title>One</title><a href='/one'>one</a></html>",
                request=request,
            )
        ),
    )
    second = GenericWebAdapter(
        "http://shape-two.test",
        target_id="fixture_shape_two",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                headers={"content-type": "application/json"},
                content=json.dumps({"openapi": "3.0.0", "paths": {"/items": {}}}),
                request=request,
            )
        ),
    )
    registry = TargetAdapterRegistry()
    first_registration = build_generic_web_registration(first)
    second_registration = build_generic_web_registration(second)
    registry.register(first_registration)
    registry.register(second_registration)

    assert registry.get("fixture_shape_one") is first_registration
    assert registry.get("fixture_shape_two") is second_registration
    assert registry.require_for_origin("http://shape-one.test") is first_registration
    assert registry.require_for_origin("http://shape-two.test") is second_registration
    assert registry.for_origin("http://unregistered.test") is None
    assert first.discover()["target_classification"] == "html"
    assert second.discover()["target_classification"] == "api"


def test_registration_and_case_lifecycle_are_explicit_and_serializable() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, request=request))
    adapter = GenericWebAdapter("http://fixture.test", transport=transport)
    registration = build_generic_web_registration(adapter)
    registry = TargetAdapterRegistry()
    registry.register(registration)

    assert registration.validate() == ()
    assert registry.for_origin("http://fixture.test") is registration
    assert registration.manifest is not None
    assert registration.manifest.allowed_scope == ("http://fixture.test",)
    assert adapter.case(GENERIC_WEB_CASE_ID) is not None
    assert adapter.case_definition().as_dict()["required_capabilities"] == [
        "same_origin_resource_observation"
    ]

    result = CaseResult(
        case_id=GENERIC_WEB_CASE_ID,
        status="observation_only",
        reason="generic_surface_is_not_a_finding",
        observation_refs=("surface:1",),
        metadata={"target_classification": "html"},
    )
    assert result.as_dict()["status"] == "observation_only"
    assert "raw_response" not in result.as_dict()


def test_case_definition_requires_capabilities() -> None:
    with pytest.raises(ValueError, match="case_required_capabilities_required"):
        CaseDefinition(case_id="case.v1", workflow_id=SAME_ORIGIN_RESOURCE_OBSERVATION)


def test_promoted_case_result_requires_proof_reference() -> None:
    with pytest.raises(ValueError, match="case_result_proof_required_for_promoted_status"):
        CaseResult(
            case_id="case.v1",
            status="confirmed",
            reason="invalid promotion",
        )


def test_workflow_v2_aliases_are_deterministic() -> None:
    assert canonical_workflow_id(AUTHORIZED_API_REQUEST) == AUTHORIZED_API_READ
    assert canonical_workflow_id(BROWSER_OBSERVATION) == BROWSER_DOM_OBSERVATION
    assert canonical_workflow_id("target_guessed_workflow") is None
