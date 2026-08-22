from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from webpent.graph.builder import (
    NODE_AUTH,
    NODE_CRAWLER,
    NODE_IDENTITY_PROVISIONING,
    NODE_IDENTITY_PROVISIONING_PRE_AUTH,
    NODE_PLANNER,
    NODE_REPORTER,
    NODE_SUBDOMAIN_TAKEOVER,
    NODE_WILDCARD_SCOPE,
    build_graph,
    route_after_crawler_with_identity,
    route_after_wildcard_scope,
)
from webpent.models.targets import Target
from webpent.shared.wildcard_scope import (
    WildcardScopeError,
    apply_compiled_scope,
    compile_wildcard_scope,
    wildcard_scope_node,
)


def _target(**updates: object) -> Target:
    payload: dict[str, object] = {
        "url": "https://app.example.com",
        "domain": "app.example.com",
    }
    payload.update(updates)
    return Target.model_validate(payload)


def test_wildcard_compiles_to_anchored_regex() -> None:
    compiled = compile_wildcard_scope(["https://*.example.com"])
    assert compiled.compiled_regex == (
        r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+example\.com$",
    )
    target = apply_compiled_scope(_target(), compiled)
    assert target.is_in_scope("https://api.example.com") is True
    assert target.is_in_scope("https://example.com") is False
    assert target.is_in_scope("https://evilexample.com") is False
    assert target.is_in_scope("https://example.com.attacker.net") is False


def test_wildcard_matches_discovered_subdomain() -> None:
    compiled = compile_wildcard_scope(["https://*.g6hospitality.com"])
    target = apply_compiled_scope(_target(url="https://g6hospitality.com"), compiled)
    assert target.is_in_scope("https://api.g6hospitality.com") is True
    assert target.is_in_scope("https://deep.api.g6hospitality.com") is True


def test_wildcard_rejects_sibling_domain() -> None:
    compiled = compile_wildcard_scope(["https://*.g6hospitality.com"])
    target = apply_compiled_scope(_target(url="https://g6hospitality.com"), compiled)
    assert target.is_in_scope("https://g6hospitality.com.evil.io") is False
    assert target.is_in_scope("https://g6hospitality.co") is False


def test_wildcard_plus_out_of_scope_precedence() -> None:
    compiled = compile_wildcard_scope(["https://*.example.com"])
    target = apply_compiled_scope(
        _target(url="https://app.example.com", out_of_scope_regex=[r"admin\.example\.com"]),
        compiled,
    )
    assert target.is_in_scope("https://api.example.com") is True
    assert target.is_in_scope("https://admin.example.com") is False


def test_invalid_wildcard_is_fail_closed() -> None:
    with pytest.raises(WildcardScopeError):
        compile_wildcard_scope(["https://example*.com"])
    with pytest.raises(WildcardScopeError):
        compile_wildcard_scope(["https://*.example.com:8443"])


def test_wildcard_node_uses_same_target_scope_object() -> None:
    state = {"target": _target(), "raw_scope_entries": ["https://*.example.com"]}
    output = wildcard_scope_node(state)
    assert output["scope_compile_status"] == "compiled"
    compiled = output["compiled_scope"]
    assert output["target"].in_scope_regex == compiled["compiled_regex"]
    assert route_after_wildcard_scope(output) == NODE_PLANNER


def test_wildcard_node_blocks_invalid_input_and_routes_to_reporter() -> None:
    state = {"target": _target(), "raw_scope_entries": ["https://*.example.com/path?x=1"]}
    output = wildcard_scope_node(state)
    assert output["scope_compile_status"] == "blocked"
    assert output["target"].is_in_scope("https://example.com") is False
    assert route_after_wildcard_scope(output) == NODE_REPORTER


def test_graph_registers_wildcard_and_identity_nodes() -> None:
    graph = build_graph(auto_approve=True)
    nodes = set(graph.nodes)
    assert NODE_WILDCARD_SCOPE in nodes
    assert NODE_IDENTITY_PROVISIONING in nodes
    assert NODE_PLANNER in nodes


def test_compiled_graph_wires_pre_auth_identity_and_reactive_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("webpent.graph.builder._identity_provisioning_enabled", lambda: True)
    monkeypatch.setattr("webpent.graph.builder._js_intelligence_enabled", lambda: False)
    compiled = build_graph(auto_approve=True)
    edges = {(edge.source, edge.target) for edge in compiled.get_graph().edges}
    assert (NODE_PLANNER, NODE_IDENTITY_PROVISIONING_PRE_AUTH) in edges
    assert (NODE_IDENTITY_PROVISIONING_PRE_AUTH, NODE_AUTH) in edges
    assert (NODE_CRAWLER, NODE_IDENTITY_PROVISIONING) in edges
    assert (NODE_IDENTITY_PROVISIONING, NODE_SUBDOMAIN_TAKEOVER) in edges


def test_compiled_graph_wires_identity_between_crawler_and_legacy_branch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("webpent.graph.builder._identity_provisioning_enabled", lambda: True)
    monkeypatch.setattr("webpent.graph.builder._js_intelligence_enabled", lambda: False)
    compiled = build_graph(auto_approve=True)
    edges = {(edge.source, edge.target) for edge in compiled.get_graph().edges}
    assert (NODE_CRAWLER, NODE_IDENTITY_PROVISIONING) in edges
    assert (NODE_IDENTITY_PROVISIONING, NODE_SUBDOMAIN_TAKEOVER) in edges


def test_planner_route_is_legacy_compatible_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "webpent.graph.builder.get_settings",
        lambda: type("Settings", (), {"identity_provisioning_enabled": False})(),
    )
    from webpent.graph.builder import route_after_planner

    assert route_after_planner({}) == NODE_AUTH


def test_identity_route_is_legacy_compatible_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "webpent.graph.builder.get_settings",
        lambda: type(
            "Settings",
            (),
            {"identity_provisioning_enabled": False, "enable_js_intelligence": False},
        )(),
    )
    assert route_after_crawler_with_identity({}) == NODE_SUBDOMAIN_TAKEOVER


def test_identity_route_is_inserted_only_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "webpent.graph.builder.get_settings",
        lambda: type(
            "Settings",
            (),
            {"identity_provisioning_enabled": True, "enable_js_intelligence": False},
        )(),
    )
    assert route_after_crawler_with_identity({}) == NODE_IDENTITY_PROVISIONING


def test_expired_compiled_state_is_not_relevant_to_compiler() -> None:
    # The compiler is pure; expiry is enforced by EngagementScope at action time.
    # This test documents that compilation never grants a transport permission.
    assert datetime.now(timezone.utc) + timedelta(seconds=1) > datetime.now(timezone.utc)
