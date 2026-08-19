from __future__ import annotations

from types import SimpleNamespace

from webpent.agents.javascript_intelligence.agent import javascript_intelligence_node
from webpent.agents.reporter.agent import _compose_bug_bounty_markdown
from webpent.config.settings import Settings
from webpent.graph.builder import (
    NODE_JAVASCRIPT_INTELLIGENCE,
    NODE_SUBDOMAIN_TAKEOVER,
    route_after_crawler,
)
from webpent.models.targets import Target
from webpent.shared.javascript_intelligence import analyze_javascript_source


def test_static_review_extracts_routes_sinks_source_map_and_redacted_secret():
    source = """
    const apiKey = 'sk_live_abcdefghijklmnopqrstuvwxyz123456';
    fetch('/api/items?id=7');
    const next = window.location.href;
    eval(window.name);
    //# sourceMappingURL=app.js.map
    """
    result = analyze_javascript_source(
        asset_url="https://example.test/static/app.js",
        source=source,
        target_url="https://example.test/",
        content_type="application/javascript",
        status_code=200,
    )

    assert result.assets[0].asset_url == "https://example.test/static/app.js"
    assert any(route.route.endswith("/api/items?id=7") for route in result.routes)
    assert any(sink.sink == "eval" for sink in result.sinks)
    assert any(asset.source_map_url for asset in result.assets)
    assert result.secret_candidates
    assert result.secret_candidates[0].redacted_value == "[REDACTED]"
    assert result.secret_candidates[0].value_sha256
    assert all("sk_live_" not in task.model_dump_json() for task in result.targeted_tasks)


def test_static_review_rejects_out_of_scope_routes_and_marks_gap():
    result = analyze_javascript_source(
        asset_url="https://example.test/app.js",
        source="fetch('https://evil.example/collect'); fetch('/same-origin');",
        target_url="https://example.test/",
        content_type="application/javascript",
        status_code=200,
    )

    assert all(route.in_scope for route in result.routes)
    assert any("out_of_scope" in gap for gap in result.coverage_gaps)
    assert all("evil.example" not in route.route for route in result.routes)


def test_node_is_noop_when_feature_flag_is_disabled(monkeypatch):
    monkeypatch.setattr(
        "webpent.agents.javascript_intelligence.agent.get_settings",
        lambda: SimpleNamespace(enable_js_intelligence=False),
    )
    state = {
        "target": Target(url="https://example.test"),
        "crawled_data": {"javascript_urls": ["https://example.test/app.js"]},
    }
    output = javascript_intelligence_node(state)
    assert output["js_targeted_tasks"] == []
    assert output["javascript_intelligence"]["assets"] == []
    assert output["javascript_intelligence"]["coverage_gaps"] == ["js_intelligence_disabled"]


def test_node_fetches_only_in_scope_assets_and_returns_redacted_projection(monkeypatch):
    settings = Settings(
        enable_js_intelligence=True,
        max_js_assets=5,
        max_js_asset_bytes=100_000,
        max_js_targeted_tasks=10,
        enable_surface_security_analysis=True,
        max_surface_security_observations=100,
    )
    monkeypatch.setattr(
        "webpent.agents.javascript_intelligence.agent.get_settings",
        lambda: settings,
    )

    class Response:
        status_code = 200
        content = (
            b"fetch('/api/profile'); document.body.innerHTML = location.hash; "
            b"const x = 'AKIAABCDEFGHIJKLMNOP';"
        )
        headers = {"content-type": "application/javascript"}

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get(self, url):
            assert url == "https://example.test/app.js"
            return Response()

    monkeypatch.setattr(
        "webpent.shared.http.make_safe_httpx_client",
        lambda **_kwargs: Client(),
    )
    state = {
        "target": Target(url="https://example.test"),
        "crawled_data": {
            "javascript_urls": [
                "https://example.test/app.js",
                "https://evil.example/evil.js",
            ]
        },
    }

    output = javascript_intelligence_node(state)
    projection = output["javascript_intelligence"]
    assert len(projection["assets"]) == 1
    assert projection["assets"][0]["asset_url"] == "https://example.test/app.js"
    assert any("out_of_scope" in gap for gap in projection["coverage_gaps"])
    assert "AKIAABCDEFGHIJKLMNOP" not in str(output)

    observations = output["surface_security"]["observations"]
    assert any(
        item["category"] == "dom_based_vulnerability" for item in observations
    )
    assert output["crawled_data"]["js_secrets"][0]["value"] == "[REDACTED]"
    assert "AKIAABCDEFGHIJKLMNOP" not in str(output["crawled_data"])


def test_bug_bounty_appendix_renders_redacted_js_secret_projection():
    markdown = _compose_bug_bounty_markdown(
        "https://example.test",
        [],
        "",
        {
            "js_secrets": [
                {
                    "type": "API token",
                    "value": "[REDACTED]",
                    "source": "https://example.test/app.js",
                    "evidence_ref": "ev-js-secret-001",
                }
            ]
        },
    )

    assert "## Appendix: Exposed Secrets in JavaScript" in markdown
    assert "[REDACTED]" in markdown
    assert "ev-js-secret-001" not in markdown


def test_graph_routes_to_js_node_only_when_enabled(monkeypatch):
    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(enable_js_intelligence=False),
    )
    assert route_after_crawler({}) == NODE_SUBDOMAIN_TAKEOVER

    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(enable_js_intelligence=True),
    )

    assert route_after_crawler({}) == NODE_JAVASCRIPT_INTELLIGENCE
