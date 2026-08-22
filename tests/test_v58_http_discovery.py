from __future__ import annotations

from types import SimpleNamespace

import pytest
import typer


def test_http_surface_discovers_authenticated_links_get_forms_and_js(monkeypatch) -> None:
    from webpent.shared import http as http_module
    from webpent.shared.http_discovery import discover_http_surface

    pages = {
        "http://lab.test/": (
            200,
            "text/html",
            """
            <a href="/vulnerabilities/sqli/?id=7">SQLi</a>
            <a href="https://outside.test/admin">outside</a>
            <script src="/static/app.js"></script>
            <form action="/transfer.php" method="POST">
              <input type="hidden" name="csrf_token" value="opaque-token">
              <input type="text" name="amount" value="1">
              <input type="password" name="password" value="secret-do-not-store">
            </form>
            <form action="/search.php" method="GET">
              <input name="q" value="hello">
              <input name="Submit" value="Search">
            </form>
            """,
        ),
        "http://lab.test/vulnerabilities/sqli/?id=7": (200, "text/html", "<h1>SQLi</h1>"),
        "http://lab.test/search.php?Submit=Search&q=hello": (200, "text/html", "<h1>Search</h1>"),
        "http://lab.test/static/app.js": (
            200,
            "application/javascript",
            "const route='/api/v1/orders';",
        ),
    }

    class FakeResponse:
        def __init__(self, status_code: int, content_type: str, text: str) -> None:
            self.status_code = status_code
            self.headers = {"content-type": content_type}
            self.text = text

    class FakeClient:
        def get(self, url: str) -> FakeResponse:
            status, content_type, text = pages.get(url, (404, "text/html", ""))
            return FakeResponse(status, content_type, text)

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_args) -> None:
            return None

    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **_kwargs: FakeClient())

    result = discover_http_surface(
        "http://lab.test/",
        session_cookies={"PHPSESSID": "opaque-session"},
        max_pages=10,
    )

    assert "http://lab.test/" in result["endpoints"]
    assert "http://lab.test/vulnerabilities/sqli/?id=7" in result["endpoints"]
    assert "http://lab.test/static/app.js" in result["endpoints"]
    assert result["discovery_metadata"]["javascript_urls"] == [
        "http://lab.test/static/app.js"
    ]
    assert all("outside.test" not in endpoint for endpoint in result["endpoints"])
    assert any(form["method"] == "POST" for form in result["forms"])
    assert any(form["method"] == "GET" for form in result["forms"])
    post_form = next(form for form in result["forms"] if form["method"] == "POST")
    assert post_form["data"]["password"] == ""
    assert "secret-do-not-store" not in str(result)


def test_http_surface_uses_browser_headers_for_default_user_agent(monkeypatch) -> None:
    from webpent.shared import http as http_module
    from webpent.shared import http_discovery as discovery_module

    captured: dict[str, object] = {}

    class FakeResponse:
        status_code = 404
        headers = {"content-type": "text/plain"}
        text = "not found"

    class FakeClient:
        def get(self, _url: str) -> FakeResponse:
            return FakeResponse()

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def fake_client(**kwargs: object) -> FakeClient:
        captured.update(kwargs)
        return FakeClient()

    monkeypatch.setattr(http_module, "make_safe_httpx_client", fake_client)
    monkeypatch.setattr(
        discovery_module,
        "get_settings",
        lambda: SimpleNamespace(
            discovery_route_seeds="",
            http_user_agent="WebPent/0.2 (+https://example.test)",
        ),
    )

    discovery_module.discover_http_surface("http://lab.test/", max_pages=1)

    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert str(headers["User-Agent"]).startswith("Mozilla/5.0")
    assert headers["Accept-Language"] == "en-US,en;q=0.9"
    assert headers["Accept-Encoding"] == "identity"


def test_crawler_uses_http_fallback_when_katana_is_missing(monkeypatch) -> None:
    from webpent.agents.crawler import agent as crawler_agent
    from webpent.models.targets import Target
    from webpent.shared.exceptions import ToolNotFoundError

    fallback = {
        "endpoints": [
            "http://lab.test/",
            "http://lab.test/vulnerabilities/sqli/?id=1",
        ],
        "forms": [
            {
                "action": "http://lab.test/transfer.php",
                "method": "POST",
                "data": {"amount": "1"},
                "source_url": "http://lab.test/",
            }
        ],
        "pages_fetched": 2,
        "coverage_gaps": [],
        "surface_records": [
            {
                "record_id": "http:1",
                "url": "http://lab.test/",
                "method": "GET",
                "source": "http_get",
            },
        ],
        "discovery_metadata": {
            "javascript_urls": ["http://lab.test/static/app.js"],
        },
    }

    monkeypatch.setattr(
        crawler_agent,
        "run_katana",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ToolNotFoundError("katana")),
    )
    monkeypatch.setattr(crawler_agent, "discover_http_surface", lambda *_args, **_kwargs: fallback)
    monkeypatch.setattr(crawler_agent, "get_llm", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(crawler_agent, "_fetch_and_analyze_js", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(crawler_agent, "_discover_html_forms", lambda *_args, **_kwargs: [])

    result = crawler_agent.crawler_node(
        {
            "target": Target(url="http://lab.test/"),
            "session_cookies": {"PHPSESSID": "opaque-session"},
            "auth_state": {"source": "operator_supplied"},
        }
    )

    crawled = result["crawled_data"]
    assert crawled["endpoints"] == fallback["endpoints"]
    assert crawled["forms"] == fallback["forms"]
    assert crawled["http_discovery"]["pages_fetched"] == 2
    assert crawled["surface_records"][0]["record_id"] == "http:1"
    assert crawled["javascript_urls"] == ["http://lab.test/static/app.js"]
    assert "opaque-session" not in str(result)


def test_http_surface_invalid_target_fails_closed() -> None:
    from webpent.shared.http_discovery import discover_http_surface

    result = discover_http_surface("not-a-url")

    assert result["endpoints"] == []
    assert "invalid_target_url" in result["coverage_gaps"]


def test_rabbit_hole_read_only_source_code_is_not_lfi() -> None:
    from webpent.agents.rabbit_hole.agent import _infer_rabbit_hole_vuln_class
    from webpent.models.findings import EXPLOITABLE_CLASSES, VulnClass

    vuln_class = _infer_rabbit_hole_vuln_class("source_code", "read_only_parse")

    assert vuln_class == VulnClass.INFO_DISCLOSURE.value
    assert vuln_class not in EXPLOITABLE_CLASSES


def test_rabbit_hole_file_artifact_remains_lfi_candidate() -> None:
    from webpent.agents.rabbit_hole.agent import _infer_rabbit_hole_vuln_class
    from webpent.models.findings import VulnClass

    assert _infer_rabbit_hole_vuln_class("file", "read_only_parse") == VulnClass.LFI.value



def test_info_disclosure_path_match_is_promoted_to_validator() -> None:
    from webpent.models.findings import VulnClass
    from webpent.models.hypothesis import Hypothesis
    from webpent.shared.prioritization import (
        PrioritizationAction,
        promote_hypothesis_to_finding,
        recommend_action,
    )

    hypothesis = Hypothesis(
        target_url="http://lab.test/instructions.php",
        statement="Follow source_code via read_only_parse",
        vuln_class=VulnClass.INFO_DISCLOSURE.value,
        confidence_score=0.9,
        deterministic_match=True,
    )
    state = {"findings": [], "hypotheses": [hypothesis], "mental_model": {}}

    action, _score, rule = recommend_action(hypothesis, state)

    assert action == PrioritizationAction.PROMOTE
    assert "validator-available" in rule
    promoted = promote_hypothesis_to_finding(hypothesis, state)
    assert promoted is not None
    assert promoted.vuln_class == VulnClass.INFO_DISCLOSURE.value




def test_http_surface_skips_state_changing_get_routes(monkeypatch) -> None:
    from webpent.shared import http as http_module
    from webpent.shared.http_discovery import discover_http_surface

    requested: list[str] = []
    pages = {
        "http://lab.test/": (
            200,
            "text/html",
            '<a href="/logout.php">Logout</a>'
            '<a href="/account?action=delete">Delete account</a>'
            '<a href="/profile">Profile</a>',
        ),
        "http://lab.test/profile": (200, "text/html", "<h1>Profile</h1>"),
    }

    class FakeResponse:
        def __init__(self, status_code: int, content_type: str, text: str) -> None:
            self.status_code = status_code
            self.headers = {"content-type": content_type}
            self.text = text

    class FakeClient:
        def get(self, url: str) -> FakeResponse:
            requested.append(url)
            status, content_type, text = pages.get(url, (404, "text/html", ""))
            return FakeResponse(status, content_type, text)

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_args) -> None:
            return None

    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **_kwargs: FakeClient())

    result = discover_http_surface("http://lab.test/", max_pages=10)

    assert "http://lab.test/profile" in result["endpoints"]
    assert "http://lab.test/logout.php" not in requested
    assert "http://lab.test/account?action=delete" not in requested
    assert result["skipped_state_changing"] == 2
    assert "state_changing_gets_not_fetched" in result["coverage_gaps"]




def test_missing_validator_is_terminal_human_review() -> None:
    from webpent.agents.validator import agent as validator_agent
    from webpent.models.findings import Finding, Severity

    finding = Finding(
        title="Candidate file read",
        severity=Severity.MEDIUM,
        description="candidate",
        tool_name="hypothesis_analyzer",
        url="http://lab.test/file.php",
        vuln_class="lfi",
        confidence_level="Pending",
    )

    updated = validator_agent._validate_with_tool(finding, "lfi", llm=None)

    assert updated.confidence_level == "Needs Human Review"
    assert updated.evidence["validation_unavailable"] is True
    assert updated.evidence["tool_infra_failure"] is True
    assert updated.evidence["missing_validator_class"] == "lfi"
    assert "not confirmation" in updated.reasoning.lower()



def test_exploit_chainer_does_not_repropose_same_pair() -> None:
    from uuid import uuid4

    from webpent.agents.exploit_chainer.agent import _find_chain_candidates
    from webpent.models.findings import Finding, Severity, VulnClass

    redirect_id = uuid4()
    xss_id = uuid4()
    redirect = Finding(
        id=redirect_id,
        title="Open redirect",
        severity=Severity.MEDIUM,
        description="redirect",
        tool_name="redirect_scanner",
        url="http://lab.test/redirect",
        vuln_class=VulnClass.OPEN_REDIRECT.value,
        confidence_level="Tool-Confirmed",
    )
    xss = Finding(
        id=xss_id,
        title="Reflected XSS",
        severity=Severity.HIGH,
        description="xss",
        tool_name="dalfox",
        url="http://lab.test/search",
        vuln_class=VulnClass.XSS.value,
        confidence_level="Tool-Confirmed",
    )
    chained = Finding(
        title="Chained candidate",
        severity=Severity.HIGH,
        description="candidate",
        url="http://lab.test/search",
        vuln_class=VulnClass.XSS.value,
        confidence_level="Pending",
        tool_name="exploit_chainer",
        evidence={
            "source_finding_a": str(redirect_id),
            "source_finding_b": str(xss_id),
        },
    )

    assert _find_chain_candidates([redirect, xss, chained]) == []
    assert len(_find_chain_candidates([redirect, xss])) == 1



def test_offline_payload_generation_is_deterministic_and_non_retryable() -> None:
    from webpent.agents.payload_generator.agent import _generate_payloads_for_finding
    from webpent.models.findings import Finding, Severity, VulnClass

    finding = Finding(
        title="Reflected XSS candidate",
        severity=Severity.HIGH,
        description="candidate",
        tool_name="hypothesis_analyzer",
        url="http://lab.test/search?q=x",
        vuln_class=VulnClass.XSS.value,
    )

    payloads, canary_token = _generate_payloads_for_finding(finding, None)
    assert len(payloads) == 1
    assert canary_token
    assert canary_token in payloads[0]
    assert payloads[0] == f'<svg/onload=alert("{canary_token}")>'
    assert finding.confidence_level == "Pending"

    non_xss = finding.model_copy(
        update={"vuln_class": VulnClass.LFI.value}
    )
    assert _generate_payloads_for_finding(non_xss, None) == ([], None)



def test_missing_validator_finding_cannot_reenter_optimizer() -> None:
    from webpent.graph.builder import NODE_DEVILS_ADVOCATE, route_after_validator
    from webpent.models.findings import Finding, Severity, VulnClass

    finding = Finding(
        title="Candidate file read",
        severity=Severity.MEDIUM,
        description="candidate",
        tool_name="hypothesis_analyzer",
        url="http://lab.test/file.php",
        vuln_class=VulnClass.LFI.value,
        confidence_level="Needs Human Review",
        evidence={
            "validation_unavailable": True,
            "tool_infra_failure": True,
        },
    )

    assert route_after_validator(
        {
            "findings": [finding],
            "payloads_to_test": {str(finding.id): ["stale-payload"]},
            "optimization_retries": {str(finding.id): 0},
        }
    ) == NODE_DEVILS_ADVOCATE



def test_tool_infra_failure_also_blocks_optimizer_even_if_confidence_is_pending() -> None:
    from webpent.graph.builder import NODE_DEVILS_ADVOCATE, route_after_validator
    from webpent.models.findings import Finding, Severity, VulnClass

    finding = Finding(
        title="SQL injection candidate",
        severity=Severity.HIGH,
        description="candidate",
        tool_name="hypothesis_analyzer",
        url="http://lab.test/item?id=1",
        vuln_class=VulnClass.SQLI.value,
        confidence_level="Pending",
        evidence={"tool_infra_failure": True},
    )

    assert route_after_validator(
        {
            "findings": [finding],
            "payloads_to_test": {str(finding.id): ["__SQLMAP_TOOL_DRIVEN__"]},
            "optimization_retries": {str(finding.id): 0},
        }
    ) == NODE_DEVILS_ADVOCATE




def test_http_surface_enriches_from_sitemap_openapi_and_graphql(monkeypatch) -> None:
    from webpent.shared import http as http_module
    from webpent.shared.http_discovery import discover_http_surface

    pages = {
        "http://lab.test/robots.txt": (
            200,
            "text/plain",
            "Sitemap: http://lab.test/sitemap.xml\nDisallow: /admin",
        ),
        "http://lab.test/sitemap.xml": (
            200,
            "application/xml",
            "<urlset><url><loc>http://lab.test/from-sitemap</loc></url></urlset>",
        ),
        "http://lab.test/openapi.json": (
            200,
            "application/json",
            '{"paths":{"/api/orders":{"get":{}}}}',
        ),
        "http://lab.test/from-sitemap": (200, "text/html", "<h1>sitemap</h1>"),
        "http://lab.test/api/orders": (200, "application/json", "{}"),
        "http://lab.test/graphql": (405, "application/json", "{}"),
    }
    requested: list[str] = []

    class FakeResponse:
        def __init__(self, status_code: int, content_type: str, text: str) -> None:
            self.status_code = status_code
            self.headers = {"content-type": content_type}
            self.text = text
            self.content = text.encode("utf-8")

    class FakeClient:
        def get(self, url: str) -> FakeResponse:
            requested.append(url)
            status, content_type, text = pages.get(url, (404, "text/plain", ""))
            return FakeResponse(status, content_type, text)

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **_kwargs: FakeClient())

    result = discover_http_surface("http://lab.test/", max_pages=10)

    assert "http://lab.test/from-sitemap" in result["endpoints"]
    assert "http://lab.test/api/orders" in result["endpoints"]
    assert result["discovery_metadata"]["robots_fetched"] is True
    assert result["discovery_metadata"]["sitemap_urls"] == ["http://lab.test/sitemap.xml"]
    assert result["discovery_metadata"]["openapi_urls"] == ["http://lab.test/openapi.json"]
    assert result["discovery_metadata"]["graphql_urls"] == ["http://lab.test/graphql"]
    assert all(not url.startswith("http://outside") for url in requested)




def test_http_surface_prioritizes_configured_route_seeds_within_budget(monkeypatch) -> None:
    from types import SimpleNamespace

    from webpent.shared import http as http_module
    from webpent.shared import http_discovery as discovery_module

    requested: list[str] = []
    pages = {
        "http://lab.test/": (200, "text/html", "<h1>home</h1>"),
        "http://lab.test/graphql": (404, "text/plain", ""),
        "http://lab.test/critical-surface": (200, "application/json", "{}"),
    }

    class FakeResponse:
        def __init__(self, status_code: int, content_type: str, text: str) -> None:
            self.status_code = status_code
            self.headers = {"content-type": content_type}
            self.text = text

    class FakeClient:
        def get(self, url: str) -> FakeResponse:
            requested.append(url)
            status, content_type, text = pages.get(url, (404, "text/plain", ""))
            return FakeResponse(status, content_type, text)

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **_kwargs: FakeClient())
    monkeypatch.setattr(
        discovery_module,
        "get_settings",
        lambda: SimpleNamespace(
            discovery_route_seeds="/critical-surface",
            http_user_agent="WebPent/test",
        ),
    )

    result = discovery_module.discover_http_surface("http://lab.test/", max_pages=3)

    assert "http://lab.test/critical-surface" in result["endpoints"]
    assert result["discovery_metadata"]["route_seed_queued"] >= 1
    assert "/critical-surface" in result["discovery_metadata"]["route_seed_candidates"]
    assert len(result["endpoints"]) <= 3
    assert any(
        record["url"] == "http://lab.test/critical-surface"
        for record in result["surface_records"]
    )



def test_http_surface_default_route_seed_is_observed_without_links(monkeypatch) -> None:
    from webpent.shared import http as http_module
    from webpent.shared import http_discovery as discovery_module
    from webpent.shared.http_discovery import discover_http_surface
    pages = {
        "http://lab.test/": (200, "text/html", "<h1>home</h1>"),

        "http://lab.test/graphql": (404, "text/plain", ""),
        "http://lab.test/swagger_ui": (404, "text/plain", ""),
        "http://lab.test/swagger": (404, "text/plain", ""),
        "http://lab.test/openapi.json": (404, "text/plain", ""),
        "http://lab.test/api/docs": (404, "text/plain", ""),
        "http://lab.test/docs": (404, "text/plain", ""),
        "http://lab.test/export-erp": (200, "application/json", "{}"),
    }

    class FakeResponse:
        def __init__(self, status_code: int, content_type: str, text: str) -> None:
            self.status_code = status_code
            self.headers = {"content-type": content_type}
            self.text = text

    class FakeClient:
        def get(self, url: str) -> FakeResponse:
            status, content_type, text = pages.get(url, (404, "text/plain", ""))
            return FakeResponse(status, content_type, text)

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **_kwargs: FakeClient())
    monkeypatch.setattr(
        discovery_module,
        "get_settings",
        lambda: SimpleNamespace(
            discovery_route_seeds="/export-erp",
            http_user_agent="WebPent/test",
        ),
    )

    result = discover_http_surface("http://lab.test/", max_pages=20)

    assert "http://lab.test/export-erp" in result["endpoints"]
    assert any(
        record["url"] == "http://lab.test/export-erp"
        for record in result["surface_records"]
    )
    assert "/export-erp" in result["discovery_metadata"]["route_seed_candidates"]




def test_http_surface_404_seed_is_not_an_observed_endpoint(monkeypatch) -> None:
    from webpent.shared import http as http_module
    from webpent.shared.http_discovery import discover_http_surface

    class FakeResponse:
        status_code = 404
        headers = {"content-type": "text/plain"}
        text = "not found"

    class FakeClient:
        def get(self, _url: str) -> FakeResponse:
            return FakeResponse()

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **_kwargs: FakeClient())
    result = discover_http_surface("http://juice.test/", max_pages=20)

    assert result["endpoints"] == []
    assert result["surface_records"] == []
    assert "/export-erp" not in result["discovery_metadata"]["route_seed_candidates"]


def test_http_surface_route_seed_metadata_is_bounded(monkeypatch) -> None:
    from webpent.shared import http as http_module
    from webpent.shared.http_discovery import discover_http_surface

    class FakeResponse:
        status_code = 404
        headers = {"content-type": "text/plain"}
        text = ""

    class FakeClient:
        def get(self, _url: str) -> FakeResponse:
            return FakeResponse()

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **_kwargs: FakeClient())

    result = discover_http_surface("http://lab.test/", max_pages=2)

    assert len(result["discovery_metadata"]["route_seed_candidates"]) <= 40
    assert result["discovery_metadata"]["route_seed_queued"] <= 40
    assert len(result["endpoints"]) <= 2



def test_crawler_adds_bounded_http_supplement_after_katana_success(monkeypatch) -> None:
    from webpent.agents.crawler import agent as crawler_agent
    from webpent.models.targets import Target

    supplement = {
        "endpoints": [
            "http://lab.test/",
            "http://lab.test/export-erp",
        ],
        "forms": [],
        "pages_fetched": 2,
        "coverage_gaps": [],
        "surface_records": [
            {
                "record_id": "http:1",
                "url": "http://lab.test/export-erp",
                "method": "GET",
                "source": "http_get",
            }
        ],
        "discovery_metadata": {
            "route_seed_candidates": ["/export-erp"],
            "route_seed_queued": 1,
        },
    }

    monkeypatch.setattr(
        crawler_agent,
        "run_katana",
        lambda *_args, **_kwargs: ["http://lab.test/home"],
    )
    monkeypatch.setattr(
        crawler_agent,
        "discover_http_surface",
        lambda *_args, **_kwargs: supplement,
    )
    monkeypatch.setattr(crawler_agent, "get_llm", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(crawler_agent, "_fetch_and_analyze_js", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(crawler_agent, "_discover_html_forms", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(
            enable_http_discovery_supplement=False,
            http_discovery_supplement_pages=20,
            enable_structure_aware_triage=False,
            max_structure_aware_triage_endpoints=25,
        ),
    )

    result = crawler_agent.crawler_node(
        {
            "target": Target(url="http://lab.test/"),
            "session_cookies": {},
            "auth_state": {},
            "profile": "vip-qualification",
        }
    )

    crawled = result["crawled_data"]
    assert crawled["endpoints"][:2] == [
        "http://lab.test/export-erp",
        "http://lab.test/",
    ]
    assert "http://lab.test/home" in crawled["endpoints"]
    assert crawled["http_discovery"]["discovery_mode"] == "katana_plus_http_supplement"
    assert crawled["surface_records"][0]["url"] == "http://lab.test/export-erp"



def test_http_supplement_remains_opt_in_outside_qualification(monkeypatch) -> None:
    from webpent.agents.crawler import agent as crawler_agent
    from webpent.models.targets import Target

    called = False

    def _unexpected_supplement(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("supplement must remain opt-in outside vip-qualification")

    monkeypatch.setattr(crawler_agent, "run_katana", lambda *_args, **_kwargs: ["http://lab.test/"])
    monkeypatch.setattr(crawler_agent, "discover_http_surface", _unexpected_supplement)
    monkeypatch.setattr(crawler_agent, "get_llm", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(crawler_agent, "_fetch_and_analyze_js", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(crawler_agent, "_discover_html_forms", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(
            enable_http_discovery_supplement=False,
            http_discovery_supplement_pages=20,
            enable_structure_aware_triage=False,
            max_structure_aware_triage_endpoints=25,
        ),
    )

    result = crawler_agent.crawler_node(
        {
            "target": Target(url="http://lab.test/"),
            "session_cookies": {},
            "auth_state": {},
            "profile": "authorized-active",
        }
    )

    assert result["crawled_data"]["endpoints"] == ["http://lab.test/"]
    assert called is False
    assert "http_discovery" not in result["crawled_data"]


def test_http_surface_discovers_api_docs_swagger_paths(monkeypatch) -> None:
    from webpent.shared import http as http_module
    from webpent.shared.http_discovery import discover_http_surface

    pages = {
        "http://lab.test/": (200, "text/html", "<h1>home</h1>"),
        "http://lab.test/api-docs/swagger.json": (
            200,
            "application/json",
            '{"openapi":"3.0.0","paths":{"/rest/user/login":{},"/api/Products":{}}}',
        ),
        "http://lab.test/rest/user/login": (405, "application/json", "{}"),
        "http://lab.test/api/Products": (200, "application/json", "[]"),
    }

    class FakeResponse:
        def __init__(self, status_code: int, content_type: str, text: str) -> None:
            self.status_code = status_code
            self.headers = {"content-type": content_type}
            self.text = text

    class FakeClient:
        def get(self, url: str) -> FakeResponse:
            status, content_type, text = pages.get(url, (404, "text/plain", ""))
            return FakeResponse(status, content_type, text)

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **_kwargs: FakeClient())

    result = discover_http_surface("http://lab.test/", max_pages=5)

    metadata = result["discovery_metadata"]
    assert metadata["openapi_urls"] == ["http://lab.test/api-docs/swagger.json"]
    assert "http://lab.test/rest/user/login" in result["endpoints"]
    assert "http://lab.test/api/Products" in result["endpoints"]
    assert all("outside.test" not in url for url in result["endpoints"])


def test_http_surface_discovers_embedded_swagger_ui_document(monkeypatch) -> None:
    from webpent.shared import http as http_module
    from webpent.shared.http_discovery import discover_http_surface

    init_js = (
        'window.onload=function(){var options={"swaggerDoc":'
        '{"openapi":"3.0.0","servers":[{"url":"/b2b/v2"}],'
        '"paths":{"/orders":{},"https://outside.test/nope":{}}};}'
    )
    pages = {
        "http://lab.test/": (200, "text/html", "<h1>home</h1>"),
        "http://lab.test/api-docs/swagger-ui-init.js": (
            200,
            "application/javascript",
            init_js,
        ),
        "http://lab.test/b2b/v2/orders": (405, "application/json", "{}"),
    }

    class FakeResponse:
        def __init__(self, status_code: int, content_type: str, text: str) -> None:
            self.status_code = status_code
            self.headers = {"content-type": content_type}
            self.text = text

    class FakeClient:
        def get(self, url: str) -> FakeResponse:
            status, content_type, text = pages.get(url, (404, "text/plain", ""))
            return FakeResponse(status, content_type, text)

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **_kwargs: FakeClient())

    result = discover_http_surface("http://lab.test/", max_pages=5)

    assert "http://lab.test/api-docs/swagger-ui-init.js" in result["discovery_metadata"][
        "openapi_urls"
    ]
    assert "http://lab.test/b2b/v2/orders" in result["endpoints"]
    assert all("outside.test" not in url for url in result["endpoints"])


def test_http_surface_materializes_bounded_js_template_routes(monkeypatch) -> None:
    from webpent.shared import http as http_module
    from webpent.shared.http_discovery import discover_http_surface

    pages = {
        "http://lab.test/": (
            200,
            "text/html",
            '<script src="/static/main.js"></script>',
        ),
        "http://lab.test/static/main.js": (
            200,
            "application/javascript",
            "const basket = `/rest/basket/${basketId}`;",
        ),
        "http://lab.test/rest/basket/1": (
            200,
            "application/json",
            '{"id":1,"UserId":1}',
        ),
    }

    class FakeResponse:
        def __init__(self, status_code: int, content_type: str, text: str) -> None:
            self.status_code = status_code
            self.headers = {"content-type": content_type}
            self.text = text

    class FakeClient:
        def get(self, url: str) -> FakeResponse:
            status, content_type, text = pages.get(url, (404, "text/plain", ""))
            return FakeResponse(status, content_type, text)

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **_kwargs: FakeClient())

    result = discover_http_surface("http://lab.test/", max_pages=10)

    assert "http://lab.test/rest/basket/1" in result["endpoints"]
    assert "http://lab.test/rest/basket/1" in result["discovery_metadata"]["js_route_candidates"]


def test_request_headers_are_bounded_and_transport_safe() -> None:
    from webpent.shared.http import sanitize_request_headers

    result = sanitize_request_headers(
        {
            "X-Lab-Mode": "browser",
            "Cookie": "should-not-enter",
            "Host": "evil.invalid",
            "X-Newline": "safe\r\nInjected: yes",
            "X-Too-Long": "x" * 2050,
        }
    )

    assert result == {"X-Lab-Mode": "browser"}


def test_crawler_propagates_session_headers_to_katana_and_fallback(monkeypatch) -> None:
    from webpent.agents.crawler import agent as crawler_agent
    from webpent.models.targets import Target
    from webpent.shared.exceptions import ToolNotFoundError

    observed: dict[str, dict] = {}
    fallback = {
        "endpoints": ["http://lab.test/secure"],
        "forms": [],
        "pages_fetched": 1,
        "surface_records": [],
        "discovery_metadata": {},
    }

    def _katana(*_args, **kwargs):
        observed["katana"] = kwargs
        raise ToolNotFoundError("katana")

    def _fallback(*_args, **kwargs):
        observed["fallback"] = kwargs
        return fallback

    monkeypatch.setattr(crawler_agent, "run_katana", _katana)
    monkeypatch.setattr(crawler_agent, "discover_http_surface", _fallback)
    monkeypatch.setattr(crawler_agent, "get_llm", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(crawler_agent, "_fetch_and_analyze_js", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(crawler_agent, "_discover_html_forms", lambda *_args, **_kwargs: [])

    result = crawler_agent.crawler_node(
        {
            "target": Target(url="http://lab.test/"),
            "session_headers": {"X-Lab-Mode": "browser"},
            "session_cookies": {},
            "auth_state": {},
        }
    )

    assert observed["katana"]["extra_headers"] == {"X-Lab-Mode": "browser"}
    assert observed["fallback"]["extra_headers"] == {"X-Lab-Mode": "browser"}
    assert result["crawled_data"]["endpoints"] == fallback["endpoints"]


def test_initial_state_keeps_request_headers_checkpoint_safe() -> None:
    from webpent.models.targets import Target
    from webpent.state.initial_state import build_initial_state

    state = build_initial_state(
        Target(url="http://lab.test/"),
        session_headers={"X-Lab-Mode": "browser"},
    )

    assert state["session_headers"] == {"X-Lab-Mode": "browser"}
    assert all(not hasattr(value, "__enter__") for value in state["session_headers"].values())


def test_cli_header_parser_rejects_cookie_and_accepts_browser_header() -> None:
    from webpent.cli import _parse_request_headers

    assert _parse_request_headers(["X-Lab-Mode: browser"]) == {"X-Lab-Mode": "browser"}
    with pytest.raises(typer.Exit):
        _parse_request_headers(["Cookie: session=opaque"])
