from __future__ import annotations

from webpent.agents.hypothesis_analyzer.agent import hypothesis_node
from webpent.models.targets import Target


def test_post_form_generates_method_body_and_target_parameter() -> None:
    result = hypothesis_node(
        {
            "target": Target(url="https://lab.test"),
            "crawled_data": {
                "endpoints": ["https://lab.test/home"],
                "forms": [
                    {
                        "action": "/vulnerabilities/sqli/",
                        "method": "POST",
                        "data": {"id": "1", "Submit": "Submit"},
                        "source_url": "https://lab.test/home",
                    }
                ],
            },
        }
    )

    hypotheses = result["hypotheses"]
    sqli = [item for item in hypotheses if item.vuln_class == "sqli"]
    assert len(sqli) == 1
    hypothesis = sqli[0]
    assert hypothesis.target_url == "https://lab.test/vulnerabilities/sqli/"
    assert hypothesis.request_method == "POST"
    assert hypothesis.request_data == {"id": "1", "Submit": "Submit"}
    assert hypothesis.target_param == "id"
    assert hypothesis.deterministic_match is True


def test_post_form_does_not_duplicate_existing_endpoint_hypothesis() -> None:
    result = hypothesis_node(
        {
            "target": Target(url="https://lab.test"),
            "crawled_data": {
                "endpoints": ["https://lab.test/vulnerabilities/sqli/"],
                "forms": [
                    {
                        "action": "/vulnerabilities/sqli/",
                        "method": "POST",
                        "data": {"id": "1", "Submit": "Submit"},
                        "source_url": "https://lab.test",
                    }
                ],
            },
        }
    )

    sqli = [item for item in result["hypotheses"] if item.vuln_class == "sqli"]
    assert len(sqli) == 1
    assert sqli[0].request_method == "POST"
    assert sqli[0].target_param == "id"


def test_js_observed_query_route_generates_xss_hypothesis_with_parameter() -> None:
    result = hypothesis_node(
        {
            "target": Target(url="https://lab.test"),
            "crawled_data": {"endpoints": ["https://lab.test/home"]},
            "javascript_intelligence": {
                "routes": [
                    {
                        "route": "/rest/products/search?q=demo",
                        "method_hint": "GET",
                        "discovery_kind": "fetch",
                        "evidence_ref": "js://route/search",
                    },
                    {
                        "route": "/rest/products/search?q=${query}",
                        "method_hint": "GET",
                        "discovery_kind": "fetch",
                        "evidence_ref": "js://route/template",
                    },
                    {
                        "route": "https://other.test/search?q=demo",
                        "method_hint": "GET",
                        "discovery_kind": "fetch",
                        "evidence_ref": "js://route/external",
                    },
                    {
                        "route": "/rest/user/whoami",
                        "method_hint": "GET",
                        "discovery_kind": "fetch",
                        "evidence_ref": "js://route/path-only",
                    },
                ]
            },
        }
    )

    matching = [
        item
        for item in result["hypotheses"]
        if item.vuln_class == "xss"
        and item.target_url == "https://lab.test/rest/products/search?q=demo"
    ]
    assert len(matching) == 1
    assert matching[0].request_method == "GET"
    assert matching[0].target_param == "q"
    assert all("${query}" not in item.target_url for item in result["hypotheses"])
    assert all("other.test" not in item.target_url for item in result["hypotheses"])
    assert all(
        item.target_url != "https://lab.test/rest/user/whoami"
        for item in result["hypotheses"]
    )


def test_path_only_endpoint_keeps_no_query_and_no_target_parameter() -> None:
    result = hypothesis_node(
        {
            "target": Target(url="https://lab.test"),
            "crawled_data": {"endpoints": ["https://lab.test/rest/user/whoami"]},
        }
    )

    hypotheses = [
        item
        for item in result["hypotheses"]
        if item.vuln_class == "xss"
        and item.target_url == "https://lab.test/rest/user/whoami"
    ]
    assert len(hypotheses) == 1
    assert hypotheses[0].target_param is None
    assert "?" not in hypotheses[0].target_url
