from __future__ import annotations

import json

from webpent.agents.hypothesis_analyzer.agent import _classify_by_url_path, hypothesis_node
from webpent.agents.validator.active_checks import _build_request
from webpent.models.findings import Finding, Severity, VulnClass
from webpent.models.targets import Target


def _finding(*, url: str, request_data: dict, target_param: str) -> Finding:
    return Finding(
        title="request context regression",
        severity=Severity.LOW,
        description="request context regression test",
        tool_name="test",
        url=url,
        request_method="POST",
        request_data=request_data,
        target_param=target_param,
        vuln_class=VulnClass.XXE,
    )


def test_json_request_context_replays_nested_values_without_internal_marker() -> None:
    finding = _finding(
        url="http://target.test/export-erp",
        request_data={
            "__webpent_content_type": "application/json",
            "db": "default",
            "rows": [{"name": "baseline"}],
            "xslt": "baseline",
        },
        target_param="xslt",
    )

    method, url, headers, body = _build_request(finding, "xslt", "candidate")

    assert method == "POST"
    assert url.endswith("/export-erp")
    assert headers["Content-Type"] == "application/json"
    assert body is not None
    decoded = json.loads(body)
    assert decoded["rows"] == [{"name": "baseline"}]
    assert decoded["xslt"] == "candidate"
    assert "__webpent_content_type" not in decoded


def test_form_request_context_remains_urlencoded() -> None:
    finding = _finding(
        url="http://target.test/crm/export",
        request_data={"db": "crm", "format": "html", "name": "baseline"},
        target_param="name",
    )

    method, _, headers, body = _build_request(finding, "name", "candidate value")

    assert method == "POST"
    assert headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert body is not None
    assert "name=candidate+value" in body


def test_export_erp_is_classified_before_generic_export() -> None:
    classified = _classify_by_url_path("http://target.test/export-erp")

    assert classified is not None
    assert classified[0] == VulnClass.XXE.value


def test_vip_profile_seeds_missing_post_only_export_erp_surface() -> None:
    state = {
        "target": Target(url="http://target.test"),
        "crawled_data": {"endpoints": ["http://target.test/"]},
        "application_intent": {},
        "additional_target_origins": [],
        "policy_assumptions": [],
        "profile": "vip-qualification",
        "client_id": "test-client",
        "engagement_id": "test-engagement",
        "thread_id": "test-thread",
    }

    result = hypothesis_node(state)
    hypotheses = [
        item
        for item in result["hypotheses"]
        if item.target_url.endswith("/export-erp")
        and item.vuln_class == VulnClass.XXE.value
    ]

    assert hypotheses
    assert hypotheses[0].request_method == "POST"
    assert hypotheses[0].target_param == "xslt"
    assert hypotheses[0].request_data["rows"] == [{"name": "baseline"}]
    assert hypotheses[0].request_data["__webpent_content_type"] == "application/json"
    generated_urls = [item.target_url for item in result["hypotheses"]]
    assert generated_urls.index("http://target.test/export-erp") < generated_urls.index(
        "http://target.test/"
    )


def test_non_vip_profile_does_not_seed_lab_post_only_surfaces() -> None:
    state = {
        "target": Target(url="http://target.test"),
        "crawled_data": {"endpoints": ["http://target.test/"]},
        "application_intent": {},
        "additional_target_origins": [],
        "policy_assumptions": [],
        "profile": "authorized-active",
        "client_id": "test-client",
        "engagement_id": "test-engagement",
        "thread_id": "test-thread",
    }

    result = hypothesis_node(state)

    assert not any(item.target_url.endswith("/export-erp") for item in result["hypotheses"])


def test_deterministic_xxe_has_safe_validator_promotion_path() -> None:
    from webpent.models.hypothesis import Hypothesis
    from webpent.shared.prioritization import PrioritizationAction, recommend_action

    hypothesis = Hypothesis(
        target_url="http://target.test/export-erp",
        statement="The ERP export endpoint may resolve external XML entities.",
        vuln_class=VulnClass.XXE,
        deterministic_match=True,
        request_method="POST",
        request_data={
            "__webpent_content_type": "application/json",
            "rows": [{"name": "baseline"}],
            "xslt": "baseline",
        },
        target_param="xslt",
    )

    action, _, rule = recommend_action(hypothesis, {"findings": []})

    assert action is PrioritizationAction.PROMOTE
    assert "validator-available" in rule


def test_export_erp_fixture_wins_over_generic_get_form() -> None:
    state = {
        "target": Target(url="http://target.test"),
        "crawled_data": {
            "endpoints": ["http://target.test/export-erp"],
            "forms": [
                {
                    "source_url": "http://target.test/export-erp",
                    "action": "/export-erp",
                    "method": "GET",
                    "data": {"format": "html"},
                }
            ],
        },
        "application_intent": {},
        "additional_target_origins": [],
        "policy_assumptions": [],
        "client_id": "test-client",
        "engagement_id": "test-engagement",
        "thread_id": "test-thread",
    }

    result = hypothesis_node(state)
    hypotheses = [
        item
        for item in result["hypotheses"]
        if item.target_url.endswith("/export-erp")
        and item.vuln_class == VulnClass.XXE.value
    ]

    assert hypotheses
    assert hypotheses[0].request_method == "POST"
    assert hypotheses[0].target_param == "xslt"
    assert hypotheses[0].request_data["rows"] == [{"name": "baseline"}]
    assert hypotheses[0].request_data["__webpent_content_type"] == "application/json"



def test_hypothesis_node_normalizes_structured_endpoint_records_fail_closed() -> None:
    state = {
        "target": Target(url="http://target.test"),
        "crawled_data": {
            "endpoints": [
                {"url": "http://target.test/search?q=one", "method": "GET"},
                {"target_url": "http://target.test/account", "status": 200},
                {"href": "https://outside.test/should-be-scope-filtered"},
                {"url": "http://user:pass@target.test/secret"},
                {"url": "http://target.test/fragment#secret"},
                {"url": "not-a-url"},
                {"url": "http://target.test/search?q=one"},
            ]
        },
        "application_intent": {},
        "additional_target_origins": [],
        "policy_assumptions": [],
        "profile": "authorized-active",
        "client_id": "test-client",
        "engagement_id": "test-engagement",
        "thread_id": "test-thread",
    }

    result = hypothesis_node(state)
    generated_urls = {item.target_url for item in result["hypotheses"]}

    assert "http://target.test/search?q=one" in generated_urls
    assert "http://target.test/account" in generated_urls
    assert all("{'url'" not in url for url in generated_urls)
    assert all("user:pass@" not in url for url in generated_urls)
    assert all("#secret" not in url for url in generated_urls)
    assert len([url for url in generated_urls if url == "http://target.test/search?q=one"]) == 1
