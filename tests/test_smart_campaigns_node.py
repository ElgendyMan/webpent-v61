from webpent.agents.smart_campaigns.agent import (
    _javascript_surface_records,
    _smart_task_cap,
    build_smart_campaign_tasks,
    smart_campaigns_execution_node,
    smart_campaigns_node,
)
from webpent.config.settings import get_settings
from webpent.models.targets import Target
from webpent.shared.coverage_ledger import project_coverage_ledger
from webpent.state.initial_state import build_initial_state


def test_safe_smart_governance_is_persisted_in_initial_state(monkeypatch) -> None:
    monkeypatch.setenv("SCAN_PROFILE", "safe-smart")
    get_settings.cache_clear()
    state = build_initial_state(Target(url="https://target.test"), auto_approve=True)
    assert state["scan_mode"] == "safe-smart"
    assert state["smart_governance"]["profile"] == "safe-smart"
    assert state["capability_manifest"]["capabilities"]["http_read"]["available"] is True
    assert state["action_budget"]["max_actions"] > 0


def _state(*, enabled: bool = True) -> dict:
    return {
        "smart_mode": enabled,
        "engagement_id": "engagement:test",
        "target": {"url": "https://target.test"},
        "crawled_data": {
            "surface_records": [
                {
                    "record_id": "surface:download:1",
                    "url": "https://target.test/download/1",
                    "method": "GET",
                }
            ]
        },
        "capability_manifest": {
            "capabilities": {"http_read": {"available": True, "status": "available"}}
        },
        "smart_governance": {"profile": "safe-smart"},
        "action_budget": {"used_actions": 0, "used_cost": 0.0},
        "campaign_ledger": {
            "entries": [
                {"id": 1, "key": "download_idor", "status": "not_observed"},
            ]
        },
        "campaign_plan": {
            "entries": [
                {
                    "key": "download_idor",
                    "status": "ready",
                    "validator_id": "idor_validator",
                    "matched_observation_refs": ["surface:download:1"],
                    "gaps": [],
                    "contract": {
                        "preconditions": ["download object reference observed"],
                        "observed_preconditions": ["download object reference observed"],
                        "identities": ["owner", "foreign_user"],
                        "negative_control": ["owner reads own object"],
                        "oracle": ["foreign denial"],
                        "budget": 2,
                        "cleanup": ["read-only"],
                    },
                },
                {
                    "key": "public_backup_disclosure",
                    "status": "not_observed",
                    "validator_id": None,
                    "matched_observation_refs": [],
                    "gaps": ["missing-validator:public_backup_disclosure"],
                    "contract": {},
                },
            ]
        },
    }


def test_javascript_routes_project_only_same_origin_concrete_routes() -> None:
    state = {
        "target": {"url": "https://target.test"},
        "javascript_intelligence": {
            "routes": [
                {
                    "route": "/rest/user/whoami",
                    "method_hint": "GET",
                    "discovery_kind": "literal-route",
                    "evidence_ref": "js:whoami",
                },
                {
                    "route": "https://third-party.test/collect",
                    "method_hint": "POST",
                    "evidence_ref": "js:external",
                },
                {"route": "/rest/products?q=${query}", "evidence_ref": "js:template"},
            ]
        },
    }

    records = _javascript_surface_records(state)
    assert [record["url"] for record in records] == [
        "https://target.test/rest/user/whoami"
    ]
    assert records[0]["category"] == "api"
    assert records[0]["evidence_ref"] == "js:whoami"


def test_authorized_active_campaign_cap_is_bounded_and_safe_smart_is_unchanged() -> None:
    assert _smart_task_cap({"smart_governance": {"profile": "safe-smart"}}) == 3
    assert _smart_task_cap({"smart_governance": {"profile": "authorized-active"}}) == 6
    assert _smart_task_cap(
        {"smart_governance": {"profile": "authorized-active"}},
        type("SettingsStub", (), {"smart_campaign_task_cap": 99})(),
    ) == 10


def test_disabled_node_is_additive_and_does_not_plan() -> None:
    result = smart_campaigns_node(_state(enabled=False))
    assert result["campaign_task_outcomes"] == []
    assert result["smart_next_actions"] == []
    assert result["smart_replanning"]["status"] == "disabled"


def test_node_plans_observed_campaign_but_never_executes_it() -> None:
    result = smart_campaigns_node(_state())
    assert result["smart_next_actions"]
    assert result["smart_replanning"]["execution_required"] is True
    assert result["smart_replanning"]["proof_required"] is True
    assert any(
        item["reason"] == "planned_not_executed"
        for item in result["campaign_task_outcomes"]
    )


def test_initial_plan_refreshes_from_observed_surface_url() -> None:
    state = _state()
    state["campaign_plan"] = {
        "entries": [
            {
                "key": "export_blade_ssti",
                "status": "not_observed",
                "validator_id": "ssti",
                "matched_observation_refs": [],
                "gaps": ["missing-surface:export_blade_ssti"],
                "contract": {},
            }
        ]
    }
    result = smart_campaigns_node(state)
    assert result["smart_next_actions"]
    assert any(
        entry["key"] == "export_blade_ssti" and entry["matched_observation_refs"]
        for entry in result["campaign_plan"]["entries"]
    )


def test_crawler_endpoint_strings_become_observed_surface_tasks() -> None:
    state = _state()
    state["crawled_data"] = {"endpoints": ["https://target.test/download/1"]}
    state["campaign_plan"] = {
        "entries": [
            {
                "key": "download_idor",
                "status": "not_observed",
                "validator_id": "idor_validator",
                "matched_observation_refs": [],
                "gaps": ["missing-surface:download_idor"],
                "contract": {},
            }
        ]
    }
    tasks, outcomes = build_smart_campaign_tasks(state)
    assert tasks
    assert len(tasks) <= 3
    assert {task.target_url for task in tasks} == {"https://target.test/download/1"}
    assert all(item["reason"] != "missing_concrete_surface_url" for item in outcomes)


def test_unobserved_or_missing_validator_campaign_is_blocked() -> None:
    tasks, outcomes = build_smart_campaign_tasks(_state())
    assert [task.vulnerability_class for task in tasks] == ["download_idor"]
    assert outcomes[0]["reason"] == "missing_observed_surface"


def test_execution_node_blocks_missing_precondition_before_handler(monkeypatch) -> None:
    state = _state()
    state["campaign_plan"]["entries"][0]["contract"].pop("observed_preconditions", None)
    called = False

    def should_not_execute(**_kwargs):
        nonlocal called
        called = True
        raise AssertionError("handler must not run when preconditions are unproven")

    monkeypatch.setattr(
        "webpent.agents.smart_campaigns.agent.make_safe_httpx_client",
        should_not_execute,
    )
    result = smart_campaigns_execution_node(state)
    assert called is False
    assert result["smart_http_observations"] == []
    assert any(
        item["status"] == "blocked_by_precondition"
        and item["reason"] == "precondition_failed"
        for item in result["campaign_task_outcomes"]
    )


def test_execution_node_uses_bounded_get_and_records_safe_metadata(monkeypatch) -> None:
    class Response:
        status_code = 200
        content = b"safe-body"
        headers = {"content-type": "text/html"}

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def get(self, url):
            assert url == "https://target.test/download/1"
            return Response()

    monkeypatch.setattr(
        "webpent.agents.smart_campaigns.agent.make_safe_httpx_client",
        lambda **_kwargs: Client(),
    )
    result = smart_campaigns_execution_node(_state())
    assert result["smart_http_observations"][0]["status_code"] == 200
    assert result["smart_http_observations"][0]["content_length"] == 9
    assert "body" not in result["smart_http_observations"][0]
    assert result["smart_replanning"]["get_only"] is True
    assert result["coverage_ledger"]["entries"][0]["attempts"] == 1
    assert result["coverage_ledger"]["entries"][0]["status"] == "inconclusive"


def test_execution_node_does_not_send_cross_origin_targets(monkeypatch) -> None:
    state = _state()
    state["crawled_data"]["surface_records"][0]["url"] = "https://evil.test/download/1"
    called = False

    def fail_client(**_kwargs):
        nonlocal called
        called = True
        raise AssertionError("transport must not be opened")

    monkeypatch.setattr(
        "webpent.agents.smart_campaigns.agent.make_safe_httpx_client",
        fail_client,
    )
    result = smart_campaigns_execution_node(state)
    assert called is False
    assert result["smart_http_observations"] == []
    assert any(item["status"] == "policy_denied" for item in result["campaign_task_outcomes"])


def test_idempotency_marks_previous_task_as_lower_priority() -> None:
    state = _state()
    first = smart_campaigns_node(state)
    state["campaign_task_outcomes"] = first["campaign_task_outcomes"]
    second = smart_campaigns_node(state)
    assert second["smart_next_actions"]
    assert any("duplication_penalty" in item["reasons"] for item in second["smart_next_actions"])


def test_initial_state_accepts_per_run_authorized_active_override(monkeypatch) -> None:
    monkeypatch.setenv("SCAN_PROFILE", "legacy")
    get_settings.cache_clear()
    state = build_initial_state(
        Target(url="https://target.test"),
        scan_mode="authorized-active",
        auto_approve=True,
    )
    assert state["scan_mode"] == "authorized-active"
    assert state["smart_governance"]["profile"] == "authorized-active"
    assert state["capability_manifest"]["capabilities"]["active_workflow"]["available"] is True
    assert state["decision_trace"] == []


def test_authorized_active_post_requires_evidence_body_and_persists_trace(monkeypatch) -> None:
    class Response:
        status_code = 201
        content = b"created"
        headers = {"content-type": "application/json"}

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, url, **kwargs):
            assert url == "https://target.test/download/1"
            assert kwargs["json"] == {"fixture": "bounded"}
            return Response()

    state = _state()
    state.update(
        {
            "scan_mode": "authorized-active",
            "auto_approve": True,
            "smart_governance": {"profile": "authorized-active"},
            "capability_manifest": {
                "capabilities": {
                    "http_read": {"available": True, "status": "available"},
                    "active_workflow": {"available": True, "status": "available"},
                }
            },
        }
    )
    state["crawled_data"]["surface_records"][0].update(
        {
            "method": "POST",
            "body": {"fixture": "bounded"},
            "content_type": "application/json",
        }
    )
    monkeypatch.setattr(
        "webpent.agents.smart_campaigns.agent.make_safe_httpx_client",
        lambda **_kwargs: Client(),
    )
    result = smart_campaigns_execution_node(state)
    assert result["smart_http_observations"][0]["method"] == "POST"
    assert result["smart_replanning"]["get_only"] is False
    assert result["smart_replanning"]["active_methods_enabled"] is True
    assert result["decision_trace"]
    assert result["decision_trace"][0]["outcome"]["status"] == "executed"


def test_human_review_only_is_a_supported_coverage_status() -> None:
    state = _state()
    state["campaign_ledger"]["entries"][0]["status"] = "human_review_only"
    state["campaign_task_outcomes"] = [
        {"vulnerability_class": "download_idor", "status": "human_review_only"}
    ]
    result = project_coverage_ledger(state)
    assert result["entries"][0]["status"] == "human_review_only"
    assert "human-review-only-validator" in result["entries"][0]["gaps"]


def test_authorized_active_form_submit_uses_typed_form_body(monkeypatch) -> None:
    class Response:
        status_code = 200
        content = b"ok"
        headers = {"content-type": "text/html"}

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, url, **kwargs):
            assert url == "https://target.test/download/1"
            assert kwargs["data"] == {"fixture": "bounded"}
            return Response()

    state = _state()
    state.update(
        {
            "scan_mode": "authorized-active",
            "auto_approve": True,
            "smart_governance": {"profile": "authorized-active"},
            "capability_manifest": {
                "capabilities": {
                    "http_read": {"available": True, "status": "available"},
                    "active_workflow": {"available": True, "status": "available"},
                }
            },
        }
    )
    state["crawled_data"]["surface_records"][0].update(
        {
            "method": "POST",
            "body": {"fixture": "bounded"},
            "body_schema": "form",
            "content_type": "application/x-www-form-urlencoded",
        }
    )
    monkeypatch.setattr(
        "webpent.agents.smart_campaigns.agent.make_safe_httpx_client",
        lambda **_kwargs: Client(),
    )
    result = smart_campaigns_execution_node(state)
    assert result["smart_http_observations"][0]["method"] == "POST"
    assert result["decision_trace"][0]["outcome"]["status"] == "executed"


def test_authorized_active_file_upload_is_bounded_and_typed(monkeypatch) -> None:
    class Response:
        status_code = 201
        content = b"uploaded"
        headers = {"content-type": "application/json"}

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, url, **kwargs):
            assert url == "https://target.test/download/1"
            assert kwargs["data"] == {"name": "fixture"}
            uploaded = kwargs["files"]["document"]
            assert uploaded[0] == "sample.csv"
            assert uploaded[1] == b"a,b\\n1,2\\n"
            assert uploaded[2] == "text/csv"
            return Response()

    state = _state()
    state.update(
        {
            "scan_mode": "authorized-active",
            "auto_approve": True,
            "smart_governance": {"profile": "authorized-active"},
            "capability_manifest": {
                "capabilities": {
                    "http_read": {"available": True, "status": "available"},
                    "active_workflow": {"available": True, "status": "available"},
                }
            },
        }
    )
    state["crawled_data"]["surface_records"][0].update(
        {
            "method": "POST",
            "body": {
                "fields": {"name": "fixture"},
                "file": {
                    "field": "document",
                    "filename": "sample.csv",
                    "content": "a,b\\n1,2\\n",
                    "content_type": "text/csv",
                },
            },
            "body_schema": "multipart",
            "content_type": "multipart/form-data",
        }
    )
    monkeypatch.setattr(
        "webpent.agents.smart_campaigns.agent.make_safe_httpx_client",
        lambda **_kwargs: Client(),
    )
    result = smart_campaigns_execution_node(state)
    assert result["smart_http_observations"][0]["method"] == "POST"
    assert result["decision_trace"][0]["outcome"]["status"] == "executed"
    assert result["smart_replanning"]["active_methods_enabled"] is True


# End of typed authorized-action regression coverage.


def test_authorized_active_direct_swagger_probe_requires_proof_bundle_for_confirmation(
    monkeypatch,
) -> None:
    from webpent.models.findings import Confidence, Finding, Severity, VulnClass

    class Response:
        status_code = 200
        headers = {"content-type": "application/json"}

        def __init__(self, content: bytes):
            self.content = content

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def get(self, url):
            if "/swagger_ui?url=" in url:
                return Response(b'{"method":"ipv6-loopback","flag":"NUA{test}"}')
            return Response(b"safe-body")

    existing = Finding(
        title="Potential SSRF at swagger_ui",
        severity=Severity.HIGH,
        description="Potential server-side request forgery.",
        tool_name="hypothesis_analyzer",
        url="https://target.test/swagger_ui",
        vuln_class=VulnClass.SSRF,
        confidence=Confidence.TENTATIVE,
    )
    state = _state()
    state["smart_governance"] = {"profile": "authorized-active"}
    state["scan_mode"] = "authorized-active"
    state["auto_approve"] = True
    state["findings"] = [existing]
    monkeypatch.setattr(
        "webpent.agents.smart_campaigns.agent.make_safe_httpx_client",
        lambda **_kwargs: Client(),
    )

    result = smart_campaigns_execution_node(state)
    direct = [item for item in result["findings"] if item.id == existing.id]
    assert len(direct) == 1
    assert direct[0].confidence == Confidence.TENTATIVE.value
    assert direct[0].confidence_level == "Needs Human Review"
    assert direct[0].evidence["matched_marker"] == "ipv6-loopback"
    assert (
        direct[0].evidence["promotion_guard"]["status"]
        == "blocked_missing_causal_signal_or_negative_control"
    )
    assert "body" not in direct[0].evidence["response"]
    assert direct[0].id == existing.id
    assert any(
        item["outcome"]["status"] == "executed"
        for item in result["decision_trace"]
        if item.get("selected_task") == "smart-swagger-ssrf-proof"
    )


def test_authorized_active_direct_swagger_probe_requires_marker(monkeypatch) -> None:
    class Response:
        status_code = 200
        content = b'{"status":"ok"}'
        headers = {"content-type": "application/json"}

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def get(self, _url):
            return Response()

    state = _state()
    state["smart_governance"] = {"profile": "authorized-active"}
    state["scan_mode"] = "authorized-active"
    monkeypatch.setattr(
        "webpent.agents.smart_campaigns.agent.make_safe_httpx_client",
        lambda **_kwargs: Client(),
    )

    result = smart_campaigns_execution_node(state)
    assert result["findings"] == []


def test_user_agent_falls_back_to_settings_when_state_has_no_settings(monkeypatch) -> None:
    monkeypatch.setenv(
        "HTTP_USER_AGENT",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 solverfileexpect_2222",
    )
    get_settings.cache_clear()
    from webpent.agents.smart_campaigns.agent import _user_agent

    assert "solverfileexpect_2222" in _user_agent({})
    from types import SimpleNamespace

    default_state = {"settings": SimpleNamespace(http_user_agent="WebPent/0.2 (+https://example.test)")}
    assert "solverfileexpect_2222" in _user_agent(default_state)
    get_settings.cache_clear()


def test_user_agent_fallback_replaces_legacy_default(monkeypatch) -> None:
    from webpent.agents.smart_campaigns.agent import _DEFAULT_BROWSER_USER_AGENT, _user_agent

    monkeypatch.delenv("HTTP_USER_AGENT", raising=False)
    monkeypatch.delenv("WEBPENT_HTTP_USER_AGENT", raising=False)
    get_settings.cache_clear()
    assert _user_agent({"settings": get_settings()}) == _DEFAULT_BROWSER_USER_AGENT


def test_generic_campaigns_use_same_origin_structured_hypotheses() -> None:
    state = _state()
    state["campaign_inventory"] = "generic"
    state["crawled_data"] = {}
    state["campaign_plan"] = {"entries": []}
    state["hypotheses"] = [
        {
            "id": "h-xss",
            "target_url": "https://target.test/search?q=demo",
            "statement": "The search parameter reflects input in the response.",
            "vuln_class": "xss",
            "request_method": "GET",
            "target_param": "q",
        },
        {
            "id": "h-out-of-scope",
            "target_url": "https://other.test/search?q=demo",
            "statement": "An unrelated origin should never become a campaign surface.",
            "vuln_class": "xss",
            "request_method": "GET",
            "target_param": "q",
        },
    ]

    tasks, outcomes = build_smart_campaign_tasks(state, max_tasks=10)

    assert any(
        task.vulnerability_class == "xss_reflected"
        and task.target_url == "https://target.test/search?q=demo"
        for task in tasks
    )
    assert all(task.target_url != "https://other.test/search?q=demo" for task in tasks)
    assert all(item["reason"] != "missing_concrete_surface_url" for item in outcomes)


def test_structured_hypothesis_model_is_projected_without_network_execution() -> None:
    state = _state()
    state["campaign_inventory"] = "generic"
    state["crawled_data"] = {}
    state["campaign_plan"] = {"entries": []}
    state["hypotheses"] = [
        {
            "id": "h-sqli",
            "target_url": "https://target.test/search?q=demo",
            "statement": "Search input may reach a database query.",
            "vuln_class": "sqli",
            "request_method": "GET",
            "target_param": "q",
            "request_data": {"q": "demo"},
        }
    ]

    tasks, _ = build_smart_campaign_tasks(state, max_tasks=10)

    sqli_tasks = [task for task in tasks if task.vulnerability_class == "sqli_param"]
    assert len(sqli_tasks) == 1
    assert sqli_tasks[0].metadata["source"] == "campaign_plan"
    assert sqli_tasks[0].target_url == "https://target.test/search?q=demo"


def test_observed_basket_route_projects_to_generic_idor_campaign() -> None:
    state = {
        "smart_mode": True,
        "engagement_id": "engagement:juice-basket",
        "campaign_inventory": "generic",
        "target": {"url": "http://lab.test"},
        "crawled_data": {
            "surface_records": [
                {
                    "record_id": "http:rest-basket-1",
                    "source": "http_get",
                    "url": "http://lab.test/rest/basket/1",
                    "endpoint": "http://lab.test/rest/basket/1",
                    "path": "/rest/basket/1",
                    "method": "GET",
                    "status_code": 200,
                    "identity": "authenticated",
                    "session_present": True,
                }
            ]
        },
        "campaign_plan": {
            "entries": [
                {
                    "key": "idor_object",
                    "status": "not_observed",
                    "validator_id": "idor_validator",
                    "matched_observation_refs": [],
                    "gaps": ["missing-surface:idor_object"],
                    "contract": {},
                }
            ]
        },
    }

    tasks, outcomes = build_smart_campaign_tasks(state)

    idor_tasks = [task for task in tasks if task.vulnerability_class == "idor_object"]
    assert idor_tasks
    assert idor_tasks[0].target_url == "http://lab.test/rest/basket/1"
    assert idor_tasks[0].metadata["observed_preconditions"]
    assert all(outcome.get("reason") != "missing_identity_context" for outcome in outcomes)


def test_observed_basket_route_without_identity_does_not_match_idor_campaign() -> None:
    state = {
        "campaign_inventory": "generic",
        "target": {"url": "http://lab.test"},
        "crawled_data": {
            "surface_records": [
                {
                    "url": "http://lab.test/rest/basket/1",
                    "source": "http_get",
                    "method": "GET",
                    "status_code": 401,
                    "identity": "anonymous",
                    "session_present": False,
                }
            ]
        },
        "campaign_plan": {
            "entries": [
                {
                    "key": "idor_object",
                    "status": "not_observed",
                    "validator_id": "idor_validator",
                    "matched_observation_refs": [],
                    "gaps": ["missing-surface:idor_object"],
                    "contract": {},
                }
            ]
        },
    }

    tasks, outcomes = build_smart_campaign_tasks(state)

    assert all(task.vulnerability_class != "idor_object" for task in tasks)
    assert any(
        outcome["reason"] == "missing_identity_context"
        and outcome["vulnerability_class"] == "idor_object"
        for outcome in outcomes
    )
