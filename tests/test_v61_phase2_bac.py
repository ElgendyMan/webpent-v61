from webpent.agents.access_control import agent as access_agent
from webpent.shared import http as shared_http


def test_bac_candidates_include_query_body_header_sources():
    records = access_agent._extract_candidate_records(
        {
            "endpoints": [
                {
                    "url": "https://lab.local/api/orders?order_id=42",
                    "method": "GET",
                    "body": {"account_id": 7},
                    "headers": {"X-Owner-Id": "alice"},
                }
            ]
        }
    )

    assert len(records) == 1
    assert records[0]["object_id"] == "42"
    assert "query:order_id" in records[0]["candidate_sources"]
    assert "body:account_id" in records[0]["candidate_sources"]
    assert "header:X-Owner-Id" in records[0]["candidate_sources"]


def test_bac_candidates_bridge_graphql_variables():
    records = access_agent._extract_candidate_records(
        {},
        {
            "graphql_operations": [
                {
                    "endpoint": "https://lab.local/graphql",
                    "method": "POST",
                    "variables": {"orderId": 42},
                }
            ]
        },
    )

    assert len(records) == 1
    assert records[0]["method"] == "POST"
    assert records[0]["object_id"] == "42"
    assert "graphql:orderId" in records[0]["candidate_sources"]


def test_bac_adjacent_enumeration_is_bounded_and_skips_uuid():
    assert access_agent._enumerate_adjacent_ids(
        {"url": "https://lab.local/orders/42", "object_id": "42"},
        {"max_neighbors": 2},
    ) == ["41", "43"]
    assert access_agent._enumerate_adjacent_ids(
        {"url": "https://lab.local/orders/550e8400-e29b-41d4-a716-446655440000"},
        {"max_neighbors": 2},
    ) == []


def test_bac_probe_rejects_state_changing_method_without_explicit_gate(monkeypatch):
    called = False

    def fake_client(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("state-changing probe must not reach the client")

    monkeypatch.setattr(shared_http, "make_safe_httpx_client", fake_client)
    assert access_agent._probe_url(
        "https://lab.local/orders/42",
        method="DELETE",
        allow_state_changing=False,
    ) == (0, 0)
    assert called is False


def test_bac_probe_allows_state_changing_method_only_with_explicit_gate(monkeypatch):
    class Response:
        status_code = 204
        content = b""

    class Client:
        def request(self, *args, **kwargs):
            return Response()

    class Context:
        def __enter__(self):
            return Client()

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(shared_http, "make_safe_httpx_client", lambda **kwargs: Context())
    assert access_agent._probe_url(
        "https://lab.local/orders/42",
        method="DELETE",
        allow_state_changing=True,
    ) == (204, 0)


def test_access_control_node_uses_bounded_enumeration_and_preserves_provenance(monkeypatch):
    monkeypatch.setattr(access_agent, "_probe_url", lambda *args, **kwargs: (403, 20))
    result = access_agent.access_control_node(
        {
            "target": {"url": "https://lab.local/"},
            "findings": [],
            "crawled_data": {
                "endpoints": [{"url": "https://lab.local/orders/42", "method": "GET"}]
            },
            "identity_profiles": {
                "alice": {"role": "user", "cookies": {"session": "alice"}},
            },
            "enable_idor_enumeration": True,
            "idor_enumeration_neighbors": 2,
            "bac_max_candidates": 3,
        }
    )

    observations = result["bac_observations"]
    assert len(observations) == 3
    assert (
        sum("bounded_adjacent_id" in item["candidate_sources"] for item in observations)
        == 2
    )
    assert all(
        item["resource_url"].startswith("https://lab.local/orders/")
        for item in observations
    )
