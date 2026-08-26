from __future__ import annotations

from webpent.agents.access_control.agent import _extract_candidate_records
from webpent.agents.authentication import agent as auth_agent
from webpent.agents.hypothesis_analyzer.agent import hypothesis_node
from webpent.models.targets import Target
from webpent.shared import stealth
from webpent.shared.bac_identity_tester import assess_access_control


def test_declared_origin_alias_attaches_form_context() -> None:
    result = hypothesis_node(
        {
            "target": Target(url="http://127.0.0.1:8000"),
            "additional_target_origins": ["http://localhost:5173"],
            "crawled_data": {
                "endpoints": ["http://127.0.0.1:8000/crm/export"],
                "forms": [
                    {
                        "action": "http://localhost:5173/crm/export",
                        "method": "POST",
                        "data": {"db": "crm", "rows[0][name]": "baseline"},
                        "source_url": "http://localhost:5173/export-page",
                    }
                ],
            },
        }
    )

    ssti = [item for item in result["hypotheses"] if item.vuln_class == "ssti"]
    assert len(ssti) == 1
    assert ssti[0].request_method == "POST"
    assert ssti[0].request_data == {"db": "crm", "rows[0][name]": "baseline"}
    assert ssti[0].target_param == "db"


def test_unknown_form_route_does_not_invent_target_specific_context() -> None:
    result = hypothesis_node(
        {
            "target": Target(url="http://127.0.0.1:8000"),
            "crawled_data": {"endpoints": ["http://127.0.0.1:8000/crm/export"]},
        }
    )

    ssti = [item for item in result["hypotheses"] if item.vuln_class == "ssti"]
    assert len(ssti) == 1
    assert ssti[0].request_method == "GET"
    assert ssti[0].request_data == {}
    assert ssti[0].target_param is None


def test_waptlab_read_only_idor_paths_are_candidates_not_confirmations() -> None:
    records = _extract_candidate_records(
        {
            "urls": [
                "http://127.0.0.1:8000/user_profile/1",
                "http://127.0.0.1:8000/download/1",
            ]
        }
    )

    assert {record["url"] for record in records} == {
        "http://127.0.0.1:8000/user_profile/1",
        "http://127.0.0.1:8000/download/1",
    }
    assert all(record["candidate_sources"] for record in records)
    assert all("owner_identity" not in record for record in records)


def test_anonymous_login_redirect_is_a_bounded_idor_negative_control() -> None:
    observations = [
        {"identity": "anonymous", "accessible": False, "status_code": 302},
        {"identity": "owner", "accessible": True, "status_code": 200},
        {"identity": "foreign", "accessible": True, "status_code": 200},
    ]

    result = assess_access_control(observations, owner_identity="owner")

    assert result["status"] == "confirmed"
    assert result["confidence_level"] == "Tool-Confirmed"
    assert result["negative_control_complete"] is True


def test_bac_pacing_override_uses_shared_rate_limiter(monkeypatch) -> None:
    stealth.reset_rate_limits()
    sleeps: list[float] = []
    monkeypatch.setattr(stealth.time, "sleep", sleeps.append)

    stealth.enforce_min_interval(True, "waptlab.local", min_interval_override=0.5)
    stealth.enforce_min_interval(True, "waptlab.local", min_interval_override=0.5)

    assert sleeps
    assert 0.0 < sleeps[0] <= 0.5


def test_operator_pacing_jitter_is_bounded(monkeypatch) -> None:
    stealth.reset_rate_limits()
    sleeps: list[float] = []
    monkeypatch.setattr(stealth.time, "sleep", sleeps.append)
    monkeypatch.setattr(stealth.random, "uniform", lambda _lo, hi: hi)

    stealth.enforce_min_interval(
        True,
        "waptlab-jitter.local",
        min_interval_override=0.5,
        jitter_max_override=0.75,
    )

    assert sleeps == [0.75]


def test_primary_login_profile_is_runtime_only_and_keeps_secondary_profiles(monkeypatch) -> None:
    monkeypatch.setattr(
        auth_agent,
        "_perform_login",
        lambda url, username, password, **kwargs: {"session": f"runtime-{username}"},
    )
    result = auth_agent.auth_node(
        {
            "target": Target(url="http://lab.local"),
            "credentials": {"username": "owner", "password": "owner-secret"},
            "identity_profiles": {
                "foreign": {
                    "name": "foreign",
                    "role": "user",
                    "credentials": {"username": "foreign", "password": "foreign-secret"},
                }
            },
        }
    )

    assert result["identity_profiles"]["owner"]["role"] == "owner"
    assert result["identity_profiles"]["owner"]["metadata"]["authenticated_primary"] is True
    assert result["identity_profiles"]["owner"]["cookies"] == {"session": "runtime-owner"}
    assert result["identity_profiles"]["foreign"]["validated"] is True
    assert "owner-secret" not in repr(result)
    assert "foreign-secret" not in repr(result)
    assert "credentials" not in result["identity_profiles"]["owner"]



def test_bac_retries_owner_after_server_throttle(monkeypatch) -> None:
    from webpent.agents.access_control import agent as access_agent

    calls: dict[str, int] = {}

    def fake_probe(url, cookies=None, **kwargs):
        session = (cookies or {}).get("session")
        calls[session] = calls.get(session, 0) + 1
        if session is None:
            return 302, 354
        if session == "owner-secret" and calls[session] == 1:
            return 429, 128
        return (200, 100) if session in {"owner-secret", "foreign-secret"} else (403, 20)

    monkeypatch.setattr(access_agent, "_probe_url", fake_probe)
    refresh_calls = {"count": 0}

    def unexpected_refresh(*args):
        refresh_calls["count"] += 1
        return None

    monkeypatch.setattr(access_agent, "_refresh_profile_after_throttle", unexpected_refresh)
    initial_waits: list[str] = []
    monkeypatch.setattr(access_agent, "_wait_before_bac", initial_waits.append)
    monkeypatch.setattr(access_agent, "_wait_after_throttle", lambda _url: 0.0)

    result = access_agent.access_control_node(
        {
            "thread_id": "throttle-test-thread",
            "target": Target(url="https://lab.local/"),
            "findings": [],
            "crawled_data": {"urls": ["https://lab.local/user_profile/1"]},
            "identity_profiles": {
                "owner": {
                    "role": "owner",
                    "cookies": {"session": "owner-secret"},
                    "metadata": {"authenticated_primary": True},
                },
                "foreign": {
                    "role": "foreign",
                    "cookies": {"session": "foreign-secret"},
                },
            },
        }
    )

    observation = result["bac_observations"][0]
    assert observation["assessment"]["status"] == "confirmed"
    assert observation["assessment"]["confidence_level"] == "Tool-Confirmed"
    owner_rows = [row for row in observation["observations"] if row["identity"] == "owner"]
    assert owner_rows[0]["status_code"] == 200
    assert calls["owner-secret"] == 2
    assert refresh_calls["count"] == 0
    assert initial_waits == ["https://lab.local/user_profile/1"]


def test_bac_initial_cooldown_is_optional_and_bounded(monkeypatch) -> None:
    from webpent.agents.access_control import agent as access_agent

    sleeps: list[float] = []
    monkeypatch.setattr(access_agent.time, "sleep", sleeps.append)
    monkeypatch.setenv("WEBPENT_BAC_INITIAL_COOLDOWN_SECONDS", "999")
    monkeypatch.setenv("WEBPENT_BAC_INITIAL_JITTER_MAX_SECONDS", "0")

    delay = access_agent._wait_before_bac("http://127.0.0.1:8000/user_profile/1")

    assert delay == 90.0
    assert sleeps == [90.0]

    sleeps.clear()
    monkeypatch.delenv("WEBPENT_BAC_INITIAL_COOLDOWN_SECONDS", raising=False)
    assert access_agent._wait_before_bac("http://127.0.0.1:8000/user_profile/1") == 0.0
    assert sleeps == []


def test_auth_preserves_operator_request_headers_without_auth_material() -> None:
    request_headers = {
        "User-Agent": "Mozilla/5.0 qualification",
        "Accept": "text/html,application/xhtml+xml",
    }
    result = auth_agent.auth_node(
        {
            "target": Target(url="http://lab.local"),
            "session_headers": request_headers,
        }
    )

    assert result["session_headers"] == request_headers
    assert result["auth_state"] == {}
    assert "Authentication: no credentials found." in result["messages"][0].content



def test_auth_preserves_request_headers_after_playwright_login(monkeypatch) -> None:
    request_headers = {"User-Agent": "Mozilla/5.0 qualification"}
    monkeypatch.setattr(
        auth_agent,
        "_perform_login",
        lambda url, username, password, **kwargs: {"session": "runtime-owner"},
    )
    result = auth_agent.auth_node(
        {
            "target": Target(url="http://lab.local"),
            "credentials": {"username": "owner", "password": "owner-secret"},
            "session_headers": request_headers,
        }
    )

    assert result["session_headers"] == request_headers
    assert result["session_cookies"] == {"session": "runtime-owner"}
