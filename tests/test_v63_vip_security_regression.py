from __future__ import annotations

import logging
import uuid

import pytest
from fastapi import HTTPException

from webpent.api.app import _authorize_scan_resource, _effective_scan_client_id
from webpent.api.auth import (
    _TOKEN_VERSIONS,
    User,
    _create_access_token,
    _decode_access_token,
    revoke_user_tokens,
)
from webpent.api.rate_limit import RateLimiter
from webpent.memory.db import DatabaseManager
from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.models.proof_bundle import build_proof_bundle
from webpent.shared.engagement_scope import (
    OriginPolicy,
    clear_engagement_target_hosts,
    is_engagement_origin_allowed,
    is_engagement_target_host,
    set_engagement_target_hosts,
)
from webpent.shared.http import make_safe_httpx_client


def test_alembic_upgrade_failure_fails_closed(monkeypatch, tmp_path) -> None:
    def fail_upgrade(_self) -> None:
        raise RuntimeError("migration failed")

    legacy = monkeypatch.setattr
    monkeypatch.setattr(DatabaseManager, "_run_alembic_upgrade", fail_upgrade)
    legacy(DatabaseManager, "_init_db_legacy", lambda _self: pytest.fail("legacy fallback used"))

    db = DatabaseManager(f"sqlite:///{tmp_path / 'migration-failure.db'}")
    with pytest.raises(RuntimeError, match="migration failed"):
        db.init_db()


def test_legacy_fallback_provisions_shared_token_versions(monkeypatch, tmp_path) -> None:
    db = DatabaseManager(f"sqlite:///{tmp_path / 'legacy-auth.db'}")
    monkeypatch.setattr(
        db,
        "_run_alembic_upgrade",
        lambda: (_ for _ in ()).throw(ImportError("alembic unavailable")),
    )

    db.init_db()
    assert db.get_token_version("legacy-user") == 1
    assert db.bump_token_version("legacy-user") == 2
    assert db.get_token_version("legacy-user") == 2


def test_alembic_init_does_not_replace_runtime_logging_handlers(tmp_path, caplog) -> None:
    db = DatabaseManager(f"sqlite:///{tmp_path / 'logging.db'}")
    db.init_db()
    with caplog.at_level(logging.CRITICAL):
        logging.getLogger("webpent.shared.preflight").critical("ALEMBIC_LOGGING_CAPTURE_SENTINEL")
    assert "ALEMBIC_LOGGING_CAPTURE_SENTINEL" in caplog.text


def test_resume_claim_is_atomic_and_retry_idempotent(tmp_path, monkeypatch) -> None:
    import webpent.api.scan_registry as registry

    db = DatabaseManager(f"sqlite:///{tmp_path / 'resume.db'}")
    monkeypatch.setattr(registry, "_get_db", lambda: db)
    thread_id = "resume-thread"
    assert registry.register_scan(thread_id, "task-1", "https://target.test")

    assert registry.claim_resume_capability(thread_id, "cap-1") is True
    assert registry.claim_resume_capability(thread_id, "cap-1") is False
    assert registry.consume_resume_capability(thread_id, "cap-1", consumer_id="celery-1") is True
    assert registry.consume_resume_capability(thread_id, "cap-1", consumer_id="celery-1") is True
    assert registry.consume_resume_capability(thread_id, "cap-1", consumer_id="celery-2") is False
    assert registry.claim_resume_capability(thread_id, "cap-2") is True


def test_jwt_contains_required_claims_and_revocation_is_effective() -> None:
    username = f"vip-regression-user-{uuid.uuid4().hex}"
    _TOKEN_VERSIONS[username] = 1
    try:
        token = _create_access_token(
            {"sub": username, "role": "operator", "ver": 1},
        )
        decoded = _decode_access_token(token)
        assert decoded.username == username
        assert decoded.role == "operator"
        assert decoded.jti
        assert decoded.token_version == 1

        revoke_user_tokens(username)
        with pytest.raises(HTTPException) as exc_info:
            _decode_access_token(token)
        assert exc_info.value.status_code == 401
    finally:
        _TOKEN_VERSIONS.pop(username, None)


def test_strategist_uses_coverage_ledger_without_fixed_top_n_cap() -> None:
    from webpent.agents.strategist.agent import strategist_node
    from webpent.models.hypothesis import Hypothesis

    hypotheses = [
        Hypothesis(
            target_url=f"https://target-{index}.test/item?id={index}",
            statement="Deterministic SQL injection candidate",
            vuln_class=VulnClass.SQLI.value,
            confidence_score=0.95,
            deterministic_match=True,
        )
        for index in range(6)
    ]
    result = strategist_node({"findings": [], "hypotheses": hypotheses, "mental_model": {}})

    assert len(result["findings"]) == 6
    ledger = result["coverage_ledger"]
    assert ledger["selection_policy"] == "coverage-based-no-fixed-top-n"
    assert ledger["status_counts"]["tested"] == 6
    assert len(ledger["entries"]) == 6


def test_scan_authorization_is_owner_scoped_and_admin_global() -> None:
    import webpent.api.scan_registry as registry

    record = {
        "thread_id": "thread-owner",
        "owner_username": "alice",
        "client_id": "client-a",
        "engagement_id": "eng-a",
        "status": "running",
    }
    original = registry.get_scan_record
    registry.get_scan_record = lambda _thread_id: record  # type: ignore[assignment]
    try:
        assert (
            _authorize_scan_resource("thread-owner", User("alice", "hash", "operator"))[
                "engagement_id"
            ]
            == "eng-a"
        )
        with pytest.raises(HTTPException) as exc_info:
            _authorize_scan_resource("thread-owner", User("mallory", "hash", "operator"))
        assert exc_info.value.status_code == 404
        assert (
            _authorize_scan_resource(
                "thread-owner",
                User("admin", "hash", "admin", is_global_admin=True),
            )["owner_username"]
            == "alice"
        )
    finally:
        registry.get_scan_record = original  # type: ignore[assignment]


def test_scan_authorization_fails_closed_for_unscoped_legacy_record() -> None:
    import webpent.api.scan_registry as registry

    original = registry.get_scan_record
    registry.get_scan_record = lambda _thread_id: {
        "thread_id": "legacy",
        "owner_username": "alice",
        "client_id": "client-a",
        "engagement_id": "",
    }  # type: ignore[assignment]
    try:
        with pytest.raises(HTTPException) as exc_info:
            _authorize_scan_resource("legacy", User("alice", "hash", "operator"))
        assert exc_info.value.status_code == 404
    finally:
        registry.get_scan_record = original  # type: ignore[assignment]


def test_rate_limiter_denies_when_required_redis_backend_fails() -> None:
    limiter = RateLimiter(enabled=True, redis_url="redis://required")
    limiter._redis = None
    limiter._redis_required = True
    limiter._redis_unavailable = True
    assert limiter.check_global("198.51.100.10") is False
    assert limiter.check_scan("198.51.100.10") is False


def test_login_rate_limiter_applies_ip_and_account_buckets() -> None:
    limiter = RateLimiter(enabled=True, login_per_minute=2)
    assert limiter.check_login("198.51.100.10", "Admin") is True
    assert limiter.check_login("198.51.100.10", "admin") is True
    assert limiter.check_login("198.51.100.10", "admin") is False

    limiter.reset()
    assert limiter.check_login("198.51.100.11", "admin") is True


def test_login_rate_limiter_denies_when_required_redis_fails() -> None:
    limiter = RateLimiter(enabled=True, redis_url="redis://required", login_per_minute=2)
    limiter._redis = None
    limiter._redis_required = True
    limiter._redis_unavailable = True
    assert limiter.check_login("198.51.100.10", "admin") is False


def test_engagement_scope_is_exact_and_context_is_cleared() -> None:
    token = set_engagement_target_hosts("https://192.168.56.10/app")
    try:
        assert is_engagement_target_host("192.168.56.10") is True
        assert is_engagement_target_host("192.168.56.11") is False
        assert is_engagement_target_host("attacker.example") is False
    finally:
        clear_engagement_target_hosts(token)
    assert is_engagement_target_host("192.168.56.10") is False


def test_scope_target_normalization_does_not_accept_credentials_as_host() -> None:
    token = set_engagement_target_hosts("https://user:password@example.test/path")
    try:
        assert is_engagement_target_host("example.test") is True
        assert is_engagement_target_host("user") is False
    finally:
        clear_engagement_target_hosts(token)


def test_tenant_admin_scan_creation_is_client_scoped() -> None:
    tenant_admin = User("tenant-admin", "hash", "admin", tenant_id="tenant-a")
    assert _effective_scan_client_id(None, tenant_admin) == "tenant-a"
    assert _effective_scan_client_id("tenant-a", tenant_admin) == "tenant-a"
    with pytest.raises(HTTPException) as exc_info:
        _effective_scan_client_id("tenant-b", tenant_admin)
    assert exc_info.value.status_code == 403

    with pytest.raises(HTTPException) as exc_info:
        _effective_scan_client_id(None, User("broken", "hash", "admin"))
    assert exc_info.value.status_code == 403


def test_tenant_admin_cannot_cross_tenant_but_can_read_own_tenant() -> None:
    import webpent.api.scan_registry as registry

    original = registry.get_scan_record
    registry.get_scan_record = lambda _thread_id: {
        "thread_id": "tenant-b-thread",
        "owner_username": "alice",
        "client_id": "tenant-b",
        "engagement_id": "eng-b",
    }  # type: ignore[assignment]
    try:
        with pytest.raises(HTTPException) as exc_info:
            _authorize_scan_resource(
                "tenant-b-thread",
                User("tenant-admin", "hash", "admin", tenant_id="tenant-a"),
            )
        assert exc_info.value.status_code == 404

        record = _authorize_scan_resource(
            "tenant-b-thread",
            User("tenant-admin", "hash", "admin", tenant_id="tenant-b"),
        )
        assert record["client_id"] == "tenant-b"
    finally:
        registry.get_scan_record = original  # type: ignore[assignment]


def test_authorization_never_returns_cross_tenant_record_to_operator() -> None:
    import webpent.api.scan_registry as registry

    original = registry.get_scan_record
    registry.get_scan_record = lambda _thread_id: {
        "thread_id": "tenant-b-thread",
        "owner_username": "alice",
        "client_id": "tenant-b",
        "engagement_id": "eng-b",
    }  # type: ignore[assignment]
    try:
        # A caller is authorized by owner, not by an arbitrary client header;
        # the registry record remains the authoritative tenant boundary.
        record = _authorize_scan_resource("tenant-b-thread", User("alice", "hash", "operator"))
        assert record["client_id"] == "tenant-b"
    finally:
        registry.get_scan_record = original  # type: ignore[assignment]


@pytest.mark.parametrize("bad_record", [{"owner_username": "alice"}, {"owner_username": ""}])
def test_authorization_rejects_missing_engagement_metadata(bad_record: dict) -> None:
    import webpent.api.scan_registry as registry

    original = registry.get_scan_record
    registry.get_scan_record = lambda _thread_id: bad_record  # type: ignore[assignment]
    try:
        with pytest.raises(HTTPException) as exc_info:
            _authorize_scan_resource("unscoped", User("alice", "hash", "operator"))
        assert exc_info.value.status_code == 404
    finally:
        registry.get_scan_record = original  # type: ignore[assignment]


def test_safe_http_client_rejects_tls_verification_downgrade() -> None:
    with pytest.raises(ValueError, match="TLS certificate verification"):
        make_safe_httpx_client(verify=False)


def test_origin_policy_is_exact_across_scheme_port_and_path() -> None:
    policy = OriginPolicy.from_url("https://example.test:8443/app/")

    assert policy.allows("https://example.test:8443/app")
    assert policy.allows("wss://example.test:8443/app/socket")
    assert policy.allows("https://example.test:8443/app/item?id=1")
    assert not policy.allows("https://example.test:8443/app2")
    assert not policy.allows("https://example.test:443/app")
    assert not policy.allows("http://example.test:8443/app")
    assert not policy.allows("https://sub.example.test:8443/app")


def test_origin_policy_context_is_shared_by_transports() -> None:
    token = set_engagement_target_hosts("https://engagement.example.test/app")
    try:
        assert is_engagement_origin_allowed("https://engagement.example.test/app/x")
        assert not is_engagement_origin_allowed("https://engagement.example.test/app2")
        assert not is_engagement_origin_allowed("http://engagement.example.test/app")
    finally:
        clear_engagement_target_hosts(token)
    assert is_engagement_origin_allowed("https://engagement.example.test/app2")


def test_sync_http_transport_rejects_origin_policy_bypass(monkeypatch) -> None:
    from unittest.mock import MagicMock

    import httpx

    from webpent.shared.http import SSRFPinningTransport, SSRFRedirectBlockedError

    wrapped = MagicMock()
    transport = SSRFPinningTransport(wrapped=wrapped)
    token = set_engagement_target_hosts("https://engagement.example.test/app")
    try:
        request = httpx.Request("GET", "https://other.example.test/app")
        with pytest.raises(SSRFRedirectBlockedError, match="OriginPolicy"):
            transport.handle_request(request)
        wrapped.handle_request.assert_not_called()
    finally:
        clear_engagement_target_hosts(token)


def test_playwright_http_and_websocket_use_same_origin_policy() -> None:
    import webpent.shared.http as http

    class FakeRoute:
        def __init__(self) -> None:
            self.aborted: str | None = None
            self.continued = False

        def abort(self, reason: str) -> None:
            self.aborted = reason

        def continue_(self) -> None:
            self.continued = True

    class FakeRequest:
        method = "GET"

        def __init__(self, url: str) -> None:
            self.url = url

    class FakeWebSocket:
        def __init__(self, url: str) -> None:
            self.url = url
            self.closed: tuple[int, str] | None = None
            self.connected = False

        def close(self, code: int, reason: str) -> None:
            self.closed = (code, reason)

        def connect_to_server(self) -> None:
            self.connected = True

    class FakeContext:
        def __init__(self) -> None:
            self.http_handler = None
            self.websocket_handler = None

        def route(self, _pattern: str, handler) -> None:
            self.http_handler = handler

        def route_web_socket(self, _pattern: str, handler) -> None:
            self.websocket_handler = handler

    token = set_engagement_target_hosts("https://engagement.example.test/app")
    try:
        context = FakeContext()
        http.install_playwright_ssrf_guard(context, target_hosts=[])

        route = FakeRoute()
        context.http_handler(route, FakeRequest("https://other.example.test/app"))
        assert route.aborted == "accessdenied"
        assert route.continued is False

        websocket = FakeWebSocket("wss://other.example.test/app/socket")
        context.websocket_handler(websocket)
        assert websocket.closed == (1008, "accessdenied")
        assert websocket.connected is False
    finally:
        clear_engagement_target_hosts(token)


def test_raw_http_refuses_out_of_scope_host_before_connect(monkeypatch) -> None:
    from webpent.agents.request_smuggling import agent as request_smuggling_agent

    token = set_engagement_target_hosts("https://engagement.example.test")
    try:

        def unexpected_connect(*_args, **_kwargs):
            raise AssertionError("out-of-scope raw HTTP attempted a socket connection")

        monkeypatch.setattr(
            request_smuggling_agent.socket,
            "create_connection",
            unexpected_connect,
        )
        assert (
            request_smuggling_agent._send_raw_http(
                "other.example.test",
                443,
                b"GET / HTTP/1.1\\r\\n\\r\\n",
                use_tls=True,
            )
            is None
        )
    finally:
        clear_engagement_target_hosts(token)


def test_oob_callback_without_proof_is_fail_closed(tmp_path) -> None:
    db = DatabaseManager(f"sqlite:///{tmp_path / 'oob.db'}")
    finding = Finding(
        id=uuid.uuid4(),
        title="OOB regression finding",
        severity=Severity.HIGH,
        description="Synthetic OOB regression finding.",
        tool_name="regression",
        url="https://target.test/oob",
        confidence=Confidence.TENTATIVE.value,
        vuln_class=VulnClass.XSS.value,
        reasoning="baseline",
    )
    db.save_finding(finding)

    first = db.mark_oob_confirmed(
        finding.id,
        reasoning_appendix="callback-1",
        payload_marker="marker-1",
    )
    replay = db.mark_oob_confirmed(
        finding.id,
        reasoning_appendix="callback-2",
        payload_marker="marker-2",
    )

    assert first is not None
    assert replay is not None
    assert first.confidence_level == "Pending"
    assert replay.confidence_level == "Pending"
    assert replay.reasoning == "baseline"
    assert replay.payload is None


def test_oob_confirmation_requires_causal_signal_and_sealed_proof(tmp_path) -> None:
    db = DatabaseManager(f"sqlite:///{tmp_path / 'oob-proof.db'}")
    finding = Finding(
        id=uuid.uuid4(),
        title="OOB proof finding",
        severity=Severity.HIGH,
        description="Synthetic OOB proof finding.",
        tool_name="regression",
        url="https://target.test/oob-proof",
        confidence=Confidence.TENTATIVE.value,
        vuln_class=VulnClass.XSS.value,
        reasoning="baseline",
    )
    db.save_finding(finding)
    evidence_ref = f"oob:{finding.id}:callback"
    proof = build_proof_bundle(
        engagement_id="regression",
        finding_id=str(finding.id),
        evidence=("callback-marker",),
        evidence_refs=(evidence_ref,),
        negative_control={"status": 404},
    ).seal(actor="oob-validator")
    causal = {
        "evidence_refs": [evidence_ref],
        "causal_signal": True,
        "negative_control_complete": True,
    }

    confirmed = db.mark_oob_confirmed(
        finding.id,
        reasoning_appendix="callback-verified",
        payload_marker="marker-proof",
        causal_observation=causal,
        proof_bundle=proof,
    )

    assert confirmed is not None
    assert confirmed.confidence_level == "Tool-Confirmed"
    assert confirmed.confidence == Confidence.CONFIRMED.value
    assert confirmed.reasoning.endswith("callback-verified")
    assert confirmed.payload == "marker-proof"


def test_origin_policy_rejects_adversarial_origin_variants() -> None:
    from webpent.shared.engagement_scope import OriginPolicy

    policy = OriginPolicy.from_url("https://Exämple.test/app")

    assert policy.allows("https://xn--exmple-cua.test/app") is True
    assert policy.allows("https://xn--exmple-cua.test/app/item") is True
    assert policy.allows("https://xn--exmple-cua.test/app2") is False
    assert policy.allows("http://xn--exmple-cua.test/app") is False
    assert policy.allows("https://xn--exmple-cua.test:444/app") is False
    assert policy.allows("https://evil.example.test/app") is False
    assert policy.allows("https://user:pass@xn--exmple-cua.test/app") is False


def test_origin_policy_canonicalizes_ipv6_and_preserves_port_boundaries() -> None:
    from webpent.shared.engagement_scope import OriginPolicy

    policy = OriginPolicy.from_url("http://[2001:0db8:0:0:0:0:0:1]:8080/lab")

    assert policy.allows("http://[2001:db8::1]:8080/lab") is True
    assert policy.allows("http://[2001:db8::1]:8080/lab/next") is True
    assert policy.allows("http://[2001:db8::1]:80/lab") is False
    assert policy.allows("http://[2001:db8::2]:8080/lab") is False
    assert policy.allows("http://[2001:db8::1]:8080/lab2") is False


def test_reference_allowlist_uses_exact_origin_and_segment_boundaries() -> None:
    from webpent.shared.reference_lookup import _is_url_allowed

    allowlist = [{"base_url": "https://docs.example.test/guide", "allowed_paths": ["/guide"]}]

    assert _is_url_allowed("https://docs.example.test/guide/page", allowlist) is True
    assert _is_url_allowed("https://docs.example.test/guidebook", allowlist) is False
    assert _is_url_allowed("https://docs.example.test.evil/guide/page", allowlist) is False
    assert _is_url_allowed("http://docs.example.test/guide/page", allowlist) is False
    assert _is_url_allowed("https://docs.example.test:444/guide/page", allowlist) is False
    assert _is_url_allowed("https://user:pass@docs.example.test/guide/page", allowlist) is False


def test_information_tasks_do_not_bypass_precondition_resolution() -> None:
    from webpent.agents.smart_campaigns.agent import smart_campaigns_execution_node

    state = {
        "scan_mode": "safe-smart",
        "smart_governance": {"profile": "safe-smart"},
        "target": {"url": "https://target.test"},
        "smart_information_actions": [
            {
                "action_id": "blocked-research",
                "fingerprint": "blocked-research",
                "target_ref": "https://target.test/robots.txt",
                "method": "GET",
                "requires_approval": True,
                "action_class": "discovery",
                "preconditions": ["planned_same_origin_information_action"],
            }
        ],
        "observed_preconditions": (),
        "blocked_preconditions": ("planned_same_origin_information_action",),
        "campaign_task_outcomes": [],
        "findings": [],
        "hypotheses": [],
        "action_budget": {"max_actions": 10, "max_cost": 10.0},
        "auto_approve": False,
    }

    result = smart_campaigns_execution_node(state)
    outcomes = result.get("campaign_task_outcomes", [])
    assert outcomes
    assert any(
        str(item.get("status")) == "blocked_by_precondition"
        for item in outcomes
        if isinstance(item, dict)
    )


def test_llm_cross_reasoning_hypothesis_is_not_deterministic() -> None:
    from webpent.agents.cross_reasoning.agent import cross_reasoning_node
    from webpent.models.targets import Target

    result = cross_reasoning_node(
        {
            "target": Target(url="https://target.test"),
            "findings": [],
            "messages": [],
        }
    )
    assert all(
        not bool(getattr(item, "deterministic_match", False))
        for item in result.get("hypotheses", [])
    )


def test_authorized_active_promotes_bounded_validator_route_below_score_threshold() -> None:
    from webpent.agents.strategist.agent import strategist_node
    from webpent.models.hypothesis import Hypothesis

    def make_hypothesis() -> Hypothesis:
        return Hypothesis(
            target_url="https://target.test/search?q=probe",
            statement="The search parameter may reflect attacker-controlled input.",
            vuln_class=VulnClass.XSS.value,
            confidence_score=0.2,
            estimated_cost=8.0,
            deterministic_match=False,
        )

    active_result = strategist_node(
        {
            "findings": [],
            "hypotheses": [make_hypothesis()],
            "mental_model": {},
            "scan_mode": "authorized-active",
        }
    )
    assert len(active_result["findings"]) == 1
    active_entry = next(iter(active_result["coverage_ledger"]["entries"].values()))
    assert active_entry["status"] == "tested"
    assert active_entry["validator_route"]

    observe_result = strategist_node(
        {
            "findings": [],
            "hypotheses": [make_hypothesis()],
            "mental_model": {},
            "scan_mode": "safe-smart",
        }
    )
    assert observe_result["findings"] == []
    observe_entry = next(iter(observe_result["coverage_ledger"]["entries"].values()))
    assert observe_entry["status"] == "blocked"
    assert observe_entry["reason"] == "prioritization_gate_deferred"
