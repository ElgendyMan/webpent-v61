from datetime import UTC, datetime, timedelta

from webpent.adapters.crapi.context_provider import (
    CrAPIObjectFixtureProvider,
    CrAPISyntheticSessionProvider,
    crapi_scope,
)
from webpent.adapters.juice_shop.context_provider import (
    JuiceShopContextProvider,
    JuiceShopFixtureProvider,
    JuiceShopSessionProvider,
    juice_shop_scope,
)
from webpent.adapters.mock_target.context_provider import (
    MockContextProvider,
    MockFixtureProvider,
    MockSessionProvider,
    mock_scope,
)
from webpent.adapters.webgoat.context_provider import (
    WebGoatLessonFixtureProvider,
    WebGoatLessonSessionProvider,
    webgoat_scope,
)
from webpent.config.settings import Settings
from webpent.shared.action_authority import ActionAuthority, ActionRisk
from webpent.shared.campaign_executor import CampaignExecutor, CampaignTask, CampaignTaskStatus
from webpent.shared.target_context import (
    CapabilityLease,
    CapabilityPolicy,
    ContextCoordinator,
    ContextRequest,
    ContextRole,
    ContextStatus,
    IdentityRequest,
    SnapshotHandle,
    TargetScope,
)


def _request(scope, *, role=ContextRole.CANDIDATE, session=False, fixture=False):
    identity = (
        IdentityRequest(scope, "synthetic-owner", "subject-owner", owner_group="owner")
        if session
        else None
    )
    fixture_request = None
    if fixture:
        from webpent.shared.target_context import FixtureRequest

        fixture_request = FixtureRequest(scope, f"fixture-{role.value}", role)
    capabilities = frozenset({"read_only_navigation"})
    return ContextRequest(
        scope,
        role,
        requested_capabilities=capabilities,
        identity_request=identity,
        fixture_request=fixture_request,
        requires_session=session,
        requires_fixture=fixture,
    )


def _coordinator(provider=None, *, session=None, fixture=None, seconds=30):
    provider = provider or MockContextProvider()
    policy = CapabilityPolicy(
        allowed_capabilities=("read_only_navigation",), lease_seconds=seconds
    )
    return ContextCoordinator(
        provider,
        policy=policy,
        session_provider=session,
        fixture_provider=fixture,
    )


def test_ready_context_acquires_snapshot_restores_and_disposes():
    session = MockSessionProvider()
    fixture = MockFixtureProvider()
    coordinator = _coordinator(session=session, fixture=fixture)

    status, reason, context = coordinator.acquire(
        _request(mock_scope(), session=True, fixture=True)
    )

    assert status is ContextStatus.READY
    assert reason == "ready"
    assert context is not None and context.session is not None and context.fixture is not None
    snapshot = coordinator.snapshot(context)
    assert snapshot.scope_key == context.scope.key
    assert coordinator.restore(context, snapshot).status is ContextStatus.READY
    assert coordinator.dispose(context).status is ContextStatus.READY
    assert session.revoked == [context.session.session_ref]
    assert fixture.disposed == [context.fixture.fixture_ref]


def test_blocked_context_is_distinguished_from_capability_unavailable():
    coordinator = _coordinator(MockContextProvider(ready=False))

    status, reason, context = coordinator.acquire(_request(mock_scope()))

    assert status is ContextStatus.LAB_NOT_READY
    assert reason == "mock_context_not_ready"
    assert context is None


def test_forbidden_capability_has_no_default_permission():
    coordinator = _coordinator()
    request = ContextRequest(
        mock_scope(),
        ContextRole.CANDIDATE,
        requested_capabilities=frozenset({"credential_use"}),
    )

    status, reason, context = coordinator.acquire(request)

    assert status is ContextStatus.CAPABILITY_UNAVAILABLE
    assert reason == "capability_lease_denied"
    assert context is None


def test_missing_session_is_explicitly_classified():
    coordinator = _coordinator()

    status, reason, context = coordinator.acquire(_request(mock_scope(), session=True))

    assert status is ContextStatus.SESSION_UNAVAILABLE
    assert reason == "session_provider_unavailable"
    assert context is None


def test_expired_lease_blocks_restore():
    scope = mock_scope()
    lease = CapabilityLease(
        "expired",
        scope.key,
        frozenset({"read_only_navigation"}),
        datetime.now(UTC) - timedelta(seconds=2),
        datetime.now(UTC) - timedelta(seconds=1),
    )
    from webpent.shared.target_context import ContextHandle, ExecutionContext

    context = ExecutionContext(
        ContextHandle("expired-context", scope, lease), ContextRole.CANDIDATE
    )
    coordinator = _coordinator()
    snapshot = SnapshotHandle("expired-snapshot", scope.key, "state")

    restored = coordinator.restore(context, coordinator.snapshot(context))
    assert restored.status is ContextStatus.EXPIRED
    assert not context.handle.ready
    assert snapshot.snapshot_ref == "expired-snapshot"


def test_restore_failure_and_cleanup_failure_are_not_hidden():
    restore_coordinator = _coordinator(
        MockContextProvider(snapshot_restore_fails=True)
    )
    status, _, context = restore_coordinator.acquire(_request(mock_scope()))
    assert status is ContextStatus.READY and context is not None
    snapshot = restore_coordinator.snapshot(context)
    assert restore_coordinator.restore(context, snapshot).status is ContextStatus.RESTORE_FAILED

    cleanup_coordinator = _coordinator(MockContextProvider(cleanup_fails=True))
    status, _, context = cleanup_coordinator.acquire(_request(mock_scope()))
    assert status is ContextStatus.READY and context is not None
    assert cleanup_coordinator.dispose(context).status is ContextStatus.DISPOSAL_FAILED


def test_candidate_and_negative_control_have_separate_contexts_and_scopes():
    coordinator = _coordinator()
    candidate_scope = TargetScope(
        "mock-target-spec", "mock-campaign", "candidate-run", "http://127.0.0.1:4200", "mock-scope"
    )
    control_scope = TargetScope(
        "mock-target-spec", "mock-campaign", "control-run", "http://127.0.0.1:4200", "mock-scope"
    )
    candidate_status, _, candidate = coordinator.acquire(
        _request(candidate_scope, role=ContextRole.CANDIDATE)
    )
    control_status, _, control = coordinator.acquire(
        _request(control_scope, role=ContextRole.NEGATIVE_CONTROL)
    )

    assert candidate_status is ContextStatus.READY
    assert control_status is ContextStatus.READY
    assert candidate is not None and control is not None
    assert candidate.role is ContextRole.CANDIDATE
    assert control.role is ContextRole.NEGATIVE_CONTROL
    assert candidate.scope.key != control.scope.key
    coordinator.dispose(candidate)
    coordinator.dispose(control)


def test_juice_shop_context_lifecycle_is_portable_and_target_local():
    coordinator = _coordinator(
        JuiceShopContextProvider(),
        session=JuiceShopSessionProvider(),
        fixture=JuiceShopFixtureProvider(),
    )
    scope = juice_shop_scope()

    status, _, context = coordinator.acquire(_request(scope, session=True, fixture=True))

    assert status is ContextStatus.READY
    assert context is not None
    assert context.scope.target_spec_id == "juice-shop-target-spec"
    assert context.scope.target_origin == "http://127.0.0.1:3000"
    assert context.session is not None and context.session.in_memory_only
    assert context.fixture is not None and context.fixture.ready
    snapshot = coordinator.snapshot(context)
    assert coordinator.restore(context, snapshot).status is ContextStatus.READY
    assert coordinator.dispose(context).status is ContextStatus.READY
    assert not context.handle.ready


def test_target_adapters_remain_target_local_and_offline():
    web_scope = webgoat_scope()
    web_coordinator = _coordinator(
        __import__(
            "webpent.adapters.webgoat.context_provider",
            fromlist=["WebGoatContextProvider"],
        ).WebGoatContextProvider(),
        session=WebGoatLessonSessionProvider(),
        fixture=WebGoatLessonFixtureProvider(),
    )
    status, _, context = web_coordinator.acquire(_request(web_scope, session=True, fixture=True))
    assert status is ContextStatus.READY
    assert context is not None
    assert context.scope.target_spec_id.startswith("webgoat")
    assert "token" not in str(context.as_dict()).lower()
    web_coordinator.dispose(context)

    crapi_scope_value = crapi_scope()
    crapi_coordinator = _coordinator(
        __import__(
            "webpent.adapters.crapi.context_provider",
            fromlist=["CrAPIContextProvider"],
        ).CrAPIContextProvider(),
        session=CrAPISyntheticSessionProvider(),
        fixture=CrAPIObjectFixtureProvider(),
    )
    status, _, context = crapi_coordinator.acquire(_request(crapi_scope_value))
    assert status is ContextStatus.READY
    assert context is not None
    assert "token" not in str(context.as_dict()).lower()
    crapi_coordinator.dispose(context)


def _settings():
    return Settings(
        scan_mode="authorized-active",
        smart_auto_approve=True,
        smart_require_idempotency=True,
        smart_action_budget=10.0,
        smart_max_actions=5,
    )


def _task(**overrides):
    values = {
        "task_id": "context-task",
        "engagement_id": "context-engagement",
        "asset_id": "context-asset",
        "source_evidence_ids": ("context-evidence",),
        "vulnerability_class": "idor",
        "hypothesis_id": "context-hypothesis",
        "preconditions": ("context_ready",),
        "identity_context": "synthetic-owner",
        "expected_information_gain": 0.5,
        "risk_tier": ActionRisk.READ_ONLY,
        "target_url": "http://127.0.0.1:4200/profile/1",
    }
    values.update(overrides)
    return CampaignTask(**values)


def test_campaign_executor_requires_context_request_when_context_layer_enabled():
    authority = ActionAuthority(
        settings=_settings(),
        allowed_origin="http://127.0.0.1:4200",
        manifest={"capabilities": {"http_read": {"available": True}}},
    )
    executor = CampaignExecutor(
        authority,
        context_coordinator=_coordinator(),
    )
    calls = []

    result = executor.execute(_task(), lambda _: calls.append(True))

    assert result["status"] == CampaignTaskStatus.CONTEXT_BLOCKED.value
    assert calls == []


def test_campaign_executor_context_lifecycle_wraps_handler_and_cleanup():
    authority = ActionAuthority(
        settings=_settings(),
        allowed_origin="http://127.0.0.1:4200",
        manifest={"capabilities": {"http_read": {"available": True}}},
    )
    executor = CampaignExecutor(authority, context_coordinator=_coordinator())
    seen = []

    result = executor.execute(
        _task(),
        lambda _: {"legacy": True},
        context_request=_request(mock_scope()),
        context_handler=lambda task, context: seen.append(context.scope.key) or {"ok": True},
    )

    assert result["status"] == CampaignTaskStatus.EXECUTED.value
    assert len(seen) == 1
    stages = [event["stage"] for event in executor.lifecycle_events]
    assert stages == [
        "planned",
        "context_acquired",
        "snapshot",
        "restored",
        "disposed",
        "authorized",
        "completed",
    ]


def test_campaign_executor_context_failure_prevents_authority_and_handler():
    authority = ActionAuthority(
        settings=_settings(),
        allowed_origin="http://127.0.0.1:4200",
        manifest={"capabilities": {"http_read": {"available": True}}},
    )
    executor = CampaignExecutor(
        authority,
        context_coordinator=_coordinator(MockContextProvider(ready=False)),
    )
    calls = []

    result = executor.execute(
        _task(),
        lambda _: calls.append(True),
        context_request=_request(mock_scope()),
    )

    assert result["status"] == CampaignTaskStatus.CONTEXT_BLOCKED.value
    assert "context_lab_not_ready" in result["reason"]
    assert calls == []


def test_dispose_revokes_lease_and_context_is_no_longer_ready():
    coordinator = _coordinator()
    status, _, context = coordinator.acquire(_request(mock_scope()))
    assert status is ContextStatus.READY and context is not None

    assert context.handle.ready
    assert coordinator.dispose(context).status is ContextStatus.READY
    assert context.handle.lease.revoked
    assert not context.handle.ready


def test_fixture_failure_revokes_session_and_lease():
    session = MockSessionProvider()
    fixture = MockFixtureProvider(ready=False)
    coordinator = _coordinator(session=session, fixture=fixture)

    status, reason, context = coordinator.acquire(
        _request(mock_scope(), session=True, fixture=True)
    )

    assert status is ContextStatus.FIXTURE_UNAVAILABLE
    assert reason == "mock_fixture_not_ready"
    assert context is None
    assert session.revoked == ["mock-session-synthetic-owner"]


def test_missing_fixture_capability_revokes_existing_session():
    session = MockSessionProvider()
    coordinator = _coordinator(session=session, fixture=MockFixtureProvider())
    coordinator.fixture_provider.capabilities = lambda: {"fixture_snapshot"}  # type: ignore[method-assign]

    status, reason, context = coordinator.acquire(
        _request(mock_scope(), session=True, fixture=True)
    )

    assert status is ContextStatus.FIXTURE_UNAVAILABLE
    assert reason == "disposable_fixture_capability_unavailable"
    assert context is None
    assert session.revoked == ["mock-session-synthetic-owner"]


def test_context_request_rejects_missing_required_session_and_fixture_requests():
    scope = mock_scope()
    try:
        ContextRequest(scope, ContextRole.CANDIDATE, requires_session=True)
    except ValueError as exc:
        assert str(exc) == "context_request_identity_required"
    else:
        raise AssertionError("missing identity request was accepted")

    try:
        ContextRequest(scope, ContextRole.CANDIDATE, requires_fixture=True)
    except ValueError as exc:
        assert str(exc) == "context_request_fixture_required"
    else:
        raise AssertionError("missing fixture request was accepted")
