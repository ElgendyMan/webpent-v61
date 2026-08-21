from datetime import datetime, timedelta, timezone
from pathlib import Path

from webpent.models.application_intent import ApplicationIntentModel
from webpent.shared.action_authority import ActionAuthority
from webpent.shared.campaign_executor import ActionExecutor
from webpent.shared.control_plane import (
    BrowserActionRequest,
    IdentityProfileRef,
    WorkflowStep,
    compile_scope,
    evaluate_scope,
)
from webpent.shared.control_plane_runtime import BrowserActionAdapter
from webpent.shared.control_plane_spine import (
    IdentityTenantObjectGraph,
    build_control_plane_runtime,
)
from webpent.shared.runtime import AdapterRegistry, RegisteredAdapter


def scope_for(engagement_id: str = "eng-spine"):
    return compile_scope(
        engagement_id=engagement_id,
        root_domains=("https://*.target.example",),
        created_by="operator",
        approval_source="ticket-spine",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )


def executor_for() -> ActionExecutor:
    registry = AdapterRegistry()
    registry.register(
        RegisteredAdapter(
            name="control_plane_browser",
            capability="browser_action",
            transport="injected_browser_handler",
            handler=lambda _request: {"status": "registered"},
            source="control_plane_spine",
            version="1",
            policy_checked=True,
            canonical_wrapper="control_plane.browser_action",
            scope_policy="engagement_scope_same_origin",
            static_inventory_ref="control_plane.browser_action.injected",
            proof_contract="observation_only_no_confirmation",
            expires_at="2099-01-01T00:00:00Z",
        )
    )
    authority = ActionAuthority(
        allowed_origin="https://app.target.example",
        manifest={"capabilities": {"browser_action": {"available": True}}},
        adapter_registry=registry,
        require_g02=True,
    )
    return ActionExecutor(authority)


def test_identity_graph_is_engagement_and_tenant_isolated() -> None:
    graph = IdentityTenantObjectGraph(engagement_id="eng-spine")
    identity = IdentityProfileRef(
        identity_id="id-1",
        engagement_id="eng-spine",
        email_ref="vault://email/id-1",
        username_ref="vault://username/id-1",
        tenant_ref="tenant-a",
        provenance="test",
    )
    graph.register(identity)
    assert graph.authorize(identity_id="id-1", tenant_ref="tenant-a")
    assert not graph.authorize(identity_id="id-1", tenant_ref="tenant-b")
    assert graph.get("id-1") is not None
    assert "vault://" not in repr(graph.diagnostics())


def test_control_plane_runtime_descriptor_omits_live_handlers_and_secrets(tmp_path: Path) -> None:
    scope = scope_for()
    runtime = build_control_plane_runtime(
        engagement_id=scope.engagement_id,
        scope=scope,
        executor=executor_for(),
        profile_root=str(tmp_path / "profiles"),
    )
    descriptor = runtime.descriptor()
    assert descriptor["engagement_id"] == "eng-spine"
    assert descriptor["control_plane"]["replay"] == "action_executor_only"
    assert "handler" not in repr(descriptor)
    assert "password" not in repr(descriptor).lower()


def test_workflow_facade_binds_application_intent_and_rejects_drift(tmp_path: Path) -> None:
    scope = scope_for()
    runtime = build_control_plane_runtime(
        engagement_id=scope.engagement_id,
        scope=scope,
        executor=executor_for(),
        profile_root=str(tmp_path / "profiles"),
    )
    identity = IdentityProfileRef(
        identity_id="id-intent",
        engagement_id=scope.engagement_id,
        email_ref="vault://email/id-intent",
        username_ref="vault://username/id-intent",
        tenant_ref="tenant-a",
        provenance="test",
    )
    session = runtime.session_manager.create_session(
        engagement_id=scope.engagement_id,
        profile_ref=identity.identity_id,
        authenticated_origins=("https://app.target.example",),
        cookie_fingerprint="sha256:" + "i" * 64,
    )
    intent = ApplicationIntentModel(
        evidence_refs=("observation://intent/1",),
    )
    record = runtime.start_workflow(
        workflow_id="workflow-intent",
        identity=identity,
        session=session,
        intent_model=intent,
    )
    assert record.application_intent_schema == "application-intent-v1"
    assert record.application_intent_fingerprint.startswith("sha256:")

    step = WorkflowStep(
        workflow_id="workflow-intent",
        step_id="load",
        action_id="action-load",
        expected_state_transition="created->loaded",
    )
    updated = runtime.apply_workflow_step(
        step,
        identity=identity,
        session=session,
        idempotency_key="intent-step-1",
        intent_model=intent,
    )
    assert updated.state == "loaded"

    changed_intent = intent.model_copy(
        update={"evidence_refs": ["observation://intent/2"]}
    )
    blocked = runtime.apply_workflow_step(
        step.model_copy(
            update={"step_id": "load-again", "action_id": "action-load-again"}
        ),
        identity=identity,
        session=session,
        idempotency_key="intent-step-2",
        intent_model=changed_intent,
    )
    assert blocked.status.value == "blocked_by_precondition"
    assert blocked.reason == "workflow_intent_mismatch"


def test_browser_replay_uses_action_executor_and_deduplicates(tmp_path: Path) -> None:
    scope = scope_for()
    executor = executor_for()
    runtime = build_control_plane_runtime(
        engagement_id=scope.engagement_id,
        scope=scope,
        executor=executor,
        profile_root=str(tmp_path / "profiles"),
    )
    session = runtime.session_manager.create_session(
        engagement_id=scope.engagement_id,
        profile_ref="id-1",
        authenticated_origins=("https://app.target.example",),
        cookie_fingerprint="sha256:" + "a" * 64,
    )
    decision = evaluate_scope(scope, "https://app.target.example/signup")
    request = BrowserActionRequest(
        action_id="browser-action-1",
        engagement_id=scope.engagement_id,
        session_id=session.session_id,
        operation="navigate",
        url="https://app.target.example/signup",
        scope_decision=decision,
        idempotency_key="browser-idem-1",
    )
    calls: list[str] = []

    def handler(received: BrowserActionRequest) -> dict[str, int]:
        calls.append(received.action_id)
        return {"status": 200}

    receipt = runtime.replay_engine.replay_browser(
        request,
        session,
        BrowserActionAdapter(handler),
        target_url=request.url,
        g02_inventory_ref="control_plane.browser_action.injected",
        g02_proof_contract="observation_only_no_confirmation",
    )
    duplicate = runtime.replay_engine.replay_browser(
        request,
        session,
        BrowserActionAdapter(handler),
        target_url=request.url,
        g02_inventory_ref="control_plane.browser_action.injected",
        g02_proof_contract="observation_only_no_confirmation",
    )
    assert receipt.status == "executed"
    assert duplicate.status == "stopped"
    assert calls == [request.action_id]


def test_browser_replay_rejects_other_engagement_before_execution(tmp_path: Path) -> None:
    scope = scope_for()
    runtime = build_control_plane_runtime(
        engagement_id=scope.engagement_id,
        scope=scope,
        executor=executor_for(),
        profile_root=str(tmp_path / "profiles"),
    )
    session = runtime.session_manager.create_session(
        engagement_id=scope.engagement_id,
        profile_ref="id-1",
        authenticated_origins=("https://app.target.example",),
        cookie_fingerprint="sha256:" + "b" * 64,
    )
    decision = evaluate_scope(scope, "https://app.target.example/signup")
    request = BrowserActionRequest(
        action_id="browser-action-other",
        engagement_id="other-engagement",
        session_id=session.session_id,
        operation="navigate",
        url="https://app.target.example/signup",
        scope_decision=decision,
        idempotency_key="browser-idem-other",
    )
    called = False

    def handler(_received: BrowserActionRequest) -> dict[str, int]:
        nonlocal called
        called = True
        return {"status": 200}

    receipt = runtime.replay_engine.replay_browser(
        request,
        session,
        BrowserActionAdapter(handler),
        target_url=request.url,
        g02_inventory_ref="control_plane.browser_action.injected",
        g02_proof_contract="observation_only_no_confirmation",
    )
    assert receipt.status == "blocked_by_precondition"
    assert receipt.reason == "replay_engagement_mismatch"
    assert called is False
