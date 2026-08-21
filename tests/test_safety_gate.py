from webpent.shared.action_authority import (
    ActionAuthority,
    ActionRequest,
    ActionStatus,
)
from webpent.shared.safety_gate import (
    EngagementKillSwitch,
    EngagementSafetyGate,
    SafetyStatus,
)

ORIGIN = "https://target.example"
ENGAGEMENT = "eng-safety"


def make_request(**overrides):
    values = {
        "task_id": "task-1",
        "engagement_id": ENGAGEMENT,
        "target_url": f"{ORIGIN}/read",
        "metadata": {},
    }
    values.update(overrides)
    return ActionRequest(**values)


def test_same_origin_is_allowed_without_network_io():
    gate = EngagementSafetyGate(
        engagement_id=ENGAGEMENT,
        allowed_origins=(ORIGIN,),
    )

    decision = gate.authorize_request(make_request())

    assert decision.status is SafetyStatus.ALLOWED
    assert decision.allowed


def test_cross_origin_and_private_egress_are_blocked():
    gate = EngagementSafetyGate(
        engagement_id=ENGAGEMENT,
        allowed_origins=(ORIGIN,),
    )

    cross_origin = gate.authorize_request(
        make_request(target_url="https://other.example/read")
    )
    private_origin = gate.authorize_request(
        make_request(target_url="http://127.0.0.1:8000/read")
    )

    assert not cross_origin.allowed
    assert "egress:origin_not_allowlisted" in cross_origin.reasons
    assert not private_origin.allowed
    assert "egress:private_network_blocked" in private_origin.reasons


def test_redirect_chain_must_remain_on_allowlisted_origin():
    gate = EngagementSafetyGate(
        engagement_id=ENGAGEMENT,
        allowed_origins=(ORIGIN,),
    )

    decision = gate.authorize_request(
        make_request(
            metadata={"redirect_chain": [f"{ORIGIN}/step", "https://evil.example/out"]}
        )
    )

    assert not decision.allowed
    assert "egress:origin_not_allowlisted" in decision.reasons


def test_raw_secret_is_rejected_but_opaque_reference_is_accepted():
    gate = EngagementSafetyGate(
        engagement_id=ENGAGEMENT,
        allowed_origins=(ORIGIN,),
    )

    raw = gate.authorize_request(make_request(metadata={"authorization": "Bearer raw"}))
    opaque = gate.authorize_request(
        make_request(metadata={"authorization": "secretref:auth-1"})
    )

    assert not raw.allowed
    assert "secrets:opaque_reference_required" in raw.reasons
    assert opaque.allowed


def test_kill_switch_is_monotonic_and_engagement_bound():
    switch = EngagementKillSwitch(ENGAGEMENT)
    gate = EngagementSafetyGate(
        engagement_id=ENGAGEMENT,
        allowed_origins=(ORIGIN,),
        kill_switch=switch,
    )

    switch.trip("operator_stop")
    blocked = gate.authorize_request(make_request())
    mismatch = gate.authorize_request(make_request(engagement_id="other-eng"))

    assert blocked.status is SafetyStatus.KILL_SWITCHED
    assert "kill_switch:tripped:operator_stop" in blocked.reasons
    assert mismatch.status is SafetyStatus.BLOCKED
    assert "kill_switch:engagement_mismatch" in mismatch.reasons


def test_action_authority_blocks_before_handler_after_kill_switch():
    switch = EngagementKillSwitch(ENGAGEMENT)
    gate = EngagementSafetyGate(
        engagement_id=ENGAGEMENT,
        allowed_origins=(ORIGIN,),
        kill_switch=switch,
    )
    authority = ActionAuthority(
        allowed_origin=ORIGIN,
        safety_gate=gate,
        manifest={"capabilities": {"http_read": {"available": True}}},
    )
    switch.trip("operator_stop")
    called = []

    result = authority.execute(make_request(), lambda _request: called.append(True))

    assert result.status is ActionStatus.POLICY_DENIED
    assert called == []
    assert any("kill_switch:tripped:operator_stop" in reason for reason in result.decision.reasons)


def test_runtime_descriptor_preserves_kill_switch_state(monkeypatch, tmp_path):
    from webpent.shared.runtime import RuntimeFactory

    monkeypatch.setenv("WEBPENT_ACTION_LEDGER_PATH", str(tmp_path / "actions.db"))
    context = RuntimeFactory.create(
        engagement_id=ENGAGEMENT,
        campaign_id="campaign-safety",
        target_origin=ORIGIN,
        enable_control_plane=True,
    )
    assert context.safety_gate is not None
    context.safety_gate.kill_switch.trip("operator_stop")

    descriptor = RuntimeFactory.descriptor(context)
    resumed = RuntimeFactory.from_descriptor(descriptor)

    assert resumed is not None
    assert resumed.safety_gate is not None
    assert resumed.safety_gate.kill_switch.tripped
    assert resumed.safety_gate.kill_switch.reason == "operator_stop"
    assert descriptor["kill_switch_reason"] == "operator_stop"
    assert "secret" not in str(descriptor).lower()
