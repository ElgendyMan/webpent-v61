from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from webpent.shared.action_authority import ActionRisk
from webpent.shared.agent_harness import (
    AgentProposal,
    AgentRunContext,
    BudgetReservation,
    CapabilityGrant,
    HarnessRunner,
    ProposedAction,
)
from webpent.shared.runtime import RuntimeFactory


class _FakeExecutor:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def execute(self, task: Any, handler: Any, *, preconditions_met: bool) -> dict[str, Any]:
        self.calls.append(str(task.task_id))
        return {"status": "executed", "output": {"target_backed": False}}


def _context(*, engagement_id: str = "eng-1") -> tuple[Any, _FakeExecutor]:
    runtime = RuntimeFactory.create(
        engagement_id=engagement_id,
        campaign_id="campaign-1",
        target_origin="http://example.test",
        use_default_ledger=False,
        manifest={},
    )
    fake = _FakeExecutor()
    registry = runtime.agent_harness.capability_registry
    registry.grant(
        CapabilityGrant(
            capability_name="http_read",
            engagement_id=engagement_id,
            lease_id="lease-1",
            expires_at=(datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
            approved_by="test-owner",
        )
    )
    harness = HarnessRunner(fake, registry, event_sink=runtime.event_sink)
    return replace(runtime, agent_harness=harness), fake


def _proposal() -> AgentProposal:
    return AgentProposal(
        proposal_id="proposal-1",
        objective="observe one scoped endpoint",
        assumptions=(),
        prerequisites=(),
        proposed_actions=(
            ProposedAction(
                action_id="action-1",
                target_url="http://example.test/health",
                capability="http_read",
                risk=ActionRisk.READ_ONLY,
                idempotency_key="idem-1",
            ),
        ),
        expected_observations=("response metadata",),
        risk=ActionRisk.READ_ONLY,
        cost=1.0,
        confidence=0.5,
        fallback="report inconclusive",
        stop_conditions=("one action",),
    )


def _run_context(*, engagement_id: str = "eng-1", package_digest: str = "pkg-a") -> AgentRunContext:
    return AgentRunContext(
        run_id="run-1",
        engagement_id=engagement_id,
        package_digest=package_digest,
        authorization_context={"approval": "test"},
        target_model_version="target-v1",
        agent_identity="agent-test",
        capabilities=("http_read",),
        budget=BudgetReservation(1, 1.0),
        deadline=(datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        stop_token="stop-1",
        trace_id="trace-1",
    )


def test_runtime_routes_governed_proposal_to_single_executor() -> None:
    runtime, fake = _context()
    outcome = runtime.run_agent_proposal(_run_context(), _proposal(), {"action-1": lambda _: {}})
    assert outcome.status.value == "executed"
    assert outcome.confirmation_status == "not_confirmed"
    assert fake.calls == ["run-1:action-1"]


def test_runtime_rejects_engagement_and_package_mismatch_before_executor() -> None:
    runtime, fake = _context()
    mismatch = runtime.run_agent_proposal(
        _run_context(engagement_id="other"),
        _proposal(),
        {"action-1": lambda _: {}},
    )
    package_mismatch = runtime.run_agent_proposal(
        _run_context(),
        _proposal(),
        {"action-1": lambda _: {}},
        expected_package_digest="pkg-b",
    )
    assert "runtime:engagement_mismatch" in mismatch.blocked_reasons
    assert "runtime:package_identity_mismatch" in package_mismatch.blocked_reasons
    assert fake.calls == []


def test_runtime_rejects_out_of_scope_before_executor() -> None:
    runtime, fake = _context()
    action = ProposedAction(
        action_id="action-1",
        target_url="http://outside.test/health",
        capability="http_read",
        risk=ActionRisk.READ_ONLY,
        idempotency_key="idem-1",
    )
    proposal = replace(_proposal(), proposed_actions=(action,))
    outcome = runtime.run_agent_proposal(_run_context(), proposal, {"action-1": lambda _: {}})
    assert "target_scope_denied" in outcome.blocked_reasons[0]
    assert fake.calls == []


def test_runtime_without_harness_fails_closed() -> None:
    runtime, fake = _context()
    runtime = replace(runtime, agent_harness=None)
    outcome = runtime.run_agent_proposal(_run_context(), _proposal(), {"action-1": lambda _: {}})
    assert "runtime:agent_harness_unavailable" in outcome.blocked_reasons
    assert fake.calls == []


__all__ = []
