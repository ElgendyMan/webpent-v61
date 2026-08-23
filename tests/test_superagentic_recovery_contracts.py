from webpent.shared.recovery import (
    CheckpointLedger,
    CheckpointRecord,
    IdempotencyLedger,
    StopState,
    StopStateMachine,
)


def _checkpoint() -> CheckpointRecord:
    return CheckpointRecord(
        checkpoint_id="cp-1",
        run_id="run-1",
        engagement_id="eng-1",
        target_package_digest="sha256:package-1",
        scope_digest="sha256:scope-1",
        policy_digest="sha256:policy-1",
        last_completed_action="a-1",
        completed_action_signatures=("sig-a-1",),
        sequence=1,
    )


def test_checkpoint_is_sealed_and_resume_is_identity_bound() -> None:
    ledger = CheckpointLedger()
    record = ledger.append(_checkpoint())
    assert record.verify()
    assert CheckpointLedger.resume(
        record,
        engagement_id="eng-1",
        target_package_digest="sha256:package-1",
        scope_digest="sha256:scope-1",
        policy_digest="sha256:policy-1",
    ).allowed
    mismatch = CheckpointLedger.resume(
        record,
        engagement_id="eng-2",
        target_package_digest="sha256:package-1",
        scope_digest="sha256:scope-1",
        policy_digest="sha256:policy-1",
    )
    assert not mismatch.allowed
    assert "engagement_id_mismatch" in " ".join(mismatch.reasons)


def test_checkpoint_terminal_states_cannot_resume() -> None:
    record = _checkpoint()
    terminal = record.__class__(**{**record.__dict__, "stop_state": StopState.COMPLETED}).seal()
    decision = CheckpointLedger.resume(
        terminal,
        engagement_id="eng-1",
        target_package_digest="sha256:package-1",
        scope_digest="sha256:scope-1",
        policy_digest="sha256:policy-1",
    )
    assert not decision.allowed
    assert "terminal_state:completed" in " ".join(decision.reasons)


def test_idempotency_ledger_requires_claim_then_complete() -> None:
    ledger = IdempotencyLedger()
    assert ledger.claim("sig-1")
    assert not ledger.claim("sig-1")
    assert ledger.complete("sig-1")
    assert not ledger.claim("sig-1")
    assert not ledger.complete("sig-1")


def test_stop_state_machine_is_monotonic_and_fail_closed() -> None:
    machine = StopStateMachine()
    assert machine.should_execute()
    assert machine.request_stop()
    assert not machine.should_execute()
    assert machine.transition(StopState.STOPPED)
    assert not machine.transition(StopState.ACTIVE)
    assert not machine.transition(StopState.COMPLETED)
