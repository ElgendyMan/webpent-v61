from pathlib import Path

from webpent.shared.action_ledger import SQLiteActionLedger


def _reserve(
    ledger: SQLiteActionLedger,
    *,
    engagement_id: str,
    idempotency_key: str,
):
    return ledger.reserve(
        idempotency_key=idempotency_key,
        engagement_id=engagement_id,
        task_id=f"task-{engagement_id}-{idempotency_key}",
        target_origin="https://example.com",
        method="GET",
        action_family="http_read",
        identity_ref="anonymous",
        tenant_context="tenant-1",
        vulnerability_class="unknown",
        validator_id="",
        estimated_cost=1.0,
        max_actions=2,
        max_budget=3.0,
    )


def test_idempotency_key_is_isolated_per_engagement(tmp_path: Path) -> None:
    ledger = SQLiteActionLedger(tmp_path / "actions.sqlite3")

    first = _reserve(ledger, engagement_id="engagement-a", idempotency_key="same-key")
    second = _reserve(ledger, engagement_id="engagement-b", idempotency_key="same-key")

    assert first.allowed
    assert second.allowed
    assert ledger.snapshot("engagement-a")["used_actions"] == 1
    assert ledger.snapshot("engagement-b")["used_actions"] == 1


def test_unknown_terminal_status_does_not_mutate_reservation(tmp_path: Path) -> None:
    ledger = SQLiteActionLedger(tmp_path / "actions.sqlite3")
    reservation = _reserve(ledger, engagement_id="engagement-a", idempotency_key="key-1")

    assert reservation.allowed
    assert not ledger.complete("engagement-a", "key-1", status="made_up_status")
    assert ledger.complete("engagement-a", "key-1", status="failed")
    assert ledger.snapshot("engagement-a")["used_actions"] == 0


def test_completed_reservation_is_terminal_and_duplicate_is_denied(tmp_path: Path) -> None:
    ledger = SQLiteActionLedger(tmp_path / "actions.sqlite3")
    reservation = _reserve(ledger, engagement_id="engagement-a", idempotency_key="key-1")

    assert reservation.allowed
    assert ledger.complete(
        "engagement-a", "key-1", status="executed", output_digest="digest"
    )
    assert not ledger.complete("engagement-a", "key-1", status="failed")
    duplicate = _reserve(ledger, engagement_id="engagement-a", idempotency_key="key-1")

    assert not duplicate.allowed
    assert duplicate.reason == "idempotency:duplicate_reservation"
    assert ledger.snapshot("engagement-a")["used_actions"] == 1
