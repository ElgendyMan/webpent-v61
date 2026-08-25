from __future__ import annotations

import multiprocessing as mp
from pathlib import Path

from webpent.shared.action_ledger import SQLiteActionLedger

_PAYLOAD = {
    "idempotency_key": "same-key",
    "engagement_id": "eng-1",
    "task_id": "task-1",
    "target_origin": "http://127.0.0.1:8000",
    "method": "GET",
    "action_family": "harmless-local-probe",
    "identity_ref": "lab-identity",
    "tenant_context": "lab",
    "vulnerability_class": "contract-test",
    "validator_id": "local-ledger",
    "estimated_cost": 1.0,
    "max_actions": 10,
    "max_budget": 10.0,
}


def _reserve(path: str, queue: mp.Queue) -> None:
    result = SQLiteActionLedger(path).reserve(**_PAYLOAD)
    queue.put((result.allowed, result.reason))


def test_cross_process_reservation_is_single_winner(tmp_path: Path) -> None:
    path = str(tmp_path / "ledger.sqlite3")
    queue: mp.Queue = mp.Queue()
    context = mp.get_context("fork")
    processes = [context.Process(target=_reserve, args=(path, queue)) for _ in range(2)]
    for process in processes:
        process.start()
    for process in processes:
        process.join(10)
        assert process.exitcode == 0

    results = [queue.get(timeout=2) for _ in processes]
    assert sum(allowed for allowed, _ in results) == 1
    assert sum(reason == "idempotency:duplicate_reservation" for _, reason in results) == 1

    ledger = SQLiteActionLedger(path)
    assert ledger.complete("eng-1", "same-key", status="executed")
    assert not ledger.complete("eng-1", "same-key", status="executed")
    assert ledger.snapshot("eng-1")["used_actions"] == 1
