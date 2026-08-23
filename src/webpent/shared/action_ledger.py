"""Durable action reservations for bounded campaign execution.

The ledger is intentionally transport-agnostic.  It records only redacted action
metadata and reservation state; request bodies, cookies, and response content
must never be persisted here.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class LedgerReservation:
    """Result of an atomic action reservation attempt."""

    allowed: bool
    reason: str = ""
    used_actions: int = 0
    used_budget: float = 0.0


class SQLiteActionLedger:
    """SQLite-backed reservation ledger safe across worker restarts."""

    _TERMINAL_STATUSES = frozenset({"executed", "failed"})

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS action_ledger (
                    idempotency_key TEXT NOT NULL,
                    engagement_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    target_origin TEXT NOT NULL,
                    method TEXT NOT NULL,
                    action_family TEXT NOT NULL,
                    identity_ref TEXT NOT NULL,
                    tenant_context TEXT NOT NULL,
                    vulnerability_class TEXT NOT NULL,
                    validator_id TEXT NOT NULL,
                    estimated_cost REAL NOT NULL,
                    status TEXT NOT NULL,
                    reserved_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    output_digest TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (engagement_id, idempotency_key)
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_action_ledger_engagement
                ON action_ledger (engagement_id, status)
                """
            )

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()

    def reserve(
        self,
        *,
        idempotency_key: str,
        engagement_id: str,
        task_id: str,
        target_origin: str,
        method: str,
        action_family: str,
        identity_ref: str,
        tenant_context: str,
        vulnerability_class: str,
        validator_id: str,
        estimated_cost: float,
        max_actions: int,
        max_budget: float,
    ) -> LedgerReservation:
        """Atomically reserve one action or return a deterministic denial."""
        key = str(idempotency_key or "").strip()
        if not key:
            return LedgerReservation(False, "idempotency:key_required")
        if not engagement_id.strip():
            return LedgerReservation(False, "identity:engagement_required")
        if estimated_cost <= 0 or estimated_cost > max_budget:
            return LedgerReservation(False, "budget:invalid_or_over_engagement_limit")

        now = self._now()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT status FROM action_ledger
                WHERE engagement_id = ? AND idempotency_key = ?
                """,
                (engagement_id, key),
            ).fetchone()
            if existing is not None:
                used = connection.execute(
                    """
                    SELECT COUNT(*) AS actions, COALESCE(SUM(estimated_cost), 0.0) AS budget
                    FROM action_ledger
                    WHERE engagement_id = ? AND status IN ('reserved', 'executed')
                    """,
                    (engagement_id,),
                ).fetchone()
                connection.rollback()
                return LedgerReservation(
                    False,
                    "idempotency:duplicate_reservation",
                    int(used["actions"]),
                    float(used["budget"]),
                )

            used = connection.execute(
                """
                SELECT COUNT(*) AS actions, COALESCE(SUM(estimated_cost), 0.0) AS budget
                FROM action_ledger
                WHERE engagement_id = ? AND status IN ('reserved', 'executed')
                """,
                (engagement_id,),
            ).fetchone()
            used_actions = int(used["actions"])
            used_budget = float(used["budget"])
            if used_actions >= max_actions:
                connection.rollback()
                return LedgerReservation(
                    False, "budget:max_actions_exhausted", used_actions, used_budget
                )
            if used_budget + estimated_cost > max_budget:
                connection.rollback()
                return LedgerReservation(
                    False, "budget:action_budget_exhausted", used_actions, used_budget
                )

            connection.execute(
                """
                INSERT INTO action_ledger (
                    idempotency_key, engagement_id, task_id, target_origin, method,
                    action_family, identity_ref, tenant_context, vulnerability_class,
                    validator_id, estimated_cost, status, reserved_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?)
                """,
                (
                    key,
                    engagement_id[:128],
                    task_id[:128],
                    target_origin[:256],
                    method.upper()[:16],
                    action_family[:64],
                    identity_ref[:128],
                    tenant_context[:128],
                    vulnerability_class[:128],
                    validator_id[:128],
                    float(estimated_cost),
                    now,
                    now,
                ),
            )
            connection.commit()
            return LedgerReservation(True, "", used_actions + 1, used_budget + estimated_cost)
        except sqlite3.Error:
            connection.rollback()
            return LedgerReservation(False, "ledger:reservation_failure")
        finally:
            connection.close()

    def complete(
        self,
        engagement_id: str,
        idempotency_key: str,
        *,
        status: str,
        output_digest: str = "",
    ) -> bool:
        """Mark a reservation terminal without persisting sensitive output."""
        if not str(idempotency_key or "").strip():
            return False
        if str(status or "").strip() not in self._TERMINAL_STATUSES:
            return False
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    """
                    UPDATE action_ledger
                    SET status = ?, updated_at = ?, output_digest = ?
                    WHERE engagement_id = ? AND idempotency_key = ? AND status = 'reserved'
                    """,
                    (
                        str(status)[:32],
                        self._now(),
                        str(output_digest)[:128],
                        engagement_id,
                        idempotency_key,
                    ),
                )
                return cursor.rowcount == 1
        except sqlite3.Error:
            return False

    def snapshot(self, engagement_id: str) -> dict[str, Any]:
        """Return redacted usage counters for operator diagnostics."""
        try:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT COUNT(*) AS actions, COALESCE(SUM(estimated_cost), 0.0) AS budget
                    FROM action_ledger
                    WHERE engagement_id = ? AND status IN ('reserved', 'executed')
                    """,
                    (engagement_id,),
                ).fetchone()
            return {
                "engagement_id": engagement_id[:128],
                "used_actions": int(row["actions"]),
                "used_budget": float(row["budget"]),
            }
        except sqlite3.Error:
            return {
                "engagement_id": engagement_id[:128],
                "used_actions": 0,
                "used_budget": 0.0,
                "error": "ledger_unavailable",
            }


__all__ = ["LedgerReservation", "SQLiteActionLedger"]
