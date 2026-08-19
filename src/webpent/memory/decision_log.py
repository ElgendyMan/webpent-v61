# src/webpent/memory/decision_log.py
"""webpent.memory.decision_log

V7 Cognitive Upgrade — Phase 6: Decision Log persistence.

Thread-safe SQLite manager for the Decision Log, following the exact
same pattern already established by:

  * :class:`webpent.memory.db.DatabaseManager` (findings), and
  * :class:`webpent.memory.lessons.LessonsManager` (lessons + hypotheses).

Per-write connections for file-backed databases, a single shared
connection for in-memory databases, writes serialised by a
:class:`threading.Lock`. The DDL uses ``CREATE TABLE IF NOT EXISTS``
so the manager is safe to call multiple times.

The Decision Log is **append-only** — there is no UPDATE or DELETE.
This is the audit-trail posture the plan calls for: a reviewer
reconstructing the engagement must see every decision the system
made, in order, with no after-the-fact edits. (Mirrors the
``evidence_hash`` / HMAC-signed-master-report-hash philosophy already
in the project.)
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from uuid import UUID

from webpent.models.decision_log import DecisionLogEntry, DecisionType

logger = logging.getLogger(__name__)

# Default location for the Decision Log database. Co-located with the
# findings DB (webpent.db) so a single backup captures the full audit
# trail. Can be overridden by passing an explicit ``database_url`` to
# :class:`DecisionLogManager`.
_DEFAULT_DECISION_LOG_DB_PATH = "./memory/global/decision_log.db"


# ---------------------------------------------------------------------------
# DDL — CREATE TABLE IF NOT EXISTS (safe to call multiple times).
# ---------------------------------------------------------------------------
_DECISION_LOG_DDL = """
CREATE TABLE IF NOT EXISTS decision_log (
    id                TEXT PRIMARY KEY,
    timestamp         TEXT NOT NULL,
    decision_type     TEXT NOT NULL,
    rule_fired        TEXT NOT NULL,
    llm_contribution  TEXT NOT NULL DEFAULT '',
    outcome           TEXT NOT NULL DEFAULT '',
    entity_refs       TEXT NOT NULL DEFAULT '[]',
    branch_id         TEXT,
    metadata          TEXT NOT NULL DEFAULT '{}'
);
"""

_DECISION_LOG_INSERT = """
INSERT INTO decision_log (
    id, timestamp, decision_type, rule_fired, llm_contribution,
    outcome, entity_refs, branch_id, metadata
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

_DECISION_LOG_SELECT = """
SELECT id, timestamp, decision_type, rule_fired, llm_contribution,
       outcome, entity_refs, branch_id, metadata
FROM decision_log
ORDER BY timestamp ASC;
"""

_DECISION_LOG_SELECT_BY_BRANCH = """
SELECT id, timestamp, decision_type, rule_fired, llm_contribution,
       outcome, entity_refs, branch_id, metadata
FROM decision_log
WHERE branch_id = ?
ORDER BY timestamp ASC;
"""

_DECISION_LOG_SELECT_BY_TYPE = """
SELECT id, timestamp, decision_type, rule_fired, llm_contribution,
       outcome, entity_refs, branch_id, metadata
FROM decision_log
WHERE decision_type = ?
ORDER BY timestamp ASC;
"""


def _resolve_db_path(database_url: str | None) -> Path:
    """Resolve a database URL or path to a :class:`Path`.

    V9 FIX B-04: Anchor relative paths to project root (same fix as
    db.py:66-69 and lessons.py) so different worker CWDs don't write
    to different files.
    """
    if database_url is None:
        p = Path(_DEFAULT_DECISION_LOG_DB_PATH)
        if not p.is_absolute():
            root = Path(__file__).resolve()
            for parent in root.parents:
                if (parent / "pyproject.toml").exists():
                    return parent / p
        return p

    if database_url == "sqlite://":
        return Path(":memory:")

    prefix = "sqlite:///"
    if database_url.startswith(prefix):
        return Path(database_url[len(prefix):])

    return Path(database_url)


class DecisionLogManager:
    """Thread-safe SQLite manager for the Decision Log.

    Follows the exact same pattern as :class:`LessonsManager`:
    per-operation connections for file-backed databases, a single
    shared connection for in-memory databases, writes serialised by a
    :class:`threading.Lock`.

    The Decision Log is **append-only** — there is no UPDATE or DELETE.
    """

    def __init__(self, database_url: str | None = None) -> None:
        """Initialise the manager.

        Args:
            database_url: Optional override for the database URL. When
                ``None`` (default), the V7 default path
                (``./memory/global/decision_log.db``) is used.
        """
        self._database_url = database_url
        self._write_lock = threading.Lock()
        self._initialised = False
        self._memory_conn: sqlite3.Connection | None = None

    # -- Connection management ----------------------------------------------
    def _db_path(self) -> Path:
        url = self._database_url or _DEFAULT_DECISION_LOG_DB_PATH
        return _resolve_db_path(url)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open a short-lived connection (file mode) or yield the shared
        persistent connection (in-memory mode).
        """
        path = self._db_path()

        if str(path) == ":memory:":
            if self._memory_conn is None:
                self._memory_conn = sqlite3.connect(
                    ":memory:",
                    isolation_level="",
                    check_same_thread=False,
                    timeout=30.0,
                )
                self._memory_conn.row_factory = sqlite3.Row
            try:
                yield self._memory_conn
            finally:
                # Intentionally do NOT close — connection is reused.
                pass
            return

        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(
            str(path),
            isolation_level="",
            check_same_thread=False,
            timeout=30.0,
        )
        conn.row_factory = sqlite3.Row
        # V9 FIX B-08: Enable WAL + busy_timeout (same as db.py:218-222).
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=30000")
        except sqlite3.OperationalError:
            pass
        try:
            yield conn
        finally:
            conn.close()

    # -- Schema -------------------------------------------------------------
    def init_db(self) -> None:
        """Create the ``decision_log`` table if absent.

        Safe to call multiple times. The schema flag prevents redundant
        DDL round-trips within a single manager instance.
        """
        if self._initialised:
            return
        with self._write_lock:
            if self._initialised:
                return
            with self._connect() as conn:
                conn.execute(_DECISION_LOG_DDL)
                conn.commit()
            self._initialised = True

    # -- Append-only writes -------------------------------------------------
    def append(self, entry: DecisionLogEntry) -> UUID:
        """Append a single Decision Log entry.

        The Decision Log is append-only — there is no UPDATE or DELETE.
        This is the audit-trail posture: a reviewer reconstructing the
        engagement must see every decision the system made, in order,
        with no after-the-fact edits.

        Args:
            entry: A populated :class:`DecisionLogEntry` instance.

        Returns:
            The entry's UUID.
        """
        self.init_db()
        # Normalise enum values for SQLite (defensive — handles both
        # enum members and post-checkpoint plain strings).
        dt_value = (
            entry.decision_type.value
            if hasattr(entry.decision_type, "value")
            else str(entry.decision_type)
        )
        with self._write_lock, self._connect() as conn:
            conn.execute(
                _DECISION_LOG_INSERT,
                (
                    str(entry.id),
                    entry.timestamp.isoformat()
                    if hasattr(entry.timestamp, "isoformat")
                    else str(entry.timestamp),
                    dt_value,
                    entry.rule_fired,
                    entry.llm_contribution or "",
                    entry.outcome or "",
                    json.dumps(list(entry.entity_refs or [])),
                    entry.branch_id,
                    json.dumps(entry.metadata or {}),
                ),
            )
            conn.commit()
        return entry.id

    # -- Reads --------------------------------------------------------------
    def get_all_entries(self) -> list[dict]:
        """Return every Decision Log entry, ordered by timestamp.

        Returns:
            A list of dicts with keys: ``id``, ``timestamp``,
            ``decision_type``, ``rule_fired``, ``llm_contribution``,
            ``outcome``, ``entity_refs`` (parsed JSON list),
            ``branch_id``, ``metadata`` (parsed JSON dict).
        """
        self.init_db()
        with self._connect() as conn:
            cursor = conn.execute(_DECISION_LOG_SELECT)
            rows = cursor.fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_entries_by_branch(self, branch_id: str) -> list[dict]:
        """Return all entries for a specific Rabbit Hole branch."""
        self.init_db()
        with self._connect() as conn:
            cursor = conn.execute(_DECISION_LOG_SELECT_BY_BRANCH, (branch_id,))
            rows = cursor.fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_entries_by_type(self, decision_type: str) -> list[dict]:
        """Return all entries of a specific decision type."""
        self.init_db()
        with self._connect() as conn:
            cursor = conn.execute(_DECISION_LOG_SELECT_BY_TYPE, (decision_type,))
            rows = cursor.fetchall()
        return [self._row_to_dict(row) for row in rows]

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        """Convert a DB row into a dict, parsing JSON columns."""
        d = dict(row)
        # Parse entity_refs JSON back to a list.
        raw_refs = d.get("entity_refs") or "[]"
        try:
            d["entity_refs"] = json.loads(raw_refs)
        except (ValueError, TypeError):
            d["entity_refs"] = []
        # Parse metadata JSON back to a dict.
        raw_meta = d.get("metadata") or "{}"
        try:
            d["metadata"] = json.loads(raw_meta)
        except (ValueError, TypeError):
            d["metadata"] = {}
        return d


# ---------------------------------------------------------------------------
# Process-wide singleton — mirrors the LessonsManager / DatabaseManager pattern.
# ---------------------------------------------------------------------------
_singleton: DecisionLogManager | None = None
_singleton_lock = threading.Lock()


def get_decision_log_manager(database_url: str | None = None) -> DecisionLogManager:
    """Return the process-wide :class:`DecisionLogManager` singleton.

    Mirrors :func:`webpent.memory.lessons.get_lessons_manager` /
    :func:`webpent.memory.db.get_db_manager` — a single shared manager
    per process so the schema-init flag and in-memory connection are
    reused across calls.
    """
    global _singleton
    if _singleton is None:
        with _singleton_lock:
            if _singleton is None:
                _singleton = DecisionLogManager(database_url=database_url)
    return _singleton


# ---------------------------------------------------------------------------
# Convenience helper — append a Decision Log entry from raw fields.
# ---------------------------------------------------------------------------
def log_decision(
    *,
    decision_type: DecisionType | str,
    rule_fired: str,
    outcome: str = "",
    llm_contribution: str = "",
    entity_refs: list[str] | None = None,
    branch_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    manager: DecisionLogManager | None = None,
) -> UUID:
    """Append a Decision Log entry from raw fields.

    Convenience helper that constructs a :class:`DecisionLogEntry` and
    appends it via the singleton manager (or an explicitly-supplied
    manager). This is the function Phase 3 / Phase 5 / Phase 7 callers
    use — they don't need to import the Pydantic model or the manager
    class directly.

    Args:
        decision_type: The :class:`DecisionType` (or its string value).
        rule_fired: The deterministic rule that fired.
        outcome: The outcome of the decision.
        llm_contribution: The LLM's contribution, kept separate from
            ``rule_fired``. Empty when no LLM was consulted.
        entity_refs: References to involved Hypothesis/Finding/MentalModel
            entities (UUIDs as strings).
        branch_id: Optional Rabbit Hole branch ID.
        metadata: Free-form dict for decision-type-specific extras.
        manager: Optional explicit manager. Defaults to the singleton.

    Returns:
        The new entry's UUID.
    """

    entry = DecisionLogEntry(
        decision_type=decision_type,
        rule_fired=rule_fired,
        outcome=outcome,
        llm_contribution=llm_contribution,
        entity_refs=list(entity_refs or []),
        branch_id=branch_id,
        metadata=dict(metadata or {}),
    )
    mgr = manager or get_decision_log_manager()
    return mgr.append(entry)
