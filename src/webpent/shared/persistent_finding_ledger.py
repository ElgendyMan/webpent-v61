"""Release-to-release cumulative finding history.

This store is intentionally separate from the per-run findings table.  A new
WebPent checkout or code revision must not erase the authoritative history for
the same authorized engagement.  The ledger stores redacted Finding snapshots,
release provenance, and a deterministic logical fingerprint; it never stores
raw credentials, cookies, OOB tokens, or authorization headers.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webpent.models.findings import Finding
from webpent.shared.finding_aggregation import aggregate_findings, finding_fingerprint

_SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "oob_token",
    "canary_token",
}


DDL = """
CREATE TABLE IF NOT EXISTS cumulative_findings (
    fingerprint TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    finding_json TEXT NOT NULL,
    release_id TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    source_threads TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (engagement_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS ix_cumulative_findings_engagement
    ON cumulative_findings(engagement_id);
"""


def _default_path() -> Path:
    configured = os.getenv("WEBPENT_FINDINGS_LEDGER_PATH", "~/.webpent/findings_ledger.sqlite3")
    return Path(configured).expanduser()


def current_release_id() -> str:
    """Return a stable operator-visible release identifier for this checkout."""
    explicit = os.getenv("WEBPENT_RELEASE_ID") or os.getenv("WEBPENT_BUILD_ID")
    if explicit:
        return explicit.strip()[:128] or "unknown-release"
    try:
        from importlib.metadata import version

        return f"webpent-{version('webpent')}"
    except Exception:
        return "webpent-dev"


def _redact(value: Any, key: str = "") -> Any:
    normalized_key = key.lower().replace("-", "_")
    if normalized_key in _SENSITIVE_KEYS or normalized_key.endswith("_token"):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item, key) for item in value]
    return value


def _safe_finding_json(finding: Finding) -> str:
    data = _redact(finding.model_dump(mode="json"))
    return json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _finding_from_json(raw: str) -> Finding | None:
    try:
        return Finding.model_validate(json.loads(raw))
    except Exception:
        return None


class PersistentFindingLedger:
    """Append/merge store that survives WebPent code revisions."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path).expanduser() if path else _default_path()
        self._lock = threading.Lock()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self.path), timeout=30.0)
        connection.row_factory = sqlite3.Row
        try:
            connection.executescript(DDL)
            yield connection
            connection.commit()
        finally:
            connection.close()

    def merge(
        self,
        engagement_id: str,
        findings: list[Finding],
        *,
        release_id: str | None = None,
        thread_id: str | None = None,
    ) -> list[Finding]:
        """Merge current findings into history and return the full projection."""
        scope = engagement_id.strip()
        if not scope:
            raise ValueError("engagement_id must not be empty")
        release = (release_id or current_release_id()).strip()[:128] or "unknown-release"
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as connection:
            for finding in findings:
                fingerprint = finding_fingerprint(finding)
                existing = connection.execute(
                    "SELECT finding_json, source_threads FROM cumulative_findings "
                    "WHERE engagement_id = ? AND fingerprint = ?",
                    (scope, fingerprint),
                ).fetchone()
                candidate = finding
                if existing:
                    previous = _finding_from_json(str(existing["finding_json"]))
                    if previous is not None:
                        candidate = aggregate_findings([previous, finding])[0]
                sources = []
                if existing:
                    try:
                        sources = list(json.loads(existing["source_threads"]))
                    except Exception:
                        sources = []
                if thread_id and thread_id not in sources:
                    sources.append(thread_id)
                if not sources and candidate.thread_id:
                    sources.append(candidate.thread_id)
                connection.execute(
                    """INSERT INTO cumulative_findings
                    (fingerprint, engagement_id, finding_json, release_id,
                     first_seen_at, last_seen_at, source_threads)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(engagement_id, fingerprint) DO UPDATE SET
                      finding_json = excluded.finding_json,
                      release_id = excluded.release_id,
                      last_seen_at = excluded.last_seen_at,
                      source_threads = excluded.source_threads
                    """,
                    (
                        fingerprint,
                        scope,
                        _safe_finding_json(candidate),
                        release,
                        now if not existing else str(
                            connection.execute(
                                "SELECT first_seen_at FROM cumulative_findings "
                                "WHERE engagement_id = ? AND fingerprint = ?",
                                (scope, fingerprint),
                            ).fetchone()["first_seen_at"]
                        ),
                        now,
                        json.dumps(sources, ensure_ascii=True),
                    ),
                )
            return self._read_locked(connection, scope)

    def get(self, engagement_id: str) -> list[Finding]:
        scope = engagement_id.strip()
        if not scope:
            return []
        with self._lock, self._connect() as connection:
            return self._read_locked(connection, scope)

    def _read_locked(self, connection: sqlite3.Connection, engagement_id: str) -> list[Finding]:
        rows = connection.execute(
            "SELECT finding_json FROM cumulative_findings WHERE engagement_id = ? "
            "ORDER BY first_seen_at ASC",
            (engagement_id,),
        ).fetchall()
        findings = [item for row in rows if (item := _finding_from_json(str(row[0]))) is not None]
        return aggregate_findings(findings)

    def export_digest(self, engagement_id: str) -> str:
        """Return a deterministic digest for audit/report comparisons."""
        findings = self.get(engagement_id)
        payload = json.dumps(
            [_safe_finding_json(finding) for finding in findings],
            ensure_ascii=True,
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
