"""Bounded experiment records for the hypothesis research loop."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class ExperimentManager:
    """Create redacted, deterministic-enough experiment records in memory."""

    MAX_RECORDS = 200

    def __init__(self) -> None:
        self._records: list[dict[str, Any]] = []

    def record(self, hypothesis_id: str, observation: dict[str, Any]) -> dict[str, Any]:
        """Store only bounded evidence metadata; never store raw requests or secrets."""
        safe_refs = observation.get("evidence_refs") or []
        if not isinstance(safe_refs, (list, tuple, set)):
            safe_refs = []
        record = {
            "hypothesis_id": str(hypothesis_id)[:120],
            "outcome": str(observation.get("outcome") or "inconclusive")[:40],
            "causal_signal": observation.get("causal_signal") is True,
            "negative_control_complete": observation.get("negative_control_complete") is True,
            "evidence_refs": [str(ref)[:240] for ref in safe_refs if str(ref).strip()][:50],
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        self._records.append(record)
        del self._records[:-self.MAX_RECORDS]
        return dict(record)

    def records(self) -> list[dict[str, Any]]:
        """Return a defensive copy suitable for state or reporting."""
        return [dict(record) for record in self._records]
