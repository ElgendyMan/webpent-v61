"""Isolated, advisory security reasoning memory.

This store is deliberately scoped to one engagement and target.  It stores only
redacted reasoning summaries and evidence references; it cannot execute a
request or promote a finding.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

from webpent.models.evidence import redact_sensitive
from webpent.models.memory import MemoryBudget, MemoryKind, MemoryRecord
from webpent.shared.memory_boundary import MemoryBoundary


class SecurityReasoningMemory:
    """A deterministic target-isolated facade over the existing memory boundary."""

    def __init__(
        self,
        *,
        engagement_id: str,
        target_id: str,
        budget: MemoryBudget | None = None,
    ) -> None:
        if not engagement_id.strip() or not target_id.strip():
            raise ValueError("engagement_and_target_scope_required")
        self.engagement_id = engagement_id.strip()
        self.target_id = target_id.strip()
        self.scope = f"{self.engagement_id}:{self.target_id}"
        self._boundary = MemoryBoundary(engagement_scope=self.scope, budget=budget)

    @property
    def records(self) -> tuple[MemoryRecord, ...]:
        return self._boundary.records

    @property
    def feedback_records(self):
        return self._boundary.feedback

    def remember(
        self,
        *,
        category: MemoryKind | str,
        content: str,
        source_ref: str = "",
        evidence_refs: Iterable[str] = (),
        relevance: float = 0.0,
        metadata: dict[str, object] | None = None,
    ) -> MemoryRecord | None:
        """Write a bounded record with a stable ID and mandatory target scope."""
        kind = category if isinstance(category, MemoryKind) else MemoryKind(str(category))
        clean_content, _ = redact_sensitive(content)
        clean_source, _ = redact_sensitive(source_ref)
        refs = tuple(redact_sensitive(str(ref))[0] for ref in evidence_refs if str(ref).strip())[
            :20
        ]
        digest = hashlib.sha256(
            f"{self.scope}|{kind.value}|{clean_content}|{clean_source}|{','.join(refs)}".encode()
        ).hexdigest()[:24]
        record = MemoryRecord(
            id=f"security-memory:{digest}",
            kind=kind,
            content=clean_content,
            target_scope=self.scope,
            provenance={
                "source": "security_reasoning",
                "source_ref": clean_source,
                "relevance": relevance,
                "evidence_refs": list(refs),
            },
            metadata=metadata or {},
        )
        return record if self._boundary.add(record) else None

    def retrieve(
        self,
        query: str,
        *,
        kinds: list[MemoryKind] | None = None,
        limit: int | None = None,
    ):
        """Return advisory memories already filtered to this exact scope."""
        return self._boundary.retrieve(query, kinds=kinds, limit=limit)

    def record_feedback(self, memory_id: str, status: str, *, note: str = ""):
        return self._boundary.record_feedback(
            memory_id, status, reviewer="ai_technical_review", note=note
        )

    def summary(self) -> dict[str, object]:
        return {
            **self._boundary.summary(),
            "engagement_id": self.engagement_id,
            "target_id": self.target_id,
            "isolated": True,
            "authoritative": False,
            "execution_capability": False,
        }


__all__ = ["SecurityReasoningMemory"]
