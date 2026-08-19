"""Small state helpers for report-safe evidence ledger updates."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from webpent.models.evidence_ledger import EvidenceLedgerEntry


def _entry_model(value: EvidenceLedgerEntry | Mapping[str, Any]) -> EvidenceLedgerEntry:
    if isinstance(value, EvidenceLedgerEntry):
        return value
    return EvidenceLedgerEntry.model_validate(dict(value))


def merge_evidence_ledger(
    current: Iterable[EvidenceLedgerEntry | Mapping[str, Any]] = (),
    incoming: Iterable[EvidenceLedgerEntry | Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    """Merge entries by stable entry id and content digest, preserving order."""
    merged: list[EvidenceLedgerEntry] = []
    seen_ids: set[str] = set()
    seen_digests: set[str] = set()
    for raw in [*current, *incoming]:
        entry = _entry_model(raw)
        digest = entry.content_digest()
        if entry.entry_id in seen_ids or digest in seen_digests:
            continue
        seen_ids.add(entry.entry_id)
        seen_digests.add(digest)
        merged.append(entry)
    return [entry.model_dump(mode="json") for entry in merged]


__all__ = ["merge_evidence_ledger"]
