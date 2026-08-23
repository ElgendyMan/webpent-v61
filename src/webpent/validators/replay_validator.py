"""Deterministic replay validation for ProofBundle artifacts."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from webpent.models.proof_bundle import ProofBundle


def validate_replay(
    value: ProofBundle | dict[str, Any],
    evidence_payloads: list[Any] | tuple[Any, ...],
    negative_control: Any = None,
    *,
    replay_context: Mapping[str, Any] | None = None,
) -> bool:
    """Replay supplied evidence against a validated ProofBundle and optional binding."""
    try:
        bundle = value if isinstance(value, ProofBundle) else ProofBundle.model_validate(value)
        return bundle.replay(
            evidence_payloads,
            negative_control,
            replay_context=replay_context,
        )
    except Exception:
        return False
