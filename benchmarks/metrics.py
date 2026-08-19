"""Deterministic benchmark metrics for evidence-gated findings."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class BenchmarkMetrics:
    """Precision/recall metrics over canonical expected and observed keys."""

    true_positives: int
    false_positives: int
    false_negatives: int

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * self.precision * self.recall / (self.precision + self.recall)

    def as_dict(self) -> dict[str, Any]:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 6),
            "recall": round(self.recall, 6),
            "f1": round(self.f1, 6),
        }


def finding_key(item: Mapping[str, Any]) -> str:
    """Return a stable benchmark key without using title text as identity."""
    return str(item.get("key") or item.get("finding_key") or item.get("id") or "").strip()


def is_confirmed_with_required_controls(item: Mapping[str, Any]) -> bool:
    """Accept only an explicit confirmed finding with all evidence gates closed."""
    status = str(item.get("status") or item.get("confidence_level") or "").lower()
    return (
        status in {"confirmed", "tool-confirmed"}
        and bool(item.get("causal_signal"))
        and bool(item.get("negative_control_complete"))
        and bool(item.get("proof_bundle_sealed"))
    )


def compute_metrics(
    expected: Iterable[Mapping[str, Any]],
    observed: Iterable[Mapping[str, Any]],
    *,
    confirmed_only: bool = True,
) -> BenchmarkMetrics:
    """Compute set metrics over stable keys; duplicates do not inflate recall."""
    expected_keys = {finding_key(item) for item in expected if finding_key(item)}
    observed_keys = {
        finding_key(item)
        for item in observed
        if finding_key(item)
        and (not confirmed_only or is_confirmed_with_required_controls(item))
    }
    return BenchmarkMetrics(
        true_positives=len(expected_keys & observed_keys),
        false_positives=len(observed_keys - expected_keys),
        false_negatives=len(expected_keys - observed_keys),
    )


__all__ = [
    "BenchmarkMetrics",
    "compute_metrics",
    "finding_key",
    "is_confirmed_with_required_controls",
]
