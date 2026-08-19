"""Adapters and fail-closed decision utilities for bounded research planning.

This module intentionally sits above the existing campaign executor. It ranks
validated proposals only; it never performs I/O, authorizes a request, or
promotes a finding.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from webpent.models.research import CandidateAction, ResearchContext
from webpent.shared.research_intelligence import InformationAction


@dataclass(frozen=True)
class ResearchDecision:
    """Explainable score for one validated candidate action."""

    candidate: CandidateAction
    score: float
    reasons: tuple[str, ...] = ()
    status: str = "ranked"

    def as_dict(self) -> dict[str, Any]:
        return {
            "candidate": self.candidate.as_dict(),
            "score": self.score,
            "reasons": list(self.reasons),
            "status": self.status,
        }


def candidate_from_information_action(
    action: InformationAction,
    *,
    gap_id: str = "",
    hypothesis_id: str = "",
    likelihood: float = 0.5,
    impact: float = 0.5,
    evidence_potential: float = 0.5,
    novelty: float = 0.5,
    coverage_value: float = 0.5,
) -> CandidateAction:
    """Convert the legacy dataclass proposal into the new validated contract."""
    return CandidateAction(
        action_id=action.action_id,
        action_class=action.action_class.value,
        objective=action.objective,
        target_ref=action.target_ref,
        method=action.method,
        gap_id=gap_id,
        hypothesis_id=hypothesis_id,
        identity_context=action.identity_context,
        tenant_context=action.tenant_context,
        workflow_state=action.workflow_state,
        expected_information_gain=action.expected_information_gain,
        likelihood=likelihood,
        impact=impact,
        evidence_potential=evidence_potential,
        novelty=novelty,
        coverage_value=coverage_value,
        cost=action.cost,
        failure_probability=action.failure_probability,
        scope_risk=action.scope_risk,
        rate_limit_cost=action.rate_limit_cost,
        dependency_penalty=action.dependency_penalty,
        capability=action.capability,
        required_capabilities=[action.capability] if action.capability else [],
        requires_approval=action.requires_approval,
        idempotency_key=action.idempotency_key,
        justification=action.justification,
        metadata=dict(action.metadata),
    )


def research_context_from_state(state: Mapping[str, Any]) -> ResearchContext:
    """Return a checkpoint-safe context without mutating LangGraph state."""
    return ResearchContext.from_state(dict(state))


class ResearchDecisionEngine:
    """Rank candidates with hard safety gates before utility scoring.

    The utility is the product of bounded likelihood, impact, evidence
    potential, information gain, novelty, and coverage value divided by
    bounded cost/risk terms. Missing capability, explicit scope mismatch, and
    exhausted budget are hard stops, not low scores.
    """

    def __init__(
        self,
        *,
        duplicate_penalty: float = 0.05,
        failed_path_penalty: float = 0.15,
    ) -> None:
        self.duplicate_penalty = max(0.0, min(1.0, float(duplicate_penalty)))
        self.failed_path_penalty = max(0.0, min(1.0, float(failed_path_penalty)))

    @staticmethod
    def _bounded(value: Any, default: float = 0.0) -> float:
        try:
            return max(0.0, min(1.0, float(value)))
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _capability_names(capabilities: Mapping[str, Any] | Iterable[str]) -> set[str]:
        if isinstance(capabilities, Mapping):
            return {
                str(name)
                for name, record in capabilities.items()
                if isinstance(record, Mapping) and record.get("available") is True
            }
        return {str(item) for item in capabilities}

    def score(
        self,
        candidate: CandidateAction,
        *,
        available_capabilities: Mapping[str, Any] | Iterable[str] = (),
        attempted_fingerprints: Iterable[str] = (),
        failed_path_fingerprints: Iterable[str] = (),
        new_evidence: bool = False,
        revisit_authorized: bool = False,
        budget_remaining: float | None = None,
        target_allowed: bool | None = None,
    ) -> ResearchDecision:
        reasons: list[str] = []
        available = self._capability_names(available_capabilities)
        required = {str(item) for item in candidate.required_capabilities if str(item)}
        missing = sorted(required - available) if required else []
        if missing:
            return ResearchDecision(
                candidate=candidate,
                score=-1.0,
                reasons=("missing_capability:" + ",".join(missing),),
                status="blocked",
            )
        if target_allowed is False:
            return ResearchDecision(
                candidate=candidate,
                score=-1.0,
                reasons=("target_scope_denied",),
                status="blocked",
            )
        if budget_remaining is not None and candidate.cost > max(0.0, float(budget_remaining)):
            return ResearchDecision(
                candidate=candidate,
                score=-1.0,
                reasons=("budget_exhausted",),
                status="blocked",
            )

        values = (
            self._bounded(candidate.likelihood, 0.5),
            self._bounded(candidate.impact, 0.5),
            self._bounded(candidate.evidence_potential, 0.5),
            self._bounded(candidate.expected_information_gain),
            self._bounded(candidate.novelty, 0.5),
            self._bounded(candidate.coverage_value, 0.5),
        )
        numerator = 1.0
        for value in values:
            numerator *= max(0.01, value)
        denominator = max(0.05, candidate.cost)
        denominator *= 1.0 + self._bounded(candidate.failure_probability)
        denominator *= 1.0 + self._bounded(candidate.scope_risk)
        denominator *= 1.0 + self._bounded(candidate.rate_limit_cost)
        denominator *= 1.0 + self._bounded(candidate.dependency_penalty)
        score = numerator / max(0.01, denominator)

        attempted = {str(item) for item in attempted_fingerprints}
        failed = {str(item) for item in failed_path_fingerprints}
        fingerprint = candidate.fingerprint()
        if fingerprint in attempted and not new_evidence:
            score *= self.duplicate_penalty
            reasons.append("duplicate_without_new_evidence_penalty")
        if fingerprint in failed and not (new_evidence or revisit_authorized):
            score *= self.failed_path_penalty
            reasons.append("failed_path_revisit_penalty")
        if candidate.requires_approval:
            reasons.append("approval_boundary_required")
        if candidate.expected_information_gain >= 0.7:
            reasons.append("high_information_gain")
        if candidate.coverage_value >= 0.7:
            reasons.append("coverage_gap_value")
        if target_allowed is True:
            reasons.append("explicit_scope_match")
        return ResearchDecision(candidate=candidate, score=round(score, 8), reasons=tuple(reasons))

    def rank(self, candidates: Sequence[CandidateAction], **kwargs: Any) -> list[ResearchDecision]:
        return sorted(
            (self.score(candidate, **kwargs) for candidate in candidates),
            key=lambda item: (-item.score, item.candidate.action_id),
        )


__all__ = [
    "ResearchDecision",
    "ResearchDecisionEngine",
    "candidate_from_information_action",
    "research_context_from_state",
]
