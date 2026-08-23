"""Adapters and fail-closed decision utilities for bounded research planning.

This module intentionally sits above the existing campaign executor. It ranks
validated proposals only; it never performs I/O, authorizes a request, or
promotes a finding.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from webpent.models.research import (
    CandidateAction,
    InformationObservation,
    ResearchContext,
    SurfaceCoverage,
)
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
        known_facts: Iterable[str] = (),
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
        known = {str(item).strip() for item in known_facts if str(item).strip()}
        missing_prerequisites = sorted(
            {
                str(item).strip()
                for item in candidate.prerequisites
                if str(item).strip() and str(item).strip() not in known
            }
        )
        if missing_prerequisites:
            return ResearchDecision(
                candidate=candidate,
                score=-1.0,
                reasons=("missing_prerequisite:" + ",".join(missing_prerequisites),),
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


@dataclass(frozen=True)
class ActiveResearchResult:
    """Safe output of one active step; no raw transport response is retained."""

    context: ResearchContext
    selected: ResearchDecision | None
    observation: InformationObservation
    coverage: SurfaceCoverage

    def as_dict(self) -> dict[str, Any]:
        return {
            "context": self.context.as_dict(),
            "selected": self.selected.as_dict() if self.selected else None,
            "observation": self.observation.model_dump(mode="json"),
            "coverage": self.coverage.as_dict(),
        }


class CoverageIntelligence:
    """Track bounded surface coverage and expose gaps for future planning."""

    def __init__(self, *, expected_action_classes: Iterable[str] = ()) -> None:
        self.expected_action_classes = {str(item) for item in expected_action_classes if str(item)}
        self._surfaces: dict[str, SurfaceCoverage] = {}

    def update(
        self,
        *,
        surface_id: str,
        target_ref: str,
        action: CandidateAction,
        observation: InformationObservation,
    ) -> SurfaceCoverage:
        current = self._surfaces.get(surface_id) or SurfaceCoverage(
            surface_id=surface_id,
            target_ref=target_ref,
            coverage_score=0.0,
        )
        attempted = list(dict.fromkeys([*current.attempted_action_ids, action.action_id]))[-100:]
        classes = list(dict.fromkeys([*current.covered_action_classes, action.action_class]))[-100:]
        positive = list(dict.fromkeys([*current.positive_observation_ids]))
        negative = list(dict.fromkeys([*current.negative_observation_ids]))
        inconclusive = list(dict.fromkeys([*current.inconclusive_observation_ids]))
        if observation.status == "positive":
            positive.append(observation.observation_id)
        elif observation.status == "negative":
            negative.append(observation.observation_id)
        else:
            inconclusive.append(observation.observation_id)
        expected = self.expected_action_classes or set(classes)
        coverage_score = len(set(classes) & expected) / max(1, len(expected))
        current = SurfaceCoverage(
            surface_id=surface_id,
            target_ref=target_ref,
            surface_type=current.surface_type,
            attempted_action_ids=attempted,
            covered_action_classes=classes,
            uncovered_action_classes=sorted(expected - set(classes)),
            positive_observation_ids=positive[-100:],
            negative_observation_ids=negative[-100:],
            inconclusive_observation_ids=inconclusive[-100:],
            coverage_score=coverage_score,
        )
        self._surfaces[surface_id] = current
        return current

    def snapshot(self) -> dict[str, dict[str, Any]]:
        return {key: value.as_dict() for key, value in self._surfaces.items()}


class ActiveResearchLoop:
    """Execute at most one policy-approved, injected research action per step."""

    def __init__(
        self,
        *,
        decision_engine: ResearchDecisionEngine | None = None,
        coverage: CoverageIntelligence | None = None,
        max_steps: int = 10,
    ) -> None:
        self.decision_engine = decision_engine or ResearchDecisionEngine()
        self.coverage = coverage or CoverageIntelligence()
        self.max_steps = max(1, min(100, int(max_steps)))

    @staticmethod
    def _blocked_observation(
        candidate: CandidateAction | None, reason: str
    ) -> InformationObservation:
        action_id = candidate.action_id if candidate else "action:none"
        fingerprint = candidate.fingerprint() if candidate else "0" * 32
        return InformationObservation(
            observation_id=f"observation:blocked:{fingerprint}",
            action_id=action_id,
            action_fingerprint=fingerprint,
            status="blocked",
            reason=reason,
            revisit_conditions=["explicit policy/capability/scope change"],
        )

    def step(
        self,
        context: ResearchContext,
        candidates: Sequence[CandidateAction],
        *,
        handler: Callable[[CandidateAction], Mapping[str, Any]] | None = None,
        available_capabilities: Mapping[str, Any] | Iterable[str] = (),
        target_allowed: bool | None = None,
        approved: bool = False,
        failed_path_fingerprints: Iterable[str] = (),
    ) -> ActiveResearchResult:
        """Select and optionally execute one action, requiring explicit scope."""
        if context.depth >= min(context.max_depth, self.max_steps):
            observation = self._blocked_observation(None, "research_depth_exhausted")
            return ActiveResearchResult(
                context, None, observation, SurfaceCoverage(surface_id="none")
            )
        if context.budget_remaining <= 0:
            observation = self._blocked_observation(None, "research_budget_exhausted")
            return ActiveResearchResult(
                context, None, observation, SurfaceCoverage(surface_id="none")
            )
        decisions = self.decision_engine.rank(
            candidates,
            available_capabilities=available_capabilities,
            attempted_fingerprints=context.attempted_action_fingerprints,
            failed_path_fingerprints=failed_path_fingerprints,
            budget_remaining=context.budget_remaining,
            target_allowed=target_allowed,
            known_facts=context.known_facts,
        )
        selected = next((item for item in decisions if item.status == "ranked"), None)
        if selected is None:
            observation = self._blocked_observation(None, "no_policy_approved_candidate")
            return ActiveResearchResult(
                context, None, observation, SurfaceCoverage(surface_id="none")
            )
        candidate = selected.candidate
        if target_allowed is not True:
            observation = self._blocked_observation(
                candidate, "target_scope_not_explicitly_allowed"
            )
        elif candidate.requires_approval and not approved:
            observation = self._blocked_observation(candidate, "human_approval_required")
        elif handler is None:
            observation = self._blocked_observation(candidate, "no_authorized_handler")
        else:
            try:
                raw = handler(candidate)
                observation = InformationObservation.model_validate(raw)
            except Exception as exc:  # handler boundary must fail closed
                observation = InformationObservation(
                    observation_id=f"observation:infrastructure:{candidate.fingerprint()}",
                    action_id=candidate.action_id,
                    action_fingerprint=candidate.fingerprint(),
                    status="infrastructure_failure",
                    reason=type(exc).__name__,
                    revisit_conditions=["repair handler and retry with fresh evidence"],
                )
        context.current_action_id = candidate.action_id
        context.attempted_action_fingerprints = list(
            dict.fromkeys([*context.attempted_action_fingerprints, candidate.fingerprint()])
        )[-200:]
        context.depth += 1
        context.budget_remaining = max(0.0, context.budget_remaining - candidate.cost)
        context.known_facts = list(
            dict.fromkeys([*context.known_facts, *observation.new_facts])
        )[-100:]
        coverage = self.coverage.update(
            surface_id=candidate.target_ref or candidate.action_id,
            target_ref=candidate.target_ref,
            action=candidate,
            observation=observation,
        )
        return ActiveResearchResult(context, selected, observation, coverage)


def active_research_node(
    state: Mapping[str, Any],
    *,
    handler: Callable[[CandidateAction], Mapping[str, Any]] | None = None,
    target_allowed: bool | None = None,
    approved: bool = False,
) -> dict[str, Any]:
    """Run one active research step under explicit scope and handler gates.

    The function is intentionally not auto-wired into legacy graph routes. A
    caller must inject an authorized handler and pass ``target_allowed=True``.
    """
    context = ResearchContext.from_state(dict(state))
    raw_candidates = state.get("research_candidate_actions") or []
    candidates: list[CandidateAction] = []
    for raw in raw_candidates[:100]:
        if not isinstance(raw, Mapping):
            continue
        try:
            candidate_payload = dict(raw)
            candidate_payload.pop("fingerprint", None)
            candidates.append(CandidateAction.model_validate(candidate_payload))
        except Exception:
            continue
    budget = state.get("action_budget") or {}
    if isinstance(budget, Mapping):
        context.budget_remaining = float(
            budget.get("research_budget_remaining", budget.get("remaining_cost", 0.0)) or 0.0
        )
    manifest = state.get("capability_manifest") or {}
    available = manifest.get("capabilities", {}) if isinstance(manifest, Mapping) else {}
    previous_coverage = state.get("surface_coverage") or {}
    coverage = CoverageIntelligence(
        expected_action_classes={candidate.action_class for candidate in candidates}
    )
    surfaces = (
        previous_coverage.get("surfaces", {})
        if isinstance(previous_coverage, Mapping)
        else {}
    )
    for surface_id, raw_surface in surfaces.items():
        if isinstance(raw_surface, Mapping):
            try:
                coverage._surfaces[str(surface_id)] = SurfaceCoverage.model_validate(raw_surface)
            except Exception:
                continue
    failed_paths = {
        str(item.get("action_fingerprint"))
        for item in state.get("research_failed_paths", [])
        if isinstance(item, Mapping) and item.get("action_fingerprint")
    }
    result = ActiveResearchLoop(coverage=coverage).step(
        context,
        candidates,
        handler=handler,
        available_capabilities=available,
        target_allowed=target_allowed,
        approved=approved,
        failed_path_fingerprints=failed_paths,
    )
    observation = result.observation.model_dump(mode="json")
    failed_update = []
    if observation["status"] in {"negative", "inconclusive", "infrastructure_failure"}:
        failed_update.append(
            {
                "action_id": observation["action_id"],
                "action_fingerprint": observation["action_fingerprint"],
                "status": observation["status"],
                "reason": observation["reason"],
                "revisit_conditions": observation["revisit_conditions"],
            }
        )
    return {
        "research_context": result.context.as_dict(),
        "research_active_observations": [observation],
        "surface_coverage": {
            "surfaces": {result.coverage.surface_id: result.coverage.as_dict()}
        },
        "research_failed_paths": failed_update,
    }


__all__ = [
    "ActiveResearchLoop",
    "active_research_node",
    "ActiveResearchResult",
    "CoverageIntelligence",
    "ResearchDecision",
    "ResearchDecisionEngine",
    "candidate_from_information_action",
    "research_context_from_state",
]
