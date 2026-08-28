"""Unified VABH-FQR v9 operating core; deterministic and advisory-only."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import (
    EvidenceDisposition,
    EvidenceRecordV9,
    LoopStage,
    LoopStepV9,
    ResearchExperimentPlanV9,
    ResearchMemorySnapshotV9,
    SecurityArchitectureMapV9,
    SecurityHypothesisV9,
    VABHFQRV9Result,
)


def _value(source: object | None, *names: str, default: object = None) -> object:
    for name in names:
        if isinstance(source, dict) and name in source:
            return source[name]
        if source is not None and hasattr(source, name):
            return getattr(source, name)
    return default


def _strings(value: object | None, limit: int = 12) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,) if value else ()
    try:
        return tuple(str(item) for item in value if str(item))[:limit]
    except TypeError:
        return (str(value),)


def _stable(*parts: object) -> str:
    import hashlib

    return hashlib.sha256("|".join(str(part) for part in parts).encode()).hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class VABHFQRV9Core:
    """Composition root for the v9 lifecycle; it never performs transport."""

    VERSION = "vabh-fqr-v9"

    def run(
        self,
        *,
        engagement_id: str,
        target_id: str,
        recorded_state: object | None = None,
        evidence_refs: tuple[str, ...] = (),
        previous_failures: tuple[str, ...] = (),
    ) -> VABHFQRV9Result:
        state = recorded_state
        assets = _strings(_value(state, "critical_assets", "assets"), 10)
        boundaries = _strings(
            _value(state, "threat_boundaries", "boundaries", "trust_boundaries"), 10
        )
        workflows = _strings(_value(state, "workflows", "user_journeys"), 10)
        assumptions = _strings(_value(state, "assumptions", "hidden_assumptions"), 12)
        invariants = _strings(_value(state, "invariants"), 10)
        privileges = _strings(_value(state, "privilege_model", "roles", "privileges"), 10)
        purpose = str(
            _value(state, "purpose", "business_purpose", default="recorded target research")
        )
        if not assets:
            assets = ("recorded critical asset",)
        if not boundaries:
            boundaries = ("recorded trust boundary",)
        if not workflows:
            workflows = ("recorded user workflow",)
        if not assumptions:
            assumptions = ("authorization and state assumptions require evidence",)
        architecture = SecurityArchitectureMapV9(
            map_id=f"arch-{_stable(engagement_id, target_id)}",
            purpose=purpose,
            critical_assets=assets,
            threat_boundaries=boundaries,
            privilege_model=privileges or ("recorded privilege model is incomplete",),
            workflows=workflows,
            invariants=invariants or ("intended behavior must be distinguished from weakness",),
            trust_relationships=_strings(_value(state, "trust_relationships"), 10)
            or ("trust relationship unverified",),
            assumptions=assumptions,
            source_refs=evidence_refs,
        )
        experiments = tuple(
            ResearchExperimentPlanV9(
                experiment_id=f"exp-{_stable(engagement_id, target_id, assumption)}",
                question=f"What recorded evidence would falsify assumption: {assumption}?",
                selected_action="offline evidence review and causal-oracle design",
                expected_information_gain=0.65,
                uncertainty_reduction=0.55,
                evidence_value=0.75,
                estimated_cost=0.10,
                risk=0.0,
                available_capability="recorded_state_only",
                preconditions=(
                    "recorded artifact exists",
                    "scope is local and authorized",
                    "no transport is permitted",
                ),
                success_criteria=(
                    "alternative explanations are documented",
                    "causal oracle requirements are explicit",
                ),
                stop_conditions=(
                    "missing observation",
                    "no causal oracle",
                    "scope or evidence uncertainty",
                ),
                source_refs=evidence_refs,
            )
            for assumption in assumptions[:6]
        )
        hypotheses = tuple(
            SecurityHypothesisV9(
                hypothesis_id=f"hyp-{_stable(engagement_id, target_id, assumption)}",
                origin="architecture-assumption-analysis",
                statement=(
                    f"The assumption may fail under a recorded state transition: {assumption}."
                ),
                reasoning_chain=(
                    f"assumption={assumption}",
                    "identify affected trust or authorization relationship",
                    "require causal observation and independent negative control",
                ),
                supporting_evidence=tuple(evidence_refs),
                conflicting_evidence=("no live causal observation is available",),
                confidence_history=(0.20,),
                next_validation_action="design safe offline validation criteria",
                source_refs=evidence_refs,
            )
            for assumption in assumptions[:6]
        )
        evidence = tuple(
            EvidenceRecordV9(
                evidence_id=f"ev-{_stable(hypothesis.hypothesis_id)}",
                subject_id=hypothesis.hypothesis_id,
                observation_refs=(),
                causal_oracle=(
                    "requires candidate/control observations and intended-behavior predicate"
                ),
                reproducibility_requirements=(
                    "sealed ProofBundle",
                    "replay verification",
                    "independent reviewer",
                ),
                proof_bundle_ref="",
                seal_verified=False,
                replay_verified=False,
                explanation="recorded reasoning only; no observation exists, so this is blocked",
                disposition=EvidenceDisposition.BLOCKED,
            )
            for hypothesis in hypotheses
        )
        steps = tuple(
            LoopStepV9(
                stage=stage,
                completed=stage
                in {LoopStage.OBSERVE, LoopStage.UNDERSTAND, LoopStage.REASON, LoopStage.PLAN},
                rationale=self._rationale(stage, previous_failures),
                inputs=(target_id,),
                outputs=(),
            )
            for stage in LoopStage
        )
        snapshot = ResearchMemorySnapshotV9(
            target_id=target_id,
            engagement_id=engagement_id,
            version=self.VERSION,
            lessons=("no causal claim without observations, oracle, sealed proof, and replay",),
            rejected_hypotheses=(),
            failed_experiments=previous_failures,
            state_digest=_stable(engagement_id, target_id, repr(state)),
        )
        return VABHFQRV9Result(
            engagement_id=engagement_id,
            target_id=target_id,
            architecture_map=architecture,
            experiments=experiments,
            hypotheses=hypotheses,
            evidence=evidence,
            memory_snapshot=snapshot,
            loop_steps=steps,
        )

    @staticmethod
    def _rationale(stage: LoopStage, previous_failures: tuple[str, ...]) -> str:
        if stage in {LoopStage.VALIDATE, LoopStage.REVIEW, LoopStage.LEARN, LoopStage.IMPROVE}:
            return "blocked until causal evidence and replayable proof exist"
        if previous_failures:
            return "adapted from recorded failure history without repeating unsupported actions"
        return f"deterministic recorded-state {stage.value} stage"


__all__ = ["VABHFQRV9Core"]
