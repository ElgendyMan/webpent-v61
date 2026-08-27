from __future__ import annotations

import pytest
from pydantic import ValidationError

from webpent.asros.adaptive_strategy import (
    AdaptiveStrategyEngine,
    OutcomeKind,
    ResearchDirection,
    ResearchOutcome,
)
from webpent.asros.attack_surface import (
    AttackSurfaceItem,
    DynamicResearchMap,
    SurfaceKind,
    SurfaceSignal,
)


def _surface(surface_id: str, impact: float, *, allowed: bool = True) -> AttackSurfaceItem:
    signals = tuple(
        SurfaceSignal(
            name=name,
            value=value,
            source="controlled-evidence",
            evidence_refs=(f"ref-{surface_id}",),
        )
        for name, value in (
            ("business_impact", impact),
            ("privilege_sensitivity", 0.8),
            ("data_sensitivity", 0.7),
            ("complexity", 0.4),
            ("unknown_behavior", 0.6),
            ("previous_evidence", 0.3),
        )
    )
    return AttackSurfaceItem(
        surface_id=surface_id,
        kind=SurfaceKind.ENDPOINT,
        canonical_name=f"GET /{surface_id}",
        target_id="controlled-loopback",
        signals=signals,
        required_capability="observation",
        scope_allowed=allowed,
        evidence_refs=(f"ref-{surface_id}",),
    )


def test_dynamic_map_ranks_by_deterministic_score_and_excludes_out_of_scope() -> None:
    high = _surface("surface-high", 1.0)
    low = _surface("surface-low", 0.2)
    blocked = _surface("surface-blocked", 1.0, allowed=False)

    research_map = DynamicResearchMap.build(
        target_id="controlled-loopback",
        surfaces=[low, blocked, high],
        generated_from=["world-model-v1"],
    )

    assert research_map.ranked_surface_ids == (
        "surface-high",
        "surface-low",
        "surface-blocked",
    )
    assert research_map.surfaces[0].score() > research_map.surfaces[1].score()
    assert research_map.surfaces[2].score() == 0.0
    assert len(research_map.content_hash()) == 64


def test_dynamic_map_rejects_rank_mismatch_and_authority() -> None:
    high = _surface("surface-high", 1.0)
    with pytest.raises(ValidationError, match="rank_order_mismatch"):
        DynamicResearchMap(
            target_id="controlled-loopback",
            surfaces=(high,),
            ranked_surface_ids=("wrong",),
        )
    with pytest.raises(ValidationError, match="authority"):
        DynamicResearchMap(
            target_id="controlled-loopback",
            surfaces=(high,),
            authoritative=True,
        )
    with pytest.raises(ValidationError, match="execution"):
        _surface("surface-exec", 1.0).model_copy(
            update={"execution_capability": True}
        ).model_validate(
            _surface("surface-exec", 1.0).model_copy(update={"execution_capability": True})
        )


def test_adaptive_strategy_changes_direction_after_low_value_outcome() -> None:
    engine = AdaptiveStrategyEngine()
    decision = engine.decide(
        current_direction=ResearchDirection.ENDPOINT,
        outcomes=(
            ResearchOutcome(
                task_id="task-1",
                hypothesis_id="hyp-1",
                direction=ResearchDirection.ENDPOINT,
                outcome=OutcomeKind.NO_EVIDENCE,
                reason="no_semantic_delta",
            ),
        ),
    )

    assert decision.next_directions[0] == ResearchDirection.WORKFLOW
    assert decision.low_value_count == 1
    assert decision.priority_multiplier == 0.9
    assert decision.advisory_only is True
    assert decision.rejected is False


def test_adaptive_strategy_deprioritizes_repeated_failures() -> None:
    engine = AdaptiveStrategyEngine()
    outcomes = tuple(
        ResearchOutcome(
            task_id=f"task-{index}",
            hypothesis_id="hyp-1",
            direction=ResearchDirection.WORKFLOW,
            outcome=OutcomeKind.FAILED,
            reason="precondition_blocked",
        )
        for index in range(2)
    )
    decision = engine.decide(
        current_direction=ResearchDirection.WORKFLOW,
        outcomes=outcomes,
        hypothesis_failures=2,
    )

    assert decision.repeated_failure_count == 4
    assert decision.priority_multiplier == 0.2
    assert decision.rejected is True
    assert "deprioritize" in decision.rationale


def test_strategy_cannot_become_authoritative() -> None:
    with pytest.raises(ValidationError, match="advisory"):
        from webpent.asros.adaptive_strategy import StrategyDecision

        StrategyDecision(
            current_direction=ResearchDirection.ENDPOINT,
            rationale="unsafe override",
            advisory_only=False,
        )
