"""Thin integration bridge from ASROS projections into AVDE advisory output."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from pydantic import BaseModel, ConfigDict, Field

from webpent.asros.world_model import SecurityWorldModel
from webpent.avde.discovery import DiscoveryHypothesis, DiscoveryHypothesisEngine
from webpent.avde.exploration import (
    AttackPath,
    AttackPathExplorer,
    AutonomousValidationStrategy,
    ValidationPlan,
)
from webpent.avde.review import ReasoningReview, SeniorReasoningReviewer


class AdvisoryDiscoverySession(BaseModel):
    """A serialisable AVDE result; it is not an execution authorization."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    engagement_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    hypotheses: tuple[DiscoveryHypothesis, ...] = Field(default=(), max_length=256)
    paths: tuple[AttackPath, ...] = Field(default=(), max_length=256)
    plans: tuple[ValidationPlan, ...] = Field(default=(), max_length=256)
    reviews: tuple[ReasoningReview, ...] = Field(default=(), max_length=256)
    advisory_only: bool = True
    creates_findings: bool = False
    executes_transport: bool = False
    overrides_policy: bool = False


class AVDEAdvisoryPipeline:
    """Compose existing ASROS projections with AVDE without a parallel authority."""

    def run(
        self,
        world_model: SecurityWorldModel,
        *,
        observations: Iterable[Mapping[str, object]] = (),
        attack_graph: Iterable[Mapping[str, object]] = (),
        available_capabilities: Iterable[str] = (),
        max_cost: int = 100,
    ) -> AdvisoryDiscoverySession:
        if not isinstance(world_model, SecurityWorldModel):
            raise TypeError("security_world_model_required")
        graph_items = tuple(attack_graph)
        hypotheses = DiscoveryHypothesisEngine().generate(
            world_model, observations=observations, attack_graph=graph_items
        )
        paths = AttackPathExplorer().explore(
            graph_items,
            target_id=world_model.target_id,
            available_capabilities=available_capabilities,
        )
        strategy = AutonomousValidationStrategy()
        reviewer = SeniorReasoningReviewer()
        plans = tuple(
            strategy.choose(
                hypothesis,
                paths,
                available_capabilities=available_capabilities,
                max_cost=max_cost,
            )
            for hypothesis in hypotheses
        )
        reviews = tuple(
            reviewer.review(hypothesis, plan)
            for hypothesis, plan in zip(hypotheses, plans, strict=True)
        )
        return AdvisoryDiscoverySession(
            engagement_id=world_model.engagement_id,
            target_id=world_model.target_id,
            hypotheses=hypotheses,
            paths=paths,
            plans=plans,
            reviews=reviews,
        )


__all__ = ["AVDEAdvisoryPipeline", "AdvisoryDiscoverySession"]
