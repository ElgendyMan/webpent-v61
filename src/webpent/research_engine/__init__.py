"""Research-engine public API.

AREX components are exposed lazily because the shared CampaignExecutor imports
some research-engine contracts during package initialization. Lazy exports
preserve the public surface without creating a package-level import cycle.
"""

from typing import Any

from webpent.research_engine.confidence_engine import (
    ConfidenceAssessment,
    ConfidenceSignals,
    assess_confidence,
)
from webpent.research_engine.evidence_aware_loop import (
    EvidenceAwareAgentLoop,
    EvidenceAwareResult,
    LoopStatus,
)
from webpent.research_engine.knowledge_gap import KnowledgeGap, KnowledgeGapEngine
from webpent.research_engine.orchestrator import ResearchOrchestrator, ResearchPlan
from webpent.research_engine.priority_engine import PrioritySignals, priority_score
from webpent.research_engine.projection_adapter import (
    ProjectionPlanningAdapter,
    ProjectionPlanningInput,
)
from webpent.research_engine.research_budget import (
    BudgetDecision,
    BudgetUsage,
    ResearchBudget,
    evaluate_budget,
)
from webpent.research_engine.research_state import ResearchState, ResearchTask


def __getattr__(name: str) -> Any:
    if name == "AutonomousScheduler":
        from webpent.research_engine.autonomous_scheduler import AutonomousScheduler

        return AutonomousScheduler
    if name == "SchedulerDecision":
        from webpent.research_engine.autonomous_scheduler import SchedulerDecision

        return SchedulerDecision
    if name == "CampaignHypothesisLifecycle":
        from webpent.research_engine.campaign_hypothesis_lifecycle import (
            CampaignHypothesisLifecycle,
        )

        return CampaignHypothesisLifecycle
    if name == "CampaignLifecycleLabel":
        from webpent.research_engine.campaign_hypothesis_lifecycle import CampaignLifecycleLabel

        return CampaignLifecycleLabel
    if name == "LifecycleProjectionResult":
        from webpent.research_engine.campaign_hypothesis_lifecycle import (
            LifecycleProjectionResult,
        )

        return LifecycleProjectionResult
    if name == "CampaignLineage":
        from webpent.research_engine.campaign_state import CampaignLineage

        return CampaignLineage
    if name == "CampaignState":
        from webpent.research_engine.campaign_state import CampaignState

        return CampaignState
    if name == "CapabilityAwareRouter":
        from webpent.research_engine.execution_router import CapabilityAwareRouter

        return CapabilityAwareRouter
    if name == "RouteDecision":
        from webpent.research_engine.execution_router import RouteDecision

        return RouteDecision
    if name == "RouteStatus":
        from webpent.research_engine.execution_router import RouteStatus

        return RouteStatus
    if name == "FeedbackResult":
        from webpent.research_engine.feedback_loop import FeedbackResult

        return FeedbackResult
    if name == "ObservationFeedback":
        from webpent.research_engine.feedback_loop import ObservationFeedback

        return ObservationFeedback
    if name == "ObservationFeedbackLoop":
        from webpent.research_engine.feedback_loop import ObservationFeedbackLoop

        return ObservationFeedbackLoop
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "AutonomousScheduler",
    "BudgetDecision",
    "CapabilityAwareRouter",
    "CampaignHypothesisLifecycle",
    "CampaignLifecycleLabel",
    "CampaignLineage",
    "CampaignState",
    "EvidenceAwareAgentLoop",
    "FeedbackResult",
    "EvidenceAwareResult",
    "BudgetUsage",
    "ConfidenceAssessment",
    "ConfidenceSignals",
    "KnowledgeGap",
    "KnowledgeGapEngine",
    "LifecycleProjectionResult",
    "LoopStatus",
    "PrioritySignals",
    "ProjectionPlanningAdapter",
    "ProjectionPlanningInput",
    "ResearchBudget",
    "ResearchOrchestrator",
    "ResearchPlan",
    "ResearchState",
    "ResearchTask",
    "ObservationFeedback",
    "ObservationFeedbackLoop",
    "RouteDecision",
    "RouteStatus",
    "SchedulerDecision",
    "assess_confidence",
    "evaluate_budget",
    "priority_score",
]
