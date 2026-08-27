"""Bounded research-loop contracts for structured hypothesis investigation."""

from webpent.research.experiment_manager import ExperimentManager
from webpent.research.hypothesis_engine import HypothesisEngine, TransitionResult
from webpent.research.hypothesis_generator import (
    DEFAULT_PATTERNS,
    HypothesisGenerator,
    VulnerabilityPattern,
)
from webpent.research.hypothesis_ranker import HypothesisRanker
from webpent.research.planner import PlannerDecision, ResearchPlanner, ResearchQueue

__all__ = [
    "DEFAULT_PATTERNS",
    "ExperimentManager",
    "HypothesisEngine",
    "HypothesisGenerator",
    "HypothesisRanker",
    "PlannerDecision",
    "ResearchPlanner",
    "ResearchQueue",
    "TransitionResult",
    "VulnerabilityPattern",
]
