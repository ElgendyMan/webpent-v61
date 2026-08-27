"""Adaptive research planning with explicit safety and capability boundaries."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass

from webpent.intelligence.contracts import ResearchHypothesis
from webpent.research_engine.research_state import ResearchTask

_RISK_PENALTY = {"low": 0.0, "medium": 0.08, "high": 0.18, "critical": 0.35}


@dataclass(frozen=True)
class ResearchQueue:
    tasks: tuple[ResearchTask, ...] = ()

    def ordered(self) -> tuple[ResearchTask, ...]:
        return tuple(
            sorted(
                self.tasks,
                key=lambda task: (
                    -task.priority,
                    -task.expected_information_gain,
                    task.cost,
                    task.task_id,
                ),
            )
        )

    def next_task(self) -> ResearchTask | None:
        return self.ordered()[0] if self.tasks else None


@dataclass(frozen=True)
class PlannerDecision:
    status: str
    selected_task_id: str | None
    queue_size: int
    rationale: str
    authoritative: bool = False
    execution_allowed: bool = False


class ResearchPlanner:
    """Select the highest-value admissible research task, never execute it."""

    def build_queue(
        self,
        hypotheses: Iterable[ResearchHypothesis],
        *,
        engagement_id: str,
        target_id: str,
        available_capabilities: Iterable[str] = (),
        completed_task_ids: Iterable[str] = (),
    ) -> ResearchQueue:
        capabilities = {str(item).strip() for item in available_capabilities if str(item).strip()}
        completed = {str(item).strip() for item in completed_task_ids if str(item).strip()}
        tasks: list[ResearchTask] = []
        for hypothesis in hypotheses:
            task_id = self.task_id(hypothesis, engagement_id=engagement_id, target_id=target_id)
            if task_id in completed or hypothesis.required_capability not in capabilities:
                continue
            risk = (
                hypothesis.risk.value if hasattr(hypothesis.risk, "value") else str(hypothesis.risk)
            )
            gain = min(
                1.0, 0.35 + len(hypothesis.evidence_needed) * 0.1 + hypothesis.confidence * 0.35
            )
            cost = min(1.0, 0.15 + len(hypothesis.attack_plan) * 0.06)
            priority = max(
                0.0,
                min(
                    1.0,
                    hypothesis.confidence
                    + gain * 0.35
                    - cost * 0.15
                    - _RISK_PENALTY.get(risk, 0.2),
                ),
            )
            tasks.append(
                ResearchTask(
                    task_id=task_id,
                    engagement_id=engagement_id,
                    target_id=target_id,
                    objective=f"Validate potential {hypothesis.vuln_class} hypothesis",
                    reason=hypothesis.reason,
                    priority=round(priority, 6),
                    risk=risk,
                    expected_information_gain=round(gain, 6),
                    cost=round(cost, 6),
                    required_capability=hypothesis.required_capability,
                    required_evidence=tuple(hypothesis.evidence_needed),
                    operation="validate",
                )
            )
        return ResearchQueue(ResearchQueue(tuple(tasks)).ordered())

    def decide(self, queue: ResearchQueue) -> PlannerDecision:
        task = queue.next_task()
        if task is None:
            return PlannerDecision(
                status="no_admissible_task",
                selected_task_id=None,
                queue_size=0,
                rationale="No task satisfies scope, completion, and capability filters.",
            )
        return PlannerDecision(
            status="planned",
            selected_task_id=task.task_id,
            queue_size=len(queue.tasks),
            rationale=(
                f"Selected {task.task_id} by deterministic utility ordering; "
                "execution remains behind the existing scope/authority/evidence gates."
            ),
        )

    @staticmethod
    def task_id(hypothesis: ResearchHypothesis, *, engagement_id: str, target_id: str) -> str:
        raw = f"{engagement_id}|{target_id}|{hypothesis.id}|{hypothesis.required_capability}"
        return "research:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


__all__ = ["PlannerDecision", "ResearchPlanner", "ResearchQueue"]
