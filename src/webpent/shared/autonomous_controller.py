"""Bounded controller loop for Smart Autonomous Bug Hunter.

The controller is orchestration only. It never creates transport clients and never
executes an action without an explicitly injected handler and ActionExecutor.
Legacy graph callers can keep using ``smart_campaigns_node`` unchanged.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from webpent.agents.smart_campaigns.agent import (
    build_smart_campaign_tasks,
    smart_campaigns_node,
)
from webpent.shared.campaign_executor import ActionExecutor, CampaignTask
from webpent.shared.capability_manifest import CapabilityRegistry

TaskHandler = Callable[[CampaignTask], Any]


class AutonomousController:
    """Run bounded plan -> gate -> execute -> observe iterations.

    A missing handler is an intentional safe stop, not an implicit transport
    fallback. Every actual action must pass through the supplied ActionExecutor.
    """

    def __init__(
        self,
        *,
        capability_registry: CapabilityRegistry | None = None,
        action_executor: ActionExecutor | None = None,
        max_iterations: int = 3,
    ) -> None:
        self.capability_registry = capability_registry or CapabilityRegistry()
        self.action_executor = action_executor
        self.max_iterations = max(1, min(10, int(max_iterations)))

    def _planning_state(self, state: Mapping[str, Any]) -> dict[str, Any]:
        manifest = self.capability_registry.ensure_discovered()
        return {**dict(state), "capability_manifest": manifest}

    @staticmethod
    def _planned_tasks(
        state: Mapping[str, Any], planning: Mapping[str, Any]
    ) -> list[CampaignTask]:
        tasks, _ = build_smart_campaign_tasks(
            {**dict(state), "campaign_plan": planning.get("campaign_plan", {})},
            max_tasks=10,
        )
        planned_ids = {
            str(item.get("task", {}).get("task_id"))
            for item in planning.get("smart_next_actions", [])
            if isinstance(item, Mapping) and isinstance(item.get("task"), Mapping)
        }
        return [task for task in tasks if task.task_id in planned_ids]

    def run(
        self,
        state: Mapping[str, Any],
        *,
        handler: TaskHandler | None = None,
        iterations: int = 1,
    ) -> dict[str, Any]:
        """Return an additive state update for bounded controller iterations."""
        limit = max(1, min(self.max_iterations, int(iterations)))
        working: dict[str, Any] = dict(state)
        all_outcomes: list[dict[str, Any]] = []
        all_lifecycle: list[dict[str, Any]] = []
        trace: list[dict[str, Any]] = []
        last_planning: dict[str, Any] = {}
        executed = 0

        for round_number in range(limit):
            planning = smart_campaigns_node(self._planning_state(working))
            last_planning = dict(planning)
            tasks = self._planned_tasks(working, planning)
            if handler is None or self.action_executor is None:
                trace.append(
                    {
                        "controller_round": round_number,
                        "status": "safe_stopped",
                        "reason": "explicit_action_handler_and_executor_required",
                        "planned_count": len(tasks),
                    }
                )
                break

            selected = tasks[:1]
            if not selected:
                trace.append(
                    {
                        "controller_round": round_number,
                        "status": "complete",
                        "reason": "no_new_ready_task",
                    }
                )
                break
            record = self.action_executor.execute(selected[0], handler)
            all_outcomes.append(record)
            all_lifecycle.extend(self.action_executor.lifecycle_events[-4:])
            trace.append(
                {
                    "controller_round": round_number,
                    "status": str(record.get("status", "unknown")),
                    "task_id": selected[0].task_id,
                    "proof_bundle_sealed": bool(record.get("proof_bundle_sealed")),
                }
            )
            executed += 1
            working = {**working, **planning, "campaign_task_outcomes": all_outcomes}

        replanning = dict(last_planning.get("smart_replanning") or {})
        replanning.update(
            {
                "status": (
                    "controller_completed"
                    if handler and self.action_executor
                    else "controller_safe_stopped"
                ),
                "controller_iterations": len(trace),
                "controller_executed": executed,
                "controller_trace": trace,
                "execution_required": (
                    executed == 0 and bool(last_planning.get("smart_next_actions"))
                ),
            }
        )
        update = dict(last_planning)
        if all_outcomes:
            update["campaign_task_outcomes"] = all_outcomes
        if all_lifecycle:
            update["lifecycle_events"] = all_lifecycle
        update["smart_replanning"] = replanning
        update["current_phase"] = "smart_autonomous_controller"
        return update


def autonomous_controller_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """Graph-safe controller node; transport remains caller-injected only."""
    return AutonomousController().run(state)


__all__ = ["AutonomousController", "autonomous_controller_node"]
