"""Bounded controller loop for Smart Autonomous Bug Hunter.

The controller is orchestration only. It never creates transport clients and never
executes an action without an explicitly injected handler and ActionExecutor.
Legacy graph callers can keep using ``smart_campaigns_node`` unchanged.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from typing import Any

from webpent.agents.smart_campaigns.agent import (
    build_smart_campaign_tasks,
    smart_campaigns_node,
)
from webpent.shared.campaign_executor import (
    ActionExecutor,
    CampaignTask,
    resolve_preconditions,
)
from webpent.shared.capability_manifest import CapabilityRegistry

TaskHandler = Callable[[CampaignTask], Any]


class AutonomousController:
    """Run bounded plan -> gate -> execute -> observe iterations.

    A missing handler or executor is a configuration error, not an implicit
    transport fallback. Every actual action must pass through the supplied
    ActionExecutor.
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
    def _state_fingerprint(state: Mapping[str, Any]) -> str:
        """Hash only redaction-safe state relevant to research convergence."""
        relevant = {
            "target_knowledge": state.get("target_knowledge", {}),
            "positive_evidence": state.get("positive_evidence_ledger", []),
            "negative_evidence": state.get("negative_evidence_ledger", []),
            "knowledge_gaps": state.get("knowledge_gaps", []),
            "findings": state.get("findings", []),
        }
        encoded = json.dumps(relevant, sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @staticmethod
    def _action_signature(task: CampaignTask) -> str:
        return task.normalized_idempotency_key() or task.task_id

    @staticmethod
    def _capability_state(
        manifest: Mapping[str, Any], capability: str
    ) -> dict[str, Any]:
        capabilities = manifest.get("capabilities", {}) if isinstance(manifest, Mapping) else {}
        value = capabilities.get(capability, {}) if isinstance(capabilities, Mapping) else {}
        if not isinstance(value, Mapping):
            return {"status": "unsupported", "capability": capability}
        return {
            "capability": capability,
            "status": str(
                value.get("status") or ("available" if value.get("available") else "unknown")
            ),
            "fallback": bool(value.get("fallback") or value.get("safe_fallback")),
        }

    @staticmethod
    def _record_has_new_evidence(record: Mapping[str, Any]) -> bool:
        return bool(
            record.get("proof_bundle_sealed")
            or record.get("output_available")
            or record.get("negative_control_present")
            or record.get("evidence_refs")
        )

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
        seen_actions: set[str] = set()
        stop_reason = "iteration_limit_reached"
        minimum_information_gain = 0.05

        for round_number in range(limit):
            state_before = self._state_fingerprint(working)
            planning = smart_campaigns_node(self._planning_state(working))
            last_planning = dict(planning)
            tasks = self._planned_tasks(working, planning)
            if handler is None or self.action_executor is None:
                raise RuntimeError(
                    "autonomous_controller_runtime_dependencies_required: "
                    "inject both action_executor and handler"
                )

            selected = tasks[:1]
            if not selected:
                stop_reason = "no_new_ready_task"
                trace.append(
                    {
                        "correlation_id": str(
                            working.get("correlation_id")
                            or working.get("engagement_id")
                            or "controller"
                        ),
                        "controller_round": round_number,
                        "task_id": None,
                        "hypothesis_id": None,
                        "action_id": None,
                        "precondition_state": "not_evaluated",
                        "capability_state": {"status": "not_selected"},
                        "status": "complete",
                        "result": "no_new_ready_task",
                        "reason": stop_reason,
                        "redacted_evidence_refs": [],
                    }
                )
                break
            task = selected[0]
            action_signature = self._action_signature(task)
            if action_signature in seen_actions:
                stop_reason = "same_action_repeated"
                trace.append(
                    {
                        "correlation_id": str(
                            working.get("correlation_id")
                            or working.get("engagement_id")
                            or "controller"
                        ),
                        "controller_round": round_number,
                        "task_id": task.task_id,
                        "hypothesis_id": task.hypothesis_id,
                        "action_id": action_signature,
                        "precondition_state": "not_evaluated",
                        "capability_state": self._capability_state(
                            planning.get("capability_manifest", {}), task.capability
                        ),
                        "status": "stopped",
                        "result": stop_reason,
                        "reason": stop_reason,
                        "redacted_evidence_refs": [],
                    }
                )
                break
            seen_actions.add(action_signature)
            if task.expected_information_gain < minimum_information_gain:
                stop_reason = "expected_information_gain_below_threshold"
                trace.append(
                    {
                        "correlation_id": str(
                            working.get("correlation_id")
                            or working.get("engagement_id")
                            or "controller"
                        ),
                        "controller_round": round_number,
                        "task_id": task.task_id,
                        "hypothesis_id": task.hypothesis_id,
                        "action_id": action_signature,
                        "precondition_state": "not_evaluated",
                        "capability_state": self._capability_state(
                            planning.get("capability_manifest", {}), task.capability
                        ),
                        "status": "stopped",
                        "result": stop_reason,
                        "reason": stop_reason,
                        "expected_information_gain": task.expected_information_gain,
                        "redacted_evidence_refs": [],
                    }
                )
                break
            observed_preconditions = working.get("observed_preconditions", ())
            blocked_preconditions = working.get("blocked_preconditions", ())
            if isinstance(observed_preconditions, str):
                observed_preconditions = (observed_preconditions,)
            if isinstance(blocked_preconditions, str):
                blocked_preconditions = (blocked_preconditions,)
            ready, _ = resolve_preconditions(
                selected[0],
                observed_preconditions=observed_preconditions,
                blocked_preconditions=blocked_preconditions,
                require_observations=True,
            )
            record = self.action_executor.execute(task, handler, preconditions_met=ready)
            all_outcomes.append(record)
            all_lifecycle.extend(self.action_executor.lifecycle_events[-4:])
            capability_state = self._capability_state(
                planning.get("capability_manifest", {}), task.capability
            )
            status = str(record.get("status", "unknown"))
            trace_entry = {
                "correlation_id": str(
                    working.get("correlation_id")
                    or working.get("engagement_id")
                    or "controller"
                ),
                "controller_round": round_number,
                "task_id": task.task_id,
                "hypothesis_id": task.hypothesis_id,
                "action_id": action_signature,
                "precondition_state": "met" if ready else "blocked",
                "capability_state": capability_state,
                "status": status,
                "result": str(record.get("reason") or status),
                "proof_bundle_sealed": bool(record.get("proof_bundle_sealed")),
                "redacted_evidence_refs": list(record.get("evidence_refs", ()))[:20]
                if isinstance(record.get("evidence_refs", ()), (list, tuple))
                else [],
            }
            trace.append(trace_entry)
            if status == "executed":
                executed += 1
            else:
                stop_reason = {
                    "blocked_by_precondition": "blocked_by_precondition",
                    "policy_denied": "capability_or_authority_blocked",
                    "infrastructure_failure": "infrastructure_failure",
                    "stopped": "action_stopped",
                }.get(status, "action_not_executed")
                trace_entry["result"] = stop_reason
                working = {**working, **planning, "campaign_task_outcomes": all_outcomes}
                break
            working = {**working, **planning, "campaign_task_outcomes": all_outcomes}
            if bool(record.get("negative_control_contradicts")):
                stop_reason = "negative_control_contradicts_theory"
                trace_entry["result"] = stop_reason
                break
            action_budget = working.get("action_budget")
            if (
                isinstance(action_budget, Mapping)
                and float(action_budget.get("remaining_cost", 1.0) or 0.0) <= 0
            ):
                stop_reason = "budget_exhausted"
                trace_entry["result"] = stop_reason
                break
            state_after = self._state_fingerprint(working)
            if state_before == state_after and not self._record_has_new_evidence(record):
                stop_reason = "no_new_evidence_or_state_delta"
                trace_entry["result"] = stop_reason
                break

        replanning = dict(last_planning.get("smart_replanning") or {})
        replanning.update(
            {
                "status": "controller_completed",
                "controller_iterations": len(trace),
                "controller_executed": executed,
                "controller_trace": trace,
                "execution_required": (
                    executed == 0 and bool(last_planning.get("smart_next_actions"))
                ),
                "stop_reason": stop_reason,
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
    """Graph-safe controller node using the single injected runtime spine."""
    from webpent.shared.runtime import RuntimeContext, RuntimeFactory

    runtime = state.get("runtime_context")
    if not isinstance(runtime, RuntimeContext):
        return RuntimeFactory.blocked_result(
            node="autonomous_controller",
            reason="runtime_context_required",
        )
    if not runtime.valid:
        return runtime.blocked_result(node="autonomous_controller")
    result = AutonomousController(action_executor=runtime.action_executor).run(state)
    result["runtime_diagnostics"] = runtime.diagnostics()
    return result


__all__ = ["AutonomousController", "autonomous_controller_node"]
