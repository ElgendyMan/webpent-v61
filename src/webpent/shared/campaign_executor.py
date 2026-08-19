"""Bounded campaign execution and next-best-action planning.

The executor is deliberately transport-agnostic. It accepts a caller-supplied
handler only after :class:`ActionAuthority` authorizes the task. Campaign
contracts, coverage records, and decision traces are redaction-safe metadata;
they never promote a hypothesis to a finding.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from webpent.models.evidence import canonical_json, redact_sensitive
from webpent.models.proof_bundle import build_proof_bundle
from webpent.shared.action_authority import (
    ActionAuthority,
    ActionRequest,
    ActionResult,
    ActionRisk,
    ActionStatus,
)


class CampaignTaskStatus(str, Enum):
    READY = "ready"
    BLOCKED_BY_PRECONDITION = "blocked_by_precondition"
    POLICY_DENIED = "policy_denied"
    EXECUTED = "executed"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"
    STOPPED = "stopped"


@dataclass(frozen=True)
class CampaignTask:
    """The bounded task contract used by the planner and executor."""

    task_id: str
    engagement_id: str
    asset_id: str
    source_evidence_ids: tuple[str, ...]
    vulnerability_class: str
    hypothesis_id: str
    preconditions: tuple[str, ...] = ()
    identity_context: str = "anonymous"
    workflow_state: str = "unknown"
    probe_family: str = "read_only_compare"
    negative_control: str = "required"
    oracle: str = "deterministic_response_compare"
    risk_tier: ActionRisk = ActionRisk.READ_ONLY
    budget: float = 1.0
    expected_information_gain: float = 0.0
    idempotency_key: str = ""
    parent_task_id: str = ""
    cleanup_plan: tuple[str, ...] = ()
    rollback_plan: tuple[str, ...] = ()
    stop_condition: str = "proof_or_blocker"
    method: str = "GET"
    capability: str = "http_read"
    action_family: str = "http_read"
    target_url: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)
    body_schema: str = "none"
    content_type: str = ""
    tenant_context: str = "unknown"
    validator_id: str = ""

    def normalized_idempotency_key(self) -> str:
        if self.idempotency_key.strip():
            return self.idempotency_key.strip()[:160]
        payload = {
            "engagement_id": self.engagement_id,
            "asset_id": self.asset_id,
            "vulnerability_class": self.vulnerability_class,
            "hypothesis_id": self.hypothesis_id,
            "probe_family": self.probe_family,
            "identity_context": self.identity_context,
            "workflow_state": self.workflow_state,
        }
        return "task:" + hashlib.sha256(canonical_json(payload).encode()).hexdigest()[:32]

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(
            {
                "task_id": self.task_id,
                "engagement_id": self.engagement_id,
                "asset_id": self.asset_id,
                "source_evidence_ids": list(self.source_evidence_ids),
                "vulnerability_class": self.vulnerability_class,
                "hypothesis_id": self.hypothesis_id,
                "preconditions": list(self.preconditions),
                "identity_context": self.identity_context,
                "workflow_state": self.workflow_state,
                "probe_family": self.probe_family,
                "negative_control": self.negative_control,
                "oracle": self.oracle,
                "risk_tier": self.risk_tier.value,
                "budget": self.budget,
                "expected_information_gain": self.expected_information_gain,
                "idempotency_key": self.normalized_idempotency_key(),
                "parent_task_id": self.parent_task_id,
                "cleanup_plan": list(self.cleanup_plan),
                "rollback_plan": list(self.rollback_plan),
                "stop_condition": self.stop_condition,
                "method": self.method,
                "capability": self.capability,
                "action_family": self.action_family,
                "target_url": self.target_url,
                "metadata": dict(self.metadata),
                "body_schema": self.body_schema,
                "content_type": self.content_type,
                "tenant_context": self.tenant_context,
                "validator_id": self.validator_id,
            }
        )
        return clean


@dataclass(frozen=True)
class PlannedAction:
    task: CampaignTask
    score: float
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {"task": self.task.as_dict(), "score": self.score, "reasons": list(self.reasons)}


def _normalize_precondition(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def resolve_preconditions(
    task: CampaignTask,
    *,
    observed_preconditions: Iterable[str] = (),
    blocked_preconditions: Iterable[str] = (),
    require_observations: bool = False,
) -> tuple[bool, tuple[str, ...]]:
    """Resolve readiness from explicit evidence without guessing missing state."""
    observed = {
        _normalize_precondition(item)
        for item in observed_preconditions
        if str(item).strip()
    }
    metadata_observed = task.metadata.get("observed_preconditions", ())
    if isinstance(metadata_observed, str):
        metadata_observed = (metadata_observed,)
    observed.update(
        _normalize_precondition(item)
        for item in metadata_observed
        if str(item).strip()
    )
    blocked = {_normalize_precondition(item) for item in blocked_preconditions if str(item).strip()}
    missing = tuple(
        precondition
        for precondition in task.preconditions
        if _normalize_precondition(precondition) in blocked
        or (
            (observed or require_observations)
            and _normalize_precondition(precondition) not in observed
        )
    )
    return not missing, missing


class NextBestActionEngine:
    """Score ready tasks while enforcing hard constraints before ranking."""

    def __init__(self, *, duplicate_penalty: float = 0.7) -> None:
        self.duplicate_penalty = max(0.0, min(1.0, duplicate_penalty))

    def score(
        self,
        task: CampaignTask,
        *,
        observed_evidence: Iterable[str] = (),
        covered_classes: Iterable[str] = (),
        attempted_keys: Iterable[str] = (),
        blocked_preconditions: Iterable[str] = (),
        observed_preconditions: Iterable[str] = (),
    ) -> PlannedAction:
        evidence = set(observed_evidence)
        covered = {str(item) for item in covered_classes}
        attempted = set(attempted_keys)
        reasons: list[str] = []
        _, hard_block = resolve_preconditions(
            task,
            observed_preconditions=observed_preconditions,
            blocked_preconditions=blocked_preconditions,
        )
        if hard_block:
            return PlannedAction(
                task=task,
                score=-1.0,
                reasons=("blocked_precondition:" + ",".join(hard_block),),
            )

        score = max(0.0, min(1.0, task.expected_information_gain))
        if any(item in evidence for item in task.source_evidence_ids):
            score += 0.25
            reasons.append("evidence_relevance")
        if task.vulnerability_class not in covered:
            score += 0.2
            reasons.append("coverage_value")
        if task.normalized_idempotency_key() in attempted:
            score -= self.duplicate_penalty
            reasons.append("duplication_penalty")
        if task.budget <= 1.0:
            score += 0.1
            reasons.append("low_cost")
        if task.risk_tier == ActionRisk.ACTIVE:
            score -= 0.05
            reasons.append("active_risk_discount")
        return PlannedAction(task=task, score=round(score, 6), reasons=tuple(reasons))

    def choose(self, tasks: Iterable[CampaignTask], **kwargs: Any) -> PlannedAction | None:
        planned = [self.score(task, **kwargs) for task in tasks]
        ready = [item for item in planned if item.score >= 0]
        return max(ready, key=lambda item: (item.score, item.task.task_id)) if ready else None


class CampaignExecutor:
    """Run at most one authorized task per call and retain an explainable trace."""

    def __init__(
        self,
        authority: ActionAuthority,
        *,
        action_engine: NextBestActionEngine | None = None,
    ) -> None:
        self.authority = authority
        self.action_engine = action_engine or NextBestActionEngine()
        self.coverage: dict[str, dict[str, Any]] = {}
        self.decision_trace: list[dict[str, Any]] = []
        self.lifecycle_events: list[dict[str, Any]] = []
        self._executed_keys: set[str] = set()

    def _emit_lifecycle(self, task: CampaignTask, stage: str, reason: str = "") -> None:
        self.lifecycle_events.append(
            {
                "task_id": task.task_id,
                "engagement_id": task.engagement_id,
                "stage": stage,
                "status": "recorded",
                "reason": reason[:240],
                "action_family": task.action_family,
                "method": task.method,
                "vulnerability_class": task.vulnerability_class,
            }
        )

    def _request(self, task: CampaignTask) -> ActionRequest:
        return ActionRequest(
            task_id=task.task_id,
            engagement_id=task.engagement_id,
            target_url=task.target_url,
            method=task.method,
            action_family=task.action_family,
            capability=task.capability,
            risk=task.risk_tier,
            identity_ref=task.identity_context,
            idempotency_key=task.normalized_idempotency_key(),
            estimated_cost=task.budget,
            human_approved=bool(task.metadata.get("human_approved", False)),
            metadata={
                "vulnerability_class": task.vulnerability_class,
                "probe_family": task.probe_family,
                "body_schema": task.body_schema,
                "content_type": task.content_type,
                "tenant_context": task.tenant_context,
                "validator_id": task.validator_id,
            },
        )

    def execute(
        self,
        task: CampaignTask,
        handler: Callable[[CampaignTask], Any],
        *,
        preconditions_met: bool = True,
    ) -> dict[str, Any]:
        key = task.normalized_idempotency_key()
        self._emit_lifecycle(task, "planned")
        if not preconditions_met:
            self._emit_lifecycle(task, "blocked", "precondition_failed")
            return self._record(
                task,
                CampaignTaskStatus.BLOCKED_BY_PRECONDITION,
                "precondition_failed",
            )
        if key in self._executed_keys:
            self._emit_lifecycle(task, "deduplicated", "duplicate_idempotency_key")
            return self._record(task, CampaignTaskStatus.STOPPED, "duplicate_idempotency_key")

        request = self._request(task)
        result: ActionResult = self.authority.execute(request, lambda _request: handler(task))
        if result.status in {ActionStatus.AUTHORIZED, ActionStatus.EXECUTED}:
            self._emit_lifecycle(task, "authorized")
        elif result.status == ActionStatus.POLICY_DENIED:
            self._emit_lifecycle(task, "denied", ",".join(result.decision.reasons))
        else:
            self._emit_lifecycle(task, "failed", result.status.value)
        status = self._status_from_action(result.status)
        if result.status == ActionStatus.EXECUTED:
            self._executed_keys.add(key)
            self._emit_lifecycle(task, "completed")
        record = self._record(
            task,
            status,
            ",".join(result.decision.reasons) or result.status.value,
            output=result.output,
            audit_event=result.decision.audit_event,
        )
        return record

    def _status_from_action(self, status: ActionStatus) -> CampaignTaskStatus:
        return {
            ActionStatus.EXECUTED: CampaignTaskStatus.EXECUTED,
            ActionStatus.INFRASTRUCTURE_FAILURE: CampaignTaskStatus.INFRASTRUCTURE_FAILURE,
            ActionStatus.POLICY_DENIED: CampaignTaskStatus.POLICY_DENIED,
            ActionStatus.AUTHORIZED: CampaignTaskStatus.READY,
        }[status]

    def _record(
        self,
        task: CampaignTask,
        status: CampaignTaskStatus,
        reason: str,
        *,
        output: Any = None,
        audit_event: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        record = {
            "task_id": task.task_id,
            "engagement_id": task.engagement_id,
            "vulnerability_class": task.vulnerability_class,
            "hypothesis_id": task.hypothesis_id,
            "status": status.value,
            "reason": reason[:240],
            "idempotency_key": task.normalized_idempotency_key(),
            "output_available": output is not None,
            "audit_event": dict(audit_event or {}),
            "proof_bundle": None,
            "proof_bundle_sealed": False,
        }
        if status == CampaignTaskStatus.EXECUTED and isinstance(output, Mapping):
            evidence = output.get("proof_evidence")
            if isinstance(evidence, (list, tuple)) and evidence:
                evidence_refs = output.get("evidence_refs", ())
                if isinstance(evidence_refs, str):
                    evidence_refs = (evidence_refs,)
                if not isinstance(evidence_refs, (list, tuple)):
                    evidence_refs = ()
                bundle = build_proof_bundle(
                    engagement_id=task.engagement_id,
                    finding_id=str(output.get("finding_id") or task.hypothesis_id),
                    evidence=list(evidence),
                    evidence_refs=list(evidence_refs),
                    negative_control=output.get("negative_control"),
                ).seal(actor="action_executor")
                record["proof_bundle"] = bundle.model_dump(mode="json")
                record["proof_bundle_sealed"] = bundle.verify_seal()
                record["negative_control_present"] = output.get("negative_control") is not None
        self.coverage[task.task_id] = record
        self.decision_trace.append({"selected_task": task.task_id, "outcome": record})
        return record


class ActionExecutor(CampaignExecutor):
    """Named central execution facade retained for graph and integration callers."""


__all__ = [
    "ActionExecutor",
    "CampaignExecutor",
    "CampaignTask",
    "CampaignTaskStatus",
    "NextBestActionEngine",
    "PlannedAction",
    "resolve_preconditions",
]
