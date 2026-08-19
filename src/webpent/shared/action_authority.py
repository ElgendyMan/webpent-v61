"""Central policy gate for autonomous actions.

This module intentionally separates authorization from transport. It never
constructs HTTP requests or shell commands; callers provide a handler only
after the request has passed the deterministic gates here.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlsplit

from webpent.config.settings import ScanMode, Settings, get_settings
from webpent.shared.action_ledger import SQLiteActionLedger
from webpent.shared.capability_manifest import capability_available


class ActionRisk(str, Enum):
    """Risk tiers used by the authority gate."""

    READ_ONLY = "read_only"
    ACTIVE = "active"
    DESTRUCTIVE = "destructive"


class ActionStatus(str, Enum):
    """Typed authorization/execution outcomes."""

    AUTHORIZED = "authorized"
    POLICY_DENIED = "policy_denied"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"
    EXECUTED = "executed"


@dataclass(frozen=True)
class ActionRequest:
    """Bounded action intent; it is not a transport request."""

    task_id: str
    engagement_id: str
    target_url: str
    method: str = "GET"
    action_family: str = "http_read"
    capability: str = "http_read"
    risk: ActionRisk = ActionRisk.READ_ONLY
    identity_ref: str = "anonymous"
    idempotency_key: str = ""
    estimated_cost: float = 1.0
    human_approved: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ActionDecision:
    """Immutable policy decision with machine-readable reasons."""

    status: ActionStatus
    reasons: tuple[str, ...]
    audit_event: dict[str, Any]

    @property
    def allowed(self) -> bool:
        return self.status == ActionStatus.AUTHORIZED


@dataclass(frozen=True)
class ActionResult:
    """Execution result returned by the central executor."""

    status: ActionStatus
    decision: ActionDecision
    output: Any = None


class ActionAuthority:
    """Deterministic, fail-closed policy authority for one engagement."""

    _ALLOWED_FAMILIES = frozenset(
        {
            "http_read",
            "browser_read",
            "browser_action",
            "recon",
            "validation",
            "workflow",
            "form_submit",
            "file_upload",
            "oob",
        }
    )
    _READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        allowed_origin: str,
        manifest: dict[str, Any] | None = None,
        used_actions: int = 0,
        used_budget: float = 0.0,
        ledger: SQLiteActionLedger | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.allowed_origin = self._normalize_origin(allowed_origin)
        self.manifest = manifest or {}
        self.used_actions = used_actions
        self.used_budget = used_budget
        self.ledger = ledger
        self.trace: list[dict[str, Any]] = []

    @staticmethod
    def _normalize_origin(value: str) -> str:
        parsed = urlsplit(str(value or "").strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        host = parsed.hostname.lower()
        port = parsed.port
        default_port = (parsed.scheme.lower() == "http" and port in {None, 80}) or (
            parsed.scheme.lower() == "https" and port in {None, 443}
        )
        return f"{parsed.scheme.lower()}://{host}{'' if default_port else f':{port}'}"

    def _decision(
        self, request: ActionRequest, reasons: list[str], status: ActionStatus
    ) -> ActionDecision:
        event = {
            "task_id": request.task_id[:128],
            "engagement_id": request.engagement_id[:128],
            "action_family": request.action_family[:64],
            "method": request.method.upper()[:16],
            "risk": request.risk.value,
            "identity_ref": request.identity_ref[:128],
            "status": status.value,
            "reasons": tuple(reasons),
        }
        self.trace.append(event)
        return ActionDecision(status=status, reasons=tuple(reasons), audit_event=event)

    def authorize(self, request: ActionRequest) -> ActionDecision:
        """Authorize an action without invoking any external handler."""
        reasons: list[str] = []
        method = request.method.upper().strip()
        mode = getattr(self.settings.scan_mode, "value", self.settings.scan_mode)
        target_origin = self._normalize_origin(request.target_url)

        if not request.task_id or not request.engagement_id:
            reasons.append("identity:task_and_engagement_required")
        if request.action_family not in self._ALLOWED_FAMILIES:
            reasons.append("policy:action_family_not_allowlisted")
        if not self.allowed_origin or target_origin != self.allowed_origin:
            reasons.append("scope:target_origin_mismatch")
        if method not in self._READ_METHODS:
            if mode != ScanMode.AUTHORIZED_ACTIVE.value:
                reasons.append("policy:active_method_requires_authorized_active_profile")
            if not request.human_approved and not self.settings.smart_auto_approve:
                reasons.append("approval:active_action_not_approved")
        if request.risk == ActionRisk.DESTRUCTIVE:
            reasons.append("policy:destructive_actions_are_not_autonomous")
        if request.risk == ActionRisk.ACTIVE and mode != ScanMode.AUTHORIZED_ACTIVE.value:
            reasons.append("policy:active_risk_requires_authorized_active_profile")
        if not capability_available(self.manifest, request.capability):
            reasons.append(f"capability:{request.capability}:unavailable")
        if (
            request.estimated_cost <= 0
            or request.estimated_cost > self.settings.smart_action_budget
        ):
            reasons.append("budget:invalid_or_over_engagement_limit")
        if self.used_actions >= self.settings.smart_max_actions:
            reasons.append("budget:max_actions_exhausted")
        if self.used_budget + request.estimated_cost > self.settings.smart_action_budget:
            reasons.append("budget:action_budget_exhausted")
        if self.settings.smart_require_idempotency and not request.idempotency_key.strip():
            reasons.append("idempotency:key_required")

        status = ActionStatus.POLICY_DENIED if reasons else ActionStatus.AUTHORIZED
        return self._decision(request, reasons, status)

    def execute(
        self, request: ActionRequest, handler: Callable[[ActionRequest], Any]
    ) -> ActionResult:
        """Authorize, then invoke a caller-supplied handler exactly once."""
        decision = self.authorize(request)
        if not decision.allowed:
            return ActionResult(status=decision.status, decision=decision)
        method = request.method.upper().strip()
        reservation = None
        if self.ledger is not None:
            reservation = self.ledger.reserve(
                idempotency_key=request.idempotency_key,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                target_origin=self._normalize_origin(request.target_url),
                method=method,
                action_family=request.action_family,
                identity_ref=request.identity_ref,
                tenant_context=str(request.metadata.get("tenant_context", "unknown")),
                vulnerability_class=str(request.metadata.get("vulnerability_class", "unknown")),
                validator_id=str(request.metadata.get("validator_id", "")),
                estimated_cost=request.estimated_cost,
                max_actions=self.settings.smart_max_actions,
                max_budget=self.settings.smart_action_budget,
            )
            if not reservation.allowed:
                denied = self._decision(
                    request,
                    [reservation.reason or "ledger:reservation_denied"],
                    ActionStatus.POLICY_DENIED,
                )
                return ActionResult(status=denied.status, decision=denied)
            self.used_actions = max(self.used_actions, reservation.used_actions)
            self.used_budget = max(self.used_budget, reservation.used_budget)

        try:
            output = handler(request)
        except Exception as exc:  # pragma: no cover - exact exception belongs to transport
            if self.ledger is not None:
                self.ledger.complete(
                    request.engagement_id, request.idempotency_key, status="failed"
                )
            failure = self._decision(
                request,
                [f"handler:infrastructure_failure:{type(exc).__name__}"],
                ActionStatus.INFRASTRUCTURE_FAILURE,
            )
            return ActionResult(status=failure.status, decision=failure)
        self.used_actions += 1 if reservation is None else 0
        self.used_budget += request.estimated_cost if reservation is None else 0.0
        if self.ledger is not None:
            self.ledger.complete(
                request.engagement_id, request.idempotency_key, status="executed"
            )
        executed = self._decision(request, [], ActionStatus.EXECUTED)
        return ActionResult(status=executed.status, decision=executed, output=output)
