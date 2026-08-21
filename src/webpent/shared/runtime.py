"""Single dependency-injection spine for WebPent runtime actions.

The runtime module is intentionally transport-agnostic.  It constructs policy and
analysis components, but never performs network, browser, subprocess, or OOB I/O.
Those operations must be registered as audited adapters and invoked through the
central :class:`ActionExecutor`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Lock
from typing import Any
from urllib.parse import urlsplit

from webpent.config.settings import Settings, get_settings
from webpent.models.evidence import redact_sensitive
from webpent.shared.action_authority import ActionAuthority
from webpent.shared.action_ledger import SQLiteActionLedger
from webpent.shared.campaign_executor import ActionExecutor
from webpent.shared.capability_manifest import CapabilityRegistry
from webpent.shared.engagement_scope import OriginPolicy
from webpent.shared.proof_oracles import NegativeControlEngine, OracleEngine
from webpent.shared.research_intelligence import (
    KnowledgeGapEngine,
    SmartNextBestActionEngine,
)


class RuntimeConfigurationError(ValueError):
    """Raised when a graph cannot obtain a valid runtime context."""


@dataclass(frozen=True)
class RuntimeEvent:
    """Redacted, correlation-aware event emitted by the runtime spine."""

    event_id: str
    event_type: str
    engagement_id: str
    campaign_id: str
    task_id: str = ""
    action_id: str = ""
    correlation_id: str = ""
    timestamp: str = ""
    payload: Mapping[str, Any] = field(default_factory=dict)


class RuntimeEventSink:
    """Small append-only event sink suitable for tests and worker injection."""

    def __init__(self, *, max_events: int = 5000) -> None:
        self.max_events = max(1, int(max_events))
        self._events: list[RuntimeEvent] = []
        self._lock = Lock()

    @staticmethod
    def _clean(value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean

    def emit(
        self,
        event_type: str,
        *,
        engagement_id: str,
        campaign_id: str,
        task_id: str = "",
        action_id: str = "",
        correlation_id: str = "",
        payload: Mapping[str, Any] | None = None,
    ) -> RuntimeEvent:
        event = RuntimeEvent(
            event_id=f"evt-{datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')}",
            event_type=str(event_type or "unknown")[:80],
            engagement_id=str(engagement_id or "")[:160],
            campaign_id=str(campaign_id or "")[:160],
            task_id=str(task_id or "")[:160],
            action_id=str(action_id or "")[:160],
            correlation_id=str(correlation_id or "")[:160],
            timestamp=datetime.now(UTC).isoformat(),
            payload=self._clean(dict(payload or {})),
        )
        with self._lock:
            self._events.append(event)
            if len(self._events) > self.max_events:
                del self._events[: len(self._events) - self.max_events]
        return event

    def snapshot(self) -> tuple[RuntimeEvent, ...]:
        with self._lock:
            return tuple(self._events)


@dataclass(frozen=True)
class RegisteredAdapter:
    """Audited adapter registration; the handler itself is never serialized."""

    name: str
    capability: str
    transport: str
    handler: Callable[..., Any]
    source: str = "runtime"
    version: str = "unknown"
    policy_checked: bool = False


class AdapterRegistry:
    """Allowlist of explicitly injected adapters.

    Missing adapters are represented as unavailable.  The registry never falls
    back to raw clients, subprocesses, sockets, or arbitrary callables.
    """

    def __init__(self) -> None:
        self._adapters: dict[str, RegisteredAdapter] = {}

    def register(self, adapter: RegisteredAdapter) -> None:
        key = str(adapter.name or "").strip()
        if not key or not adapter.capability.strip() or not adapter.transport.strip():
            raise RuntimeConfigurationError("adapter registration is incomplete")
        if not adapter.policy_checked:
            raise RuntimeConfigurationError(
                f"adapter:{key}:policy_checked_manifest_required"
            )
        if key in self._adapters:
            raise RuntimeConfigurationError(f"adapter:{key}:duplicate_registration")
        self._adapters[key] = adapter

    def get(self, name: str) -> RegisteredAdapter | None:
        return self._adapters.get(str(name or "").strip())

    def available(self, name: str) -> bool:
        return self.get(name) is not None

    def manifest(self) -> list[dict[str, Any]]:
        return [
            {
                "name": adapter.name,
                "capability": adapter.capability,
                "transport": adapter.transport,
                "source": adapter.source,
                "version": adapter.version,
                "policy_checked": adapter.policy_checked,
            }
            for adapter in sorted(self._adapters.values(), key=lambda item: item.name)
        ]


@dataclass(frozen=True)
class RuntimeContext:
    """Explicit dependency-injection context consumed by graph nodes."""

    schema_version: str
    engagement_id: str
    campaign_id: str
    target_origin: str
    settings: Settings
    action_authority: ActionAuthority
    action_executor: ActionExecutor
    scope_matcher: OriginPolicy
    capabilities: CapabilityRegistry
    adapters: AdapterRegistry
    event_sink: RuntimeEventSink
    proof_bundle_store: Any | None
    oracle_engine: OracleEngine
    negative_control_engine: NegativeControlEngine
    coverage_ledger: dict[str, Any]
    identity_tenant_object_graph: Any | None
    workflow_state_machine: Any | None
    replay_engine: Any | None
    knowledge_gap_engine: KnowledgeGapEngine
    next_best_action_engine: SmartNextBestActionEngine
    configuration_errors: tuple[str, ...] = ()

    @property
    def valid(self) -> bool:
        return not self.configuration_errors and bool(
            self.engagement_id and self.campaign_id and self.target_origin
        )

    def require_valid(self) -> RuntimeContext:
        if not self.valid:
            reasons = ",".join(self.configuration_errors) or "identity:runtime_context_incomplete"
            raise RuntimeConfigurationError(reasons)
        return self

    def blocked_result(self, *, node: str, reason: str = "") -> dict[str, Any]:
        """Return the graph-safe result for an unavailable context."""
        detail = reason or ",".join(self.configuration_errors) or "runtime_context_invalid"
        self.event_sink.emit(
            "runtime.blocked_by_configuration",
            engagement_id=self.engagement_id,
            campaign_id=self.campaign_id,
            payload={"node": str(node)[:120], "reason": detail[:300]},
        )
        return {
            "status": "blocked_by_configuration",
            "lifecycle_stage": "blocked_by_configuration",
            "node": str(node)[:120],
            "reason": detail[:300],
            "runtime_context_valid": False,
            "clean": False,
        }

    def diagnostics(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "engagement_id": self.engagement_id,
            "campaign_id": self.campaign_id,
            "target_origin": self.target_origin,
            "valid": self.valid,
            "configuration_errors": list(self.configuration_errors),
            "capabilities": self.capabilities.diagnostics(),
            "adapters": self.adapters.manifest(),
            "event_count": len(self.event_sink.snapshot()),
        }


class RuntimeFactory:
    """Construct one explicit runtime spine for an engagement/campaign."""

    @staticmethod
    def _origin(value: str) -> str:
        parsed = urlsplit(str(value or "").strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        port = parsed.port
        default = (parsed.scheme.lower() == "http" and port in {None, 80}) or (
            parsed.scheme.lower() == "https" and port in {None, 443}
        )
        return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}{'' if default else f':{port}'}"

    @classmethod
    def create(
        cls,
        *,
        engagement_id: str,
        campaign_id: str,
        target_origin: str,
        settings: Settings | None = None,
        manifest: dict[str, Any] | None = None,
        ledger: SQLiteActionLedger | None = None,
        use_default_ledger: bool = True,
        used_actions: int = 0,
        used_budget: float = 0.0,
        event_sink: RuntimeEventSink | None = None,
        adapters: AdapterRegistry | None = None,
        proof_bundle_store: Any | None = None,
        identity_tenant_object_graph: Any | None = None,
        workflow_state_machine: Any | None = None,
        replay_engine: Any | None = None,
    ) -> RuntimeContext:
        settings = settings or get_settings()
        normalized_engagement = str(engagement_id or "").strip()[:160]
        normalized_campaign = str(campaign_id or "").strip()[:160]
        normalized_origin = cls._origin(target_origin)
        errors: list[str] = []
        if not normalized_engagement:
            errors.append("identity:engagement_id_required")
        if not normalized_campaign:
            errors.append("identity:campaign_id_required")
        if not normalized_origin:
            errors.append("scope:valid_http_origin_required")

        try:
            scope_matcher = OriginPolicy.from_url(normalized_origin)
        except ValueError:
            errors.append("scope:origin_policy_invalid")
            scope_matcher = OriginPolicy.from_url("http://127.0.0.1")

        capability_registry = CapabilityRegistry(settings)
        if manifest is not None:
            capability_registry._manifest = dict(manifest)
        else:
            capability_registry.ensure_discovered()
        action_ledger = (
            ledger
            if ledger is not None
            else SQLiteActionLedger(settings.action_ledger_path)
            if use_default_ledger
            else None
        )
        authority = ActionAuthority(
            settings=settings,
            allowed_origin=normalized_origin,
            manifest=capability_registry.ensure_discovered(),
            used_actions=max(0, int(used_actions)),
            used_budget=max(0.0, float(used_budget)),
            ledger=action_ledger,
        )
        executor = ActionExecutor(authority)
        sink = event_sink or RuntimeEventSink()
        registry = adapters or AdapterRegistry()
        sink.emit(
            "runtime.created",
            engagement_id=normalized_engagement,
            campaign_id=normalized_campaign,
            payload={"target_origin": normalized_origin},
        )
        return RuntimeContext(
            schema_version="runtime-context-v1",
            engagement_id=normalized_engagement,
            campaign_id=normalized_campaign,
            target_origin=normalized_origin,
            settings=settings,
            action_authority=authority,
            action_executor=executor,
            scope_matcher=scope_matcher,
            capabilities=capability_registry,
            adapters=registry,
            event_sink=sink,
            proof_bundle_store=proof_bundle_store,
            oracle_engine=OracleEngine(),
            negative_control_engine=NegativeControlEngine(),
            coverage_ledger={},
            identity_tenant_object_graph=identity_tenant_object_graph,
            workflow_state_machine=workflow_state_machine,
            replay_engine=replay_engine,
            knowledge_gap_engine=KnowledgeGapEngine(),
            next_best_action_engine=SmartNextBestActionEngine(),
            configuration_errors=tuple(dict.fromkeys(errors)),
        )

    @staticmethod
    def blocked_result(*, node: str, reason: str) -> dict[str, Any]:
        return {
            "status": "blocked_by_configuration",
            "lifecycle_stage": "blocked_by_configuration",
            "node": str(node)[:120],
            "reason": str(reason or "runtime_context_unavailable")[:300],
            "runtime_context_valid": False,
            "clean": False,
        }


__all__ = [
    "AdapterRegistry",
    "RegisteredAdapter",
    "RuntimeConfigurationError",
    "RuntimeContext",
    "RuntimeEvent",
    "RuntimeEventSink",
    "RuntimeFactory",
]
