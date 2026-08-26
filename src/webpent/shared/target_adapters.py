"""Explicit, target-scoped adapter contracts for evidence workflows.

The shared proof infrastructure must not know target-specific routes, challenge
IDs, or semantic fingerprints.  A target adapter supplies those facts through
an explicit immutable registration.  Missing or mismatched registrations fail
closed; there is no default target and no cross-target fallback.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

from webpent.shared.semantic_observations import (
    SemanticProfileRegistry,
)


@dataclass(frozen=True)
class TargetCaseBinding:
    """Target-local case metadata used by an orchestrator."""

    case_id: str
    operation: str
    path: str
    oracle_id: str
    workflow_id: str
    semantic_profile: str | None = None
    scoring_status: str = "not_scored"

    def __post_init__(self) -> None:
        if not str(self.case_id).strip() or not str(self.path).strip():
            raise ValueError("target_case_binding_identity_required")
        if not str(self.oracle_id).strip():
            raise ValueError("target_case_binding_oracle_id_required")
        if not str(self.workflow_id).strip():
            raise ValueError("target_case_binding_workflow_id_required")
        if self.operation not in {"navigate", "typed_search"}:
            raise ValueError("target_case_binding_operation_not_allowlisted")
        if self.semantic_profile is not None and not str(self.semantic_profile).strip():
            raise ValueError("target_case_binding_semantic_profile_invalid")
        if not str(self.scoring_status).strip():
            raise ValueError("target_case_binding_scoring_status_required")


WorkflowExecutor = Callable[[Any, str, int], str | None]


@runtime_checkable
class TargetAdapter(Protocol):
    """Minimal target-specific surface required by generic proof orchestration."""

    target_id: str
    target_origin: str
    semantic_profiles: SemanticProfileRegistry

    def workflow_ids(self) -> Sequence[str]:
        """Return reviewed workflow IDs allowed for this target."""

    def workflow_executors(self) -> Mapping[str, WorkflowExecutor]:
        """Return target-local executors for workflows that perform browser I/O."""

    def case_ids(self) -> Sequence[str]:
        """Return the immutable execution set for this target."""

    def case(self, case_id: str) -> TargetCaseBinding | None:
        """Return one target-local case binding, or ``None``."""

    def semantic_profile_for_case(self, case_id: str) -> str | None:
        """Return an explicitly registered profile, never an inferred fallback."""

    def accepts_origin(self, origin: str) -> bool:
        """Return whether an origin belongs to this adapter."""


@dataclass(frozen=True)
class RegisteredTargetAdapter:
    """Auditable target adapter registration."""

    adapter: TargetAdapter
    source: str
    version: str
    policy_ref: str
    proof_contract: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def target_id(self) -> str:
        return str(self.adapter.target_id).strip()

    def validate(self) -> tuple[str, ...]:
        if not isinstance(self.adapter, TargetAdapter):
            return ("target_adapter:adapter_contract_invalid",)
        errors: list[str] = []
        if not self.target_id:
            errors.append("target_adapter:target_id_required")
        if not str(self.adapter.target_origin).strip():
            errors.append(f"target_adapter:{self.target_id}:origin_required")
        if not str(self.source).strip():
            errors.append(f"target_adapter:{self.target_id}:source_required")
        if not str(self.version).strip():
            errors.append(f"target_adapter:{self.target_id}:version_required")
        if not str(self.policy_ref).strip():
            errors.append(f"target_adapter:{self.target_id}:policy_ref_required")
        if not str(self.proof_contract).strip():
            errors.append(f"target_adapter:{self.target_id}:proof_contract_required")
        if not isinstance(self.adapter.semantic_profiles, SemanticProfileRegistry):
            errors.append(f"target_adapter:{self.target_id}:semantic_registry_required")
        normalized_origin = _origin(self.adapter.target_origin)
        if not normalized_origin:
            errors.append(f"target_adapter:{self.target_id}:origin_invalid")
        else:
            try:
                if self.adapter.accepts_origin(normalized_origin) is not True:
                    errors.append(f"target_adapter:{self.target_id}:origin_not_accepted")
            except Exception as exc:
                errors.append(
                    f"target_adapter:{self.target_id}:origin_check_failed:{type(exc).__name__}"
                )

        try:
            workflows = tuple(str(item).strip() for item in self.adapter.workflow_ids())
        except Exception as exc:
            workflows = ()
            errors.append(
                f"target_adapter:{self.target_id}:workflow_ids_failed:{type(exc).__name__}"
            )
        if not workflows or any(not item for item in workflows):
            errors.append(f"target_adapter:{self.target_id}:workflow_allowlist_required")
        if len(set(workflows)) != len(workflows):
            errors.append(f"target_adapter:{self.target_id}:workflow_allowlist_duplicate")
        workflow_set = frozenset(workflows)

        try:
            raw_executors = self.adapter.workflow_executors()
        except Exception as exc:
            raw_executors = {}
            errors.append(
                f"target_adapter:{self.target_id}:workflow_executors_failed:{type(exc).__name__}"
            )
        if not isinstance(raw_executors, Mapping):
            raw_executors = {}
            errors.append(
                f"target_adapter:{self.target_id}:workflow_executors_invalid"
            )
        executor_keys = tuple(str(key).strip() for key in raw_executors)
        if len(set(executor_keys)) != len(executor_keys):
            errors.append(
                f"target_adapter:{self.target_id}:workflow_executor_duplicate"
            )
        if any(key not in workflow_set for key in executor_keys):
            errors.append(
                f"target_adapter:{self.target_id}:workflow_executor_not_allowlisted"
            )
        for key, executor in raw_executors.items():
            if str(key).strip() in workflow_set and not callable(executor):
                errors.append(
                    f"target_adapter:{self.target_id}:workflow_executor_not_callable:{str(key).strip()}"
                )

        try:
            case_ids = tuple(str(item).strip() for item in self.adapter.case_ids())
        except Exception as exc:
            case_ids = ()
            errors.append(
                f"target_adapter:{self.target_id}:case_ids_failed:{type(exc).__name__}"
            )
        if not case_ids:
            errors.append(f"target_adapter:{self.target_id}:case_ids_required")
        if any(not item for item in case_ids):
            errors.append(f"target_adapter:{self.target_id}:case_id_invalid")
        if len(set(case_ids)) != len(case_ids):
            errors.append(f"target_adapter:{self.target_id}:case_id_duplicate")

        if isinstance(self.adapter.semantic_profiles, SemanticProfileRegistry):
            for case_id in case_ids:
                try:
                    binding = self.adapter.case(case_id)
                    declared_profile = self.adapter.semantic_profile_for_case(case_id)
                except Exception as exc:
                    errors.append(
                        f"target_adapter:{self.target_id}:case_resolution_failed:"
                        f"{case_id}:{type(exc).__name__}"
                    )
                    continue
                if binding is None:
                    errors.append(
                        f"target_adapter:{self.target_id}:case_missing:{case_id}"
                    )
                    continue
                if binding.case_id != case_id:
                    errors.append(
                        f"target_adapter:{self.target_id}:case_identity_mismatch:{case_id}"
                    )
                if binding.workflow_id not in workflow_set:
                    errors.append(
                        f"target_adapter:{self.target_id}:case_workflow_not_allowlisted:{case_id}"
                    )
                if (
                    binding.operation == "typed_search"
                    and (
                        binding.workflow_id not in raw_executors
                        or not callable(raw_executors.get(binding.workflow_id))
                    )
                ):
                    errors.append(
                        f"target_adapter:{self.target_id}:typed_workflow_executor_missing:{case_id}"
                    )
                if declared_profile != binding.semantic_profile:
                    errors.append(
                        f"target_adapter:{self.target_id}:case_profile_mismatch:{case_id}"
                    )
                if (
                    binding.semantic_profile is not None
                    and self.adapter.semantic_profiles.contract(binding.semantic_profile)
                    is None
                ):
                    errors.append(
                        f"target_adapter:{self.target_id}:case_profile_not_registered:{case_id}"
                    )
        return tuple(errors)


class TargetAdapterRegistry:
    """Explicit registry with origin matching and no implicit fallback."""

    def __init__(self) -> None:
        self._targets: dict[str, RegisteredTargetAdapter] = {}

    def register(self, registration: RegisteredTargetAdapter) -> None:
        errors = registration.validate()
        if errors:
            raise ValueError(";".join(errors))
        key = registration.target_id
        if key in self._targets:
            raise ValueError(f"target_adapter:{key}:duplicate_registration")
        self._targets[key] = registration

    def get(self, target_id: str) -> RegisteredTargetAdapter | None:
        return self._targets.get(str(target_id or "").strip())

    def for_origin(self, origin: str) -> RegisteredTargetAdapter | None:
        normalized = _origin(origin)
        if not normalized:
            return None
        matches: list[RegisteredTargetAdapter] = []
        for item in self._targets.values():
            # Registrations are immutable, but their injected adapter may be
            # mutable. Revalidate before every origin lookup so a post-register
            # mutation or provider failure cannot become executable implicitly.
            try:
                if item.validate():
                    continue
                accepted = item.adapter.accepts_origin(normalized)
            except Exception:
                accepted = False
            if accepted is True:
                matches.append(item)
        return matches[0] if len(matches) == 1 else None

    def require_for_origin(self, origin: str) -> RegisteredTargetAdapter:
        registration = self.for_origin(origin)
        if registration is None:
            raise ValueError("target_adapter_origin_not_registered_or_ambiguous")
        return registration

    def manifest(self) -> list[dict[str, Any]]:
        return [
            {
                "target_id": item.target_id,
                "target_origin": _origin(item.adapter.target_origin),
                "source": item.source,
                "version": item.version,
                "policy_ref": item.policy_ref,
                "proof_contract": item.proof_contract,
                "case_count": len(tuple(item.adapter.case_ids())),
            }
            for item in sorted(self._targets.values(), key=lambda value: value.target_id)
        ]


def _origin(value: str) -> str:
    parsed = urlsplit(str(value or ""))
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    port = parsed.port
    default = (parsed.scheme.lower() == "http" and port in {None, 80}) or (
        parsed.scheme.lower() == "https" and port in {None, 443}
    )
    suffix = "" if default else f":{port}"
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}{suffix}"


__all__ = [
    "RegisteredTargetAdapter",
    "TargetAdapter",
    "TargetAdapterRegistry",
    "TargetCaseBinding",
    "WorkflowExecutor",
]
