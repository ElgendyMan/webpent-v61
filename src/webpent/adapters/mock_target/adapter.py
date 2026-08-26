"""Minimal mock target for adapter-swap and safety-contract tests.

This adapter is intentionally non-networking. Its blocked precondition and
unsupported capability methods are target-local facts consumed only by tests;
the generic core remains unaware of them.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from webpent.shared.semantic_observations import SemanticProfileRegistry
from webpent.shared.target_adapters import (
    RegisteredTargetAdapter,
    TargetCaseBinding,
    TargetManifest,
)
from webpent.shared.workflow_contracts import READ_ONLY_NAVIGATION

MOCK_TARGET_ORIGIN = "http://127.0.0.1:4200"
MOCK_TARGET_CASE_ID = "mock.public_observation.v1"
MOCK_TARGET_ORACLE_ID = "mock.read_only.public_observation"


class MockTargetAdapter:
    """Non-networking adapter with explicit safe and blocked capabilities."""

    target_id = "mock_target"
    target_origin = MOCK_TARGET_ORIGIN
    semantic_profiles = SemanticProfileRegistry({})

    def workflow_ids(self) -> tuple[str, ...]:
        return (READ_ONLY_NAVIGATION,)

    def workflow_executors(self) -> dict[str, object]:
        return {}

    def case_ids(self) -> tuple[str, ...]:
        return (MOCK_TARGET_CASE_ID,)

    def case(self, case_id: str) -> TargetCaseBinding | None:
        if str(case_id or "").strip() != MOCK_TARGET_CASE_ID:
            return None
        return TargetCaseBinding(
            case_id=MOCK_TARGET_CASE_ID,
            operation="navigate",
            path="/status",
            oracle_id=MOCK_TARGET_ORACLE_ID,
            workflow_id=READ_ONLY_NAVIGATION,
            semantic_profile=None,
            scoring_status="fixture_only_not_benchmark_scored",
        )

    def semantic_profile_for_case(self, case_id: str) -> str | None:
        if str(case_id or "").strip() == MOCK_TARGET_CASE_ID:
            return None
        return None

    def accepts_origin(self, origin: str) -> bool:
        return _normalize_origin(origin) == MOCK_TARGET_ORIGIN

    def preconditions_ready(self, case_id: str) -> bool:
        """Return false for the fixture: no live target has been started."""
        return False if str(case_id or "").strip() == MOCK_TARGET_CASE_ID else False

    def supports_operation(self, operation: str) -> bool:
        """Expose the intentionally unsupported typed-search capability."""
        return str(operation or "").strip() == "navigate"


MOCK_TARGET_ADAPTER = MockTargetAdapter()
MOCK_TARGET_REGISTRATION = RegisteredTargetAdapter(
    adapter=MOCK_TARGET_ADAPTER,
    source="webpent.adapters.mock_target.adapter",
    version="1",
    policy_ref="non-networking-mock-fixture",
    proof_contract="central-causal-negative-sealed-replay-v1",
    manifest=TargetManifest(
        target_id="mock_target",
        adapter_version="1",
        supported_capabilities=frozenset({"read_only_navigation"}),
        supported_case_types=frozenset({"navigate"}),
        authorization_requirements=("explicit_fixture_authorization", "loopback_origin"),
        allowed_scope=(MOCK_TARGET_ORIGIN,),
        redaction_policy="metadata_only_no_raw_bodies_or_credentials",
        cleanup_policy="fixture_context_dispose_without_target_mutation",
    ),
    metadata={
        "target_family": "mock_target",
        "fixture_only": True,
        "network_io": False,
    },
)


def _normalize_origin(value: str) -> str:
    parsed = urlsplit(str(value or ""))
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    port = parsed.port
    default = (parsed.scheme.lower() == "http" and port in {None, 80}) or (
        parsed.scheme.lower() == "https" and port in {None, 443}
    )
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}" + (
        "" if default else f":{port}"
    )


__all__ = [
    "MOCK_TARGET_ADAPTER",
    "MOCK_TARGET_CASE_ID",
    "MOCK_TARGET_ORIGIN",
    "MOCK_TARGET_REGISTRATION",
    "MockTargetAdapter",
]
