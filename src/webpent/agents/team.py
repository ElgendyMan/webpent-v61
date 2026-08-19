"""Explicit multi-agent role contracts for the smart campaign.

The registry documents and validates role boundaries. It does not dispatch tools,
approve actions, or promote findings; those decisions remain in the existing
scope and proof gates.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class AgentRoleSpec:
    """Static responsibility contract for one agent role."""

    role: str
    implementation: str
    responsibilities: tuple[str, ...]
    required_inputs: tuple[str, ...]
    emitted_artifacts: tuple[str, ...]


ROLE_SPECS: tuple[AgentRoleSpec, ...] = (
    AgentRoleSpec(
        role="recon",
        implementation="webpent.agents.recon.agent",
        responsibilities=("discover assets", "collect passive surface evidence"),
        required_inputs=("target_url", "scope"),
        emitted_artifacts=("surface_observation", "evidence_ref"),
    ),
    AgentRoleSpec(
        role="target_understanding",
        implementation="webpent.agents.target_understanding.agent",
        responsibilities=("build target model", "identify workflows and coverage gaps"),
        required_inputs=("target_url", "engagement_id"),
        emitted_artifacts=("target_knowledge", "coverage_gap"),
    ),
    AgentRoleSpec(
        role="hypothesis",
        implementation="webpent.agents.hypothesis_analyzer.agent",
        responsibilities=("rank structured hypotheses", "request bounded experiments"),
        required_inputs=("target_knowledge", "evidence_refs"),
        emitted_artifacts=("hypothesis", "research_action"),
    ),
    AgentRoleSpec(
        role="validator",
        implementation="webpent.agents.validator.agent",
        responsibilities=("replay evidence", "apply negative controls"),
        required_inputs=("hypothesis", "proof_bundle"),
        emitted_artifacts=("validation_result", "proof_bundle"),
    ),
    AgentRoleSpec(
        role="reviewer",
        implementation="webpent.agents.devils_advocate.agent",
        responsibilities=("challenge causal claims", "identify alternative explanations"),
        required_inputs=("validation_result", "negative_control"),
        emitted_artifacts=("review_decision", "review_evidence_ref"),
    ),
)

_ROLE_BY_NAME = {spec.role: spec for spec in ROLE_SPECS}


def get_role_spec(role: str) -> AgentRoleSpec | None:
    """Return a role contract or None for an unknown role."""
    return _ROLE_BY_NAME.get(str(role).strip().lower())


def team_manifest() -> list[dict[str, Any]]:
    """Return JSON-safe role metadata for reports and capability artifacts."""
    return [asdict(spec) for spec in ROLE_SPECS]


def validate_role_artifact(role: str, artifact: Any) -> bool:
    """Accept only a mapping with the role's declared artifact keys."""
    spec = get_role_spec(role)
    if spec is None or not isinstance(artifact, dict):
        return False
    declared = set(spec.emitted_artifacts)
    return any(key in artifact and artifact[key] not in (None, "", [], {}) for key in declared)


__all__ = [
    "AgentRoleSpec",
    "ROLE_SPECS",
    "get_role_spec",
    "team_manifest",
    "validate_role_artifact",
]
