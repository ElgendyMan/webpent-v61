"""Discovery-oriented hypothesis generation for the bounded AVDE layer.

This module deliberately produces hypotheses, not findings.  It consumes a
redacted world-model projection and optional attack-graph metadata, and never
performs I/O, grants authority, or changes canonical promotion policy.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.asros.world_model import SecurityWorldModel
from webpent.models.evidence import redact_sensitive


class DiscoveryHypothesisStatus(str, Enum):
    GENERATED = "generated"
    INVESTIGATING = "investigating"
    BLOCKED = "blocked"
    VALIDATED = "validated"
    REJECTED = "rejected"


class DiscoveryHypothesis(BaseModel):
    """A falsifiable, target-scoped research proposal."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    hypothesis_id: str = Field(min_length=16, max_length=128)
    engagement_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    identity_boundary: str = Field(min_length=3, max_length=300)
    affected_asset: str = Field(min_length=1, max_length=240)
    security_assumption: str = Field(min_length=8, max_length=700)
    failure_condition: str = Field(min_length=8, max_length=700)
    validation_strategy: tuple[str, ...] = Field(min_length=1, max_length=8)
    expected_evidence: tuple[str, ...] = Field(min_length=1, max_length=8)
    source_refs: tuple[str, ...] = Field(min_length=1, max_length=32)
    required_capabilities: tuple[str, ...] = Field(default=(), max_length=16)
    novelty_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    status: DiscoveryHypothesisStatus = DiscoveryHypothesisStatus.GENERATED

    @field_validator(
        "validation_strategy",
        "expected_evidence",
        "source_refs",
        "required_capabilities",
    )
    @classmethod
    def _clean_items(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        cleaned: list[str] = []
        for value in values:
            redacted, _ = redact_sensitive(str(value))
            if redacted.strip():
                cleaned.append(redacted.strip()[:320])
        return tuple(dict.fromkeys(cleaned))

    @classmethod
    def stable_id(cls, *, target_id: str, asset: str, condition: str) -> str:
        payload = json.dumps(
            {"asset": asset.strip(), "condition": condition.strip(), "target": target_id.strip()},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()


class DiscoveryHypothesisEngine:
    """Generate novel hypotheses from invariants, deviations, and graph hints."""

    def generate(
        self,
        world_model: SecurityWorldModel,
        *,
        observations: Iterable[Mapping[str, Any]] = (),
        attack_graph: Iterable[Mapping[str, Any]] = (),
        prior_hypotheses: Iterable[DiscoveryHypothesis] = (),
    ) -> tuple[DiscoveryHypothesis, ...]:
        if not isinstance(world_model, SecurityWorldModel):
            raise TypeError("security_world_model_required")
        prior_ids = {item.hypothesis_id for item in prior_hypotheses}
        graph = tuple(self._redacted_mapping(item) for item in attack_graph)
        observed = tuple(self._redacted_mapping(item) for item in observations)
        generated: list[DiscoveryHypothesis] = []
        for invariant in world_model.invariants:
            related_deviation = any(
                str(item.get("asset", item.get("protected_resource", "")))
                == invariant.protected_resource
                and str(item.get("status", "")) in {"deviation", "unexpected"}
                for item in observed
            ) or any(
                behaviour.subject == invariant.protected_resource
                and behaviour.status.value == "deviation"
                for behaviour in world_model.behaviours
            )
            graph_hint = next(
                (
                    item
                    for item in graph
                    if str(item.get("asset", item.get("resource", "")))
                    == invariant.protected_resource
                ),
                {},
            )
            condition = (
                f"{invariant.statement} is false for a subject outside the allowed "
                "condition under a controlled candidate/control comparison."
            )
            hypothesis_id = DiscoveryHypothesis.stable_id(
                target_id=world_model.target_id,
                asset=invariant.protected_resource,
                condition=condition,
            )
            if hypothesis_id in prior_ids:
                continue
            capability = str(graph_hint.get("required_capability", "analysis"))
            confidence = min(
                0.9, invariant.lineage.confidence + (0.15 if related_deviation else 0.0)
            )
            novelty = 0.85 if related_deviation else 0.7
            generated.append(
                DiscoveryHypothesis(
                    hypothesis_id=hypothesis_id,
                    engagement_id=world_model.engagement_id,
                    target_id=world_model.target_id,
                    identity_boundary=invariant.subject,
                    affected_asset=invariant.protected_resource,
                    security_assumption=invariant.statement,
                    failure_condition=condition,
                    validation_strategy=(
                        "establish safe precondition",
                        "run authorized candidate/control comparison",
                        "require causal oracle and central proof references",
                    ),
                    expected_evidence=(
                        "redacted candidate observation",
                        "independent negative-control observation",
                        "central verifier result",
                    ),
                    source_refs=invariant.lineage.evidence_refs,
                    required_capabilities=(capability,),
                    novelty_score=novelty,
                    confidence=confidence,
                )
            )
        return tuple(sorted(generated, key=lambda item: (-item.novelty_score, item.hypothesis_id)))

    @staticmethod
    def _redacted_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise TypeError("mapping_required")
        return {
            str(key)[:80]: re.sub(
                r"(?i)(token|secret|password|cookie|authorization)\s*[:=]\s*[^\s,;]+",
                "[REDACTED]",
                redact_sensitive(str(item))[0],
            )[:320]
            for key, item in value.items()
            if str(key).lower() not in {"body", "raw", "token", "cookie", "secret"}
        }


__all__ = [
    "DiscoveryHypothesis",
    "DiscoveryHypothesisEngine",
    "DiscoveryHypothesisStatus",
]
