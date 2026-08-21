"""Deterministic evidence-quality assessment for security findings.

This module separates three concepts that must not be conflated:

* a detector observed a suspicious condition;
* the observation has enough causal and control evidence to be useful;
* the finding is confirmed and reproducible by an auditor.

The assessor never executes requests and never trusts an LLM-emitted score.
It consumes only normalized finding/evidence data and fails closed when proof
signals are missing or contradictory.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from webpent.models.proof_bundle import validate_proof_bundle


class EvidenceClassification(str, Enum):
    """Closed set of evidence postures exposed to reports and operators."""

    CONFIRMED = "confirmed"
    SUPPORTED = "supported"
    NEEDS_HUMAN_REVIEW = "needs_human_review"
    UNCONFIRMED = "unconfirmed"
    CLEAN = "clean"
    NOT_SCANNED = "not_scanned"


class EvidenceAssessment(BaseModel):
    """Safe, value-free assessment of one finding's evidence posture."""

    model_config = ConfigDict(extra="forbid")

    classification: EvidenceClassification
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    causal_signal: bool = False
    negative_control_complete: bool = False
    proof_bundle_valid: bool = False
    reproducible: bool = False
    contradictory_signal: bool = False
    present_signals: list[str] = Field(default_factory=list, max_length=12)
    missing_signals: list[str] = Field(default_factory=list, max_length=12)
    reasons: list[str] = Field(default_factory=list, max_length=12)


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        try:
            dumped = value.model_dump(mode="json")
            return dumped if isinstance(dumped, dict) else {}
        except Exception:
            return {}
    return {}


def _finding_parts(finding: Any) -> tuple[str, dict[str, Any], dict[str, Any]]:
    data = _as_dict(finding)
    evidence = _as_dict(data.get("evidence"))
    evidence_bundle = _as_dict(data.get("evidence_bundle"))
    return str(data.get("confidence_level") or ""), evidence, evidence_bundle


def _has_reproduction(evidence: dict[str, Any], evidence_bundle: dict[str, Any]) -> bool:
    reproduction = evidence.get("reproduction")
    if isinstance(reproduction, dict) and reproduction:
        return True
    if evidence.get("steps_to_reproduce") or evidence.get("proof"):
        return True
    request = evidence_bundle.get("request")
    response = evidence_bundle.get("response")
    if request and response:
        return True
    # Sealed proof bundles contain bounded replay evidence rather than the
    # legacy request/response envelope.
    return bool(evidence_bundle.get("sealed") and evidence_bundle.get("evidence"))


def _proof_bundle(finding_data: dict[str, Any], evidence: dict[str, Any]) -> Any:
    direct = finding_data.get("proof_bundle")
    if direct:
        return direct
    return evidence.get("proof_bundle")


def _bool_signal(evidence: dict[str, Any], name: str) -> bool:
    if evidence.get(name) is True:
        return True
    assessment = evidence.get("assessment")
    return isinstance(assessment, dict) and assessment.get(name) is True


def annotate_finding_evidence(finding: Any) -> Any:
    """Attach a value-free assessment to a Pydantic finding when possible.

    The annotation is informational and deterministic; it never changes the
    finding's confidence tier. Promotion remains owned by the validator's
    existing proof gates.
    """
    assessment = assess_finding_evidence(finding)
    if not hasattr(finding, "model_copy"):
        return finding
    data = _as_dict(finding)
    evidence = _as_dict(data.get("evidence"))
    evidence["evidence_quality"] = assessment.model_dump(mode="json")
    return finding.model_copy(update={"evidence": evidence})


def assess_finding_evidence(finding: Any) -> EvidenceAssessment:
    """Assess evidence using bounded deterministic signals only.

    ``Tool-Confirmed`` is considered evidence-confirmed only when all of the
    following are present: a causal signal, a completed negative control, a
    valid sealed proof bundle requiring that control, and reproducible evidence.
    A contradictory validator result always wins and produces ``unconfirmed``.
    """
    level, evidence, evidence_bundle = _finding_parts(finding)
    if level == "Clean":
        return EvidenceAssessment(
            classification=EvidenceClassification.CLEAN,
            reasons=["detector_reported_clean"],
        )
    if level == "Not Scanned":
        return EvidenceAssessment(
            classification=EvidenceClassification.NOT_SCANNED,
            reasons=["validation_not_completed"],
        )

    causal_signal = _bool_signal(evidence, "causal_signal")
    negative_control_complete = _bool_signal(evidence, "negative_control_complete")
    proof_bundle_valid = validate_proof_bundle(
        _proof_bundle(_as_dict(finding), evidence), require_negative_control=True
    )
    reproducible = _has_reproduction(evidence, evidence_bundle) or proof_bundle_valid
    contradictory_signal = bool(
        evidence.get("contradictory_evidence") is True
        or evidence.get("validation_failure_reason") in {"llm_rejected", "contradictory"}
        or (
            isinstance(evidence.get("assessment"), dict)
            and evidence["assessment"].get("status") in {"rejected", "contradictory"}
        )
    )

    present_signals: list[str] = []
    missing_signals: list[str] = []
    for name, present in (
        ("causal_signal", causal_signal),
        ("negative_control_complete", negative_control_complete),
        ("sealed_proof_bundle", proof_bundle_valid),
        ("reproducible_evidence", reproducible),
    ):
        (present_signals if present else missing_signals).append(name)

    score = sum(
        weight
        for present, weight in (
            (causal_signal, 0.25),
            (negative_control_complete, 0.25),
            (proof_bundle_valid, 0.30),
            (reproducible, 0.20),
        )
        if present
    )
    reasons: list[str] = []
    if contradictory_signal:
        classification = EvidenceClassification.UNCONFIRMED
        score = 0.0
        reasons.append("contradictory_validation_signal")
    elif (
        level == "Tool-Confirmed"
        and causal_signal
        and negative_control_complete
        and proof_bundle_valid
        and reproducible
    ):
        classification = EvidenceClassification.CONFIRMED
        reasons.append("causal_signal_negative_control_and_replayable_proof_present")
    elif causal_signal or negative_control_complete or proof_bundle_valid or reproducible:
        classification = (
            EvidenceClassification.NEEDS_HUMAN_REVIEW
            if level == "Tool-Confirmed"
            or causal_signal
            or negative_control_complete
            else EvidenceClassification.SUPPORTED
        )
        reasons.append("evidence_present_but_confirmation_contract_incomplete")
    else:
        classification = EvidenceClassification.UNCONFIRMED
        reasons.append("no_replayable_causal_evidence")

    return EvidenceAssessment(
        classification=classification,
        score=round(min(1.0, max(0.0, score)), 4),
        causal_signal=causal_signal,
        negative_control_complete=negative_control_complete,
        proof_bundle_valid=proof_bundle_valid,
        reproducible=reproducible,
        contradictory_signal=contradictory_signal,
        present_signals=present_signals,
        missing_signals=missing_signals,
        reasons=reasons,
    )


__all__ = [
    "EvidenceAssessment",
    "EvidenceClassification",
    "annotate_finding_evidence",
    "assess_finding_evidence",
]
