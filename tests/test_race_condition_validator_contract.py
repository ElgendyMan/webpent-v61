from __future__ import annotations

import hashlib
from typing import Any

from webpent.agents.validator.active_checks import (
    _target_fingerprint,
    validate_race_condition,
)
from webpent.agents.validator.registry import capability_for, validator_id_for
from webpent.models.findings import Finding, Severity

_TARGET_URL = "https://target.example/checkout"


def _finding(evidence: dict[str, Any] | None = None) -> Finding:
    return Finding(
        title="Race condition candidate",
        description="A bounded concurrent workflow probe produced a race candidate.",
        severity=Severity.HIGH,
        tool_name="business_logic_fuzzer",
        vuln_class="race_condition",
        url=_TARGET_URL,
        evidence=evidence,
    )


def _observation(role: str, request_label: str, status_code: int) -> dict[str, Any]:
    digest = hashlib.sha256(request_label.encode()).hexdigest()
    return {
        "target_backed": True,
        "observation_role": role,
        "target_fingerprint": _target_fingerprint(_TARGET_URL),
        "request_digest": f"sha256:{digest}",
        "response_digest": f"sha256:{hashlib.sha256(str(status_code).encode()).hexdigest()}",
        "method": "POST",
        "url": _TARGET_URL,
        "status_code": status_code,
        "body_length": 0,
        "body_sha256": f"sha256:{'0' * 64}",
        "headers": {"content-type": "application/json"},
        "elapsed_ms": 10,
    }


def _race_replay(*, independent_control: bool = True) -> dict[str, Any]:
    return {
        "baseline": _observation("baseline", "baseline", 409),
        "candidate": _observation("candidate", "candidate-burst", 200),
        "negative_control": _observation(
            "negative_control",
            "negative-control" if independent_control else "candidate-burst",
            409,
        ),
        "baseline_successes": 0,
        "candidate_successes": 3,
        "negative_control_successes": 0,
        "burst_size": 10,
        "independent_control": independent_control,
    }


def test_race_condition_is_explicitly_registered() -> None:
    assert validator_id_for("race_condition") == "race_condition"
    capability = capability_for("race_condition")
    assert capability.status == "tested"
    assert capability.evidence_mode == "deterministic"


def test_race_condition_without_proof_replay_stays_human_review() -> None:
    result = validate_race_condition(
        _finding({"race_probe": {"candidate_successes": 3, "burst_size": 10}}),
        verification_context={"engagement_id": "engagement-race"},
    )

    assert result.confidence_level == "Needs Human Review"
    assert result.confidence.value != "confirmed"
    assert result.evidence["validation_unavailable"] is True
    assert result.evidence["validation_failure_reason"] == "race_replay_required"


def test_race_condition_rejects_non_independent_negative_control() -> None:
    result = validate_race_condition(
        _finding({"race_replay": _race_replay(independent_control=False)}),
        verification_context={"engagement_id": "engagement-race"},
    )

    assert result.confidence_level == "Needs Human Review"
    assert result.evidence["promotion_guard"]["reason"] == (
        "causal_signal_and_negative_control_required"
    )


def test_race_condition_requires_real_provenance_for_promotion() -> None:
    result = validate_race_condition(
        _finding({"race_replay": _race_replay()}),
        verification_context={
            "engagement_id": "engagement-race",
            "hypothesis_id": "hypothesis-race",
            "scope_context": {"target_origin": "https://target.example", "scope_bound": True},
            "identity_context": {"mode": "authenticated", "cookie_count": 0},
        },
    )

    assert result.confidence_level == "Tool-Confirmed"
    assert result.evidence["proof_bundle_sealed"] is True
    assert result.evidence["target_backed"] is True
    assert result.evidence["negative_control_independent"] is True
    assert result.evidence_bundle is not None
