"""Strict evidence verifier for deterministic promotion.

The verifier is deliberately small and side-effect free.  It does not perform
network I/O and it never promotes a finding by itself; callers must provide
observations produced by an authorized validator.  It checks that a baseline
and a candidate exist, that the validator supplied independent causal and
negative-control signals, and that the resulting sealed ProofBundle can be
replayed from the redaction-safe observations.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlunparse

from webpent.models.evidence import redact_sensitive
from webpent.models.findings import Finding
from webpent.models.proof_bundle import (
    ProofBundle,
    build_proof_bundle,
    proof_bundle_promotion_ready,
)


@dataclass(frozen=True)
class VerificationResult:
    """Immutable result of one bounded verifier pass."""

    passed: bool
    reason: str
    evidence: dict[str, Any]
    proof_bundle: ProofBundle | None = None


def _target_fingerprint(url: str) -> str:
    """Hash only the stable origin/path shape; never persist query values."""
    parsed = urlparse(str(url))
    shape = urlunparse(parsed._replace(query="", fragment=""))
    return f"sha256:{hashlib.sha256(shape.encode('utf-8', 'replace')).hexdigest()}"


def _digest(value: Any) -> str:
    import json

    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return f"sha256:{hashlib.sha256(encoded.encode('utf-8', 'replace')).hexdigest()}"


def _target_observation_ok(
    value: Any,
    *,
    role: str,
    target_fingerprint: str,
) -> bool:
    """Accept only redacted observations carrying transport-level provenance."""
    if not isinstance(value, Mapping):
        return False
    return bool(
        value.get("target_backed") is True
        and value.get("observation_role") == role
        and value.get("target_fingerprint") == target_fingerprint
        and isinstance(value.get("request_digest"), str)
        and value.get("request_digest", "").startswith("sha256:")
        and isinstance(value.get("response_digest"), str)
        and value.get("response_digest", "").startswith("sha256:")
    )


def verify_replay_evidence(
    finding: Finding,
    *,
    baseline: dict[str, Any] | None,
    candidate: dict[str, Any] | None,
    negative_control: dict[str, Any] | None,
    causal_signal: bool,
    negative_control_complete: bool,
    validator_id: str,
    validator_version: str,
    causal_basis: str,
    engagement_id: str,
    hypothesis_id: str | None = None,
    scope_context: dict[str, Any] | None = None,
    identity_context: dict[str, Any] | None = None,
    replay_metadata: dict[str, Any] | None = None,
    target_package_id: str | None = None,
    target_package_sha256: str | None = None,
    target_package_scope_digest: str | None = None,
    target_package_policy_digest: str | None = None,
    require_target_backed: bool = False,
) -> VerificationResult:
    """Verify a baseline/candidate replay and create a strict proof bundle.

    ``causal_signal`` and ``negative_control_complete`` are accepted only as
    deterministic outputs of the class-specific validator.  The verifier still
    rejects missing observations, missing provenance, missing replay metadata,
    and any bundle that fails its own promotion contract.  It therefore cannot
    turn an LLM assertion or a marker-less response into a confirmation.
    """
    evidence: dict[str, Any] = {
        "verifier": "webpent.replay.v1",
        "causal_signal": bool(causal_signal),
        "negative_control_complete": bool(negative_control_complete),
        "causal_basis": str(causal_basis)[:240],
        "validator_id": str(validator_id)[:120],
        "validator_version": str(validator_version)[:80],
    }
    if baseline is None or candidate is None:
        evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": "baseline_and_candidate_required",
        }
        return VerificationResult(False, "baseline_and_candidate_required", evidence)
    if negative_control is None:
        evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": "negative_control_required",
        }
        return VerificationResult(False, "negative_control_required", evidence)
    if not causal_signal or not negative_control_complete:
        evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": "causal_signal_and_negative_control_required",
        }
        return VerificationResult(
            False,
            "causal_signal_and_negative_control_required",
            evidence,
        )
    target_fingerprint = _target_fingerprint(finding.url)
    if require_target_backed:
        if not _target_observation_ok(
            baseline, role="baseline", target_fingerprint=target_fingerprint
        ) or not _target_observation_ok(
            candidate, role="candidate", target_fingerprint=target_fingerprint
        ):
            evidence["promotion_guard"] = {
                "status": "blocked",
                "reason": "target_backed_baseline_and_candidate_required",
            }
            return VerificationResult(
                False,
                "target_backed_baseline_and_candidate_required",
                evidence,
            )
        if not _target_observation_ok(
            negative_control, role="negative_control", target_fingerprint=target_fingerprint
        ):
            evidence["promotion_guard"] = {
                "status": "blocked",
                "reason": "independent_target_backed_negative_control_required",
            }
            return VerificationResult(
                False,
                "independent_target_backed_negative_control_required",
                evidence,
            )
        request_digests = {
            candidate.get("request_digest"),
            negative_control.get("request_digest"),
        }
        if len(request_digests) != 2:
            evidence["promotion_guard"] = {
                "status": "blocked",
                "reason": "negative_control_must_be_independent",
            }
            return VerificationResult(False, "negative_control_must_be_independent", evidence)
    provenance_values = {
        "engagement_id": str(engagement_id or "").strip(),
        "validator_id": str(validator_id or "").strip(),
        "validator_version": str(validator_version or "").strip(),
        "causal_basis": str(causal_basis or "").strip(),
    }
    placeholder_engagements = {
        "default",
        "default-engagement",
        "runtime-unbound",
        "unknown",
        "none",
    }
    if (
        not all(provenance_values.values())
        or provenance_values["engagement_id"].lower() in placeholder_engagements
    ):
        evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": "verifier_provenance_incomplete_or_placeholder",
        }
        return VerificationResult(
            False,
            "verifier_provenance_incomplete_or_placeholder",
            evidence,
        )

    clean_scope = dict(scope_context or {})
    clean_identity = dict(identity_context or {})
    if not clean_scope or not clean_identity:
        evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": "scope_and_identity_context_required",
        }
        return VerificationResult(False, "scope_and_identity_context_required", evidence)

    replay = {
        "replayable": True,
        "sequence": ["baseline", "candidate", "negative_control"],
        "negative_control": "negative_control",
        "observations": 3,
        "target_backed": bool(require_target_backed),
        "independent_control": bool(require_target_backed),
    }
    bundle = build_proof_bundle(
        engagement_id=engagement_id,
        finding_id=str(finding.id),
        hypothesis_id=hypothesis_id or f"finding:{finding.id}",
        target_fingerprint=target_fingerprint,
        target_package_id=target_package_id,
        target_package_sha256=target_package_sha256,
        target_package_scope_digest=target_package_scope_digest,
        target_package_policy_digest=target_package_policy_digest,
        scope_context=clean_scope,
        identity_context=clean_identity,
        evidence=[baseline, candidate, negative_control],
        evidence_refs=(
            f"replay:{validator_id}:baseline",
            f"replay:{validator_id}:candidate",
            f"replay:{validator_id}:negative_control",
        ),
        negative_control=negative_control,
        baseline=baseline,
        request_evidence=[baseline, candidate, negative_control],
        response_evidence=[baseline, candidate, negative_control],
        causal_oracle={
            "causal_signal": True,
            "negative_control_complete": True,
            "requires_target_backed": bool(require_target_backed),
            "basis": str(causal_basis)[:240],
        },
        target_backed=bool(require_target_backed),
        negative_control_independent=bool(require_target_backed),
        validator_id=validator_id,
        validator_version=validator_version,
        replay_metadata={**replay, **(replay_metadata or {})},
        cleanup_status="not_applicable",
        redaction_manifest=(
            "request_body",
            "cookie",
            "authorization",
            "set-cookie",
            "raw_response_body",
        ),
    ).seal(actor="strict_replay_verifier")
    replay_context: dict[str, Any] = {
        "engagement_id": str(engagement_id),
        "finding_id": str(finding.id),
        "hypothesis_id": hypothesis_id or f"finding:{finding.id}",
        "target_fingerprint": target_fingerprint,
    }
    if target_package_id:
        replay_context.update(
            {
                "target_package_id": target_package_id,
                "target_package_sha256": target_package_sha256,
                "target_package_scope_digest": target_package_scope_digest,
                "target_package_policy_digest": target_package_policy_digest,
            }
        )
    if not proof_bundle_promotion_ready(bundle):
        evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": "proof_bundle_promotion_contract_failed",
        }
        return VerificationResult(False, "proof_bundle_promotion_contract_failed", evidence)
    if not bundle.verify_seal():
        evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": "proof_bundle_seal_verification_failed",
        }
        return VerificationResult(False, "proof_bundle_seal_verification_failed", evidence)
    if not bundle.replay(
        [baseline, candidate, negative_control],
        negative_control,
        replay_context=replay_context,
    ):
        evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": "proof_bundle_replay_failed",
        }
        return VerificationResult(False, "proof_bundle_replay_failed", evidence)

    clean_baseline = redact_sensitive(baseline)[0]
    clean_candidate = redact_sensitive(candidate)[0]
    clean_negative_control = redact_sensitive(negative_control)[0]
    clean_replay_metadata = redact_sensitive(
        {**replay, **(replay_metadata or {}), "replay_verified": True}
    )[0]
    evidence.update(
        {
            "proof_verified": True,
            "proof_bundle_sealed": True,
            "target_backed": bool(require_target_backed),
            "negative_control_independent": bool(require_target_backed),
            "proof_bundle": bundle.model_dump(mode="json"),
            "proof_evidence": [clean_baseline, clean_candidate, clean_negative_control],
            "baseline": clean_baseline,
            "candidate": clean_candidate,
            "negative_control": clean_negative_control,
            "evidence_refs": [
                f"replay:{validator_id}:baseline",
                f"replay:{validator_id}:candidate",
                f"replay:{validator_id}:negative_control",
            ],
            "request_evidence": [clean_baseline, clean_candidate, clean_negative_control],
            "response_evidence": [clean_baseline, clean_candidate, clean_negative_control],
            "scope_context": clean_scope,
            "identity_context": clean_identity,
            "causal_oracle": {
                "causal_signal": True,
                "negative_control_complete": True,
                "requires_target_backed": bool(require_target_backed),
                "basis": str(causal_basis)[:240],
            },
            "validator_id": validator_id,
            "validator_version": validator_version,
            "cleanup_status": "not_applicable",
            "finding_id": str(finding.id),
            "hypothesis_id": hypothesis_id or f"finding:{finding.id}",
            "target_fingerprint": target_fingerprint,
            "replay_context": replay_context,
            "replay_metadata": clean_replay_metadata,
            "promotion_guard": {
                "status": "passed",
                "proof_bundle_sealed": True,
                "replayable": True,
                "replay_verified": True,
                "replay_context": replay_context,
            },
        }
    )
    return VerificationResult(True, "verified_replay", evidence, bundle)


__all__ = ["VerificationResult", "verify_replay_evidence"]
