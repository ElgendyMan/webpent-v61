from webpent.agents.validator.structural_checks import validate_jwt_weakness
from webpent.models.findings import Finding, Severity
from webpent.shared.verifier import verify_replay_evidence


def _finding(**updates):
    return Finding(
        title="JWT weak secret candidate",
        description="Captured JWT signature matched a bounded candidate.",
        severity=Severity.HIGH,
        confidence_level="Tool-Confirmed",
        vuln_class="jwt_weakness",
        url="https://engagement.example.test/api/me",
        tool_name="api_testing_agent",
        evidence={
            "causal_signal": True,
            "negative_control_complete": True,
        },
        **updates,
    )


def test_jwt_weakness_blocks_missing_proof_bundle():
    finding = _finding()

    result = validate_jwt_weakness(finding)

    assert result.confidence_level == "Needs Human Review"
    assert result.evidence["proof_bundle_verified"] is False
    assert result.evidence["validation_failure_reason"].startswith(
        "jwt_weakness_requires_sealed_proof_bundle"
    )


def test_jwt_weakness_preserves_only_sealed_proof_bundle():
    finding = _finding()
    verification = verify_replay_evidence(
        finding,
        baseline={"case": "weak_secret_baseline", "signature_verified": False},
        candidate={"case": "weak_secret_candidate", "signature_verified": True},
        negative_control={"case": "wrong_secret_rejected", "observed": True},
        causal_signal=True,
        negative_control_complete=True,
        validator_id="api_testing.jwt_weak_secret",
        validator_version="jwt-offline-replay.v1",
        causal_basis="captured_signature_matches_bounded_candidate_and_rejects_wrong_secret",
        engagement_id="engagement-jwt-test",
        scope_context={"target_origin": "https://engagement.example.test"},
        identity_context={"mode": "offline-captured-token"},
        replay_metadata={"mode": "offline_signature_replay", "network_io": False},
    )
    assert verification.passed is True
    assert verification.proof_bundle is not None

    finding = finding.model_copy(
        update={
            "evidence": {
                **finding.evidence,
                "proof_bundle": verification.proof_bundle.model_dump(mode="json"),
            },
            "evidence_bundle": {
                "proof_bundle": verification.proof_bundle.model_dump(mode="json"),
                "causal_signal": True,
                "negative_control": {"case": "wrong_secret_rejected", "observed": True},
            },
        }
    )

    result = validate_jwt_weakness(finding)

    assert result.confidence_level == "Tool-Confirmed"
    assert result.evidence["proof_bundle_verified"] is True
    assert result.evidence["negative_control_complete"] is True
