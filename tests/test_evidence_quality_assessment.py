from webpent.models.proof_bundle import build_proof_bundle
from webpent.shared.evidence_quality import (
    EvidenceClassification,
    assess_finding_evidence,
)


def _finding(**overrides):
    value = {
        "id": "finding-eq-1",
        "confidence_level": "Pending",
        "url": "https://target.test/item/1",
        "evidence": {},
    }
    value.update(overrides)
    return value


def _sealed_proof():
    return build_proof_bundle(
        engagement_id="engagement-eq",
        finding_id="finding-eq-1",
        hypothesis_id="hypothesis-eq-1",
        target_fingerprint="sha256:target-eq",
        scope_context={"origin": "https://target.test"},
        identity_context={"actor": "owner", "control_actor": "anonymous"},
        evidence=[{"status": 200, "fingerprint": "owner"}],
        evidence_refs=["execution:eq:1"],
        negative_control={"status": 403, "fingerprint": "anonymous"},
        baseline={"status": 403, "fingerprint": "baseline"},
        request_evidence=[{"method": "GET", "path": "/item/1"}],
        response_evidence=[{"status": 200, "fingerprint": "owner"}],
        causal_oracle={
            "causal_signal": True,
            "negative_control_complete": True,
        },
        validator_id="test.validator",
        validator_version="1.0",
        replay_metadata={"replayable": True},
        cleanup_status="not_applicable",
    ).seal(actor="test").model_dump(mode="json")


def test_confirmed_requires_causal_negative_control_and_sealed_proof():
    proof = _sealed_proof()
    assessment = assess_finding_evidence(
        _finding(
            confidence_level="Tool-Confirmed",
            proof_bundle=proof,
            evidence={
                "causal_signal": True,
                "negative_control_complete": True,
            },
        )
    )

    assert assessment.classification == EvidenceClassification.CONFIRMED
    assert assessment.score == 1.0
    assert assessment.missing_signals == []


def test_tool_confirmed_without_sealed_proof_is_needs_review():
    assessment = assess_finding_evidence(
        _finding(
            confidence_level="Tool-Confirmed",
            evidence={
                "causal_signal": True,
                "negative_control_complete": True,
                "reproduction": {"steps_to_reproduce": ["repeat"]},
            },
        )
    )

    assert assessment.classification == EvidenceClassification.NEEDS_HUMAN_REVIEW
    assert "sealed_proof_bundle" in assessment.missing_signals


def test_partial_candidate_evidence_is_not_promoted_to_confirmed():
    assessment = assess_finding_evidence(
        _finding(
            evidence={
                "causal_signal": True,
                "reproduction": {"steps_to_reproduce": ["repeat"]},
            }
        )
    )

    assert assessment.classification == EvidenceClassification.NEEDS_HUMAN_REVIEW
    assert assessment.negative_control_complete is False


def test_contradictory_signal_forces_unconfirmed():
    assessment = assess_finding_evidence(
        _finding(
            confidence_level="Tool-Confirmed",
            evidence={
                "causal_signal": True,
                "negative_control_complete": True,
                "contradictory_evidence": True,
            },
        )
    )

    assert assessment.classification == EvidenceClassification.UNCONFIRMED
    assert assessment.score == 0.0
    assert "contradictory_validation_signal" in assessment.reasons


def test_no_evidence_is_unconfirmed_and_clean_is_coverage_signal():
    assert (
        assess_finding_evidence(_finding()).classification
        == EvidenceClassification.UNCONFIRMED
    )
    assert (
        assess_finding_evidence(_finding(confidence_level="Clean")).classification
        == EvidenceClassification.CLEAN
    )
