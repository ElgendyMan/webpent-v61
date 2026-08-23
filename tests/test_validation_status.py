from webpent.models.proof_bundle import build_proof_bundle
from webpent.shared.evidence_quality import (
    EvidenceClassification,
    build_validation_status,
)


def _complete_finding(
    *, root_cause: str = "server-side object authorization uses actor input"
) -> dict:
    baseline = {"status": 200, "owner": "actor-a"}
    candidate = {"status": 200, "owner": "actor-b"}
    control = {"status": 403, "owner": "actor-b"}
    bundle = build_proof_bundle(
        engagement_id="engagement-1",
        finding_id="finding-1",
        hypothesis_id="hypothesis-1",
        target_fingerprint="target-fp-1",
        evidence=[baseline, candidate, control],
        evidence_refs=["execution:baseline", "execution:candidate", "execution:control"],
        negative_control=control,
        scope_context={"scope": "target.test"},
        identity_context={"actor": "owner-versus-foreign"},
        baseline=baseline,
        request_evidence=[{"method": "GET"}],
        response_evidence=[{"status": 200}],
        causal_oracle={
            "causal_signal": True,
            "negative_control_complete": True,
            "requires_target_backed": False,
            "root_cause": root_cause,
        },
        validator_id="idor-validator",
        validator_version="1.0",
        replay_metadata={"replayable": True},
        cleanup_status="complete",
    ).seal(actor="test")
    return {
        "id": "finding-1",
        "confidence_level": "Tool-Confirmed",
        "business_impact": "A foreign actor can read another actor's object.",
        "evidence": {
            "causal_signal": True,
            "negative_control_complete": True,
            "root_cause": root_cause,
            "reproduction": {"steps": ["baseline", "candidate", "control"]},
            "proof_bundle": bundle.model_dump(mode="json"),
            "replay": {
                "evidence_payloads": [baseline, candidate, control],
                "negative_control": control,
                "context": {
                    "engagement_id": "engagement-1",
                    "finding_id": "finding-1",
                    "target_fingerprint": "target-fp-1",
                },
            },
        },
    }


def test_validation_status_is_fail_closed_when_root_cause_is_missing():
    finding = _complete_finding(root_cause="")
    finding["evidence"].pop("root_cause")
    status = build_validation_status(finding)

    assert status.confirmation_ready is False
    assert status.classification != EvidenceClassification.CONFIRMED
    assert "root_cause" in status.missing_gates
    assert status.replay_verified is True


def test_validation_status_requires_all_gates_and_is_replay_verified():
    status = build_validation_status(_complete_finding())

    assert status.confirmation_ready is True
    assert status.classification == EvidenceClassification.CONFIRMED
    assert status.impact_present is True
    assert status.root_cause_present is True
    assert status.evidence_present is True
    assert status.reproducible is True
    assert status.causal_signal is True
    assert status.negative_control_complete is True
    assert status.proof_bundle_valid is True
    assert status.promotion_ready_proof_bundle is True
    assert status.replay_verified is True
    assert status.missing_gates == []


def test_validation_status_does_not_mutate_finding_or_promote_candidate():
    finding = _complete_finding()
    before = dict(finding["evidence"])
    build_validation_status(finding)

    assert finding["confidence_level"] == "Tool-Confirmed"
    assert finding["evidence"] == before
    assert "execute" not in finding["evidence"]
