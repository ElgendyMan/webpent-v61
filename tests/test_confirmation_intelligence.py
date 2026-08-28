from __future__ import annotations

from webpent.models.proof_bundle import build_proof_bundle
from webpent.shared.confirmation_intelligence import (
    ChainStep,
    ConfirmationPosture,
    evaluate_bounded_chain,
    evaluate_confirmation,
)
from webpent.shared.proof_oracles import (
    CausalObservation,
    CausalOracleContract,
    OracleFamily,
)

_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_B = "sha256:" + "b" * 64
_DIGEST_C = "sha256:" + "c" * 64


def observation(
    role: str,
    digest: str,
    signals: dict[str, object],
    *,
    semantic_fingerprint: str | None = None,
) -> CausalObservation:
    return CausalObservation(
        observation_ref=f"obs-{role}",
        role=role,
        semantic_fingerprint=semantic_fingerprint or f"semantic-{role}",
        request_digest=digest,
        response_digest=digest,
        signals=signals,
        target_backed=False,
        evidence_origin="offline_fixture",
    )


def confirmed_contract() -> CausalOracleContract:
    return CausalOracleContract(
        family=OracleFamily.IDOR,
        baseline=observation(
            "baseline",
            _DIGEST_A,
            {"invariant_holds": True, "owner_relation": "owner"},
        ),
        candidate=observation(
            "candidate",
            _DIGEST_B,
            {"invariant_violated": True, "owner_relation": "foreign"},
        ),
        negative_control=observation(
            "negative_control",
            _DIGEST_C,
            {"invariant_holds": True, "owner_relation": "control"},
        ),
        expected_invariant="owner can access owned object",
        violated_invariant="foreign owner can access object",
    )


def proof_for(contract: CausalOracleContract):
    baseline_payload = {"observation": "baseline", "ref": contract.baseline.observation_ref}
    candidate_payload = {"observation": "candidate", "ref": contract.candidate.observation_ref}
    control_payload = {"observation": "negative", "ref": contract.negative_control.observation_ref}
    bundle = build_proof_bundle(
        engagement_id="eng-confirmation-test",
        finding_id="recorded-evidence-only",
        hypothesis_id="hypothesis-idor-1",
        target_fingerprint="offline-fixture",
        evidence=(baseline_payload, candidate_payload),
        evidence_refs=(
            contract.baseline.observation_ref,
            contract.candidate.observation_ref,
            contract.negative_control.observation_ref,
        ),
        negative_control=control_payload,
        baseline=baseline_payload,
        request_evidence=("request-baseline", "request-candidate"),
        response_evidence=("response-baseline", "response-candidate"),
        scope_context={"mode": "offline"},
        identity_context={"model": "synthetic"},
        causal_oracle={
            "causal_signal": True,
            "negative_control_complete": True,
        },
        validator_id="test-verifier",
        validator_version="1",
        replay_metadata={"replayable": True},
        cleanup_status="not_applicable",
        oracle_decision="CONFIRMED",
        evidence_origin="offline_fixture",
    )
    return bundle.seal(), (baseline_payload, candidate_payload), control_payload


def test_offline_confirmed_requires_proof_but_never_grants_qualification():
    bundle, evidence, control = proof_for(confirmed_contract())
    assessment = evaluate_confirmation(
        confirmed_contract(),
        proof_bundle=bundle,
        evidence_payloads=evidence,
        negative_control_payload=control,
    )

    assert assessment.posture == ConfirmationPosture.ENGINEERING_CONFIRMED
    assert assessment.causal_signal is True
    assert assessment.proof_bundle_valid is True
    assert assessment.replay_verified is True
    assert assessment.scoring_eligible is False
    assert assessment.official_qualification_granted is False
    assert assessment.missing == ()
    assert "offline_evidence_not_scoring_eligible" in assessment.reasons


def test_confirmed_oracle_without_proof_is_needs_proof():
    assessment = evaluate_confirmation(confirmed_contract())

    assert assessment.posture == ConfirmationPosture.NEEDS_PROOF
    assert assessment.causal_signal is True
    assert assessment.proof_bundle_valid is False
    assert assessment.replay_verified is False


def test_clean_semantics_are_not_blocked():
    contract = CausalOracleContract(
        family=OracleFamily.IDOR,
        baseline=observation(
            "baseline",
            _DIGEST_A,
            {"invariant_holds": True, "ownership": "owner"},
            semantic_fingerprint="semantic-owner",
        ),
        candidate=observation(
            "candidate",
            _DIGEST_B,
            {"invariant_holds": True, "ownership": "owner"},
            semantic_fingerprint="semantic-owner",
        ),
        negative_control=observation(
            "negative_control",
            _DIGEST_C,
            {"invariant_holds": True, "ownership": "owner"},
            semantic_fingerprint="semantic-owner",
        ),
        expected_invariant="owner access remains bounded",
        violated_invariant="ownership boundary is crossed",
    )
    assessment = evaluate_confirmation(contract)

    assert assessment.posture == ConfirmationPosture.CLEAN
    assert assessment.oracle_decision == "CLEAN"


def test_transport_only_observations_are_blocked():
    contract = CausalOracleContract(
        family=OracleFamily.IDOR,
        baseline=observation("baseline", _DIGEST_A, {"status_code": 200}),
        candidate=observation("candidate", _DIGEST_B, {"status_code": 200}),
        negative_control=observation("negative_control", _DIGEST_C, {"status_code": 403}),
        expected_invariant="semantic ownership boundary",
        violated_invariant="semantic ownership boundary crossed",
    )
    assessment = evaluate_confirmation(contract)

    assert assessment.posture == ConfirmationPosture.BLOCKED
    assert "baseline_invariant_boolean" in assessment.missing


def test_bounded_chain_requires_every_step_and_dependency():
    contract = confirmed_contract()
    bundle, evidence, control = proof_for(contract)
    confirmed = evaluate_confirmation(
        contract,
        proof_bundle=bundle,
        evidence_payloads=evidence,
        negative_control_payload=control,
    )
    first = ChainStep(
        step_id="step-1",
        hypothesis_id="hyp-1",
        assessment=confirmed,
        evidence_refs=("obs-baseline", "obs-candidate", "obs-negative_control"),
    )
    second = ChainStep(
        step_id="step-2",
        hypothesis_id="hyp-2",
        prerequisite_step_ids=("step-1",),
        assessment=confirmed,
        evidence_refs=("obs-2",),
    )

    result = evaluate_bounded_chain("chain-1", (first, second))

    assert result.complete is True
    assert result.score == 1.0
    assert result.official_qualification_granted is False


def test_bounded_chain_blocks_unconfirmed_dependency():
    contract = confirmed_contract()
    first = ChainStep(
        step_id="step-1",
        hypothesis_id="hyp-1",
        assessment=evaluate_confirmation(contract),
        evidence_refs=("obs-1",),
    )
    second = ChainStep(
        step_id="step-2",
        hypothesis_id="hyp-2",
        prerequisite_step_ids=("step-1",),
        assessment=evaluate_confirmation(contract),
        evidence_refs=("obs-2",),
    )

    result = evaluate_bounded_chain("chain-2", (first, second))

    assert result.complete is False
    assert result.score == 0.0
    assert "step-1" in result.blocked_step_ids
    assert "step-2" in result.blocked_step_ids
