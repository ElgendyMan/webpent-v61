from webpent.models.proof_bundle import (
    build_proof_bundle,
    proof_bundle_promotion_ready,
    validate_proof_bundle,
)


def _complete_bundle(**overrides):
    values = {
        "engagement_id": "engagement-proof",
        "finding_id": "finding-proof",
        "hypothesis_id": "hypothesis-proof",
        "target_fingerprint": "target-fingerprint",
        "evidence": [{"status": 200, "marker": "candidate"}],
        "evidence_refs": ["obs:proof"],
        "negative_control": {"status": 403, "marker": "control"},
        "baseline": {"status": 403, "marker": "baseline"},
        "request_evidence": [{"method": "GET", "role": "candidate"}],
        "response_evidence": [{"status": 200, "role": "candidate"}],
        "causal_oracle": {
            "causal_signal": True,
            "negative_control_complete": True,
            "requires_target_backed": True,
        },
        "target_backed": True,
        "negative_control_independent": True,
        "validator_id": "fixture.validator",
        "validator_version": "1.0",
        "replay_metadata": {"replayable": True},
        "cleanup_status": "not_applicable",
    }
    values.update(overrides)
    return build_proof_bundle(**values).seal(actor="test")


def test_sealed_bundle_tampering_invalidates_integrity_and_replay() -> None:
    bundle = _complete_bundle()
    assert validate_proof_bundle(bundle, require_negative_control=True)
    assert bundle.verify_seal()

    object.__setattr__(bundle, "causal_oracle", {"causal_signal": False})

    assert not bundle.verify_seal()
    assert not bundle.replay(
        [{"status": 200, "marker": "candidate"}],
        {"status": 403, "marker": "control"},
    )
    assert not proof_bundle_promotion_ready(bundle)


def test_target_backed_promotion_requires_independent_control() -> None:
    bundle = _complete_bundle(negative_control_independent=False)

    assert validate_proof_bundle(bundle, require_negative_control=True)
    assert not proof_bundle_promotion_ready(bundle)


def test_missing_provenance_cannot_promote_even_with_causal_flags() -> None:
    bundle = _complete_bundle(
        evidence_refs=[],
        validator_id=None,
        validator_version=None,
    )

    assert validate_proof_bundle(bundle, require_negative_control=True) is False
    assert proof_bundle_promotion_ready(bundle) is False
