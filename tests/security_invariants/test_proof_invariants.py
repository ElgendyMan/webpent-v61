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


def test_replay_rejects_cross_engagement_or_target_binding() -> None:
    bundle = _complete_bundle()
    evidence = [{"status": 200, "marker": "candidate"}]
    control = {"status": 403, "marker": "control"}
    matching_context = {
        "engagement_id": "engagement-proof",
        "finding_id": "finding-proof",
        "hypothesis_id": "hypothesis-proof",
        "target_fingerprint": "target-fingerprint",
    }

    assert bundle.replay(evidence, control, replay_context=matching_context) is True
    assert bundle.replay(
        evidence,
        control,
        replay_context={**matching_context, "engagement_id": "other-engagement"},
    ) is False
    assert bundle.replay(
        evidence,
        control,
        replay_context={**matching_context, "target_fingerprint": "other-target"},
    ) is False


def test_replay_binding_requires_hypothesis_scope_and_identity_context() -> None:
    bundle = _complete_bundle(
        scope_context={"target_url": "https://lab.test/resource"},
        identity_context={"owner_ref": "identity:owner", "foreign_ref": "identity:foreign"},
    )
    evidence = [{"status": 200, "marker": "candidate"}]
    control = {"status": 403, "marker": "control"}
    context = {
        "engagement_id": "engagement-proof",
        "finding_id": "finding-proof",
        "hypothesis_id": "hypothesis-proof",
        "target_fingerprint": "target-fingerprint",
        "scope_context": {"target_url": "https://lab.test/resource"},
        "identity_context": {"owner_ref": "identity:owner", "foreign_ref": "identity:foreign"},
    }

    assert bundle.replay(evidence, control, replay_context=context) is True
    assert bundle.replay(
        evidence,
        control,
        replay_context={key: value for key, value in context.items() if key != "hypothesis_id"},
    ) is False
    assert bundle.replay(
        evidence,
        control,
        replay_context={**context, "identity_context": {"owner_ref": "identity:other"}},
    ) is False
    assert bundle.replay(
        evidence,
        control,
        replay_context={**context, "scope_context": {"target_url": "https://other.test/resource"}},
    ) is False
    assert bundle.replay(
        evidence, control, replay_context={**context, "untrusted_hint": "ignored-before-hardening"}
    ) is False


def test_replay_is_idempotent_and_does_not_mutate_sealed_bundle() -> None:
    bundle = _complete_bundle()
    evidence = [{"status": 200, "marker": "candidate"}]
    control = {"status": 403, "marker": "control"}
    context = {
        "engagement_id": "engagement-proof",
        "finding_id": "finding-proof",
        "hypothesis_id": "hypothesis-proof",
        "target_fingerprint": "target-fingerprint",
    }
    before = bundle.model_dump(mode="json")

    assert bundle.replay(evidence, control, replay_context=context) is True
    assert bundle.replay(evidence, control, replay_context=context) is True
    assert bundle.model_dump(mode="json") == before


def test_replay_binding_requires_package_identity_when_bundle_is_package_bound() -> None:
    bundle = _complete_bundle(
        target_package_id="package-proof",
        target_package_sha256="a" * 64,
        target_package_scope_digest="b" * 64,
        target_package_policy_digest="c" * 64,
    )
    evidence = [{"status": 200, "marker": "candidate"}]
    control = {"status": 403, "marker": "control"}
    context = {
        "engagement_id": "engagement-proof",
        "finding_id": "finding-proof",
        "hypothesis_id": "hypothesis-proof",
        "target_fingerprint": "target-fingerprint",
        "target_package_id": "package-proof",
        "target_package_sha256": "a" * 64,
        "target_package_scope_digest": "b" * 64,
        "target_package_policy_digest": "c" * 64,
    }

    assert bundle.replay(evidence, control, replay_context=context) is True
    assert bundle.replay(
        evidence,
        control,
        replay_context={**context, "target_package_scope_digest": "d" * 64},
    ) is False
    assert bundle.replay(
        evidence,
        control,
        replay_context={**context, "target_package_id": "other-package"},
    ) is False
