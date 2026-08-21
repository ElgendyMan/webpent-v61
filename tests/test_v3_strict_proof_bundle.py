from webpent.models.proof_bundle import (
    build_proof_bundle,
    proof_bundle_promotion_ready,
    validate_proof_bundle,
)


def _strict_bundle():
    return build_proof_bundle(
        engagement_id="engagement-1",
        finding_id="finding-1",
        hypothesis_id="hypothesis-1",
        target_fingerprint="sha256:" + "a" * 64,
        scope_context={"origin": "http://127.0.0.1:3000", "decision": "allowed"},
        identity_context={"actor_class": "owner", "tenant_ref": "tenant-a"},
        evidence=("causal response marker",),
        evidence_refs=("obs:causal-1",),
        request_evidence=("GET /rest/resource?id=1",),
        response_evidence=("HTTP 200 response fingerprint",),
        baseline="HTTP 403 baseline",
        negative_control="HTTP 403 negative control",
        causal_oracle={
            "causal_signal": True,
            "negative_control_complete": True,
            "oracle": "differential_access_oracle",
        },
        validator_id="idor-differential",
        validator_version="1",
        validator_config={"mode": "safe"},
        replay_metadata={"replayable": True, "attempts": 2},
        cleanup_status="complete",
        redaction_manifest=("authorization", "cookie", "token"),
    ).seal(actor="test")


def test_strict_bundle_is_promotion_ready_and_immutable():
    bundle = _strict_bundle()

    assert validate_proof_bundle(bundle, require_negative_control=True)
    assert proof_bundle_promotion_ready(bundle)
    assert bundle.sealed is True
    assert bundle.verify_seal()

    try:
        bundle.cleanup_status = "tampered"
    except Exception as exc:
        assert "frozen" in str(exc).lower()
    else:
        raise AssertionError("sealed proof bundle must remain immutable")


def test_legacy_bundle_remains_valid_but_not_promotion_ready():
    bundle = build_proof_bundle(
        engagement_id="engagement-1",
        finding_id="finding-1",
        evidence=("observation",),
        evidence_refs=("obs:1",),
    ).seal()

    assert validate_proof_bundle(bundle)
    assert not proof_bundle_promotion_ready(bundle)


def test_strict_bundle_redacts_sensitive_context_before_sealing():
    bundle = build_proof_bundle(
        engagement_id="engagement-1",
        finding_id="finding-1",
        hypothesis_id="hypothesis-1",
        target_fingerprint="sha256:" + "b" * 64,
        scope_context={"origin": "http://127.0.0.1:3000", "cookie": "secret-cookie"},
        identity_context={"authorization": "Bearer secret-token"},
        evidence=("safe evidence",),
        evidence_refs=("obs:1",),
        request_evidence=("GET /safe",),
        response_evidence=("HTTP 200",),
        baseline="baseline",
        negative_control="negative",
        causal_oracle={"causal_signal": True, "negative_control_complete": True},
        validator_id="validator",
        validator_version="1",
        replay_metadata={"replayable": True},
        cleanup_status="not_applicable",
    )

    assert bundle.scope_context["cookie"] == "[REDACTED]"
    assert bundle.identity_context["authorization"] == "[REDACTED]"
    assert "secret-token" not in str(bundle.model_dump())
    assert proof_bundle_promotion_ready(bundle.seal())


def test_causal_oracle_must_be_explicit_for_promotion():
    bundle = _strict_bundle().model_copy(
        update={"causal_oracle": {"causal_signal": False, "negative_control_complete": True}}
    )

    assert not proof_bundle_promotion_ready(bundle)
    assert not bundle.verify_seal()
