from __future__ import annotations

from webpent.models.findings import Finding, Severity, VulnClass
from webpent.shared.verifier import _target_fingerprint, verify_replay_evidence

ENGAGEMENT = "engagement-browser-proof"
HYPOTHESIS = "hypothesis-browser-proof"
TARGET_URL = "https://lab.example.test/search"


def _finding() -> Finding:
    return Finding(
        title="Reflected input reaches browser sink",
        severity=Severity.HIGH,
        description="Fixture finding for a target-backed replay contract.",
        tool_name="fixture.browser.validator",
        url=TARGET_URL,
        vuln_class=VulnClass.XSS,
    )


def _observation(role: str, marker: str) -> dict[str, object]:
    return {
        "target_backed": True,
        "observation_role": role,
        "target_fingerprint": _target_fingerprint(TARGET_URL),
        "request_digest": f"sha256:{marker * 64}",
        "response_digest": f"sha256:{marker * 64}",
        "status_code": 200 if role == "candidate" else 204,
        "dom_digest": f"sha256:{marker * 64}",
        "replayable": True,
    }


def _verify(**overrides):
    values = {
        "finding": _finding(),
        "baseline": _observation("baseline", "a"),
        "candidate": _observation("candidate", "b"),
        "negative_control": _observation("negative_control", "c"),
        "causal_signal": True,
        "negative_control_complete": True,
        "validator_id": "fixture.browser.validator",
        "validator_version": "1.0",
        "causal_basis": "target-backed differential browser observation",
        "engagement_id": ENGAGEMENT,
        "hypothesis_id": HYPOTHESIS,
        "scope_context": {"allowed_origin": "https://lab.example.test"},
        "identity_context": {"session_ref": "session-fixture"},
        "replay_metadata": {"replayable": True},
        "require_target_backed": True,
    }
    values.update(overrides)
    return verify_replay_evidence(**values)


def test_target_backed_verifier_seals_and_replays_before_passing():
    result = _verify()

    assert result.passed is True
    assert result.reason == "verified_replay"
    assert result.proof_bundle is not None
    assert result.proof_bundle.verify_seal() is True
    assert result.proof_bundle.replay(
        [
            result.evidence["baseline"],
            result.evidence["candidate"],
            result.evidence["negative_control"],
        ],
        result.evidence["negative_control"],
        replay_context=result.evidence["promotion_guard"]["replay_context"],
    ) is True
    assert result.evidence["promotion_guard"]["replay_verified"] is True


def test_identical_candidate_and_negative_request_is_not_independent():
    candidate = _observation("candidate", "b")
    result = _verify(
        candidate=candidate,
        negative_control={
            **_observation("negative_control", "c"),
            "request_digest": candidate["request_digest"],
        },
    )

    assert result.passed is False
    assert result.reason == "negative_control_must_be_independent"
    assert result.proof_bundle is None


def test_missing_scope_or_identity_context_cannot_produce_proof():
    result = _verify(scope_context={}, identity_context={"session_ref": "session-fixture"})

    assert result.passed is False
    assert result.reason == "scope_and_identity_context_required"
    assert result.proof_bundle is None


def test_wrong_target_observation_fails_before_bundle_creation():
    result = _verify(
        candidate={
            **_observation("candidate", "b"),
            "target_fingerprint": "sha256:" + "f" * 64,
        }
    )

    assert result.passed is False
    assert result.reason == "target_backed_baseline_and_candidate_required"
    assert result.proof_bundle is None


def test_passed_bundle_mutation_invalidates_seal_and_replay():
    result = _verify()
    assert result.proof_bundle is not None
    bundle = result.proof_bundle
    object.__setattr__(bundle, "causal_oracle", {"causal_signal": False})

    assert bundle.verify_seal() is False
    assert bundle.replay(
        [
            result.evidence["baseline"],
            result.evidence["candidate"],
            result.evidence["negative_control"],
        ],
        result.evidence["negative_control"],
        replay_context=result.evidence["promotion_guard"]["replay_context"],
    ) is False


def test_false_causal_signal_never_reaches_bundle_creation():
    result = _verify(causal_signal=False)

    assert result.passed is False
    assert result.reason == "causal_signal_and_negative_control_required"
    assert result.proof_bundle is None


def test_root_target_fingerprint_normalizes_missing_trailing_slash():
    assert _target_fingerprint("http://127.0.0.1:3000") == _target_fingerprint(
        "http://127.0.0.1:3000/"
    )
    assert _target_fingerprint("http://127.0.0.1:3000/#/") == _target_fingerprint(
        "http://127.0.0.1:3000/"
    )


def test_root_target_backed_verifier_accepts_normalized_browser_shape():
    target = "http://127.0.0.1:3000"
    finding = Finding(
        title="Root target-backed browser proof",
        severity=Severity.HIGH,
        description="Regression fixture for root-origin normalization.",
        tool_name="fixture.browser.validator",
        url=target,
        vuln_class=VulnClass.XSS,
    )
    def observation(role: str, marker: str) -> dict[str, object]:
        return {
            "target_backed": True,
            "observation_role": role,
            "target_fingerprint": _target_fingerprint(target + "/"),
            "request_digest": f"sha256:{marker * 64}",
            "response_digest": f"sha256:{marker * 64}",
            "status_code": 200,
            "replayable": True,
        }
    result = verify_replay_evidence(
        finding,
        baseline=observation("baseline", "a"),
        candidate=observation("candidate", "b"),
        negative_control=observation("negative_control", "c"),
        causal_signal=True,
        negative_control_complete=True,
        validator_id="fixture.browser.validator",
        validator_version="1.0",
        causal_basis="target-backed response differential",
        engagement_id=ENGAGEMENT,
        hypothesis_id=HYPOTHESIS,
        scope_context={"allowed_origin": target},
        identity_context={"session_ref": "session-fixture"},
        replay_metadata={"replayable": True},
        require_target_backed=True,
    )
    assert result.passed is True
    assert result.proof_bundle is not None
    assert result.proof_bundle.verify_seal() is True
    assert result.proof_bundle.replay(
        [
            result.evidence["baseline"],
            result.evidence["candidate"],
            result.evidence["negative_control"],
        ],
        result.evidence["negative_control"],
        replay_context=result.evidence["promotion_guard"]["replay_context"],
    ) is True
