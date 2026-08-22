from __future__ import annotations

from uuid import uuid4

from webpent.models.findings import Finding, Severity
from webpent.shared.verifier import _target_fingerprint, verify_replay_evidence


def _finding() -> Finding:
    return Finding(
        id=uuid4(),
        title="controlled differential candidate",
        severity=Severity.HIGH,
        description="candidate",
        tool_name="active-validator",
        url="https://target.test/item?id=redacted",
        vuln_class="lfi",
        target_param="id",
        request_data={"id": "safe"},
    )


def _context() -> dict[str, object]:
    return {
        "engagement_id": "engagement-1",
        "hypothesis_id": "hypothesis-1",
        "scope_context": {"target_origin": "https://target.test", "scope_bound": True},
        "identity_context": {"mode": "anonymous", "cookie_count": 0},
    }


def test_strict_verifier_builds_replayable_proof_bundle() -> None:
    baseline = {"status_code": 200, "body_sha256": "baseline", "body_length": 4}
    candidate = {"status_code": 200, "body_sha256": "candidate", "body_length": 18}
    result = verify_replay_evidence(
        _finding(),
        baseline=baseline,
        candidate=candidate,
        negative_control=baseline,
        causal_signal=True,
        negative_control_complete=True,
        validator_id="lfi-replay",
        validator_version="1.0",
        causal_basis="root_marker_absent_in_baseline_present_in_candidate",
        **_context(),
    )

    assert result.passed is True
    assert result.proof_bundle is not None
    assert result.proof_bundle.verify_seal() is True
    assert result.proof_bundle.replay([baseline, candidate], negative_control=baseline)
    assert result.evidence["promotion_guard"]["status"] == "passed"


def test_strict_verifier_blocks_missing_signal_and_tampered_replay() -> None:
    baseline = {"status_code": 200, "body_sha256": "baseline"}
    candidate = {"status_code": 200, "body_sha256": "candidate"}
    blocked = verify_replay_evidence(
        _finding(),
        baseline=baseline,
        candidate=candidate,
        negative_control=baseline,
        causal_signal=False,
        negative_control_complete=True,
        validator_id="lfi-replay",
        validator_version="1.0",
        causal_basis="",
        **_context(),
    )
    assert blocked.passed is False
    assert blocked.proof_bundle is None

    passed = verify_replay_evidence(
        _finding(),
        baseline=baseline,
        candidate=candidate,
        negative_control=baseline,
        causal_signal=True,
        negative_control_complete=True,
        validator_id="lfi-replay",
        validator_version="1.0",
        causal_basis="controlled differential",
        **_context(),
    )
    assert passed.proof_bundle is not None
    tampered = {**candidate, "body_sha256": "tampered"}
    assert not passed.proof_bundle.replay([baseline, tampered], negative_control=baseline)


def _target_observation(role: str, request_digest: str, response_digest: str) -> dict[str, object]:
    return {
        "target_backed": True,
        "observation_role": role,
        "target_fingerprint": _target_fingerprint("https://target.test/item?id=redacted"),
        "request_digest": request_digest,
        "response_digest": response_digest,
        "status_code": 200,
        "body_sha256": role,
        "body_length": len(role),
    }


def test_target_backed_contract_requires_independent_control_and_replays_three_observations(
) -> None:
    baseline = _target_observation("baseline", "sha256:" + "2" * 64, "sha256:" + "3" * 64)
    candidate = _target_observation("candidate", "sha256:" + "4" * 64, "sha256:" + "5" * 64)
    negative_control = _target_observation(
        "negative_control", "sha256:" + "6" * 64, "sha256:" + "7" * 64
    )
    result = verify_replay_evidence(
        _finding(),
        baseline=baseline,
        candidate=candidate,
        negative_control=negative_control,
        causal_signal=True,
        negative_control_complete=True,
        validator_id="target-backed-replay",
        validator_version="2.0",
        causal_basis="controlled target observation",
        require_target_backed=True,
        **_context(),
    )

    assert result.passed is True
    assert result.proof_bundle is not None
    bundle = result.proof_bundle
    assert bundle.target_backed is True
    assert bundle.negative_control_independent is True
    assert bundle.causal_oracle["requires_target_backed"] is True
    assert bundle.verify_seal() is True
    assert bundle.replay([baseline, candidate, negative_control], negative_control=negative_control)
    assert not bundle.replay([baseline, candidate], negative_control=negative_control)
    assert not bundle.replay(
        [baseline, candidate, {**negative_control, "response_digest": "sha256:" + "8" * 64}],
        negative_control=negative_control,
    )


def test_target_backed_contract_blocks_missing_provenance_or_reused_candidate_control() -> None:
    baseline = _target_observation("baseline", "sha256:" + "2" * 64, "sha256:" + "3" * 64)
    candidate = _target_observation("candidate", "sha256:" + "4" * 64, "sha256:" + "5" * 64)
    missing = {"status_code": 200, "body_sha256": "control"}
    blocked_missing = verify_replay_evidence(
        _finding(),
        baseline=baseline,
        candidate=candidate,
        negative_control=missing,
        causal_signal=True,
        negative_control_complete=True,
        validator_id="target-backed-replay",
        validator_version="2.0",
        causal_basis="controlled target observation",
        require_target_backed=True,
        **_context(),
    )
    assert blocked_missing.passed is False
    assert blocked_missing.reason == "independent_target_backed_negative_control_required"

    reused = {**candidate, "observation_role": "negative_control"}
    blocked_reused = verify_replay_evidence(
        _finding(),
        baseline=baseline,
        candidate=candidate,
        negative_control=reused,
        causal_signal=True,
        negative_control_complete=True,
        validator_id="target-backed-replay",
        validator_version="2.0",
        causal_basis="controlled target observation",
        require_target_backed=True,
        **_context(),
    )
    assert blocked_reused.passed is False
    assert blocked_reused.reason == "negative_control_must_be_independent"


def test_flags_alone_cannot_claim_target_backed_confirmation() -> None:
    baseline = {"status_code": 200, "body_sha256": "baseline"}
    candidate = {"status_code": 200, "body_sha256": "candidate"}
    result = verify_replay_evidence(
        _finding(),
        baseline=baseline,
        candidate=candidate,
        negative_control=baseline,
        causal_signal=True,
        negative_control_complete=True,
        validator_id="target-backed-replay",
        validator_version="2.0",
        causal_basis="flags only",
        require_target_backed=True,
        **_context(),
    )
    assert result.passed is False
    assert result.reason == "target_backed_baseline_and_candidate_required"
    assert result.proof_bundle is None
