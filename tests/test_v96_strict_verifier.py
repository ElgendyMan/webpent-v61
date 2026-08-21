from __future__ import annotations

from uuid import uuid4

from webpent.models.findings import Finding, Severity
from webpent.shared.verifier import verify_replay_evidence


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
