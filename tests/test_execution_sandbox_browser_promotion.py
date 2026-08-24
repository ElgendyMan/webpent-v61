from __future__ import annotations

from typing import Any

from webpent.agents.execution_sandbox.agent import _test_finding_payloads
from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.shared.browser_proof_runner import BrowserProofRun


class _AttestingRunner:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def run(self, finding: Finding, **kwargs: Any) -> BrowserProofRun:
        self.calls.append({"finding_id": str(finding.id), **kwargs})
        return BrowserProofRun(
            passed=True,
            reason="replay_verified",
            observations={
                "baseline": {"target_backed": True},
                "candidate": {"target_backed": True},
                "negative_control": {"target_backed": True},
            },
            attestation={
                "proof_verified": True,
                "proof_evidence": ({"evidence_ref": "ev:browser-proof"},),
                "baseline": {"target_backed": True},
                "candidate": {"target_backed": True},
                "negative_control": {"target_backed": True},
                "evidence_refs": ("ev:browser-proof",),
                "scope_context": {"scope_bound": True},
                "identity_context": {"mode": "anonymous"},
                "validator_id": "test.browser-proof",
                "validator_version": "1",
                "replay_metadata": {"replayable": True},
            },
        )


def test_execution_sandbox_does_not_promote_before_central_bundle() -> None:
    finding = Finding(
        title="Typed browser candidate",
        severity=Severity.HIGH,
        description="A candidate requiring central bundle storage.",
        tool_name="fixture.browser",
        url="https://app.example.test/search",
        vuln_class=VulnClass.XSS,
    )
    runner = _AttestingRunner()

    updated = _test_finding_payloads(
        None,
        finding,
        ["candidate-value"],
        {},
        verification_context={
            "scope_context": {"target_origin": "https://app.example.test", "scope_bound": True},
            "identity_context": {"mode": "anonymous"},
        },
        proof_runner=runner,
    )

    assert len(runner.calls) == 1
    assert updated.confidence == Confidence.TENTATIVE
    assert updated.confidence_level != "Tool-Confirmed"
    evidence = updated.evidence or {}
    assert evidence["browser_validation_result"] == (
        "typed_replay_attestation_pending_bundle"
    )
    assert evidence["proof_verified"] is True
    assert evidence["promotion_guard"]["status"] == "central_bundle_required"
    assert evidence.get("proof_bundle_sealed") is not True
    assert "candidate-value" not in repr(evidence)
