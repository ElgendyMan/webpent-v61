from webpent.agents.validator.agent import _validate_known_swagger_ssrf
from webpent.models.findings import Finding
from webpent.models.proof_bundle import build_proof_bundle


def _finding(evidence: dict[str, object]) -> Finding:
    return Finding(
        title="Swagger SSRF proof",
        severity="high",
        description="A controlled server-side request was observed.",
        tool_name="action_executor",
        url="http://example.test/swagger_ui",
        vuln_class="ssrf",
        confidence="confirmed",
        confidence_level="Tool-Confirmed",
        evidence=evidence,
    )


def test_swagger_direct_promotion_rejects_marker_without_proof_bundle():
    finding = _finding(
        {
            "action_executor_probe": True,
            "causal_signal": True,
            "negative_control_complete": True,
        }
    )

    assert _validate_known_swagger_ssrf(finding, {}) is None


def test_swagger_direct_promotion_accepts_sealed_proof_with_controls():
    positive = {"status": 200, "canary": "observed"}
    negative = {"status": 403, "canary": "not-observed"}
    bundle = build_proof_bundle(
        engagement_id="engagement-1",
        finding_id=str(_finding({}).id),
        evidence=[positive],
        evidence_refs=["action-executor:positive"],
        negative_control=negative,
    ).seal(actor="action_executor")
    finding = _finding(
        {
            "action_executor_probe": True,
            "causal_signal": True,
            "negative_control_complete": True,
            "proof_bundle": bundle.model_dump(mode="json"),
        }
    )

    assert _validate_known_swagger_ssrf(finding, {}) == finding
