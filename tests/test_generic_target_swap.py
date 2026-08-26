from __future__ import annotations

from webpent.benchmark.generic_test_target_adapter import (
    GENERIC_TEST_CASE_ID,
    GENERIC_TEST_ORIGIN,
    GENERIC_TEST_PROFILE_ID,
    GENERIC_TEST_TARGET_ADAPTER,
    GENERIC_TEST_TARGET_REGISTRATION,
)
from webpent.benchmark.juice_shop_target_adapter import (
    JUICE_SHOP_ORIGIN,
    JUICE_SHOP_TARGET_REGISTRATION,
)
from webpent.shared.semantic_observations import derive_semantic_observation
from webpent.shared.target_adapters import TargetAdapterRegistry


def test_generic_target_registration_is_complete_and_origin_scoped() -> None:
    assert GENERIC_TEST_TARGET_REGISTRATION.validate() == ()
    manifest = GENERIC_TEST_TARGET_REGISTRATION.effective_manifest
    assert manifest is not None
    assert manifest.explicit is True
    assert manifest.target_id == "generic_test_target"
    assert "read_only_navigation" in manifest.supported_capabilities
    assert GENERIC_TEST_TARGET_ADAPTER.accepts_origin(GENERIC_TEST_ORIGIN)
    assert not GENERIC_TEST_TARGET_ADAPTER.accepts_origin(JUICE_SHOP_ORIGIN)


def test_same_registry_contract_supports_two_target_adapters() -> None:
    registry = TargetAdapterRegistry()
    registry.register(JUICE_SHOP_TARGET_REGISTRATION)
    registry.register(GENERIC_TEST_TARGET_REGISTRATION)

    assert registry.require_for_origin(JUICE_SHOP_ORIGIN).target_id == "owasp_juice_shop"
    assert registry.require_for_origin(GENERIC_TEST_ORIGIN).target_id == "generic_test_target"
    assert registry.for_origin("http://127.0.0.1:9999") is None
    assert registry.manifest()[1]["target_manifest"]["target_id"] == "owasp_juice_shop"


def test_generic_target_case_and_observation_use_generic_contracts() -> None:
    binding = GENERIC_TEST_TARGET_ADAPTER.case(GENERIC_TEST_CASE_ID)
    assert binding is not None
    assert binding.workflow_id == "read_only_navigation"
    assert binding.semantic_profile == GENERIC_TEST_PROFILE_ID

    observation = derive_semantic_observation(
        GENERIC_TEST_PROFILE_ID,
        status_code=200,
        content_type="text/plain; version=0.0.4",
        body="# HELP generic_total Generic\n# TYPE generic_total counter\ngeneric_total 1\n",
        final_path="/public-info",
        registry=GENERIC_TEST_TARGET_ADAPTER.semantic_profiles,
    )
    assert observation["semantic_match"] is True
    assert observation["semantic_oracle_ready"] is True
    assert "generic_total" not in str(observation)



def test_generic_target_backed_proof_is_sealed_replayable_and_redacted():
    from webpent.models.findings import Finding, Severity, VulnClass
    from webpent.shared.verifier import verify_replay_evidence

    finding = Finding(
        title="Generic semantic proof",
        severity=Severity.LOW,
        description="Bounded generic target test finding.",
        tool_name="generic-test",
        url="http://generic-target.test/resource",
        vuln_class=VulnClass.INFO_DISCLOSURE,
    )
    target_fingerprint = (
        "sha256:"
        "2d5e8c1f1f3d7e8653b6f1b4f8e3c5d4c8e1e14f5f5e0e9f2e1a1b9c2d3e4f50"
    )
    observations = {
        "baseline": {
            "target_backed": True,
            "observation_role": "baseline",
            "target_fingerprint": target_fingerprint,
            "request_digest": "sha256:generic-baseline-request",
            "response_digest": "sha256:generic-baseline-response",
            "semantic_match": False,
            "raw_response_body": "must-not-escape",
        },
        "candidate": {
            "target_backed": True,
            "observation_role": "candidate",
            "target_fingerprint": target_fingerprint,
            "request_digest": "sha256:generic-candidate-request",
            "response_digest": "sha256:generic-candidate-response",
            "semantic_match": True,
        },
        "negative_control": {
            "target_backed": True,
            "observation_role": "negative_control",
            "target_fingerprint": target_fingerprint,
            "request_digest": "sha256:generic-negative-request",
            "response_digest": "sha256:generic-negative-response",
            "semantic_match": False,
        },
    }

    result = verify_replay_evidence(
        finding,
        baseline=observations["baseline"],
        candidate=observations["candidate"],
        negative_control=observations["negative_control"],
        target_fingerprint=target_fingerprint,
        causal_signal=True,
        negative_control_complete=True,
        validator_id="generic-test-validator",
        validator_version="1.0",
        causal_basis="generic-test:independent semantic delta",
        engagement_id="generic-proof-engagement",
        hypothesis_id=f"finding:{finding.id}",
        scope_context={"origin": "http://generic-target.test"},
        identity_context={"mode": "anonymous"},
        replay_metadata={"target_id": "generic-test-target"},
        require_target_backed=True,
    )

    assert result.passed is True
    assert result.proof_bundle is not None
    assert result.proof_bundle.verify_seal() is True
    assert result.evidence["proof_bundle_sealed"] is True
    assert result.evidence["promotion_guard"]["replay_verified"] is True
    assert "must-not-escape" not in str(result.evidence)

    from webpent.shared.generic_case_lifecycle import case_result_from_verification

    case_result = case_result_from_verification(
        "generic.info_disclosure.v1",
        result,
        metadata={"raw_response_body": "must-not-escape", "target_classification": "api"},
    )
    assert case_result.status == "confirmed"
    assert case_result.proof_bundle_ref == result.proof_bundle.bundle_id
    assert case_result.negative_control_ref is not None
    assert "must-not-escape" not in str(case_result.as_dict())



def test_generic_target_proof_fails_closed_without_independent_control():

    from webpent.models.findings import Finding, Severity, VulnClass
    from webpent.shared.verifier import verify_replay_evidence

    finding = Finding(
        title="Generic proof control failure",
        severity=Severity.LOW,
        description="Control independence must be enforced.",
        tool_name="generic-test",
        url="http://generic-target.test/resource",
        vuln_class=VulnClass.INFO_DISCLOSURE,
    )
    observation = {
        "target_backed": True,
        "observation_role": "candidate",
        "target_fingerprint": "sha256:generic-target",
        "request_digest": "sha256:same-request",
        "response_digest": "sha256:same-response",
    }
    result = verify_replay_evidence(
        finding,
        baseline={**observation, "observation_role": "baseline"},
        candidate=observation,
        negative_control={**observation, "observation_role": "negative_control"},
        target_fingerprint="sha256:generic-target",
        causal_signal=True,
        negative_control_complete=True,
        validator_id="generic-test-validator",
        validator_version="1.0",
        causal_basis="generic-test:control independence",
        engagement_id="generic-proof-engagement",
        scope_context={"origin": "http://generic-target.test"},
        identity_context={"mode": "anonymous"},
        require_target_backed=True,
    )

    assert result.passed is False
    assert result.reason == "negative_control_must_be_independent"
    assert result.evidence["promotion_guard"]["status"] == "blocked"

    from webpent.shared.generic_case_lifecycle import case_result_from_verification

    case_result = case_result_from_verification("generic.info_disclosure.v1", result)
    assert case_result.status == "blocked"
    assert case_result.proof_bundle_ref is None
    assert case_result.negative_control_ref is None


__all__ = []




def test_mock_target_isolated_and_fail_closed_for_unavailable_live_preconditions():
    from webpent.adapters.mock_target.adapter import (
        MOCK_TARGET_ADAPTER,
        MOCK_TARGET_CASE_ID,
        MOCK_TARGET_ORIGIN,
        MOCK_TARGET_REGISTRATION,
    )

    registry = TargetAdapterRegistry()
    registry.register(MOCK_TARGET_REGISTRATION)

    assert MOCK_TARGET_REGISTRATION.validate() == ()
    assert registry.require_for_origin(MOCK_TARGET_ORIGIN).target_id == "mock_target"
    assert not MOCK_TARGET_ADAPTER.accepts_origin("http://127.0.0.1:3000")
    assert MOCK_TARGET_ADAPTER.preconditions_ready(MOCK_TARGET_CASE_ID) is False
    assert MOCK_TARGET_ADAPTER.supports_operation("navigate") is True
    assert MOCK_TARGET_ADAPTER.supports_operation("typed_search") is False


def test_mock_target_cannot_supply_unregistered_semantic_profile_or_cross_target_case():
    from webpent.adapters.mock_target.adapter import (
        MOCK_TARGET_ADAPTER,
        MOCK_TARGET_CASE_ID,
    )

    binding = MOCK_TARGET_ADAPTER.case(MOCK_TARGET_CASE_ID)
    assert binding is not None
    assert binding.semantic_profile is None
    assert MOCK_TARGET_ADAPTER.semantic_profile_for_case(MOCK_TARGET_CASE_ID) is None
    assert MOCK_TARGET_ADAPTER.case(GENERIC_TEST_CASE_ID) is None
    assert MOCK_TARGET_ADAPTER.case("juice.exposed_metrics.v1") is None
