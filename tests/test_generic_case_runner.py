from __future__ import annotations

import json
from uuid import uuid4

import httpx
import pytest

import webpent.adapters.generic_web.adapter as generic_adapter_module
from webpent.adapters.generic_web.adapter import (
    GENERIC_WEB_CASE_ID,
    GenericWebAdapter,
    build_generic_web_registration,
)
from webpent.adapters.mock_target.adapter import (
    MOCK_TARGET_CASE_ID,
    MOCK_TARGET_REGISTRATION,
    READY_MOCK_TARGET_REGISTRATION,
)
from webpent.benchmark.generic_test_target_adapter import GENERIC_TEST_TARGET_REGISTRATION
from webpent.models.findings import Finding, Severity
from webpent.shared.generic_case_runner import GenericCaseRunner
from webpent.shared.generic_web_contracts import (
    LIFECYCLE_CONTRACT_VERSION,
    CaseDefinition,
    LifecycleAuthorization,
    LifecycleRunContext,
    LifecycleStageResult,
)
from webpent.shared.target_adapters import (
    RegisteredTargetAdapter,
    TargetAdapterRegistry,
    lifecycle_adapter_for_registration,
)
from webpent.shared.verifier import verify_replay_evidence
from webpent.shared.workflow_contracts import (
    READ_ONLY_NAVIGATION,
    SAME_ORIGIN_RESOURCE_OBSERVATION,
)


@pytest.fixture(autouse=True)
def _safe_client_with_injected_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    def factory(**kwargs: object) -> httpx.Client:
        return httpx.Client(**kwargs)

    monkeypatch.setattr(generic_adapter_module, "make_safe_httpx_client", factory)


def _authorization(origin: str, *, authorized: bool = True) -> LifecycleAuthorization:
    return LifecycleAuthorization(
        authorized=authorized,
        engagement_id="offline-lifecycle-fixture",
        allowed_origin=origin,
        satisfied_requirements=("operator_declared_authorization",),
    )


def _context(registration: RegisteredTargetAdapter, case_id: str) -> LifecycleRunContext:
    target_id = str(registration.adapter.target_id)
    return LifecycleRunContext(
        run_id="run-lifecycle-001",
        target_id=target_id,
        case_id=case_id,
        engagement_id="offline-lifecycle-fixture",
    )


def _generic_case(adapter: GenericWebAdapter) -> CaseDefinition:
    return adapter.case_definition()


def test_lifecycle_resolver_is_explicit_and_legacy_compatible() -> None:
    adapter = GenericWebAdapter("http://resolver.test")
    registration = build_generic_web_registration(adapter)
    assert lifecycle_adapter_for_registration(registration) is adapter
    assert (
        lifecycle_adapter_for_registration(GENERIC_TEST_TARGET_REGISTRATION, required=False)
        is None
    )
    with pytest.raises(ValueError, match="target_lifecycle_provider_missing"):
        lifecycle_adapter_for_registration(GENERIC_TEST_TARGET_REGISTRATION)


def test_generic_runner_returns_observation_only_or_needs_profile_without_finding() -> None:
    adapter = GenericWebAdapter(
        "http://runner.test",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                headers={"content-type": "text/html"},
                content="<html><title>Fixture</title><a href='/about'>About</a></html>",
                request=request,
            )
        ),
    )
    registration = build_generic_web_registration(adapter)
    case = _generic_case(adapter)

    result = GenericCaseRunner.execute_case(
        registration,
        case,
        _authorization("http://runner.test"),
        _context(registration, case.case_id),
    )

    assert result.status == "needs_profile"
    assert result.reason == (
        "generic_surface_observation_has_no_independent_semantic_negative_control"
    )
    assert result.proof_bundle_ref is None
    assert result.observation_refs
    serialized = result.as_dict()
    assert "verification" not in serialized
    assert "raw_response" not in json.dumps(serialized)


def test_runner_target_swap_is_registration_scoped() -> None:
    generic = GenericWebAdapter(
        "http://swap-one.test",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                headers={"content-type": "text/html"},
                content="<html><title>Swap one</title></html>",
                request=request,
            )
        ),
    )
    generic_registration = build_generic_web_registration(generic)
    registry = TargetAdapterRegistry()
    registry.register(generic_registration)
    registry.register(MOCK_TARGET_REGISTRATION)

    generic_case = generic.case_definition()
    generic_result = GenericCaseRunner.execute_case(
        registry.require_for_origin("http://swap-one.test"),
        generic_case,
        _authorization("http://swap-one.test"),
        _context(generic_registration, generic_case.case_id),
    )
    assert generic_result.status == "needs_profile"

    mock_case = CaseDefinition(
        case_id=MOCK_TARGET_CASE_ID,
        workflow_id=READ_ONLY_NAVIGATION,
        required_capabilities=("read_only_navigation",),
        requires_negative_control=False,
    )
    mock_result = GenericCaseRunner.execute_case(
        registry.require_for_origin("http://127.0.0.1:4200"),
        mock_case,
        LifecycleAuthorization(
            authorized=True,
            engagement_id="offline-lifecycle-fixture",
            allowed_origin="http://127.0.0.1:4200",
            satisfied_requirements=("explicit_fixture_authorization", "loopback_origin"),
        ),
        _context(MOCK_TARGET_REGISTRATION, mock_case.case_id),
    )
    assert mock_result.status == "blocked"
    assert mock_result.reason == "mock_target_not_started_and_precondition_not_ready"


def test_generic_runner_blocks_without_explicit_authorization() -> None:
    adapter = GenericWebAdapter("http://unauthorized.test")
    registration = build_generic_web_registration(adapter)
    result = GenericCaseRunner.execute_case(
        registration,
        adapter.case_definition(),
        _authorization("http://unauthorized.test", authorized=False),
        _context(registration, GENERIC_WEB_CASE_ID),
    )
    assert result.status == "blocked"
    assert result.reason == "explicit_authorization_required"


def test_generic_runner_rejects_cross_origin_authorization() -> None:
    adapter = GenericWebAdapter("http://origin-one.test")
    registration = build_generic_web_registration(adapter)
    result = GenericCaseRunner.execute_case(
        registration,
        adapter.case_definition(),
        _authorization("http://origin-two.test"),
        _context(registration, GENERIC_WEB_CASE_ID),
    )
    assert result.status == "blocked"
    assert result.reason == "authorized_origin_outside_registration"


def test_generic_runner_rejects_mutating_case_before_adapter_execution() -> None:
    adapter = GenericWebAdapter("http://mutation.test")
    registration = build_generic_web_registration(adapter)
    case = CaseDefinition(
        case_id=GENERIC_WEB_CASE_ID,
        workflow_id=SAME_ORIGIN_RESOURCE_OBSERVATION,
        required_capabilities=("same_origin_resource_observation",),
        mutates_state=True,
        requires_negative_control=False,
    )
    result = GenericCaseRunner.execute_case(
        registration,
        case,
        _authorization("http://mutation.test"),
        _context(registration, case.case_id),
    )
    assert result.status == "unsupported"
    assert result.reason == "state_changing_case_not_allowed_by_generic_runner"


def test_generic_runner_reports_missing_capability_as_unsupported() -> None:
    adapter = GenericWebAdapter("http://capability.test")
    registration = build_generic_web_registration(adapter)
    case = CaseDefinition(
        case_id=GENERIC_WEB_CASE_ID,
        workflow_id=SAME_ORIGIN_RESOURCE_OBSERVATION,
        required_capabilities=("unregistered_capability",),
        requires_negative_control=False,
    )
    result = GenericCaseRunner.execute_case(
        registration,
        case,
        _authorization("http://capability.test"),
        _context(registration, case.case_id),
    )
    assert result.status == "unsupported"
    assert result.reason == "required_capability_missing:unregistered_capability"


def test_mock_lifecycle_is_deterministically_blocked_by_precondition() -> None:
    case = CaseDefinition(
        case_id=MOCK_TARGET_CASE_ID,
        workflow_id=READ_ONLY_NAVIGATION,
        required_capabilities=("read_only_navigation",),
        requires_negative_control=False,
    )
    result = GenericCaseRunner.execute_case(
        MOCK_TARGET_REGISTRATION,
        case,
        LifecycleAuthorization(
            authorized=True,
            engagement_id="offline-lifecycle-fixture",
            allowed_origin="http://127.0.0.1:4200",
            satisfied_requirements=("explicit_fixture_authorization", "loopback_origin"),
        ),
        _context(MOCK_TARGET_REGISTRATION, case.case_id),
    )
    assert result.status == "blocked"
    assert result.reason == "mock_target_not_started_and_precondition_not_ready"
    assert result.proof_bundle_ref is None


def test_mock_ready_opt_in_uses_central_proof_pipeline() -> None:
    adapter = READY_MOCK_TARGET_REGISTRATION.adapter
    case = adapter.case_definition()
    result = GenericCaseRunner.execute_case(
        READY_MOCK_TARGET_REGISTRATION,
        case,
        LifecycleAuthorization(
            authorized=True,
            engagement_id="offline-lifecycle-fixture",
            allowed_origin="http://127.0.0.1:4200",
            satisfied_requirements=("explicit_fixture_authorization", "loopback_origin"),
        ),
        _context(READY_MOCK_TARGET_REGISTRATION, case.case_id),
    )

    assert result.status == "confirmed"
    assert result.reason == "verified_replay"
    assert result.proof_bundle_ref
    assert result.negative_control_ref == "mock:run-lifecycle-001:negative_control"
    assert "verification" not in result.as_dict()
    serialized = json.dumps(result.as_dict(), sort_keys=True).lower()
    assert "cookie" not in serialized
    assert "authorization" not in serialized
    assert "raw_response_body" not in serialized

    verification = adapter._last_verification
    assert verification is not None
    assert verification.proof_bundle.verify_seal() is True
    replay_context = verification.evidence["replay_context"]
    assert verification.proof_bundle.replay(
        [
            verification.evidence["baseline"],
            verification.evidence["candidate"],
            verification.evidence["negative_control"],
        ],
        verification.evidence["negative_control"],
        replay_context=replay_context,
    ) is True
    assert (
        verification.evidence["candidate"]["request_digest"]
        != verification.evidence["negative_control"]["request_digest"]
    )
    assert all(
        observation["target_backed"]
        for observation in (
            verification.evidence["baseline"],
            verification.evidence["candidate"],
            verification.evidence["negative_control"],
        )
    )


class _ProofLifecycleAdapter(GenericWebAdapter):
    def baseline(self, case, authorization, run_context):
        return LifecycleStageResult(
            stage="baseline",
            status="completed",
            reason="baseline_observation_ready",
            observation_refs=("replay:fixture:baseline",),
        )

    def execute_safe_action(self, case, authorization, run_context):
        return LifecycleStageResult(
            stage="execute_safe_action",
            status="completed",
            reason="candidate_observation_ready",
            observation_refs=("replay:fixture:candidate",),
        )

    def observe(self, case, authorization, run_context):
        baseline = {"status_code": 200, "body_sha256": "baseline", "body_length": 4}
        candidate = {"status_code": 200, "body_sha256": "candidate", "body_length": 18}
        verification = verify_replay_evidence(
            Finding(
                id=uuid4(),
                title="controlled differential candidate",
                severity=Severity.HIGH,
                description="offline fixture",
                tool_name="offline-validator",
                url="http://proof-runner.test/item?id=safe",
                vuln_class="lfi",
                target_param="id",
                request_data={"id": "safe"},
            ),
            baseline=baseline,
            candidate=candidate,
            negative_control=baseline,
            causal_signal=True,
            negative_control_complete=True,
            validator_id="offline-replay",
            validator_version="1.0",
            causal_basis="controlled_differential_fixture",
            engagement_id="offline-lifecycle-fixture",
            hypothesis_id="offline-hypothesis",
            scope_context={"target_origin": "http://proof-runner.test", "scope_bound": True},
            identity_context={"mode": "anonymous", "cookie_count": 0},
        )
        return LifecycleStageResult(
            stage="observe",
            status="completed",
            reason="verification_completed",
            observation_refs=("replay:fixture:negative_control",),
            verification=verification,
        )

    def execute_negative_control(self, case, authorization, run_context):
        return LifecycleStageResult(
            stage="execute_negative_control",
            status="completed",
            reason="negative_control_completed",
            observation_refs=("replay:fixture:negative_control",),
        )

    def cleanup(self, case, authorization, run_context):
        return LifecycleStageResult(
            stage="cleanup",
            status="completed",
            reason="not_applicable",
        )


def test_runner_promotes_only_verifier_backed_sealed_replayable_proof() -> None:
    adapter = _ProofLifecycleAdapter("http://proof-runner.test")
    registration = build_generic_web_registration(adapter)
    case = adapter.case_definition()
    result = GenericCaseRunner.execute_case(
        registration,
        case,
        _authorization("http://proof-runner.test"),
        _context(registration, case.case_id),
    )

    assert result.status == "confirmed"
    assert result.reason == "verified_replay"
    assert result.proof_bundle_ref
    assert result.negative_control_ref == "replay:fixture:negative_control"


def test_lifecycle_contract_objects_are_declarative_and_callbacks_are_not_serialized() -> None:
    adapter = GenericWebAdapter("http://serialization.test")
    registration = build_generic_web_registration(adapter)
    case = adapter.case_definition()
    context = _context(registration, case.case_id)
    authorization = _authorization("http://serialization.test")

    payload = {
        "authorization": authorization.as_dict(),
        "context": context.as_dict(),
        "case": case.as_dict(),
        "registration": registration.manifest.as_dict() if registration.manifest else None,
    }
    encoded = json.dumps(payload, sort_keys=True)
    assert LIFECYCLE_CONTRACT_VERSION in encoded
    assert "callback" not in encoded.lower()
    assert "transport" not in encoded.lower()
    assert "cookies" not in encoded.lower()
    assert "raw_response_bodies_saved" not in encoded
    assert "credentials_or_cookies_saved" not in encoded
