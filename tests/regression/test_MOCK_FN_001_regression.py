from webpent.adapters.mock_target.adapter import (
    MOCK_TARGET_CASE_ID,
    MOCK_TARGET_REGISTRATION,
)
from webpent.shared.generic_case_runner import GenericCaseRunner
from webpent.shared.generic_web_contracts import (
    CaseDefinition,
    LifecycleAuthorization,
    LifecycleRunContext,
)
from webpent.shared.workflow_contracts import READ_ONLY_NAVIGATION


def test_mock_fn_001_default_fixture_remains_fail_closed() -> None:
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
            engagement_id="offline-mock-fn-001",
            allowed_origin="http://127.0.0.1:4200",
            satisfied_requirements=("explicit_fixture_authorization", "loopback_origin"),
        ),
        LifecycleRunContext(
            run_id="mock-fn-001-regression",
            target_id=str(MOCK_TARGET_REGISTRATION.adapter.target_id),
            case_id=case.case_id,
            engagement_id="offline-mock-fn-001",
        ),
    )

    assert result.status == "blocked"
    assert result.reason == "mock_target_not_started_and_precondition_not_ready"
    assert result.proof_bundle_ref is None
    assert result.observation_refs == ()
