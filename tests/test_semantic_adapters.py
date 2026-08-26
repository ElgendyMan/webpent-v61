from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

from webpent.benchmark.juice_shop_target_adapter import (
    JUICE_SHOP_SEMANTIC_PROFILES,
    JUICE_SHOP_TARGET_ADAPTER,
)
from webpent.shared.semantic_observations import (
    SemanticProfileRegistry,
    derive_semantic_observation,
)
from webpent.shared.semantic_proof_runner import SemanticProofRunner
from webpent.shared.target_adapters import (
    RegisteredTargetAdapter,
    TargetAdapterRegistry,
    TargetCaseBinding,
)

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "run_juice_shop_p10_full.py"
spec = importlib.util.spec_from_file_location("juice_shop_p10_full", MODULE_PATH)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_metrics_semantic_adapter_returns_bounded_match_without_body() -> None:
    result = derive_semantic_observation(
        "juice.exposed_metrics.v1",
        status_code=200,
        content_type="text/plain; version=0.0.4",
        body=b"# HELP requests_total Requests\n# TYPE requests_total counter\nrequests_total 1\n",
        final_path="/metrics",
        registry=JUICE_SHOP_SEMANTIC_PROFILES,
    )

    assert result["semantic_match"] is True
    assert result["semantic_oracle_ready"] is True
    assert result["content_type_family"] == "text/plain"
    assert result["metric_line_count_bucket"] >= 2
    assert "body" not in result
    assert "requests_total" not in str(result)


def test_error_semantic_adapter_requires_server_error_and_stack_shape() -> None:
    result = derive_semantic_observation(
        "juice.error_disclosure.v1",
        status_code=500,
        content_type="text/html",
        body="Error\n    at handler (/app/server.js:42:7)\n",
        final_path="/rest/qwertz",
        registry=JUICE_SHOP_SEMANTIC_PROFILES,
    )

    assert result["semantic_match"] is True
    assert result["verbose_error_shape"] is True
    assert result["status_code"] == 500
    assert "/app/server.js" not in str(result)


def test_unregistered_semantic_profile_is_observation_only() -> None:
    result = derive_semantic_observation(
        "juice.unknown.v1",
        status_code=200,
        content_type="text/plain",
        body="# HELP x x\nx 1\n",
        final_path="/unknown",
        registry=JUICE_SHOP_SEMANTIC_PROFILES,
    )

    assert result["semantic_match"] is False
    assert result["semantic_oracle_ready"] is False
    assert result["semantic_reason"] == "semantic_profile_not_registered"


def test_semantic_runner_rejects_unregistered_profile_before_execution() -> None:
    with pytest.raises(ValueError, match="semantic_profile_not_registered"):
        SemanticProofRunner(
            replay_engine=None,
            adapter=None,
            session=None,
            scope=None,
            engagement_id="engagement",
            semantic_profile="juice.policy_resource.v1",
            semantic_profiles=JUICE_SHOP_SEMANTIC_PROFILES,
            validator_id="test-validator",
        )


def test_record_proof_result_does_not_promote_incomplete_attestation() -> None:
    proof_result = SimpleNamespace(
        passed=True,
        attestation={
            "proof_verified": True,
            "proof_bundle_sealed": True,
            "proof_bundle": {"sealed": True},
            "causal_signal": True,
            "negative_control_complete": False,
            "promotion_guard": {
                "replay_verified": True,
                "replayable": True,
                "status": "passed",
            },
        },
        observations={"baseline": {}, "candidate": {}, "negative_control": {}},
        reason="verified",
        diagnostics={},
    )
    observations: dict[str, dict[str, object]] = {}
    statuses: dict[str, str] = {}
    proof_states: dict[str, dict[str, object]] = {}
    proof_bundles: dict[str, dict[str, object]] = {}

    module.record_proof_result(
        "juice.exposed_metrics.v1",
        proof_result,
        observations=observations,
        statuses=statuses,
        proof_states=proof_states,
        proof_bundles=proof_bundles,
    )

    assert statuses["juice.exposed_metrics.v1"] == "confirmed_metadata_only"
    assert proof_states["juice.exposed_metrics.v1"]["promotion_ready"] is False
    assert "juice.exposed_metrics.v1" in proof_bundles


def test_semantic_case_mapping_is_owned_by_target_adapter() -> None:
    assert JUICE_SHOP_TARGET_ADAPTER.semantic_profile_for_case(
        "juice.exposed_metrics.v1"
    ) == "juice.exposed_metrics.v1"
    assert JUICE_SHOP_TARGET_ADAPTER.semantic_profile_for_case(
        "juice.error_handling.v1"
    ) == "juice.error_disclosure.v1"
    assert JUICE_SHOP_TARGET_ADAPTER.semantic_profile_for_case(
        "juice.privacy_policy_proof.v1"
    ) is None
    assert JUICE_SHOP_TARGET_ADAPTER.semantic_profile_for_case(
        "other-target.metrics.v1"
    ) is None


@pytest.mark.parametrize(
    "profile, status, content_type, body, expected",
    [
        (
            "juice.exposed_metrics.v1",
            200,
            "text/html",
            "<html>not metrics</html>",
            False,
        ),
        (
            "juice.error_disclosure.v1",
            404,
            "text/html",
            "Error\n at handler (/app/server.js:42:7)",
            False,
        ),
    ],
)
def test_semantic_profiles_fail_closed_on_nonmatching_controls(
    profile: str,
    status: int,
    content_type: str,
    body: str,
    expected: bool,
) -> None:
    result = derive_semantic_observation(
        profile,
        status_code=status,
        content_type=content_type,
        body=body,
        final_path="/control",
        registry=JUICE_SHOP_SEMANTIC_PROFILES,
    )
    assert result["semantic_match"] is expected
    assert result["semantic_oracle_ready"] is True
    assert "server.js" not in str(result)


def test_semantic_observation_does_not_retain_raw_response_keys() -> None:
    result = derive_semantic_observation(
        "juice.exposed_metrics.v1",
        status_code=200,
        content_type="text/plain",
        body="secret-body-value\n# HELP x x\nx 1",
        final_path="/metrics",
        registry=JUICE_SHOP_SEMANTIC_PROFILES,
    )

    forbidden = {"body", "headers", "cookies", "payload", "raw_response_body"}
    assert forbidden.isdisjoint(result)
    assert "secret-body-value" not in str(result)


class TestSemanticAdapterModule:
    def test_target_specific_profiles_do_not_leak_into_generic_names(self) -> None:
        assert all(
            profile.startswith("juice.")
            for profile in JUICE_SHOP_SEMANTIC_PROFILES.profiles()
        )

    def test_target_adapter_is_explicitly_origin_scoped(self) -> None:
        assert JUICE_SHOP_TARGET_ADAPTER.accepts_origin("http://127.0.0.1:3000")
        assert not JUICE_SHOP_TARGET_ADAPTER.accepts_origin("http://127.0.0.1:4000")


class _Unused:
    pass


class _FakeTargetAdapter:
    target_id = "fake_target"
    target_origin = "http://127.0.0.1:4100"
    semantic_profiles = SemanticProfileRegistry(
        {
            "fake.metrics.v1": {
                "target_family": "fake_target",
                "promotable": True,
                "rule": "prometheus_publication",
            }
        }
    )

    def workflow_ids(self) -> tuple[str, ...]:
        return ("fake-read-only-navigation",)

    def workflow_executors(self) -> dict[str, object]:
        return {}

    def case_ids(self) -> tuple[str, ...]:
        return ("fake.metrics.v1",)

    def case(self, case_id: str) -> TargetCaseBinding | None:
        if case_id != "fake.metrics.v1":
            return None
        return TargetCaseBinding(
            case_id=case_id,
            operation="navigate",
            path="/metrics",
            oracle_id="fake.metrics.oracle.v1",
            workflow_id="fake-read-only-navigation",
            semantic_profile="fake.metrics.v1",
            scoring_status="oracle_approved_partial",
        )

    def semantic_profile_for_case(self, case_id: str) -> str | None:
        return "fake.metrics.v1" if case_id == "fake.metrics.v1" else None

    def accepts_origin(self, origin: str) -> bool:
        return origin.rstrip("/") == self.target_origin


def test_generic_target_registry_accepts_independent_target_without_juice_fallback() -> None:
    fake = _FakeTargetAdapter()
    registrations = TargetAdapterRegistry()
    registrations.register(
        RegisteredTargetAdapter(
            adapter=fake,
            source="tests.fake_target",
            version="1",
            policy_ref="test-read-only",
            proof_contract="central-causal-negative-sealed-replay-v1",
        )
    )

    assert registrations.require_for_origin("http://127.0.0.1:4100").target_id == (
        "fake_target"
    )
    assert registrations.for_origin("http://127.0.0.1:3000") is None

    fake_result = derive_semantic_observation(
        "fake.metrics.v1",
        status_code=200,
        content_type="text/plain; version=0.0.4",
        body="# HELP fake_total Fake\n# TYPE fake_total counter\nfake_total 1\n",
        final_path="/metrics",
        registry=fake.semantic_profiles,
    )
    juice_result = derive_semantic_observation(
        "juice.exposed_metrics.v1",
        status_code=200,
        content_type="text/plain",
        body="# HELP requests_total Requests\nrequests_total 1\n",
        final_path="/metrics",
        registry=fake.semantic_profiles,
    )

    assert fake_result["semantic_match"] is True
    assert juice_result["semantic_oracle_ready"] is False
    assert juice_result["semantic_reason"] == "semantic_profile_not_registered"


def test_target_case_binding_does_not_infer_semantic_profile() -> None:
    fake = _FakeTargetAdapter()
    assert fake.case("unknown") is None
    assert fake.semantic_profile_for_case("unknown") is None
    assert fake.case("fake.metrics.v1").semantic_profile == "fake.metrics.v1"



class _MissingWorkflowAdapter(_FakeTargetAdapter):
    def workflow_ids(self) -> tuple[str, ...]:
        return ()


class _DuplicateWorkflowAdapter(_FakeTargetAdapter):
    def workflow_ids(self) -> tuple[str, ...]:
        return ("fake-read-only-navigation", "fake-read-only-navigation")


def _registration(adapter) -> RegisteredTargetAdapter:
    return RegisteredTargetAdapter(
        adapter=adapter,
        source="tests.fake_target",
        version="1",
        policy_ref="test-read-only",
        proof_contract="central-causal-negative-sealed-replay-v1",
    )


def test_target_registry_rejects_missing_workflow_allowlist() -> None:
    with pytest.raises(ValueError, match="workflow_allowlist_required"):
        TargetAdapterRegistry().register(_registration(_MissingWorkflowAdapter()))


def test_target_registry_rejects_duplicate_workflow_allowlist() -> None:
    with pytest.raises(ValueError, match="workflow_allowlist_duplicate"):
        TargetAdapterRegistry().register(_registration(_DuplicateWorkflowAdapter()))


class _UnallowlistedCaseWorkflowAdapter(_FakeTargetAdapter):
    def case(self, case_id: str) -> TargetCaseBinding | None:
        binding = super().case(case_id)
        if binding is None:
            return None
        return TargetCaseBinding(
            case_id=binding.case_id,
            operation=binding.operation,
            path=binding.path,
            oracle_id=binding.oracle_id,
            workflow_id="unreviewed-workflow",
            semantic_profile=binding.semantic_profile,
            scoring_status=binding.scoring_status,
        )


class _MismatchedCaseProfileAdapter(_FakeTargetAdapter):
    def semantic_profile_for_case(self, case_id: str) -> str | None:
        return None


class _FailingWorkflowAdapter(_FakeTargetAdapter):
    def workflow_ids(self) -> tuple[str, ...]:
        raise RuntimeError("workflow source unavailable")


def test_target_registry_rejects_case_workflow_outside_allowlist() -> None:
    with pytest.raises(ValueError, match="case_workflow_not_allowlisted"):
        TargetAdapterRegistry().register(_registration(_UnallowlistedCaseWorkflowAdapter()))


def test_target_registry_rejects_case_profile_mismatch() -> None:
    with pytest.raises(ValueError, match="case_profile_mismatch"):
        TargetAdapterRegistry().register(_registration(_MismatchedCaseProfileAdapter()))


def test_target_registry_converts_workflow_provider_failure_to_validation_error() -> None:
    with pytest.raises(ValueError, match="workflow_ids_failed:RuntimeError"):
        TargetAdapterRegistry().register(_registration(_FailingWorkflowAdapter()))


def test_target_case_binding_requires_workflow_and_oracle_identity() -> None:
    with pytest.raises(ValueError, match="target_case_binding_workflow_id_required"):
        TargetCaseBinding(
            case_id="case",
            operation="navigate",
            path="/safe",
            oracle_id="oracle",
            workflow_id="",
        )
    with pytest.raises(ValueError, match="target_case_binding_oracle_id_required"):
        TargetCaseBinding(
            case_id="case",
            operation="navigate",
            path="/safe",
            oracle_id="",
            workflow_id="workflow",
        )


class _InvalidTargetObject:
    target_id = "invalid"


def test_target_registry_rejects_non_adapter_objects() -> None:
    with pytest.raises(ValueError, match="adapter_contract_invalid"):
        TargetAdapterRegistry().register(_registration(_InvalidTargetObject()))


def test_target_registry_origin_lookup_revalidates_mutated_adapter() -> None:
    fake = _FakeTargetAdapter()
    registrations = TargetAdapterRegistry()
    registrations.register(_registration(fake))

    assert registrations.require_for_origin("http://127.0.0.1:4100").target_id == (
        "fake_target"
    )
    fake.target_origin = "not-an-origin"

    assert registrations.for_origin("http://127.0.0.1:4100") is None
    with pytest.raises(ValueError, match="origin_not_registered_or_ambiguous"):
        registrations.require_for_origin("http://127.0.0.1:4100")


def test_target_registry_origin_lookup_fails_closed_on_provider_exception() -> None:
    class _MutableOriginAdapter(_FakeTargetAdapter):
        broken = False

        def accepts_origin(self, origin: str) -> bool:
            if self.broken:
                raise RuntimeError("origin provider unavailable")
            return super().accepts_origin(origin)

    adapter = _MutableOriginAdapter()
    registrations = TargetAdapterRegistry()
    registrations.register(_registration(adapter))
    adapter.broken = True

    assert registrations.for_origin("http://127.0.0.1:4100") is None
