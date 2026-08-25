from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

from webpent.shared.semantic_observations import derive_semantic_observation
from webpent.shared.semantic_proof_runner import SemanticProofRunner

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
    )

    assert result["semantic_match"] is False
    assert result["semantic_oracle_ready"] is False
    assert result["semantic_reason"] == "semantic_profile_not_registered"


def test_semantic_runner_rejects_non_promotable_profile_before_execution() -> None:
    with pytest.raises(ValueError, match="semantic_profile_not_promotable"):
        SemanticProofRunner(
            replay_engine=None,
            adapter=None,
            session=None,
            scope=None,
            engagement_id="engagement",
            semantic_profile="juice.policy_resource.v1",
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


def test_semantic_case_mapping_is_explicit_and_target_specific() -> None:
    assert module.semantic_profile_for_case("juice.exposed_metrics.v1") == (
        "juice.exposed_metrics.v1"
    )
    assert module.semantic_profile_for_case("juice.error_handling.v1") == (
        "juice.error_disclosure.v1"
    )
    assert module.semantic_profile_for_case("juice.privacy_policy_proof.v1") is None
    assert module.semantic_profile_for_case("other-target.metrics.v1") is None


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
    )

    forbidden = {"body", "headers", "cookies", "payload", "raw_response_body"}
    assert forbidden.isdisjoint(result)
    assert "secret-body-value" not in str(result)


class TestSemanticAdapterModule:
    def test_target_specific_profiles_do_not_leak_into_generic_names(self) -> None:
        assert all(key.startswith("juice.") for key in module.SEMANTIC_CASE_PROFILES)

    def test_metrics_profile_is_the_only_currently_promotable_get_profile_used(self) -> None:
        assert module.SEMANTIC_CASE_PROFILES["juice.exposed_metrics.v1"] == (
            "juice.exposed_metrics.v1"
        )
        assert module.SEMANTIC_CASE_PROFILES["juice.error_handling.v1"] == (
            "juice.error_disclosure.v1"
        )
        assert len(module.SEMANTIC_CASE_PROFILES) == 2


class _Unused:
    pass
