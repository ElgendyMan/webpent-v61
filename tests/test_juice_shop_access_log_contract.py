from __future__ import annotations

from webpent.benchmark.juice_shop_target_adapter import JUICE_SHOP_TARGET_REGISTRATION
from webpent.shared.semantic_observations import derive_semantic_observation

CASE_ID = "juice.access_log_disclosure.v1"


def test_access_log_case_is_bound_to_reviewed_semantic_contract() -> None:
    adapter = JUICE_SHOP_TARGET_REGISTRATION.adapter
    case = adapter.case(CASE_ID)

    assert case is not None
    assert case.operation == "navigate"
    assert case.path.startswith("/support/logs/access.log.")
    assert case.semantic_profile == "juice.access_log.v1"
    assert case.oracle_id == "http.read_only.log_resource_metadata"
    assert adapter.semantic_profile_for_case(CASE_ID) == case.semantic_profile


def test_access_log_semantic_predicate_and_control_are_distinct_and_redacted() -> None:
    adapter = JUICE_SHOP_TARGET_REGISTRATION.adapter
    profile = adapter.semantic_profiles
    candidate = derive_semantic_observation(
        "juice.access_log.v1",
        status_code=200,
        content_type="application/octet-stream",
        body=b"GET /api/Products HTTP/1.1\nPOST /rest/user/login HTTP/1.1\n",
        final_path="/support/logs/access.log.2026-08-26",
        registry=profile,
    )
    control = derive_semantic_observation(
        "juice.access_log.v1",
        status_code=200,
        content_type="text/html",
        body=b"<html><body>not a log resource</body></html>",
        final_path="/p10-negative-control-not-found",
        registry=profile,
    )

    assert candidate["semantic_match"] is True
    assert candidate["log_record_count_bucket"] >= 2
    assert control["semantic_match"] is False
    assert control["log_record_count_bucket"] == 0
    for observation in (candidate, control):
        serialized = str(observation)
        assert "raw_response_body" not in serialized
        assert "cookie" not in serialized.lower()
        assert "authorization" not in serialized.lower()
