from __future__ import annotations

from webpent.adapters.webgoat.causal_experiment import (
    WEBGOAT_IDOR_CASE_ID,
    webgoat_idor_causal_design,
)


def test_webgoat_redesigned_experiment_is_bounded_and_blocked_without_fixture():
    design = webgoat_idor_causal_design()

    assert design.case_id == WEBGOAT_IDOR_CASE_ID
    assert design.execution_mode.startswith("design_only")
    assert design.method == "GET"
    assert design.preconditions_ready is False
    assert design.historical_flow_reused is False
    assert design.target_backed_confirmation_allowed is False
    assert design.blocker_code == "WEBGOAT_LESSON_SESSION_OWNER_FIXTURE_UNAVAILABLE"
    assert len(design.required_observables) >= 4
    assert "status/redirect/route" in design.blocker_reason or "observable" in design.blocker_reason


def test_webgoat_design_requires_distinct_identity_and_control_resources():
    design = webgoat_idor_causal_design()

    assert design.owner_identity_ref != design.requester_identity_ref
    assert design.owner_resource_ref == design.candidate_resource_ref.split("-under-")[0]
    assert design.candidate_resource_ref != design.negative_control_resource_ref
    assert any("negative control" in item for item in design.required_observables)


def test_webgoat_design_is_serializable_without_sensitive_material():
    payload = webgoat_idor_causal_design().as_dict()
    serialized = repr(payload).lower()

    assert payload["target_backed_confirmation_allowed"] is False
    assert "password" not in serialized
    assert "cookie" not in serialized
    assert "token" not in serialized
