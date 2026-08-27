from re import compile

from webpent.adapters.local_causal_lab.option_b_contract import (
    OptionBCase,
    TargetEvidenceReadiness,
    validate_option_b_preconditions,
    validate_target_evidence_readiness,
)


def _readiness(**overrides: bool) -> TargetEvidenceReadiness:
    values = {
        "identity_model_available": True,
        "ownership_model_available": True,
        "reset_available": True,
        "oracle_signal_available": True,
        "observable_security_invariant": True,
        "replayable_state_transition": True,
    }
    values.update(overrides)
    return TargetEvidenceReadiness(**values)


def _case() -> OptionBCase:
    return OptionBCase(
        case_id="WEBGOAT-IDOR-CAUSAL-001",
        target_id="webgoat-local",
        origin="http://127.0.0.1:8080",
        route_pattern=compile(r"/safe/object/[a-z0-9_-]+"),
        approved_methods=("GET",),
        approved_query_keys=(),
        track="idor",
        requires_auth=False,
        requires_target_fixture_injection=False,
        precondition_status="ready",
        precondition_reason="bounded local case",
        baseline_role="owner",
        candidate_role="requester",
        negative_control_roles=("requester-unrelated",),
    )


def test_target_evidence_readiness_is_ready_only_when_all_capabilities_exist():
    result = validate_target_evidence_readiness(_readiness())

    assert result["status"] == "ready"
    assert result["runnable"] is True
    assert result["network_allowed"] is True
    assert result["missing_capabilities"] == ()
    assert result["network_attempted"] is False


def test_target_evidence_readiness_blocks_missing_capability():
    result = validate_target_evidence_readiness(
        _readiness(ownership_model_available=False, reset_available=False)
    )

    assert result["status"] == "blocked"
    assert result["runnable"] is False
    assert result["network_allowed"] is False
    assert result["missing_capabilities"] == (
        "ownership_model_available",
        "reset_available",
    )
    assert result["network_attempted"] is False


def test_option_b_preflight_blocks_before_request_when_target_readiness_is_missing():
    result = validate_option_b_preconditions(
        case=_case(),
        method="GET",
        url="http://127.0.0.1:8080/safe/object/owner-object",
        expected_origin="http://127.0.0.1:8080",
        readiness_status="ready",
        fixture_snapshot_status="verified",
        target_evidence_readiness=_readiness(oracle_signal_available=False),
    )

    assert result["status"] == "blocked"
    assert result["runnable"] is False
    assert result["network_allowed"] is False
    assert "target_evidence_oracle_signal_available_unavailable" in result["errors"]
    assert result["network_attempted"] is False
