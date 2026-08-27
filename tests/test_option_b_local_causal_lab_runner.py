from __future__ import annotations

from scripts.run_option_b_local_causal_lab import build_result


def test_option_b_runner_emits_only_redacted_blocked_records() -> None:
    result = build_result()
    assert result["scope"]["loopback_only"] is True
    assert result["scope"]["methods"] == ["GET"]
    assert result["scope"]["official_isolated_p10_runs_authorized"] is False
    assert result["summary"]["target_backed_causal_confirmations"] == 0
    assert result["summary"]["proof_bundles_sealed"] == 0
    assert result["summary"]["quality_metrics"] == "WITHHELD"
    assert len(result["cases"]) == 6
    assert all(
        case["final_classification"] == "LAB_NOT_READY/PRECONDITION_BLOCKED"
        for case in result["cases"]
    )
    assert result["summary"]["lab_status"] == "LAB_NOT_READY"
    assert result["summary"]["precondition_blocked_case_count"] == 6
    assert all(
        case["runnable_precondition"]["network_attempted"] is False for case in result["cases"]
    )
    assert all(case["baseline"]["status"] == "not_run" for case in result["cases"])
    assert all(case["proof_bundle"]["seal"] == "not_created" for case in result["cases"])
    assert all(case["cleanup"]["status"] == "verified_no_mutation" for case in result["cases"])


def test_option_b_runner_records_runtime_digest_blockers_without_sensitive_material() -> None:
    result = build_result()
    assert (
        result["target_provenance"]["owasp_webgoat"]["runtime"]["runtime_digest"]
        is not None
    )
    assert (
        result["target_provenance"]["crapi"]["runtime"]["runtime_digest"] is not None
    )
    assert (
        result["target_provenance"]["owasp_webgoat"]["runtime"]["readiness"]["status"]
        == "blocked"
    )
    assert (
        result["target_provenance"]["crapi"]["runtime"]["readiness"]["status"]
        == "ready"
    )
    serialized = str(result)
    for forbidden in ("Cookie:", "Set-Cookie:", "Bearer ", "password=", "token="):
        assert forbidden not in serialized
    for case in result["cases"]:
        assert case["cleanup"]["network_attempted"] is False
        assert case["identity_model"]["status"] == "offline_opaque_only"
        assert case["fixture_model"]["snapshot_restore"]["status"] == "verified"
