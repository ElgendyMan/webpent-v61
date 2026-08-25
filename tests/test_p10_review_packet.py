from __future__ import annotations

import json
from pathlib import Path

_PACKET = Path(__file__).parents[1] / "docs" / "p10_independent_review_packet_v1.json"


def test_review_packet_is_pre_result_and_fail_closed() -> None:
    packet = json.loads(_PACKET.read_text(encoding="utf-8"))
    cases = packet["candidate_cases"]
    categories = {case["category"] for case in cases}
    in_scope_categories = {
        case["category"]
        for case in cases
        if case["case_id"] != "juice.redirect_local.v1"
    }

    assert len(cases) == 13
    assert len(categories) == 7
    assert len(in_scope_categories) == 6
    assert packet["independence"]["results_seen_by_reviewer"] is False
    assert packet["independence"]["review_status"] == (
        "mapping_approved_pending_oracle_freeze_and_full_runs"
    )
    assert packet["independence"]["mapping_review_approved"] is True
    assert packet["independence"]["full_p10_qualification_approved"] is False
    assert packet["approval_record"]["approved"] is True
    assert packet["approval_record"]["approval_scope"] == (
        "case_mapping_and_safety_posture_only"
    )
    assert packet["approval_record"]["approved_case_count"] == 11
    assert packet["approval_record"]["approved_class_count"] == 6
    assert packet["approval_record"]["full_p10_qualification_approved"] is False
    assert packet["approval_record"]["mapping_hash"] == (
        "sha256:602b2411df9b259911b1ae0757e5e26fabdc86b928fb5b43b040750182762ad5"
    )
    assert packet["approval_record"]["oracle_contract_hash"] == (
        "sha256:63977f8451f0709abff5671d1ac24943abe35b0bb0a4f399791e2c1f66aeb71c"
    )
    assert sum(
        case["review_decision"] == "approved_mapping" for case in cases
    ) == 11
    assert all(
        case["review_decision"] in {"approved_mapping", "out_of_scope"}
        for case in cases
    )
    assert {
        case["case_id"] for case in cases if case["review_decision"] == "out_of_scope"
    } == {
        "juice.application_version_surface.v1",
        "juice.redirect_local.v1",
    }
    assert packet["independence"]["reviewer_id"] == (
        "independent-reviewer:grok-p10-mapping"
    )
    assert packet["independence"]["results_seen_by_reviewer"] is False


def test_review_packet_is_loopback_get_only_and_redacted() -> None:
    packet = json.loads(_PACKET.read_text(encoding="utf-8"))
    contract = packet["safety_contract"]

    assert contract["allowed_origin"] == "http://127.0.0.1:3000"
    assert contract["allowed_methods"] == ["GET"]
    assert contract["credentials_used"] is False
    assert contract["account_actions"] is False
    assert contract["external_destinations"] is False
    assert contract["raw_bodies_retained"] is False
    assert contract["raw_headers_retained"] is False
    assert contract["cookies_retained"] is False
    assert contract["secrets_retained"] is False
