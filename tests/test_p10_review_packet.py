from __future__ import annotations

import json
from pathlib import Path

_PACKET = Path(__file__).parents[1] / "docs" / "p10_independent_review_packet_v1.json"


def test_review_packet_is_pre_result_and_fail_closed() -> None:
    packet = json.loads(_PACKET.read_text(encoding="utf-8"))
    cases = packet["candidate_cases"]
    categories = {case["category"] for case in cases}

    assert len(cases) == 10
    assert len(categories) == 6
    assert packet["independence"]["results_seen_by_reviewer"] is False
    assert packet["independence"]["review_status"] == "pending_external_reviewer"
    assert packet["approval_record"]["approved"] is False
    assert packet["approval_record"]["approved_case_count"] == 0
    assert packet["approval_record"]["approved_class_count"] == 0
    assert all(case["review_decision"] == "pending" for case in cases)


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
