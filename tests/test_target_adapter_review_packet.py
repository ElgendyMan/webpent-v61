"""Tests for the target-adapter review packet governance contract."""
from __future__ import annotations

import json
from pathlib import Path

from webpent.shared.target_adapter_review import validate_target_adapter_review_packet

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = PROJECT_ROOT / "docs" / "target_adapter_review_packet_template_v1.json"


def _template() -> dict:
    return json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))


def test_checked_in_template_is_draft_and_valid() -> None:
    packet = _template()

    assert packet["packet_status"] == "draft"
    assert validate_target_adapter_review_packet(packet) == ()


def test_review_packet_rejects_qualification_claim() -> None:
    packet = _template()
    packet["qualification_claim"] = True

    errors = validate_target_adapter_review_packet(packet)

    assert "packet:qualification_claim_must_be_false" in errors


def test_closed_packet_requires_reviewer_and_complete_dispositions() -> None:
    packet = _template()
    packet["packet_status"] = "mapping_approved"
    packet["workflows"][0].update(
        {
            "workflow_id": "navigate-v1",
            "operation": "navigate",
            "reviewed": True,
            "allowlisted": True,
        }
    )
    packet["cases"][0].update(
        {
            "case_id": "case-v1",
            "operation": "navigate",
            "path": "/safe",
            "workflow_id": "navigate-v1",
            "oracle_id": "oracle-v1",
            "mapping_status": "approved",
        }
    )
    errors = validate_target_adapter_review_packet(packet)

    assert "review:decision_pending_for_closed_status" in errors
    assert "review:reviewer_id_required" in errors
    assert "review:case_dispositions_must_cover_all_cases" in errors
    assert "cases[0]:target_backed_causal_contract_required" in errors
