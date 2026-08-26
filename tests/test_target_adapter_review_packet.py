"""Tests for the target-adapter review packet governance contract."""
from __future__ import annotations

import copy
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


def _closed_packet(*, status: str = "mapping_approved") -> dict:
    packet = copy.deepcopy(_template())
    packet["packet_status"] = status
    packet["target"].update(
        {
            "target_id": "target-v1",
            "target_origin": "http://127.0.0.1:8080",
            "source_ref": "local-review-source",
            "adapter_module": "example.target_adapter",
            "adapter_version": "v1",
            "scope_digest": "a" * 64,
            "authorization_ref": "local-authorization-v1",
        }
    )
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
            "expected_disposition": "approved",
            "causal_signal_contract": {
                "defined": True,
                "target_backed": True,
                "observation_only": False,
                "description": "A target-backed causal transition is required.",
            },
            "negative_control_contract": {
                "defined": True,
                "independent": True,
                "description": "An independent control must not produce the signal.",
            },
        }
    )
    packet["review"].update(
        {
            "reviewer_id": "external-reviewer",
            "reviewed_at_utc": "2026-08-26T00:00:00Z",
            "reviewed_mapping_sha256": "b" * 64,
            "reviewed_oracle_contract_sha256": "c" * 64,
            "approved_case_ids": ["case-v1"],
            "approval_decision": "approved",
            "results_seen_by_reviewer": status == "approved",
        }
    )
    packet["live_runs"]["authorized"] = status in {"qualified_for_runs", "approved"}
    if status == "approved":
        packet["live_runs"].update(
            {
                "run_ids": ["run-1", "run-2", "run-3"],
                "executed_case_ids": ["case-v1"],
                "proof_bundle_ids": ["bundle-v1"],
                "run_case_matrix": {
                    "run-1": ["case-v1"],
                    "run-2": ["case-v1"],
                    "run-3": ["case-v1"],
                },
                "replay_statuses": {
                    "run-1": "passed",
                    "run-2": "passed",
                    "run-3": "passed",
                },
                "verify_seal_results": {
                    "run-1": True,
                    "run-2": True,
                    "run-3": True,
                },
            }
        )
    return packet


def test_review_packet_rejects_qualification_claim() -> None:
    packet = _template()
    packet["qualification_claim"] = True

    errors = validate_target_adapter_review_packet(packet)

    assert "packet:qualification_claim_must_be_false" in errors


def test_mapping_approved_packet_is_pre_run_and_complete() -> None:
    packet = _closed_packet()

    assert validate_target_adapter_review_packet(packet) == ()


def test_final_approved_packet_requires_authorized_results() -> None:
    packet = _closed_packet(status="approved")

    assert validate_target_adapter_review_packet(packet) == ()


def test_final_approved_packet_rejects_missing_run_traceability() -> None:
    packet = _closed_packet(status="approved")
    packet["live_runs"]["run_ids"] = ["run-1"]
    packet["live_runs"]["executed_case_ids"] = []
    packet["live_runs"]["proof_bundle_ids"] = []

    errors = validate_target_adapter_review_packet(packet)

    assert "live_runs:three_distinct_run_ids_required" in errors
    assert "live_runs:proof_bundle_ids_required" in errors
    assert "live_runs:executed_cases_must_match_approved_cases" in errors


def test_final_approved_packet_rejects_malformed_traceability_without_exception() -> None:
    packet = _closed_packet(status="approved")
    packet["live_runs"]["run_ids"] = None
    packet["live_runs"]["run_case_matrix"] = {"run-1": None}

    errors = validate_target_adapter_review_packet(packet)

    assert "live_runs:run_ids_list_required" in errors
    assert "live_runs:run_case_matrix_must_cover_all_runs" in errors


def test_final_approved_packet_rejects_failed_replay_or_seal() -> None:
    packet = _closed_packet(status="approved")
    packet["live_runs"]["replay_statuses"]["run-2"] = "failed"
    packet["live_runs"]["verify_seal_results"]["run-3"] = False

    errors = validate_target_adapter_review_packet(packet)

    assert "live_runs:replay_statuses_must_be_passed" in errors
    assert "live_runs:verify_seal_results_must_be_true" in errors


def test_closed_packet_rejects_pending_case_and_mismatched_disposition() -> None:
    packet = _closed_packet()
    packet["cases"][0]["mapping_status"] = "pending"

    errors = validate_target_adapter_review_packet(packet)

    assert "cases[0]:pending_mapping_in_closed_packet" in errors
    assert "cases[0]:disposition_mismatch" in errors
    assert "cases[0]:review_disposition_mismatch" in errors


def test_qualified_for_runs_requires_live_authorization() -> None:
    packet = _closed_packet(status="qualified_for_runs")
    packet["live_runs"]["authorized"] = False

    errors = validate_target_adapter_review_packet(packet)

    assert "live_runs:authorization_required_for_run_lifecycle" in errors


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
