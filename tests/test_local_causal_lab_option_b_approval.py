from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.check_local_causal_lab_option_b_approval import validate

ROOT = Path(__file__).resolve().parents[1]
IMPORT = (
    ROOT
    / "reports/evaluation/owner_decision/LOCAL-CAUSAL-LAB-OPTION-B-OWNER-APPROVAL-IMPORT-v1.json"
)
PACKET = ROOT / "reports/evaluation/owner_decision/LOCAL-CAUSAL-LAB-OWNER-DECISION-PACKET-v1.json"
INVENTORY = ROOT / "reports/evaluation/source_inventory/SOURCE-BACKED-CANDIDATE-INVENTORY-v1.json"
APPROVAL = Path("/home/ubuntu/upload/pasted_content.txt")


def _copy_json(tmp_path: Path, source: Path, name: str) -> Path:
    target = tmp_path / name
    target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    return target


def test_option_b_import_validates_and_original_packet_stays_pending() -> None:
    assert validate(IMPORT, PACKET, INVENTORY, APPROVAL) == []
    packet = json.loads(PACKET.read_text(encoding="utf-8"))
    assert packet["status"] == "PENDING_OWNER_APPROVAL"
    assert packet["owner_decision"]["decision"] is None
    assert packet["current_governance_state"]["official_isolated_p10_runs_authorized"] is False


@pytest.mark.parametrize(
    ("path", "mutation", "expected"),
    [
        (
            "network_boundary",
            lambda value: value.update(host_allowlist=["0.0.0.0"]),
            "host_allowlist_must_be_loopback_only",
        ),
        (
            "record",
            lambda value: value.update(approved_methods=["POST"]),
            "approved_methods_must_be_get_only",
        ),
        (
            "record",
            lambda value: value.update(approved_case_ids=["webgoat.stored_xss.comments.v1"]),
            "case_allowlist_mismatch",
        ),
        (
            "fixture",
            lambda value: value.update(login_or_session_bootstrap_allowed=True),
            "fixture_boundary_forbidden:login_or_session_bootstrap_allowed",
        ),
        (
            "invariants",
            lambda value: value.update(official_isolated_p10_runs_authorized=True),
            "official_run_gate_must_be_false",
        ),
    ],
)
def test_option_b_import_rejects_scope_expansion(
    tmp_path: Path, path: str, mutation, expected: str
) -> None:
    import_path = _copy_json(tmp_path, IMPORT, "import.json")
    data = json.loads(import_path.read_text(encoding="utf-8"))
    field_map = {
        "record": data,
        "network_boundary": data["network_boundary"],
        "fixture": data["fixture_and_identity_boundary"],
        "invariants": data["global_invariants"],
    }
    mutation(field_map[path])
    import_path.write_text(json.dumps(data), encoding="utf-8")
    assert expected in validate(import_path, PACKET, INVENTORY, APPROVAL)


def test_option_b_import_rejects_prefilled_original_packet(tmp_path: Path) -> None:
    packet_path = _copy_json(tmp_path, PACKET, "packet.json")
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    packet["owner_decision"]["decision"] = "B"
    packet_path.write_text(json.dumps(packet), encoding="utf-8")
    assert "original_packet_contains_prefilled_approval" in validate(
        IMPORT, packet_path, INVENTORY, APPROVAL
    )


def test_option_b_import_rejects_changed_approval_source(tmp_path: Path) -> None:
    approval_path = tmp_path / "approval.txt"
    approval_path.write_text(APPROVAL.read_text(encoding="utf-8") + "\nchanged", encoding="utf-8")
    assert "approval_source_hash_mismatch" in validate(IMPORT, PACKET, INVENTORY, approval_path)


def test_option_b_import_has_no_human_signoff_or_promotion_effect() -> None:
    record = json.loads(IMPORT.read_text(encoding="utf-8"))
    assert record["authority"]["human_independent_signoff_obtained"] is False
    assert record["global_invariants"]["official_isolated_p10_runs_authorized"] is False
    assert record["global_invariants"]["scoring_promotion_allowed"] is False
    assert all(value is False for value in record["import_effect"].values())
