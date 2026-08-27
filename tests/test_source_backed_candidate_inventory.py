from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "reports/evaluation/source_inventory/SOURCE-BACKED-CANDIDATE-INVENTORY-v1.json"


def load_inventory() -> dict:
    return json.loads(INVENTORY.read_text(encoding="utf-8"))


def test_inventory_validator_passes() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_source_backed_candidate_inventory.py")],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS: source-backed candidate inventory is valid and fail-closed" in result.stdout


def test_inventory_keeps_non_admitted_targets_out_of_scoring() -> None:
    data = load_inventory()
    targets = {target["target_id"]: target for target in data["targets"]}
    assert set(targets) == {"owasp_juice_shop", "owasp_webgoat", "crapi"}
    assert targets["owasp_webgoat"]["ground_truth_manifest"]["approved_case_ids"] == []
    assert targets["crapi"]["ground_truth_manifest"]["approved_case_ids"] == []
    assert all(
        candidate["decision"] != "accepted_scoring_ready_partial"
        for target_id in ("owasp_webgoat", "crapi")
        for candidate in targets[target_id]["source_candidate_surfaces"]
    )


def test_inventory_preserves_approved_juice_case_set_and_gate() -> None:
    data = load_inventory()
    juice = next(target for target in data["targets"] if target["target_id"] == "owasp_juice_shop")
    accepted = {
        candidate["case_id"]
        for candidate in juice["candidates"]
        if candidate["decision"] == "accepted_scoring_ready_partial"
    }
    assert accepted == {
        "juice.error_handling.v1",
        "juice.exposed_metrics.v1",
        "juice.local_xss.v1",
    }
    assert data["global_safety"]["official_isolated_p10_runs_authorized"] is False
    assert data["qualification_state"]["official_isolated_p10_runs_authorized"] is False
    assert data["qualification_state"]["p10"] == "NOT_QUALIFIED"
    assert data["qualification_state"]["vip"] == "NOT_QUALIFIED"
