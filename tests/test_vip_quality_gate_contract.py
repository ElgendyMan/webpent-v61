from __future__ import annotations

import json

from scripts import run_vip_quality_gate as gate


def _write_regression(path, summary):
    path.write_text(
        json.dumps(
            {
                "campaign_count": 20,
                "summary": summary,
                "target_contacted": False,
                "waptlab_modified": False,
            }
        ),
        encoding="utf-8",
    )


def test_artifact_safety_accepts_current_complete_offline_summary(monkeypatch, tmp_path):
    _write_regression(
        tmp_path / "waptlab_regression.json",
        {"inconclusive": 18, "missing-validator": 2},
    )
    monkeypatch.setattr(gate, "DOCS", tmp_path)

    result = gate._artifact_safety()

    assert result["passed"] is True
    assert result["campaign_count"] == 20


def test_artifact_safety_rejects_incomplete_or_invalid_summary(monkeypatch, tmp_path):
    path = tmp_path / "waptlab_regression.json"
    monkeypatch.setattr(gate, "DOCS", tmp_path)

    _write_regression(path, {"inconclusive": 19})
    assert gate._artifact_safety()["passed"] is False

    _write_regression(path, {"inconclusive": -1, "missing-validator": 21})
    assert gate._artifact_safety()["passed"] is False
