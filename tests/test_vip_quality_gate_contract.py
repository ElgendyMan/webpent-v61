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


def test_optional_bbscout_check_is_explicit_and_fail_closed(monkeypatch, tmp_path):
    monkeypatch.delenv("BBSCOUT_SOURCE_ROOT", raising=False)
    monkeypatch.setattr(gate, "BUNDLED_BBSCOUT_ROOT", tmp_path / "missing-bbscout")
    monkeypatch.setattr(gate.importlib.util, "find_spec", lambda name: None)

    result = gate._bbscout_integration_check()

    assert result["passed"] is False
    assert result["status"] == "blocked"
    assert result["required_for_full_gate"] is True
    assert "source" in result["reason"]


def test_bundled_bbscout_check_is_reproducible(monkeypatch, tmp_path):
    package_dir = tmp_path / "bbscout"
    package_dir.mkdir()
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.delenv("BBSCOUT_SOURCE_ROOT", raising=False)
    monkeypatch.setattr(gate, "BUNDLED_BBSCOUT_ROOT", tmp_path)

    result = gate._bbscout_integration_check()

    assert result["passed"] is True
    assert result["status"] == "bundled-reviewed-source"
    assert result["source_root"] == "integrations/bbscout/src"


def test_optional_bbscout_check_reports_available_without_importing_code(monkeypatch, tmp_path):
    monkeypatch.delenv("BBSCOUT_SOURCE_ROOT", raising=False)
    monkeypatch.setattr(gate, "BUNDLED_BBSCOUT_ROOT", tmp_path / "missing-bbscout")
    monkeypatch.setattr(gate.importlib.util, "find_spec", lambda name: object())

    result = gate._bbscout_integration_check()

    assert result["passed"] is True
    assert result["status"] == "available"
    assert result["required_for_full_gate"] is True
    assert result["reason"] == "bbscout source is importable"


def test_optional_bbscout_check_accepts_explicit_external_source(monkeypatch, tmp_path):
    package_dir = tmp_path / "bbscout"
    package_dir.mkdir()
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.setenv("BBSCOUT_SOURCE_ROOT", str(tmp_path))
    result = gate._bbscout_integration_check()

    assert result["passed"] is True
    assert result["status"] == "external-reviewed-source"
    assert result["source_root"] == "external:BBSCOUT_SOURCE_ROOT"


def test_gate_blockers_include_missing_bbscout_source():
    report = gate._build_gate_report(
        [
            {
                "name": "bbscout-integration-source",
                "passed": False,
                "returncode": 1,
                "status": "blocked",
                "required_for_full_gate": True,
                "reason": "bbscout source tree is unavailable",
            }
        ],
        {"passed": True},
    )

    assert report["passed"] is False
    assert any("bbscout" in blocker for blocker in report["known_blockers"])
