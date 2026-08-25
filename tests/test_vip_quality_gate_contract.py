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


def _write_json(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_p8_live_proof_artifact_accepts_strict_target_backed_run(monkeypatch, tmp_path):
    _write_json(
        tmp_path / "juice_shop_qualification_report.json",
        {
            "runs": [
                {
                    "passed": True,
                    "verifier_passed": True,
                    "central_store_put": True,
                    "central_verify_seal": True,
                    "central_replay": True,
                    "proof_bundle_sealed": True,
                    "replay_status": "passed",
                    "target_backed_all": True,
                    "replayable_all": True,
                    "raw_response_bodies_saved": False,
                }
            ]
        },
    )
    monkeypatch.setattr(gate, "DOCS", tmp_path)

    result = gate._p8_live_proof_check()

    assert result["passed"] is True
    assert result["returncode"] == 0


def test_p9_distributed_artifact_names_incomplete_required_checks(monkeypatch, tmp_path):
    _write_json(
        tmp_path / "p9_distributed_runtime_evidence.json",
        {"qualification_checks": {"docker_health": True}},
    )
    monkeypatch.setattr(gate, "DOCS", tmp_path)

    result = gate._p9_distributed_check()

    assert result["passed"] is False
    assert "P9 required checks incomplete:" in result["tail"][0]
    assert "backup_restore" in result["tail"][0]
    assert "tls_enforced" in result["tail"][0]


def test_p10_incomplete_artifact_is_blocked_by_explicit_gate_reason(monkeypatch, tmp_path):
    _write_json(
        tmp_path / "juice_shop_qualification_report.json",
        {
            "gate": {
                "p10_passed": False,
                "blocking_reasons": ["approved mapping is missing"],
            },
            "metrics": {"run_count": 4, "successful_proof_runs": 3},
        },
    )
    monkeypatch.setattr(gate, "DOCS", tmp_path)

    result = gate._p10_benchmark_check()

    assert result["passed"] is False
    assert result["tail"] == [
        "P10 benchmark not qualified: approved mapping is missing"
    ]


def test_dynamic_artifact_checks_fail_closed_on_malformed_json(monkeypatch, tmp_path):
    (tmp_path / "juice_shop_qualification_report.json").write_text(
        "{not-json", encoding="utf-8"
    )
    monkeypatch.setattr(gate, "DOCS", tmp_path)

    result = gate._p8_live_proof_check()

    assert result["passed"] is False
    assert result["returncode"] == 1
    assert "JSONDecodeError" in result["tail"][0]


def test_gate_report_uses_dynamic_blockers_not_old_waptlab_live_blocker():
    checks = [
        {"name": "p8-live-proof-artifact", "passed": True},
        {
            "name": "p9-distributed-qualification-artifact",
            "passed": False,
        },
        {"name": "p10-juice-shop-benchmark-artifact", "passed": False},
        {"name": "pip-audit-strict", "passed": True},
        {"name": "bandit-high-severity", "passed": True},
        {"name": "release-manifest", "passed": True},
        {"name": "bbscout-integration-source", "passed": True},
    ]

    report = gate._build_gate_report(checks, {"passed": True})

    assert report["passed"] is False
    assert "P9 distributed qualification is incomplete" in report["known_blockers"]
    assert "P10 Juice Shop benchmark is incomplete or not qualified" in report[
        "known_blockers"
    ]
    assert not any("WAPTLab" in blocker for blocker in report["known_blockers"])
    assert not any("mock" in blocker.lower() for blocker in report["known_blockers"])
