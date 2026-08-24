from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


_SECRET = "super-secret-value"


def _finding(**overrides):
    value = {
        "id": "finding-quality-1",
        "title": "Evidence-backed finding",
        "severity": "high",
        "description": "A deterministic test finding",
        "tool_name": "safe-test-tool",
        "payload": "marker",
        "url": "https://target.test/item?id=1&token=" + _SECRET,
        "confidence": "high",
        "confidence_level": "Tool-Confirmed",
        "cvss_score": 8.1,
        "business_impact": "An unauthorized user can access protected data.",
        "vuln_class": "broken_access_control",
        "reasoning": "The response differential was observed deterministically.",
        "evidence_bundle": {
            "request": {
                "method": "GET",
                "url": "https://target.test/item?id=1",
                "headers": {"Authorization": "Bearer " + _SECRET},
            },
            "response": {"status": 200, "body": "marker"},
            "reproduction": {"steps_to_reproduce": ["Repeat the read-only request."]},
            "scope_status": "allowed",
            "hypothesis": {"hypothesis_id": "hyp-quality-1"},
            "related_findings": ["finding-prerequisite-1"],
        },
        "evidence_hash": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "compliance_tags": [],
        "canary_token": None,
        "strategic_confidence_score": 0.95,
        "hypothesis_id": "hyp-quality-1",
        "post_exploitation_data": {"token": _SECRET},
    }
    value.update(overrides)
    return value


def test_quality_gate_ready_uses_shared_lifecycle_and_returns_no_values():
    from webpent.shared.report_quality import evaluate_report_quality

    result = evaluate_report_quality([_finding()])
    dumped = result.model_dump(mode="json")

    assert result.ready is True
    assert result.status == "ready"
    assert result.ready_finding_count == 1
    assert result.findings[0].lifecycle_stage == "Reproduction"
    assert result.findings[0].blocking_issues == []
    assert result.findings[0].evidence_classification == "needs_human_review"
    assert result.findings[0].evidence_missing_signals == [
        "causal_signal",
        "negative_control_complete",
        "sealed_proof_bundle",
        "promotion_ready_proof_bundle",
    ]
    assert _SECRET not in str(dumped)
    assert "evidence_bundle" not in str(dumped)


def test_quality_gate_does_not_call_unproven_tool_confirmed_finding_confirmed():
    from webpent.shared.report_quality import evaluate_report_quality

    result = evaluate_report_quality([_finding()])

    assert result.findings[0].evidence_classification == "needs_human_review"
    assert result.findings[0].lifecycle_stage != "Confirmed"
    assert result.findings[0].lifecycle_stage == "Reproduction"


def test_quality_gate_blocks_missing_contract_fields_without_exposing_values():
    from webpent.shared.report_quality import evaluate_report_quality

    incomplete = _finding(
        confidence_level="Pending",
        cvss_score="",
        business_impact="",
        hypothesis_id=None,
        evidence_bundle={"request": {"method": "GET"}},
    )
    result = evaluate_report_quality([incomplete])
    item = result.findings[0]

    assert result.ready is False
    assert result.status == "blocked"
    assert set(item.blocking_issues) >= {
        "hypothesis",
        "reproduction",
        "business_impact",
        "cvss",
    }
    assert _SECRET not in str(result.model_dump(mode="json"))


def test_strict_report_export_fails_closed_but_legacy_mode_remains_available(tmp_path):
    from webpent.reporter.export import build_report_data
    from webpent.shared.report_quality import ReportQualityGateError

    with pytest.raises(ReportQualityGateError):
        build_report_data(
            "https://target.test",
            [_finding(business_impact="")],
            strict_quality_gate=True,
        )

    legacy_data = build_report_data(
        "https://target.test",
        [_finding(business_impact="")],
        strict_quality_gate=False,
    )
    assert legacy_data["quality_gate"]["status"] == "blocked"
    assert legacy_data["evidence_confirmed_count"] == 0
    assert legacy_data["evidence_review_count"] == 1
    assert _SECRET not in str(legacy_data)
    assert (
        legacy_data["findings"][0]["evidence_bundle"]["request"]["headers"]["Authorization"]
        == "[REDACTED]"
    )
    assert legacy_data["findings"][0]["post_exploitation_data"]["token"] == "[REDACTED]"


def test_html_report_surfaces_quality_gate_and_finding_lifecycle(tmp_path):
    from webpent.reporter.export import export_to_html

    path = export_to_html("https://target.test", [_finding()], tmp_path)
    html = path.read_text(encoding="utf-8")

    assert "Evidence Quality Gate" in html
    assert "Status:" in html
    assert "Lifecycle: Reproduction" in html
    assert _SECRET not in html

    from webpent.reporter.export import build_report_data

    data = build_report_data("https://target.test", [_finding()])
    assert data["findings"][0]["confidence_level"] == "Needs Human Review"


def test_report_promotion_does_not_mutate_live_finding():
    from webpent.reporter.export import build_report_data

    finding = _finding()
    build_report_data("https://target.test", [finding])
    assert finding["confidence_level"] == "Tool-Confirmed"
    assert finding["confidence"] == "high"


def test_report_quality_flag_is_safe_by_default_and_env_configurable(monkeypatch):
    from webpent.config.settings import Settings

    assert Settings().enable_report_quality_gate is False
    monkeypatch.setenv("ENABLE_REPORT_QUALITY_GATE", "true")
    assert Settings().enable_report_quality_gate is True


def test_report_exports_redacted_execution_observations_without_promotion(tmp_path):
    from webpent.reporter.export import build_report_data, export_to_html, export_to_markdown

    raw_payload = "<script>alert('secret-marker')</script>"
    observations = [
        {
            "event": "tested",
            "finding_id": "finding-quality-1",
            "vuln_class": "xss",
            "payload_sha256": "digest-only",
            "result": "no_dialog",
            "reason": "browser_validation_completed",
        }
    ]
    data = build_report_data(
        "https://target.test",
        [_finding()],
        execution_observations=observations,
    )

    assert data["execution_observations"] == observations
    assert data["confirmed_count"] == 0
    assert data["findings"][0]["confidence_level"] == "Needs Human Review"
    assert raw_payload not in str(data)

    html = export_to_html(
        "https://target.test",
        [_finding()],
        tmp_path,
        execution_observations=observations,
    ).read_text(encoding="utf-8")
    markdown = export_to_markdown(
        "https://target.test",
        [_finding()],
        tmp_path,
        execution_observations=observations,
    ).read_text(encoding="utf-8")

    assert "Execution Observations" in html
    assert "browser_validation_completed" in html
    assert "Execution Observations" in markdown
    assert "digest-only" in markdown
    assert raw_payload not in html
    assert raw_payload not in markdown


def test_cli_final_export_preserves_execution_observations(tmp_path):
    from types import SimpleNamespace

    from webpent.cli import _export_cli_reports

    observations = [
        {
            "event": "payload_test",
            "finding_id": "finding-quality-1",
            "result": "no_dialog",
            "reason": "dialog_not_observed",
            "payload_sha256": "digest-only",
        }
    ]
    paths = _export_cli_reports(
        target_url="https://target.test",
        findings=[_finding()],
        final_state={"execution_observations": observations},
        workspace=SimpleNamespace(reports_dir=tmp_path),
        settings=SimpleNamespace(enable_report_quality_gate=False),
        selected_formats=["json"],
    )

    report = __import__("json").loads(paths["json"].read_text(encoding="utf-8"))
    assert report["execution_observations"] == observations
    assert report["confirmed_count"] == 0
    assert report["findings"][0]["confidence_level"] == "Needs Human Review"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
