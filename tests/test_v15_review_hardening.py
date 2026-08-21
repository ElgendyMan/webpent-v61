"""Regression tests for the project-wide review hardening changes."""
from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def _finding_dict(**overrides):
    value = {
        "id": str(uuid.uuid4()),
        "title": "Checkpoint finding",
        "severity": "high",
        "description": "Evidence-backed finding",
        "tool_name": "test-tool",
        "payload": "marker",
        "url": "http://target.test/item?id=1",
        "confidence": "high",
        "confidence_level": "Tool-Confirmed",
        "cvss_score": 8.1,
        "business_impact": "Impact",
        "vuln_class": "xss",
        "reasoning": "Observed by deterministic test",
        "evidence_bundle": {"status": 200, "body": "marker"},
        "evidence_hash": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "compliance_tags": [],
        "canary_token": None,
        "strategic_confidence_score": 0.95,
        "hypothesis_id": None,
        "post_exploitation_data": None,
    }
    value.update(overrides)
    return value


def test_exporter_accepts_checkpoint_finding_dict_and_builds_tags():
    from webpent.reporter.export import build_report_data

    data = build_report_data("http://target.test", [_finding_dict()])

    assert data["total_findings"] == 1
    assert data["confirmed_count"] == 0
    assert data["findings"][0]["confidence_level"] == "Needs Human Review"
    assert data["severity_counts"]["high"] == 1
    assert "CWE-79" in data["findings"][0]["compliance_tags"]
    assert data["findings"][0]["evidence_hash"]


def test_reporter_render_helpers_accept_checkpoint_finding_dict():
    from webpent.agents.reporter.agent import (
        _compute_stats,
        _findings_to_dicts,
        _render_findings_table,
    )

    finding = _finding_dict()
    stats = _compute_stats([finding])
    rendered = _render_findings_table([finding])
    normalized = _findings_to_dicts([finding])

    assert stats == {"confirmed_count": 1, "critical_count": 0, "high_count": 1}
    assert "Checkpoint finding" in rendered
    assert normalized[0]["confidence_level"] == "Tool-Confirmed"


def test_reporter_bug_bounty_accepts_checkpoint_target_dict(tmp_path, monkeypatch):
    from webpent.agents.reporter import agent

    monkeypatch.setattr(
        agent,
        "get_settings",
        lambda: type("S", (), {"ensure_output_dir": lambda self: tmp_path})(),
    )
    monkeypatch.setattr(
        agent,
        "_save_report",
        lambda markdown, output_dir, filename: output_dir / filename,
    )

    result = agent.reporter_node_bug_bounty(
        {
            "target": {"url": "http://target.test"},
            "findings": [],
            "crawled_data": {},
        }
    )

    assert result["current_phase"] == "reporting"
    assert "Bug-bounty report generated" in result["messages"][0].content


def test_chainer_severity_rank_normalizes_strings_and_enum_like_values():
    from webpent.agents.exploit_chainer.agent import _severity_rank
    from webpent.models.findings import Severity

    assert _severity_rank("critical") > _severity_rank("high")
    assert _severity_rank(Severity.HIGH) == _severity_rank("high")
    assert _severity_rank("unrecognized") == _severity_rank("medium")


def test_dalfox_wrapper_uses_timeout_from_settings_without_local_import_bug(monkeypatch):
    from webpent.tools.exploitation import dalfox

    class Settings:
        dalfox_path = "dalfox"
        dalfox_timeout = 7

    calls = {}
    monkeypatch.setattr(dalfox, "get_settings", lambda: Settings())
    monkeypatch.setattr(
        dalfox,
        "run_command",
        lambda command, timeout: calls.update(command=command, timeout=timeout) or "tool output",
    )

    result = dalfox.run_dalfox("https://target.test/x?q=1")

    assert result == "tool output"
    assert calls["timeout"] == 7
    # Dalfox 2.13 removed --skip-boring; emitting it would abort scanning.
    assert "--skip-boring" not in calls["command"]
    assert "--silence" not in calls["command"]
    assert "--no-color" in calls["command"]


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))


def test_v55_architecture_flags_are_default_safe_and_env_configurable(monkeypatch):
    from webpent.config.settings import Settings

    defaults = Settings()
    assert defaults.enable_target_understanding is False
    assert defaults.enable_attack_graph is False
    assert defaults.enable_adaptive_hunt is False

    monkeypatch.setenv("ENABLE_TARGET_UNDERSTANDING", "true")
    monkeypatch.setenv("ENABLE_ATTACK_GRAPH", "1")
    monkeypatch.setenv("ENABLE_ADAPTIVE_HUNT", "yes")
    configured = Settings()

    assert configured.enable_target_understanding is True
    assert configured.enable_attack_graph is True
    assert configured.enable_adaptive_hunt is True
    assert configured.max_graph_steps == defaults.max_graph_steps
    assert configured.http_timeout == defaults.http_timeout


def test_v55_legacy_path_remains_disabled_by_default():
    from webpent.config.settings import Settings

    settings = Settings()

    assert not any(
        (
            settings.enable_target_understanding,
            settings.enable_attack_graph,
            settings.enable_adaptive_hunt,
        )
    )
    assert settings.max_graph_steps > 0


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))

