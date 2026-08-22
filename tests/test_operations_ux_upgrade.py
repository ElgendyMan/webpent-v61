"""Regression tests for the additive operations/UX upgrade."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from webpent.cli import _parse_report_formats, _promote_named_owner_profile
from webpent.cli.loaders import load_cookie_file, load_creds_file, load_payload_file
from webpent.models.targets import Target
from webpent.reporter.export import export_all_formats
from webpent.shared import stealth
from webpent.shared.preflight import _check_llm_providers
from webpent.shared.target_workspace import TargetWorkspace
from webpent.state.initial_state import build_initial_state


def test_loaders_accept_bounded_profiles_cookies_and_deduplicated_payloads(tmp_path: Path) -> None:
    creds_path = tmp_path / "creds.json"
    creds_path.write_text(
        json.dumps(
            {
                "admin": {"username": "admin", "password": "secret"},
                "auditor": {"username": "auditor", "password": "secret-2"},
            }
        ),
        encoding="utf-8",
    )
    cookie_path = tmp_path / "cookies.txt"
    cookie_path.write_text(
        "# Netscape HTTP Cookie File\n"
        ".example.test\tTRUE\t/\tFALSE\t0\tSESSION\tabc\n",
        encoding="utf-8",
    )
    payload_path = tmp_path / "payloads.txt"
    payload_path.write_text("<x>\n\n# comment\n<x>\n{{7*7}}\n", encoding="utf-8")

    assert set(load_creds_file(creds_path)) == {"admin", "auditor"}
    assert load_cookie_file(cookie_path) == {"SESSION": "abc"}
    assert load_payload_file(payload_path) == ["<x>", "{{7*7}}"]


def test_named_owner_profile_is_promoted_without_implicit_promotion() -> None:
    credentials, remaining = _promote_named_owner_profile(
        {},
        {
            "owner": {
                "role": "owner",
                "username": "owner@example.test",
                "password": "owner-pass",
            },
            "foreign": {
                "role": "secondary",
                "username": "foreign@example.test",
                "password": "foreign-pass",
            },
        },
    )
    assert credentials == {"username": "owner@example.test", "password": "owner-pass"}
    assert set(remaining) == {"foreign"}

    untouched_credentials, untouched_profiles = _promote_named_owner_profile(
        {},
        {"auditor": {"username": "auditor@example.test", "password": "auditor-pass"}},
    )
    assert untouched_credentials == {}
    assert set(untouched_profiles) == {"auditor"}


def test_loaders_fail_closed_on_invalid_shapes(tmp_path: Path) -> None:
    bad_creds = tmp_path / "bad-creds.json"
    bad_creds.write_text('{"admin": {"username": "only"}}', encoding="utf-8")
    bad_cookies = tmp_path / "bad-cookies.txt"
    bad_cookies.write_text("not-a-netscape-row", encoding="utf-8")

    with pytest.raises(ValueError):
        load_creds_file(bad_creds)
    with pytest.raises(ValueError):
        load_cookie_file(bad_cookies)


def test_initial_state_carries_per_run_ux_contract() -> None:
    state = build_initial_state(
        Target(url="https://example.test"),
        thread_id="thread-1",
        engagement_id="engagement-1",
        llm_override=False,
        custom_payloads=[" one ", "", "two"],
        report_formats=["md", "json"],
    )

    assert state["llm_enabled_override"] is False
    assert state["custom_payloads"] == ["one", "two"]
    assert state["payloads_to_test"] == {"custom": ["one", "two"]}
    assert state["report_formats"] == ["md", "json"]
    assert state["profile"] == "legacy"


def test_cli_final_export_writes_report_into_target_workspace(tmp_path: Path) -> None:
    from webpent.cli import _export_cli_reports

    workspace = TargetWorkspace.for_target(
        workspace_root=tmp_path,
        target_origin="http://127.0.0.1:3000",
        client_id="test-client",
        engagement_id="test-engagement",
    ).ensure()

    paths = _export_cli_reports(
        target_url="http://127.0.0.1:3000",
        findings=[],
        final_state={"executive_summary": "completed", "risk_score": "Low"},
        workspace=workspace,
        settings=SimpleNamespace(enable_report_quality_gate=False),
        selected_formats=["json"],
    )

    report_path = workspace.reports_dir / "report.json"
    assert paths == {"json": report_path}
    assert report_path.is_file()
    assert json.loads(report_path.read_text(encoding="utf-8"))["findings"] == []


def test_report_selection_exports_only_requested_format(tmp_path: Path) -> None:
    paths = export_all_formats(
        target_url="https://example.test",
        findings=[],
        output_dir=tmp_path,
        formats=["md"],
    )

    assert set(paths) == {"md"}
    assert (tmp_path / "report.md").is_file()
    assert not (tmp_path / "report.json").exists()
    assert not (tmp_path / "report.html").exists()


def test_report_format_parser_normalizes_and_deduplicates() -> None:
    assert _parse_report_formats("JSON, md, json") == ["json", "md"]
    assert _parse_report_formats("all") == ["all"]
    assert _parse_report_formats(None) is None


def test_stealth_telemetry_is_redaction_safe_and_resettable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stealth.reset_stealth_telemetry()
    monkeypatch.setattr(stealth, "_draw_jitter_seconds", lambda: 0.25)
    monkeypatch.setattr(stealth.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        stealth,
        "get_settings",
        lambda: SimpleNamespace(stealth_min_request_interval=0.0),
    )

    stealth.apply_jitter(True, label="test")
    stealth.enforce_min_interval(True, "example.test")
    summary = stealth.get_stealth_summary()

    assert summary["jitter_calls"] == 1
    assert summary["rate_limit_calls"] == 1
    assert summary["jitter_sleep_seconds"] == 0.25
    assert summary["total_sleep_seconds"] == 0.25

    stealth.reset_stealth_telemetry()
    assert stealth.get_stealth_summary()["total_sleep_seconds"] == 0.0


def test_llm_preflight_is_read_only_and_reports_fallback_shape() -> None:
    report = _check_llm_providers()

    assert "status" in report
    assert isinstance(report["configured_providers"], list)
    assert isinstance(report["fallback_chains"], dict)
    assert "analysis" in report["fallback_chains"]
