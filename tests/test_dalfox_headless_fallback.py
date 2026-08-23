from __future__ import annotations

from types import SimpleNamespace

from webpent.shared.exceptions import ToolExecutionError
from webpent.tools.exploitation import dalfox


def _settings() -> SimpleNamespace:
    return SimpleNamespace(dalfox_path="dalfox", dalfox_timeout=5)


def test_empty_dalfox_output_fails_closed_without_unsupported_retry(monkeypatch):
    calls: list[list[str]] = []

    def fake_run_command(cmd: list[str], timeout: int) -> str:
        calls.append(cmd)
        return ""

    monkeypatch.setattr(dalfox, "get_settings", _settings)
    monkeypatch.setattr(dalfox, "run_command", fake_run_command)

    result = dalfox.run_dalfox("http://127.0.0.1:3000")

    assert result == "TOOL_INFRA_FAILURE: dalfox produced no output."
    assert len(calls) == 1
    assert "--skip-headless" not in calls[0]
    assert "--deep-domxss" not in calls[0]
    assert "--context-aware" not in calls[0]


def test_known_headless_crash_fails_closed_without_unsupported_retry(monkeypatch):
    calls: list[list[str]] = []

    def fake_run_command(cmd: list[str], timeout: int) -> str:
        calls.append(cmd)
        raise ToolExecutionError(
            cmd,
            1,
            stderr="unhandled node event *dom.EventTopLayerElementsUpdated",
        )

    monkeypatch.setattr(dalfox, "get_settings", _settings)
    monkeypatch.setattr(dalfox, "run_command", fake_run_command)

    result = dalfox.run_dalfox("http://127.0.0.1:3000/graphql")

    assert result == "TOOL_INFRA_FAILURE: dalfox produced no output."
    assert len(calls) == 1
    assert "--skip-headless" not in calls[0]
