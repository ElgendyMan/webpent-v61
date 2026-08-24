from types import SimpleNamespace


def _settings():
    return SimpleNamespace(
        dalfox_path="/usr/local/bin/dalfox",
        dalfox_timeout=30,
    )


def test_dalfox_keeps_clean_scan_summary(monkeypatch):
    from webpent.tools.exploitation import dalfox as module

    calls = []

    def fake_run_command(cmd, timeout=None):
        calls.append((cmd, timeout))
        assert cmd[0].endswith("/dalfox")
        assert cmd[1] == "url"
        assert cmd[2].startswith("http://")
        assert "--no-color" in cmd
        assert "--format" in cmd
        assert cmd[cmd.index("--format") + 1] == "json"
        assert "--silence" not in cmd
        return "[]\n"

    monkeypatch.setattr(module, "get_settings", _settings)
    monkeypatch.setattr(module, "run_command", fake_run_command)
    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda host: True,
    )

    result = module.run_dalfox(
        "http://127.0.0.1:3000/rest/user/security-question?email=test@example.com"
    )

    assert result.strip() == "[]"
    assert len(calls) == 1


def test_dalfox_empty_output_remains_infrastructure_failure(monkeypatch):
    from webpent.tools.exploitation import dalfox as module

    calls = []

    def fake_run_command(cmd, timeout=None):
        calls.append((cmd, timeout))
        assert cmd[1] == "url"
        assert cmd[2].startswith("http://")
        assert "--deep-domxss" not in cmd
        assert "--context-aware" not in cmd
        assert "--skip-headless" not in cmd
        return ""

    monkeypatch.setattr(module, "get_settings", _settings)
    monkeypatch.setattr(module, "run_command", fake_run_command)
    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda host: True,
    )

    result = module.run_dalfox("http://127.0.0.1:3000")

    assert result == "TOOL_INFRA_FAILURE: dalfox produced no output."
    assert len(calls) == 1
