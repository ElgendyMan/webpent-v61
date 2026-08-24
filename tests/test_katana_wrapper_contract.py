from types import SimpleNamespace

from webpent.tools.recon import katana as katana_module


def test_katana_requests_jsonl_form_and_xhr_observations(monkeypatch):
    captured = {}

    def fake_run_command(cmd, timeout=None):
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        return '{"request":{"endpoint":"http://app:8000/login"}}\n'

    monkeypatch.setattr(katana_module, "run_command", fake_run_command)
    monkeypatch.setattr(
        katana_module,
        "get_settings",
        lambda: SimpleNamespace(katana_path="katana"),
    )
    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda host: host == "app",
    )

    endpoints = katana_module.run_katana("http://app:8000")

    assert endpoints == ["http://app:8000/login"]
    assert captured["timeout"] == 120
    command = captured["cmd"]
    assert "-jc" in command
    assert "-j" in command
    assert "-fx" in command
    assert "-xhr" in command
    assert "-nc" in command


def test_katana_drops_offscope_observation(monkeypatch):
    def fake_run_command(_cmd, timeout=None):
        return (
            '{"request":{"endpoint":"http://app:8000/in-scope"}}\n'
            '{"request":{"endpoint":"http://169.254.169.254/latest"}}\n'
        )

    monkeypatch.setattr(katana_module, "run_command", fake_run_command)
    monkeypatch.setattr(
        katana_module,
        "get_settings",
        lambda: SimpleNamespace(katana_path="katana"),
    )
    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda host: host == "app",
    )

    assert katana_module.run_katana("http://app:8000") == [
        "http://app:8000/in-scope"
    ]


def test_katana_does_not_treat_target_body_words_as_crash(monkeypatch, caplog):
    raw = (
        '{"request":{"endpoint":"http://app:8000/fatal"},'
        '"response":{"body":"fatal: application message"}}\n'
    )

    monkeypatch.setattr(katana_module, "run_command", lambda _cmd, timeout=None: raw)
    monkeypatch.setattr(
        katana_module,
        "get_settings",
        lambda: SimpleNamespace(katana_path="katana"),
    )
    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda host: host == "app",
    )

    with caplog.at_level("WARNING"):
        endpoints = katana_module.run_katana("http://app:8000")

    assert endpoints == ["http://app:8000/fatal"]
    assert "katana crashed" not in caplog.text
