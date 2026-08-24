from __future__ import annotations

import pytest

from webpent.shared.exceptions import ToolExecutionError
from webpent.tools.recon import nuclei


def test_default_nuclei_templates_fail_closed_without_manifest(monkeypatch, tmp_path):
    monkeypatch.setenv("WEBPENT_NUCLEI_TEMPLATE_DIR", str(tmp_path))
    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda _host: True,
    )

    with pytest.raises(ToolExecutionError, match="manifest"):
        nuclei.run_nuclei("https://example.test")


def test_default_nuclei_templates_accept_valid_manifest(monkeypatch, tmp_path):
    (tmp_path / "manifest.json").write_text(
        '{"schema_version":"nuclei-template-manifest-v1",'
        '"version":"nuclei-v3.9.0","digest":"' + "a" * 64 + '",'
        '"file_count":1,"total_bytes":1}\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("WEBPENT_NUCLEI_TEMPLATE_DIR", str(tmp_path))
    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda _host: True,
    )
    monkeypatch.setattr(nuclei, "get_settings", lambda: type(
        "Settings",
        (),
        {
            "nuclei_path": "nuclei",
            "http_user_agent": "webpent-test",
            "nuclei_timeout": 1,
            "nuclei_request_timeout": 10,
            "nuclei_retries": 1,
            "nuclei_concurrency": 25,
            "nuclei_rate_limit": 150,
        },
    )())
    captured = {}

    def fake_run_command(cmd, timeout):
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        return ""

    monkeypatch.setattr(nuclei, "run_command", fake_run_command)

    assert nuclei.run_nuclei("https://example.test") == []
    assert captured["timeout"] == 1
    assert captured["cmd"][captured["cmd"].index("-timeout") + 1] == "10"
    assert captured["cmd"][captured["cmd"].index("-retries") + 1] == "1"
    assert captured["cmd"][captured["cmd"].index("-c") + 1] == "25"
    assert captured["cmd"][captured["cmd"].index("-rl") + 1] == "150"


__all__ = []


def _nuclei_test_settings():
    return type(
        "Settings",
        (),
        {
            "nuclei_path": "nuclei",
            "http_user_agent": "webpent-test",
            "nuclei_timeout": 1,
            "nuclei_request_timeout": 10,
            "nuclei_retries": 1,
            "nuclei_concurrency": 25,
            "nuclei_rate_limit": 150,
        },
    )()


def test_local_target_excludes_external_template_categories(monkeypatch, tmp_path):
    (tmp_path / "manifest.json").write_text(
        '{"schema_version":"nuclei-template-manifest-v1",'
        '"version":"nuclei-v3.11.1","digest":"' + "a" * 64 + '",'
        '"file_count":4,"total_bytes":1}\n',
        encoding="utf-8",
    )
    paths = [
        tmp_path / "http/osint",
        tmp_path / "http/exposures/tokens/google/google-gemini-key-exposure.yaml",
        tmp_path / "http/miscellaneous/rdap-whois.yaml",
        tmp_path / "http/misconfiguration/intercom-identity-misconfiguration.yaml",
    ]
    for path in paths:
        if path.suffix:
            path.parent.mkdir(parents=True, exist_ok=True)
        else:
            path.mkdir(parents=True, exist_ok=True)
        path.touch()
    monkeypatch.setenv("WEBPENT_NUCLEI_TEMPLATE_DIR", str(tmp_path))
    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda _host: True,
    )
    monkeypatch.setattr(nuclei, "get_settings", _nuclei_test_settings)
    captured = {}

    def fake_run_command(cmd, timeout):
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        return ""

    monkeypatch.setattr(nuclei, "run_command", fake_run_command)
    assert nuclei.run_nuclei("http://127.0.0.1:18000") == []
    command = captured["cmd"]
    assert command[command.index("-etags") + 1] == "osint"
    excluded = {command[index + 1] for index, value in enumerate(command[:-1]) if value == "-et"}
    assert excluded == {str(path) for path in paths}


def test_public_target_does_not_receive_local_template_exclusions(monkeypatch, tmp_path):
    (tmp_path / "manifest.json").write_text(
        '{"schema_version":"nuclei-template-manifest-v1",'
        '"version":"nuclei-v3.11.1","digest":"' + "a" * 64 + '",'
        '"file_count":1,"total_bytes":1}\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("WEBPENT_NUCLEI_TEMPLATE_DIR", str(tmp_path))
    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda _host: True,
    )
    monkeypatch.setattr(nuclei, "get_settings", _nuclei_test_settings)
    captured = {}

    def fake_run_command(cmd, timeout):
        captured["cmd"] = cmd
        return ""

    monkeypatch.setattr(nuclei, "run_command", fake_run_command)
    assert nuclei.run_nuclei("https://example.test") == []
    assert "-etags" not in captured["cmd"]
    assert "-et" not in captured["cmd"]
    assert "-duc" not in captured["cmd"]
    assert "-ni" not in captured["cmd"]
    assert "-auth=false" not in captured["cmd"]
    assert "-dr" not in captured["cmd"]
    assert "-pt" not in captured["cmd"]


def test_local_target_gets_offline_and_http_only_hardening(monkeypatch, tmp_path):
    (tmp_path / "manifest.json").write_text(
        '{"schema_version":"nuclei-template-manifest-v1",'
        '"version":"nuclei-v3.11.1","digest":"' + "a" * 64 + '",'
        '"file_count":1,"total_bytes":1}\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("WEBPENT_NUCLEI_TEMPLATE_DIR", str(tmp_path))
    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda _host: True,
    )
    monkeypatch.setattr(nuclei, "get_settings", _nuclei_test_settings)
    captured = {}

    def fake_run_command(cmd, timeout):
        captured["cmd"] = cmd
        return ""

    monkeypatch.setattr(nuclei, "run_command", fake_run_command)
    assert nuclei.run_nuclei("http://127.0.0.1:18000") == []
    command = captured["cmd"]
    assert "-duc" in command
    assert "-ni" in command
    assert "-auth=false" in command
    assert "-dr" in command
    assert command[command.index("-pt") + 1] == "http"


def test_explicit_templates_on_local_target_keep_local_exclusions(monkeypatch, tmp_path):
    (tmp_path / "manifest.json").write_text(
        '{"schema_version":"nuclei-template-manifest-v1",'
        '"version":"nuclei-v3.11.1","digest":"' + "a" * 64 + '",'
        '"file_count":1,"total_bytes":1}\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("WEBPENT_NUCLEI_TEMPLATE_DIR", str(tmp_path))
    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda _host: True,
    )
    monkeypatch.setattr(nuclei, "get_settings", _nuclei_test_settings)
    captured = {}

    def fake_run_command(cmd, timeout):
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        return ""

    monkeypatch.setattr(nuclei, "run_command", fake_run_command)
    assert nuclei.run_nuclei("http://127.0.0.1:18000", templates=["http/test.yaml"]) == []
    assert "http/test.yaml" in captured["cmd"]
    assert captured["cmd"][captured["cmd"].index("-etags") + 1] == "osint"
    assert captured["timeout"] == 1


__all__ = []
