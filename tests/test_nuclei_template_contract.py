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
        {"nuclei_path": "nuclei", "http_user_agent": "webpent-test", "nuclei_timeout": 1},
    )())
    monkeypatch.setattr(nuclei, "run_command", lambda cmd, timeout: "")

    assert nuclei.run_nuclei("https://example.test") == []


__all__ = []
