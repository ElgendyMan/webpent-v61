from __future__ import annotations

import pytest

from webpent.tools.utils.subprocess import validate_executable


def test_projectdiscovery_httpx_pd_is_in_canonical_manifest() -> None:
    validate_executable("/usr/local/bin/httpx-pd")


def test_unregistered_executable_remains_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEBPENT_ALLOWED_EXECUTABLES", raising=False)
    with pytest.raises(PermissionError):
        validate_executable("/tmp/unregistered-webpent-tool")
