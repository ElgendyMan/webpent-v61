from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from webpent.shared import http as http_module
from webpent.tools.utils import subprocess as subprocess_module

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"


def test_subprocess_wrapper_executes_only_explicit_argv_and_safe_process(monkeypatch):
    captured: dict[str, object] = {}

    class FakeProcess:
        returncode = 0
        pid = 1234

        def communicate(self, *, input=None, timeout=None):
            captured["input"] = input
            captured["timeout"] = timeout
            return "ok", ""

        def poll(self):
            return self.returncode

    monkeypatch.setattr(subprocess_module.shutil, "which", lambda _: "/usr/bin/echo")

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        captured.update(kwargs)
        return FakeProcess()

    monkeypatch.setattr(subprocess_module.subprocess, "Popen", fake_popen)
    assert subprocess_module.run_command(["echo", "safe"], timeout=7) == "ok"
    assert captured["cmd"] == ["echo", "safe"]
    assert captured["shell"] is False
    assert captured["start_new_session"] is True
    assert captured["timeout"] == 7

    with pytest.raises(TypeError):
        subprocess_module.run_command("echo unsafe")  # type: ignore[arg-type]


def test_http_runtime_guards_block_tls_downgrade_and_internal_host(monkeypatch):
    with pytest.raises(ValueError):
        http_module.make_safe_httpx_client(verify=False)

    monkeypatch.setattr(http_module, "is_engagement_origin_allowed", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(http_module, "is_engagement_target_host", lambda _host: False)
    transport = http_module.SSRFPinningTransport()
    request = http_module.httpx.Request("GET", "http://127.0.0.1/")
    with pytest.raises(http_module.SSRFRedirectBlockedError):
        transport.handle_request(request)
    transport.close()


def test_expired_approval_errors_fail_closed_with_injected_date():
    from webpent.shared.direct_io_inventory import expired_approval_errors

    errors = expired_approval_errors(today=date(2099, 1, 1))

    assert errors
    assert all("expired expires_at=" in error for error in errors)


def test_runtime_gate_rejects_each_wrapper_mutation(tmp_path):
    from scripts.check_g02_runtime import runtime_source_invariant_errors

    copied = tmp_path / "src"
    copied.mkdir()
    subprocess_target = copied / "webpent/tools/utils"
    http_target = copied / "webpent/shared"
    subprocess_target.mkdir(parents=True)
    http_target.mkdir(parents=True)

    subprocess_source = (SOURCE_ROOT / "webpent/tools/utils/subprocess.py").read_text(
        encoding="utf-8"
    )
    http_source = (SOURCE_ROOT / "webpent/shared/http.py").read_text(encoding="utf-8")
    (subprocess_target / "subprocess.py").write_text(subprocess_source, encoding="utf-8")
    (http_target / "http.py").write_text(http_source, encoding="utf-8")

    assert runtime_source_invariant_errors(copied) == []

    mutations = [
        (subprocess_target / "subprocess.py", "shell=False", "shell=True"),
        (subprocess_target / "subprocess.py", "timeout=effective_timeout", "timeout=None"),
        (http_target / "http.py", 'kwargs["verify"] = True', 'kwargs["verify"] = False'),
        (http_target / "http.py", "_redirect_guard", "removed_hook"),
        (http_target / "http.py", "is_engagement_origin_allowed", "removed_scope_check"),
        (http_target / "http.py", "sanitize_cookie_pair", "removed_redaction"),
    ]
    for path, old, new in mutations:
        original = path.read_text(encoding="utf-8")
        path.write_text(original.replace(old, new), encoding="utf-8")
        assert runtime_source_invariant_errors(copied), (path, old)
        path.write_text(original, encoding="utf-8")
