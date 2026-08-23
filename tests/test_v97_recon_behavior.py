from __future__ import annotations

from types import SimpleNamespace

import pytest

from webpent.shared.exceptions import ToolExecutionError


def test_katana_parses_jsonl_skips_malformed_and_drops_offscope(monkeypatch):
    import webpent.tools.recon.katana as katana

    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda host: host == "target.test",
    )
    monkeypatch.setattr(
        katana,
        "get_settings",
        lambda: SimpleNamespace(katana_path="katana"),
    )
    captured: dict[str, object] = {}

    def fake_run(cmd, timeout):
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        return (
            '{"request":{"endpoint":"https://target.test/a"}}\n'
            "not-json\n"
            '{"url":"https://target.test/b"}\n'
            '{"url":"https://internal.test/secret"}\n'
            '{"request":{"endpoint":"/relative"}}\n'
        )

    monkeypatch.setattr(katana, "run_command", fake_run)
    assert katana.run_katana("https://target.test", depth=2) == [
        "https://target.test/a",
        "https://target.test/b",
    ]
    assert captured["timeout"] == 120
    assert "-nc" in captured["cmd"]


def test_katana_extract_url_rejects_missing_values():
    import webpent.tools.recon.katana as katana

    assert katana._extract_url({}) is None
    assert katana._extract_url({"request": {"endpoint": "  "}}) is None
    assert katana._extract_url({"url": " https://target.test/path "}) == (
        "https://target.test/path"
    )


def test_katana_refuses_out_of_scope_before_subprocess(monkeypatch):
    import webpent.tools.recon.katana as katana

    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("katana subprocess must not run out of scope")

    monkeypatch.setattr(katana, "run_command", fail_if_called)
    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda _host: False,
    )
    assert katana.run_katana("https://out-of-scope.test") == []
    assert called is False


def test_katana_reraises_non_timeout_failure(monkeypatch):
    import webpent.tools.recon.katana as katana

    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda _host: True,
    )
    monkeypatch.setattr(
        katana,
        "get_settings",
        lambda: SimpleNamespace(katana_path="katana"),
    )
    error = ToolExecutionError(["katana"], 2, stderr="fatal configuration error")
    monkeypatch.setattr(
        katana,
        "run_command",
        lambda *args, **kwargs: (_ for _ in ()).throw(error),
    )
    with pytest.raises(ToolExecutionError):
        katana.run_katana("https://target.test")


def test_katana_uses_partial_output_after_timeout(monkeypatch):
    import webpent.tools.recon.katana as katana

    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda _host: True,
    )
    monkeypatch.setattr(
        katana,
        "get_settings",
        lambda: SimpleNamespace(katana_path="katana"),
    )
    partial = '{"url":"https://target.test/partial"}\n'
    monkeypatch.setattr(
        katana,
        "run_command",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            ToolExecutionError(
                ["katana"], 124, stdout=partial, stderr="timed out"
            )
        ),
    )
    assert katana.run_katana("https://target.test") == [
        "https://target.test/partial"
    ]


def test_httpx_scopes_input_and_parses_valid_json(monkeypatch):
    import webpent.tools.recon.httpx as httpx

    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda host: host == "target.test",
    )
    monkeypatch.setattr(
        httpx,
        "get_settings",
        lambda: SimpleNamespace(httpx_path="httpx"),
    )
    captured: dict[str, object] = {}

    def fake_run(cmd, input_data, timeout):
        captured.update(cmd=cmd, input_data=input_data, timeout=timeout)
        return '{"url":"https://target.test","status-code":200}\ninvalid\n[]\n'

    monkeypatch.setattr(httpx, "run_command", fake_run)
    assert httpx.run_httpx(
        ["https://target.test", "https://internal.test", " "]
    ) == [{"url": "https://target.test", "status-code": 200}]
    assert captured["input_data"] == "https://target.test"
    assert captured["timeout"] == 120


def test_httpx_empty_output_is_not_a_finding(monkeypatch):
    import webpent.tools.recon.httpx as httpx

    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda _host: True,
    )
    monkeypatch.setattr(
        httpx,
        "get_settings",
        lambda: SimpleNamespace(httpx_path="httpx"),
    )
    monkeypatch.setattr(httpx, "run_command", lambda *args, **kwargs: "")
    assert httpx.run_httpx(["https://target.test"]) == []


def test_httpx_reraises_non_timeout_failure(monkeypatch):
    import webpent.tools.recon.httpx as httpx

    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda _host: True,
    )
    monkeypatch.setattr(
        httpx,
        "get_settings",
        lambda: SimpleNamespace(httpx_path="httpx"),
    )
    error = ToolExecutionError(["httpx"], 2, stderr="fatal configuration error")
    monkeypatch.setattr(
        httpx,
        "run_command",
        lambda *args, **kwargs: (_ for _ in ()).throw(error),
    )
    with pytest.raises(ToolExecutionError):
        httpx.run_httpx(["https://target.test"])


def test_httpx_returns_partial_records_after_timeout(monkeypatch):
    import webpent.tools.recon.httpx as httpx

    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda _host: True,
    )
    monkeypatch.setattr(
        httpx,
        "get_settings",
        lambda: SimpleNamespace(httpx_path="httpx"),
    )
    partial = '{"url":"https://target.test","status-code":200}\n'
    monkeypatch.setattr(
        httpx,
        "run_command",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            ToolExecutionError(
                ["httpx"], 124, stdout=partial, stderr="timed out"
            )
        ),
    )
    assert httpx.run_httpx(["https://target.test"]) == [
        {"url": "https://target.test", "status-code": 200}
    ]


def test_httpx_sends_sanitized_headers_and_cookies(monkeypatch):
    import webpent.tools.recon.httpx as httpx

    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda _host: True,
    )
    monkeypatch.setattr(
        httpx,
        "get_settings",
        lambda: SimpleNamespace(httpx_path="httpx"),
    )
    captured: dict[str, object] = {}

    def fake_run(cmd, input_data, timeout):
        captured.update(cmd=cmd, input_data=input_data, timeout=timeout)
        return ""

    monkeypatch.setattr(httpx, "run_command", fake_run)
    httpx.run_httpx(["target.test"], stealth_mode=False)
    assert captured["input_data"] == "target.test"


def test_subfinder_deduplicates_and_preserves_order(monkeypatch):
    import webpent.tools.recon.subfinder as subfinder

    monkeypatch.setattr(
        subfinder,
        "get_settings",
        lambda: SimpleNamespace(subfinder_path="subfinder"),
    )
    monkeypatch.setattr(
        subfinder,
        "run_command",
        lambda cmd, timeout: "a.target.test\n\na.target.test\nb.target.test\n",
    )
    assert subfinder.run_subfinder("target.test") == [
        "a.target.test",
        "b.target.test",
    ]


def test_subfinder_uses_partial_output_after_timeout(monkeypatch):
    import webpent.tools.recon.subfinder as subfinder

    monkeypatch.setattr(
        subfinder,
        "get_settings",
        lambda: SimpleNamespace(subfinder_path="subfinder"),
    )
    partial = "a.target.test\n"
    monkeypatch.setattr(
        subfinder,
        "run_command",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            ToolExecutionError(
                ["subfinder"], 124, stdout=partial, stderr="timed out"
            )
        ),
    )
    assert subfinder.run_subfinder("target.test") == ["a.target.test"]


def test_subfinder_empty_output_is_not_a_finding(monkeypatch):
    import webpent.tools.recon.subfinder as subfinder

    monkeypatch.setattr(
        subfinder,
        "get_settings",
        lambda: SimpleNamespace(subfinder_path="subfinder"),
    )
    monkeypatch.setattr(subfinder, "run_command", lambda *args, **kwargs: "")
    assert subfinder.run_subfinder("target.test") == []


def test_subfinder_reraises_non_timeout_tool_failure(monkeypatch):
    import webpent.tools.recon.subfinder as subfinder

    monkeypatch.setattr(
        subfinder,
        "get_settings",
        lambda: SimpleNamespace(subfinder_path="subfinder"),
    )
    error = ToolExecutionError(
        ["subfinder"], 2, stderr="configuration error"
    )
    monkeypatch.setattr(
        subfinder,
        "run_command",
        lambda *args, **kwargs: (_ for _ in ()).throw(error),
    )
    with pytest.raises(ToolExecutionError):
        subfinder.run_subfinder("target.test")


def test_worker_graph_state_distinguishes_pending_completed_and_paused():
    from webpent.workers.pentest_worker import _check_graph_state

    class Graph:
        def __init__(self, snapshot):
            self.snapshot = snapshot

        def get_state(self, _config):
            return self.snapshot

    assert _check_graph_state(Graph(None), {})["status"] == "pending"
    assert _check_graph_state(
        Graph(SimpleNamespace(values={}, next=("node",))), {}
    )["status"] == "pending"
    assert _check_graph_state(
        Graph(SimpleNamespace(values={"x": 1}, next=())), {}
    )["status"] == "completed"
    paused = _check_graph_state(
        Graph(SimpleNamespace(values={"x": 1}, next=("execution_sandbox",))),
        {},
    )
    assert paused["status"] == "paused"
    assert paused["is_paused_at_sandbox"] is True
