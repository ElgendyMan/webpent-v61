"""Regression tests for the additive canonical adapter registry."""

from __future__ import annotations

import pytest

from webpent.shared.tool_adapters import builtin_adapters, get_tool_adapter

EXPECTED_TOOLS = {
    "httpx",
    "katana",
    "nuclei",
    "subfinder",
    "ffuf",
    "dalfox",
    "sqlmap",
}


def test_all_first_party_security_wrappers_have_canonical_adapters() -> None:
    adapters = builtin_adapters()

    assert EXPECTED_TOOLS.issubset(adapters)
    assert {name for name in EXPECTED_TOOLS if callable(adapters[name].runner)} == EXPECTED_TOOLS
    assert adapters["dalfox"].category == "exploitation"
    assert adapters["sqlmap"].category == "exploitation"
    assert adapters["ffuf"].category == "recon"
    assert adapters["subfinder"].category == "recon"


def test_expanded_adapters_normalize_their_legacy_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "webpent.tools.recon.subfinder.run_subfinder",
        lambda domain, **_kwargs: [f"api.{domain}"],
    )
    monkeypatch.setattr(
        "webpent.tools.recon.ffuf.run_ffuf",
        lambda target_url, wordlist_path, **_kwargs: [
            {"url": f"{target_url.rstrip('/')}/admin", "status": 200, "wordlist": wordlist_path}
        ],
    )
    monkeypatch.setattr(
        "webpent.tools.exploitation.dalfox.run_dalfox",
        lambda url, **_kwargs: '{"type":"xss","url":"' + url + '"}',
    )
    monkeypatch.setattr(
        "webpent.tools.exploitation.sqlmap.run_sqlmap",
        lambda url, **_kwargs: "parameter 'id' is vulnerable",
    )

    cases = [
        ("subfinder", "example.test", {}, "recon"),
        ("ffuf", "https://example.test", {"wordlist_path": "/tmp/words.txt"}, "recon"),
        ("dalfox", "https://example.test?q=1", {}, "exploitation"),
        ("sqlmap", "https://example.test/item?id=1", {}, "exploitation"),
    ]
    for name, target, kwargs, category in cases:
        result = get_tool_adapter(name).run(target, scope_decision="allowed", **kwargs)
        assert result.execution.tool_name == name
        assert result.execution.status == "success"
        assert result.observations
        assert result.observations[0].metadata["category"] == category
        assert result.observations[0].evidence_refs


def test_missing_ffuf_wordlist_is_fail_closed_without_running_the_wrapper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def fake_ffuf(*_args: object, **_kwargs: object) -> list[dict[str, object]]:
        nonlocal called
        called = True
        return []

    monkeypatch.setattr("webpent.tools.recon.ffuf.run_ffuf", fake_ffuf)
    result = get_tool_adapter("ffuf").run("https://example.test", scope_decision="allowed")

    assert not called
    assert result.execution.status == "not_run"
    assert result.execution.error_class == "MissingToolInputError"
    assert not result.observations
