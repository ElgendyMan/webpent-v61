from __future__ import annotations

from webpent.agents.access_control import agent as access_agent


def test_bac_initial_cooldown_accepts_documented_secs_alias(monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setenv("WEBPENT_BAC_INITIAL_COOLDOWN_SECS", "65")
    monkeypatch.delenv("WEBPENT_BAC_INITIAL_COOLDOWN_SECONDS", raising=False)
    monkeypatch.setenv("WEBPENT_BAC_INITIAL_JITTER_MAX_SECONDS", "0")
    monkeypatch.setattr(access_agent.time, "sleep", sleeps.append)

    delay = access_agent._wait_before_bac("http://lab.test/resource/1")

    assert delay == 65.0
    assert sleeps == [65.0]


def test_bac_initial_cooldown_preserves_legacy_seconds_alias(monkeypatch):
    sleeps: list[float] = []
    monkeypatch.delenv("WEBPENT_BAC_INITIAL_COOLDOWN_SECS", raising=False)
    monkeypatch.setenv("WEBPENT_BAC_INITIAL_COOLDOWN_SECONDS", "12")
    monkeypatch.setenv("WEBPENT_BAC_INITIAL_JITTER_MAX_SECONDS", "0")
    monkeypatch.setattr(access_agent.time, "sleep", sleeps.append)

    delay = access_agent._wait_before_bac("http://lab.test/resource/1")

    assert delay == 12.0
    assert sleeps == [12.0]


def test_bac_initial_cooldown_remains_bounded(monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setenv("WEBPENT_BAC_INITIAL_COOLDOWN_SECS", "999")
    monkeypatch.setenv("WEBPENT_BAC_INITIAL_JITTER_MAX_SECONDS", "0")
    monkeypatch.setattr(access_agent.time, "sleep", sleeps.append)

    delay = access_agent._wait_before_bac("http://lab.test/resource/1")

    assert delay == 90.0
    assert sleeps == [90.0]
