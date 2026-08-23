"""Regression tests for the bounded optional Interactsh provider."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from webpent.shared.oob_provider import InteractshProvider, build_oob_provider


class _FakeProcess:
    def __init__(self) -> None:
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return None

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: float) -> None:
        del timeout

    def kill(self) -> None:
        self.killed = True


def test_interactsh_provider_is_explicitly_disabled_without_server() -> None:
    provider = InteractshProvider(server="")

    assert not provider.enabled
    assert provider.open("finding-1") is None


def test_interactsh_provider_uses_bounded_jsonl_session_without_leaking_token() -> None:
    captured: dict[str, Any] = {}
    process = _FakeProcess()

    def fake_runner(command: list[str], **kwargs: Any) -> _FakeProcess:
        captured["command"] = command
        captured["kwargs"] = kwargs
        output_dir = Path(kwargs["env"]["HOME"])
        payload_path = output_dir / "payloads.txt"
        payload_path.write_text("abc123.oast.test\n")
        return process

    provider = InteractshProvider(
        server="https://oast.example.test",
        token="super-secret-token",
        command_runner=fake_runner,
    )
    payload = provider.open("finding-1")

    assert payload == "https://abc123.oast.test"
    command = captured["command"]
    assert "-server" in command
    assert "https://oast.example.test" in command
    assert "-token" in command
    assert "super-secret-token" in command
    assert captured["kwargs"].get("shell", False) is not True
    assert captured["kwargs"]["start_new_session"] is True

    session = provider._sessions["finding-1"]
    session.output_path.write_text(
        json.dumps(
            {
                "protocol": "dns",
                "timestamp": "2026-08-23T00:00:00Z",
                "full-id": "abc123.oast.test",
            }
        )
        + "\n"
    )
    interaction = provider.poll("finding-1", timeout_seconds=1, max_attempts=1)

    assert interaction is not None
    assert interaction.provider == "interactsh"
    assert interaction.interaction_type == "dns"
    assert interaction.evidence_digest
    provider.close("finding-1")
    assert process.terminated
    assert "super-secret-token" not in json.dumps(interaction.__dict__)


def test_build_oob_provider_keeps_local_default_and_reads_secret_value() -> None:
    class Settings:
        oob_provider = "local"
        interactsh_server = "https://oast.example.test"
        interactsh_binary = "interactsh-client"
        interactsh_token = "unused"
        interactsh_poll_interval_seconds = 1

    assert build_oob_provider(Settings()) is None

    Settings.oob_provider = "interactsh"
    provider = build_oob_provider(Settings())
    assert isinstance(provider, InteractshProvider)
    assert provider.server == "https://oast.example.test"


def test_provider_cleanup_is_idempotent_for_unknown_finding() -> None:
    provider = InteractshProvider(server="https://oast.example.test")

    provider.close("unknown")
    assert provider.poll("unknown", timeout_seconds=1, max_attempts=1) is None
