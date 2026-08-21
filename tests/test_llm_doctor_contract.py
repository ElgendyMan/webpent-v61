from __future__ import annotations

from types import SimpleNamespace

import scripts.doctor as doctor


def test_doctor_rejects_negative_or_verbose_probe_response(monkeypatch) -> None:
    settings = SimpleNamespace(groq_api_key="test-key")
    monkeypatch.setattr(doctor, "_get_api_key", lambda _settings, _provider: "test-key")
    monkeypatch.setattr(
        doctor,
        "_build_probe_model",
        lambda _provider, _settings: SimpleNamespace(
            invoke=lambda _messages: SimpleNamespace(content="not ok — quota exhausted")
        ),
    )

    result = doctor._probe_provider("groq", settings, timeout=1)

    assert result["status"] == "FAILING"
    assert "unexpected response" in result["detail"]


def test_doctor_accepts_exact_ok_acknowledgement(monkeypatch) -> None:
    settings = SimpleNamespace(groq_api_key="test-key")
    monkeypatch.setattr(doctor, "_get_api_key", lambda _settings, _provider: "test-key")
    monkeypatch.setattr(
        doctor,
        "_build_probe_model",
        lambda _provider, _settings: SimpleNamespace(
            invoke=lambda _messages: SimpleNamespace(content="`OK`.")
        ),
    )

    result = doctor._probe_provider("groq", settings, timeout=1)

    assert result["status"] == "ACTIVE"
    assert "responded" in result["detail"]
