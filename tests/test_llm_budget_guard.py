from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableLambda

from webpent.config.settings import Settings
from webpent.shared import llm as llm_router


def test_llm_call_cap_blocks_before_provider_io() -> None:
    calls: list[str] = []
    response = AIMessage(content="bounded")
    guarded = llm_router._guard_provider_runnable(
        RunnableLambda(lambda _input: (calls.append("provider"), response)[1]),
        "local",
        model_name="test-model",
        task_type=llm_router.TaskType.FAST.value,
    )
    settings = Settings(llm_max_calls_per_run=1, llm_warning_tokens_per_run=100)

    with llm_router.llm_usage_scope(settings):
        assert guarded.invoke("first") == response
        with pytest.raises(llm_router.LLMBudgetExhaustedError):
            guarded.invoke("second")
        summary = llm_router.get_llm_budget_summary()

    assert calls == ["provider"]
    assert summary["active"] is True
    assert summary["calls"] == 1
    assert summary["blocked"] is True
    assert summary["max_calls"] == 1


def test_llm_budget_warns_on_reported_tokens_without_pricing() -> None:
    responses = iter(
        [
            AIMessage(
                content="one",
                usage_metadata={"input_tokens": 4, "output_tokens": 6, "total_tokens": 10},
            ),
            AIMessage(
                content="two",
                usage_metadata={"input_tokens": 3, "output_tokens": 7, "total_tokens": 10},
            ),
        ]
    )
    guarded = llm_router._guard_provider_runnable(
        RunnableLambda(lambda _input: next(responses)),
        "local",
        model_name="test-model",
        task_type=llm_router.TaskType.ANALYSIS.value,
    )
    settings = Settings(llm_max_calls_per_run=3, llm_warning_tokens_per_run=15)

    with llm_router.llm_usage_scope(settings):
        guarded.invoke("first")
        guarded.invoke("second")
        summary = llm_router.get_llm_budget_summary()

    assert summary["calls"] == 2
    assert summary["reported_tokens"] == 20
    assert summary["warning_tokens"] == 15
    assert summary["warning_emitted"] is True
    assert summary["blocked"] is False
    assert all(key not in summary for key in ("api_key", "prompt", "response"))


def test_llm_budget_settings_are_bounded_and_aliasable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_MAX_CALLS_PER_RUN", "7")
    monkeypatch.setenv("LLM_WARNING_TOKENS_PER_RUN", "1234")
    settings = Settings()
    assert settings.llm_max_calls_per_run == 7
    assert settings.llm_warning_tokens_per_run == 1234

    with pytest.raises(ValueError):
        Settings(llm_max_calls_per_run=0)
    with pytest.raises(ValueError):
        Settings(llm_warning_tokens_per_run=-1)
