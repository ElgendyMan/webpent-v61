from __future__ import annotations

import logging

from webpent.agents.reflection.agent import _parse_lessons


def test_empty_lessons_response_is_explicit_noop_without_warning(caplog) -> None:
    with caplog.at_level(logging.WARNING):
        assert _parse_lessons("") == []
        assert _parse_lessons("   \n") == []

    assert "Could not parse LLM lessons response" not in caplog.text


def test_non_empty_malformed_lessons_response_still_warns(caplog) -> None:
    with caplog.at_level(logging.WARNING):
        assert _parse_lessons("not-json") == []

    assert "Could not parse LLM lessons response" in caplog.text
