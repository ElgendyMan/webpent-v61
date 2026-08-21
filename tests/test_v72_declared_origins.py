from __future__ import annotations

import inspect

import pytest
from pydantic import ValidationError

from webpent.api.app import ScanRequest
from webpent.models.targets import Target
from webpent.shared.engagement_scope import (
    OriginPolicy,
    clear_engagement_target_hosts,
    is_engagement_target_host,
    normalize_declared_origins,
    set_engagement_target_hosts,
)
from webpent.state.initial_state import build_initial_state
from webpent.workers.pentest_worker import run_pentest_task


def test_declared_origins_are_normalized_and_deduplicated() -> None:
    origins = normalize_declared_origins(
        [
            " http://localhost:5173/ ",
            "http://localhost:5173",
            "https://frontend.example.test/path",
        ]
    )

    assert origins == ["http://localhost:5173", "https://frontend.example.test/path"]


def test_localhost_matches_declared_loopback_companion_origin() -> None:
    policy = OriginPolicy.from_url("http://127.0.0.1:5173")

    assert policy.allows("http://localhost:5173/@vite/client")
    assert policy.allows("http://127.0.0.1:5173/@vite/client")
    assert not policy.allows("http://localhost:5174/@vite/client")


def test_localhost_requires_declared_loopback_scope() -> None:
    token = set_engagement_target_hosts("http://127.0.0.1:8000")
    try:
        assert is_engagement_target_host("localhost")
        assert is_engagement_target_host("127.0.0.1")
    finally:
        clear_engagement_target_hosts(token)

    assert not is_engagement_target_host("localhost")


def test_declared_origins_reject_unsafe_url_forms() -> None:
    with pytest.raises(ValueError):
        normalize_declared_origins(["http://user:pass@example.test"])

    with pytest.raises(ValueError):
        normalize_declared_origins(["file:///tmp/frontend"])


def test_initial_state_and_scan_request_carry_declared_origins() -> None:
    state = build_initial_state(
        Target(url="http://127.0.0.1:8000"),
        additional_target_origins=["http://localhost:5173/"],
    )
    request = ScanRequest(
        url="http://127.0.0.1:8000",
        additional_target_origins=["http://localhost:5173/"],
    )

    assert state["additional_target_origins"] == ["http://localhost:5173/"]
    assert request.additional_target_origins == ["http://localhost:5173"]


def test_worker_keeps_additional_origins_optional_for_legacy_calls() -> None:
    parameters = inspect.signature(run_pentest_task.run).parameters

    assert "additional_target_origins" in parameters
    assert parameters["additional_target_origins"].default is None


def test_scan_request_rejects_more_than_eight_declared_origins() -> None:
    origins = [f"https://frontend-{index}.example.test" for index in range(9)]

    with pytest.raises(ValidationError):
        ScanRequest(url="https://target.example.test", additional_target_origins=origins)
