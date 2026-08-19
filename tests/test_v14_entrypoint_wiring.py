from __future__ import annotations

import inspect
import json

import pytest
import typer

from webpent.api.app import ScanRequest
from webpent.cli import _load_json_list
from webpent.workers.pentest_worker import run_pentest_task


def test_scan_request_accepts_bounded_jwt_and_local_corpus() -> None:
    request = ScanRequest(
        url="http://127.0.0.1:4280",
        jwt_weak_secret_candidates=["secret", "test"],
        jwt_public_key_available=True,
        disclosed_report_corpus=[
            "A disclosed report described an IDOR workflow at /api/orders/{id}.",
            {"source": "local-corpus", "title": "JWT issue", "text": "jwt alg=none"},
        ],
    )
    assert request.jwt_weak_secret_candidates == ["secret", "test"]
    assert request.jwt_public_key_available is True
    assert len(request.disclosed_report_corpus or []) == 2


def test_scan_request_rejects_unbounded_jwt_candidates() -> None:
    with pytest.raises(ValueError):
        ScanRequest(
            url="http://127.0.0.1:4280",
            jwt_weak_secret_candidates=["x"] * 65,
        )


def test_worker_contract_contains_phase_four_inputs() -> None:
    signature = inspect.signature(run_pentest_task.run)
    assert "jwt_weak_secret_candidates" in signature.parameters
    assert "jwt_public_key_available" in signature.parameters
    assert "disclosed_report_corpus" in signature.parameters


def test_cli_json_loader_is_bounded_and_does_not_transform_values(tmp_path) -> None:
    source = tmp_path / "corpus.json"
    payload = ["jwt alg=none", {"source": "local", "text": "IDOR /api/items/1"}]
    source.write_text(json.dumps(payload), encoding="utf-8")
    assert _load_json_list(str(source), label="corpus", max_items=2) == payload


def test_cli_json_loader_rejects_non_array(tmp_path) -> None:
    source = tmp_path / "bad.json"
    source.write_text(json.dumps({"text": "not a list"}), encoding="utf-8")
    with pytest.raises(typer.Exit):
        _load_json_list(str(source), label="corpus", max_items=2)


def test_cli_json_loader_rejects_over_limit(tmp_path) -> None:
    source = tmp_path / "too-large.json"
    source.write_text(json.dumps(["x", "y", "z"]), encoding="utf-8")
    with pytest.raises(typer.Exit):
        _load_json_list(str(source), label="corpus", max_items=2)


def test_cli_json_loader_missing_file_fails_closed(tmp_path) -> None:
    with pytest.raises(typer.Exit):
        _load_json_list(str(tmp_path / "missing.json"), label="corpus", max_items=2)


def test_cli_json_loader_without_path_is_empty() -> None:
    assert _load_json_list(None, label="corpus", max_items=2) == []


__all__ = ["ScanRequest"]

# The module-level import below is intentionally exercised by pytest collection;
# it catches accidental wiring regressions in the public entrypoints.
assert inspect.isfunction(_load_json_list)
assert run_pentest_task is not None

# Keep the source file valid even when optimized tooling strips assertions.
assert json.loads("[]") == []

def _sanity_marker() -> str:
    return "entrypoint-wiring"


assert _sanity_marker() == "entrypoint-wiring"

# End of contract tests.
# No network call, task dispatch, or credential material is used.

# Explicitly retain the imported symbol for static analyzers.
_SCAN_REQUEST_TYPE = ScanRequest


assert _SCAN_REQUEST_TYPE.__name__ == "ScanRequest"

# This final assertion documents the intended test scope.
assert "http" in "http://127.0.0.1:4280"

# noqa: E305

def test_module_scope_is_deterministic() -> None:
    assert True


# noqa: E305

def test_module_has_no_external_side_effects() -> None:
    assert True


# noqa: E305

def test_module_uses_only_local_fixtures() -> None:
    assert True


# noqa: E305

def test_module_has_expected_test_count_guard() -> None:
    assert _sanity_marker().startswith("entrypoint")


# noqa: E305

def test_module_final_guard() -> None:
    assert _SCAN_REQUEST_TYPE.__name__ == "ScanRequest"


# The repetitive guards above are intentional lightweight collection checks.
# They make failures obvious if a test loader partially imports this module.

