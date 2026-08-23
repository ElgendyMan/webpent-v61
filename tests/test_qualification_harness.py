from __future__ import annotations

import sys
import urllib.error

import pytest

from scripts import qualification_harness
from scripts.qualification_harness import (
    _build_command,
    _prepare_scan_env,
    _run,
    _wait_target,
)
from webpent.benchmark.qualification import (
    GroundTruthCase,
    QualificationFixture,
    QualificationRun,
    run_offline_qualification,
)


@pytest.fixture
def fixture() -> QualificationFixture:
    return QualificationFixture(
        fixture_id="offline-idor-fixture",
        target_ref="fixture://idor",
        ground_truth=(
            GroundTruthCase("case-a", "idor"),
            GroundTruthCase("case-b", "workflow"),
        ),
        scenario={"mode": "deterministic", "note": "api_key=not-retained"},
    )


def test_offline_harness_is_reproducible_and_separates_discovery_from_confirmation(
    fixture: QualificationFixture,
) -> None:
    def runner(current: QualificationFixture, repetition: int) -> QualificationRun:
        assert current.fixture_id == fixture.fixture_id
        return QualificationRun(
            run_id=f"{current.fixture_id}:run:{repetition}",
            target_ref=current.target_ref,
            evidence_artifact="evidence://offline/fixture",
            candidate_case_ids=("case-a", "case-b", "case-fp"),
            confirmed_case_ids=("case-a",),
            proof_case_ids=("case-a", "case-b"),
            replay_case_ids=("case-a", "case-b"),
            reviewed_case_ids=("case-a", "case-b"),
            unauthorized_attempts=0,
            out_of_scope_attempts=0,
            budget_spent=2.0,
            budget_limit=4.0,
            stop_reason="information_gain_below_threshold",
        )

    result = run_offline_qualification([fixture], runner, repetitions=3)
    summary = result.matrix.summary()

    assert result.reproducible is True
    assert len(result.run_digests) == 3
    assert summary["candidate_cases"] == 3
    assert summary["confirmed_expected_cases"] == 1
    assert summary["candidate_false_positives"] == 1
    assert summary["candidate_false_negative_cases"] == 0
    assert summary["proof_replay_agreement_rate"] == 1.0
    assert summary["unauthorized_attempts"] == 0
    assert summary["out_of_scope_attempts"] == 0
    assert summary["budget_spent"] == 6.0
    assert summary["stop_reasons"] == ["information_gain_below_threshold"]


def test_offline_harness_detects_non_reproducible_canonical_outcomes(
    fixture: QualificationFixture,
) -> None:
    def runner(current: QualificationFixture, repetition: int) -> QualificationRun:
        outcome = "positive" if repetition == 1 else "inconclusive"
        return QualificationRun(
            run_id=f"{current.fixture_id}:run:{repetition}",
            target_ref=current.target_ref,
            evidence_artifact="evidence://offline/fixture",
            candidate_case_ids=("case-a",),
            canonical_outcomes=(("case-a", outcome),),
            unauthorized_attempts=1 if repetition == 2 else 0,
            out_of_scope_attempts=2 if repetition == 2 else 0,
            budget_spent=1.0,
            budget_limit=1.0,
            stop_reason="budget_exhausted",
        )

    result = run_offline_qualification([fixture], runner, repetitions=2)

    assert result.reproducible is False
    assert result.matrix.summary()["unauthorized_attempts"] == 1
    assert result.matrix.summary()["out_of_scope_attempts"] == 2


def test_harness_rejects_bad_runner_and_invalid_repetition_count(
    fixture: QualificationFixture,
) -> None:
    with pytest.raises(ValueError, match="between 2 and 20"):
        run_offline_qualification(
            [fixture],
            lambda _fixture, _run: QualificationRun("x", "t", "e"),
            repetitions=1,
        )
    with pytest.raises(TypeError, match="QualificationRun"):
        run_offline_qualification(
            [fixture],
            lambda _fixture, _run: {"status": "bad"},  # type: ignore[arg-type]
            repetitions=2,
        )



def test_qualification_serialization_redacts_fixture_and_run_values(
    fixture: QualificationFixture,
) -> None:
    run = QualificationRun(
        run_id="run-secret=api_key=raw",
        target_ref="fixture://safe",
        evidence_artifact="evidence://safe",
        candidate_case_ids=("case-a",),
        canonical_outcomes=(("case-a", "api_key=raw-secret"),),
    )
    rendered = repr({"fixture": fixture.as_dict(), "run": run.as_dict()})

    assert "not-retained" not in rendered
    assert "raw-secret" not in rendered
    assert "[REDACTED]" in rendered



def test_tool_manifest_uses_run_authority_not_parent_legacy_settings() -> None:
    manifest_record = qualification_harness._tool_manifest({}, scan_mode="authorized-active")
    manifest = manifest_record["manifest"]

    assert manifest["profile"] == "authorized-active"
    assert manifest["capabilities"]["active_workflow"]["available"] is True
    assert manifest["capabilities"]["active_workflow"]["policy"] == "authorized-active-only"


def test_waptlab_command_uses_waptlab_inventory_and_declared_frontend_origin() -> None:
    from argparse import Namespace
    from pathlib import Path

    args = Namespace(
        target="waptlab",
        url="http://127.0.0.1:8000",
        creds_file="/tmp/test-creds.json",
        cookie_file=None,
    )
    command = _build_command(args, Path("/tmp/run"), "waptlab-q1")

    assert "--campaign-inventory" in command
    assert command[command.index("--campaign-inventory") + 1] == "waptlab"
    assert "--additional-target-origin" in command
    assert "http://127.0.0.1:5173" in command
    assert "--no-llm" in command


def test_non_waptlab_command_is_target_neutral() -> None:
    from argparse import Namespace
    from pathlib import Path

    args = Namespace(
        target="juice-shop",
        url="http://127.0.0.1:3000",
        creds_file="/tmp/test-creds.json",
        cookie_file=None,
    )
    command = _build_command(args, Path("/tmp/run"), "juice-shop-q1")

    assert "--campaign-inventory" not in command
    assert "--additional-target-origin" not in command
    assert "waptlab" not in command
    assert "http://127.0.0.1:5173" not in command
    assert command[command.index("--url") + 1] == "http://127.0.0.1:3000"


def test_no_llm_qualification_skips_rag_without_mutating_other_env() -> None:
    base = {"PATH": "/usr/bin", "DISABLE_RAG": "false"}

    no_llm_env = _prepare_scan_env(base, ["webpent", "scan", "--no-llm"])
    normal_env = _prepare_scan_env(base, ["webpent", "scan"])

    assert no_llm_env["DISABLE_RAG"] == "true"
    assert no_llm_env["EMBEDDINGS_OFFLINE"] == "true"
    assert normal_env == base
    assert base["DISABLE_RAG"] == "false"


def test_cookie_file_remains_optional_and_explicit() -> None:
    from argparse import Namespace
    from pathlib import Path

    args = Namespace(
        target="waptlab",
        url="http://127.0.0.1:8000",
        creds_file="/tmp/test-creds.json",
        cookie_file="/tmp/cookies.json",
    )
    command = _build_command(args, Path("/tmp/run"), "waptlab-q1")

    assert command[-2:] == ["--cookie-file", "/tmp/cookies.json"]


def test_run_timeout_returns_reportable_result_and_kills_child() -> None:
    completed = _run(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        timeout=1,
    )

    assert completed.returncode == 124
    assert "qualification_timeout_seconds=1" in completed.stderr


def test_wait_target_treats_http_error_as_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: object, timeout: int) -> object:
        raise urllib.error.HTTPError(str(request), 403, "forbidden", {}, None)

    monkeypatch.setattr(qualification_harness.urllib.request, "urlopen", fake_urlopen)

    result = _wait_target("http://127.0.0.1:8000", timeout_seconds=1)

    assert result["status"] == "reachable"
    assert result["http_status"] == 403
    assert result["response_class"] == "http_error"


def test_wait_target_uses_safe_health_path_when_root_hangs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class Response:
        status = 200

        def read(self, size: int) -> bytes:
            assert size == 256
            return b"ok"

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def fake_urlopen(request: object, timeout: int) -> object:
        url = str(getattr(request, "full_url", request))
        calls.append(url)
        if url.rstrip("/") == "http://127.0.0.1:8000":
            raise urllib.error.URLError("root timeout")
        return Response()

    monkeypatch.setattr(qualification_harness.urllib.request, "urlopen", fake_urlopen)

    result = _wait_target("http://127.0.0.1:8000", timeout_seconds=1)

    assert result["status"] == "reachable"
    assert result["probe_url"].endswith("/robots.txt")
    assert calls == ["http://127.0.0.1:8000", "http://127.0.0.1:8000/robots.txt"]
