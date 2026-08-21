from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _finding(key: str) -> dict[str, object]:
    return {
        "key": key,
        "status": "confirmed",
        "causal_signal": True,
        "negative_control_complete": True,
        "proof_bundle_sealed": True,
    }


def test_evaluator_reports_delta_and_fails_large_regression(tmp_path: Path) -> None:
    benchmark = tmp_path / "benchmark.json"
    baseline = tmp_path / "baseline.json"
    observed = tmp_path / "observed.json"
    result = tmp_path / "result.json"
    _write(benchmark, {"entries": [{"key": key} for key in ("a", "b", "c", "d")]})
    _write(baseline, {"findings": [_finding("a"), _finding("b")]})
    _write(observed, {"findings": [_finding("a")]})

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/evaluate_benchmark.py",
            "--benchmark",
            str(benchmark),
            "--baseline",
            str(baseline),
            "--observed",
            str(observed),
            "--output",
            str(result),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    report = json.loads(result.read_text(encoding="utf-8"))
    assert report["detection_rate"] == 0.25
    assert report["baseline"]["detection_rate"] == 0.5
    assert report["detection_rate_delta"] == -0.25
    assert report["regression_gate"] == "failed"
