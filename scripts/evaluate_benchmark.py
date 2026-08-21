#!/usr/bin/env python3
"""Evaluate an observed WebPent result against a versioned benchmark."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Make the repository-local benchmark package importable when this script is
# invoked directly as ``python scripts/evaluate_benchmark.py``.
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from benchmarks.metrics import compute_metrics  # noqa: E402


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _findings(payload: Any) -> list[dict[str, Any]]:
    value = payload.get("findings", payload) if isinstance(payload, dict) else payload
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise SystemExit("observed payload must be a JSON array or an object with findings")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", type=Path, required=True)
    parser.add_argument("--observed", type=Path, required=True)
    parser.add_argument(
        "--baseline",
        type=Path,
        help="Optional previous observed JSON report used for detection-rate comparison.",
    )
    parser.add_argument(
        "--max-detection-rate-drop",
        type=float,
        default=0.05,
        help="Maximum allowed absolute detection-rate regression (default: 0.05).",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    if args.max_detection_rate_drop < 0 or args.max_detection_rate_drop > 1:
        raise SystemExit("--max-detection-rate-drop must be between 0 and 1")

    benchmark = _load(args.benchmark)
    expected = (
        benchmark.get("entries", benchmark)
        if isinstance(benchmark, dict)
        else benchmark
    )
    observed = _findings(_load(args.observed))
    if not isinstance(expected, list) or not all(isinstance(item, dict) for item in expected):
        raise SystemExit("benchmark payload must be a JSON array or an object with entries")

    metrics = compute_metrics(expected, observed, confirmed_only=True).as_dict()
    detection_rate = float(metrics["recall"])
    result: dict[str, Any] = {
        "benchmark": str(args.benchmark),
        "observed": str(args.observed),
        "confirmed_only": True,
        "metrics": metrics,
        "detection_rate": detection_rate,
        "baseline": None,
        "detection_rate_delta": None,
        "regression_gate": "not_evaluated",
    }

    if args.baseline is not None:
        baseline_findings = _findings(_load(args.baseline))
        baseline_metrics = compute_metrics(
            expected, baseline_findings, confirmed_only=True
        ).as_dict()
        baseline_rate = float(baseline_metrics["recall"])
        delta = round(detection_rate - baseline_rate, 6)
        result["baseline"] = {
            "observed": str(args.baseline),
            "metrics": baseline_metrics,
            "detection_rate": baseline_rate,
        }
        result["detection_rate_delta"] = delta
        if delta < -args.max_detection_rate_drop:
            result["regression_gate"] = "failed"
        else:
            result["regression_gate"] = "passed"

    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    if result["regression_gate"] == "failed":
        raise SystemExit(
            "detection-rate regression exceeded threshold: "
            f"{result['detection_rate_delta']:.4f} < {-args.max_detection_rate_drop:.4f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
