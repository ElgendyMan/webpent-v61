#!/usr/bin/env python3
"""Evaluate captured WebPent run artifacts without executing a target.

The input is a JSON file containing either a list of run objects or
``{"runs": [...], "ground_truth": [...]}``. This command performs no network,
subprocess, target, or AutoPentestX execution.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.metrics import compare_runs


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=Path, required=True, help="offline run-matrix JSON")
    parser.add_argument("--output", type=Path, help="optional JSON output path")
    args = parser.parse_args()

    payload = _load(args.runs)
    if isinstance(payload, dict):
        runs = payload.get("runs", [])
        ground_truth = payload.get("ground_truth", [])
    else:
        runs = payload
        ground_truth = []
    if not isinstance(runs, list) or not all(isinstance(item, dict) for item in runs):
        raise SystemExit("runs must be a JSON array of objects")
    if not isinstance(ground_truth, list) or not all(
        isinstance(item, dict) for item in ground_truth
    ):
        raise SystemExit("ground_truth must be a JSON array of objects")

    result = {
        "mode": "offline_artifact_metrics",
        "live_target_executed": False,
        "autopentestx_executed": False,
        **compare_runs(runs, ground_truth=ground_truth),
    }
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
