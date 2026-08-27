"""Generate ABHIP v5 benchmark and internal metrics from recorded evidence only."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from benchmarks.abhip_v4_controlled import build_report
from benchmarks.abhip_v4_metrics import score_report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-artifact",
        type=Path,
        default=Path("reports/evaluation/asros/asros_advanced_controlled_benchmark_v1.json"),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metrics-output", type=Path, required=True)
    args = parser.parse_args()

    report = build_report(args.source_artifact)
    previous_path = Path("reports/evaluation/abhie/abhie_v4_controlled_benchmark.json")
    previous = (
        json.loads(previous_path.read_text(encoding="utf-8"))
        if previous_path.exists()
        else None
    )
    metrics = score_report(report, previous_report=previous)
    report["quality_score"] = metrics
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.metrics_output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.metrics_output.write_text(
        json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"benchmark": str(args.output), "metrics": str(args.metrics_output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
