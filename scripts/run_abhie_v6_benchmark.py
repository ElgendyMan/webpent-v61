"""Generate ABHIE v6 benchmark and scorecard from recorded evidence only."""

from __future__ import annotations

import argparse
from pathlib import Path

from benchmarks.abhie_v6_controlled import build_report
from benchmarks.abhie_v6_scorecard import score_report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-artifact", type=Path, required=True)
    parser.add_argument("--benchmark-output", type=Path, required=True)
    parser.add_argument("--scorecard-output", type=Path, required=True)
    args = parser.parse_args()

    benchmark = build_report(args.source_artifact)
    args.benchmark_output.parent.mkdir(parents=True, exist_ok=True)
    args.benchmark_output.write_text(
        __import__("json").dumps(benchmark, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    scorecard = score_report(args.benchmark_output)
    args.scorecard_output.parent.mkdir(parents=True, exist_ok=True)
    args.scorecard_output.write_text(
        __import__("json").dumps(scorecard, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        {
            "benchmark_output": str(args.benchmark_output),
            "scorecard_output": str(args.scorecard_output),
            "scorable_cases": len(benchmark["recorded_complete_case_ids"]),
            "requests_sent": benchmark["execution"]["requests_sent"],
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
