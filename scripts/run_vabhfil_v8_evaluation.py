#!/usr/bin/env python3
"""Generate VABH-FIL v8 evaluation artifacts without contacting any target."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from webpent.vabhfil_v8 import (
    AutonomousResearchQualityEvaluatorV8,
    VABHFILV8Core,
    VIPArchitectureReadinessReviewerV8,
    VIPControlledBenchmarkV7,
)


def jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [jsonable(item) for item in value]
    return value


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(jsonable(payload), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def run(output_dir: Path) -> dict[str, str]:
    benchmark = VIPControlledBenchmarkV7().run()
    core_result = VABHFILV8Core().run(
        engagement_id="recorded-v8-evaluation",
        target_id="recorded-target-neutral",
        mental_model={
            "security_assumptions": ("recorded authorization assumption",),
            "trust_boundaries": ("recorded trust boundary",),
            "protected_assets": ("recorded asset",),
        },
        coverage={"coverage_gaps": ("causal oracle unavailable",)},
    )
    score = AutonomousResearchQualityEvaluatorV8().score(
        engagement_id=core_result.engagement_id,
        target_id=core_result.target_id,
        benchmark=benchmark,
        investigation_count=len(core_result.investigations),
        hypothesis_count=len(core_result.hypotheses),
        memory_lesson_count=len(core_result.memory_lessons),
    )
    review = VIPArchitectureReadinessReviewerV8().review(
        engagement_id=core_result.engagement_id,
        target_id=core_result.target_id,
        score=score,
        benchmark=benchmark,
    )
    benchmark_path = output_dir / "vabhfil_v8_vip_benchmark_v7.json"
    score_path = output_dir / "vabhfil_v8_research_intelligence_score_v1.json"
    review_path = output_dir / "vabhfil_v8_architecture_readiness_v1.json"
    write_json(benchmark_path, benchmark)
    write_json(score_path, score)
    write_json(review_path, review)
    return {
        "benchmark": str(benchmark_path),
        "score": str(score_path),
        "readiness": str(review_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports/evaluation/vabhfil_v8"),
    )
    args = parser.parse_args()
    paths = run(args.output_dir)
    print(json.dumps(paths, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
