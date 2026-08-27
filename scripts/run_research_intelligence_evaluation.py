#!/usr/bin/env python3
"""Run the repeatable, lab-scoped research-intelligence evaluation."""

from __future__ import annotations

import json
from pathlib import Path

from webpent.benchmark.research_intelligence import (
    ResearchEvaluationCase,
    evaluate_research_intelligence,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "reports/evaluation/research_intelligence/CORE-EVALUATION-v1.json"


def main() -> int:
    cases = (
        ResearchEvaluationCase(
            case_id="controlled-id-or-001",
            target_id="controlled-local-id-or",
            hypothesis_generated=True,
            rank=1,
            expected_rank=1,
            information_gain=0.95,
            evidence_quality=1.0,
            validation_outcome="confirmed",
            ground_truth_outcome="confirmed",
            proof_complete=True,
            requests_used=3,
        ),
        ResearchEvaluationCase(
            case_id="controlled-id-or-negative-control-001",
            target_id="controlled-local-id-or",
            hypothesis_generated=True,
            rank=2,
            expected_rank=2,
            information_gain=0.70,
            evidence_quality=1.0,
            validation_outcome="blocked",
            ground_truth_outcome="blocked",
            proof_complete=False,
            requests_used=0,
        ),
    )
    report = evaluate_research_intelligence(
        engagement_id="local-controlled-research-v1",
        cases=cases,
    )
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report.model_dump(mode="json"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
