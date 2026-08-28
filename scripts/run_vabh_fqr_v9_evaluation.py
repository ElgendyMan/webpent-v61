#!/usr/bin/env python3
"""Generate VABH-FQR v9 artifacts from recorded state only."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.vabhfqr_v9 import V9AnalyticsReview, VIPBenchmarkSuiteV9  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT_REPORTS = ROOT / "reports" / "evaluation" / "vabhfqr_v9"
OUT_ARTIFACTS = ROOT / "artifacts" / "vabhfqr_v9"


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    suite = VIPBenchmarkSuiteV9.from_recorded_state()
    review = V9AnalyticsReview()
    score = review.score(engagement_id="recorded-v9", target_id="offline-recorded", suite=suite)
    readiness = review.readiness(
        engagement_id="recorded-v9", target_id="offline-recorded", suite=suite
    )
    benchmark = {
        "schema": "vabh-fqr-v9-controlled-benchmark-v1",
        "mode": "offline_recorded_state_only",
        "runner_requests": 0,
        "suite": suite.summary(),
        "cases": [asdict(case) for case in suite.cases],
        "governance": {
            "official_isolated_p10_runs_authorized": False,
            "p10_qualification": "NOT_QUALIFIED",
            "vip_gate": "NOT_QUALIFIED",
            "bug_bounty": "BLOCKED",
            "human_signoff": False,
        },
    }
    scorecard = {
        "schema": "vabh-fqr-v9-research-quality-scorecard-v1",
        "score": asdict(score),
        "interpretation": (
            "engineering metrics are advisory; qualification metrics remain null "
            "without valid causal evidence"
        ),
    }
    readiness_payload = {
        "schema": "vabh-fqr-v9-vip-readiness-assessment-v1",
        "assessment": asdict(readiness),
        "interpretation": (
            "engineering-complete and ready for formal VIP qualification process only"
        ),
    }
    gate_summary = {
        "schema": "vabh-fqr-v9-gate-summary-v1",
        "focused_tests": {"status": "pending_source_tree_gate"},
        "full_tests": {"status": "pending_source_tree_gate"},
        "benchmark": {
            "registered_classes": len(suite.cases),
            "blocked_cases": len(suite.cases) - len(suite.scorable_cases),
            "scorable_cases": len(suite.scorable_cases),
            "requests_sent": 0,
            "metrics": {"precision": None, "recall": None, "f1": None},
        },
        "governance": benchmark["governance"],
    }
    write_json(OUT_REPORTS / "vabh_fqr_v9_controlled_benchmark_v1.json", benchmark)
    write_json(OUT_REPORTS / "vabh_fqr_v9_research_quality_scorecard_v1.json", scorecard)
    write_json(OUT_REPORTS / "vabh_fqr_v9_vip_readiness_assessment_v1.json", readiness_payload)
    write_json(OUT_ARTIFACTS / "VABH-FQR-v9-Gate-Summary.json", gate_summary)
    print(json.dumps({"benchmark": benchmark["suite"], "requests_sent": 0}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
