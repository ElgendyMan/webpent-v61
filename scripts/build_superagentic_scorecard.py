#!/usr/bin/env python3
"""Build a local superagentic scorecard without contacting targets."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from webpent.shared.behavior_scenarios import BehaviorScenarioRunner
from webpent.shared.evaluation import QualificationScorecard, evaluate_behavior_results


def revision(repo: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--full-regression-passed",
        action="store_true",
        help="Only use when a separately recorded full regression has passed.",
    )
    args = parser.parse_args()
    repo = args.repo.resolve()
    output = args.output or repo / "docs" / "superagentic_scorecard.json"
    results = BehaviorScenarioRunner().run_all()
    behavior = evaluate_behavior_results(results)
    scorecard = QualificationScorecard.build(
        revision=revision(repo),
        behavior=behavior,
        full_regression_passed=args.full_regression_passed,
        blockers=(
            "integration:bbscout_reviewed_source_missing",
            "environment:docker_runtime_unavailable",
            "live:waptlab_owner_authorized_three_run_evidence_missing",
            "live:target_backed_proof_bundles_missing_for_this_run",
        ),
    )
    payload = {
        "artifact_type": "superagentic_scorecard",
        "schema_version": "superagentic-scorecard-v2",
        "offline_only": True,
        "target_contacted": False,
        "signed": False,
        "integrity_seal": scorecard.integrity_signature,
        "scorecard": scorecard.as_dict(),
        "scenario_results": [item.as_dict() for item in results],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), **scorecard.as_dict()}, indent=2, sort_keys=True))
    return 0 if scorecard.qualification_status == "qualified" else 2


if __name__ == "__main__":
    raise SystemExit(main())
