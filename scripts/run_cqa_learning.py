from __future__ import annotations

import json
from pathlib import Path

CAMPAIGN = Path("reports/cqa_v1/campaign_observations.json")
OUTPUT = Path("metrics/cqa_v1_learning.json")


def main() -> None:
    rows = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
    blocked = sum(1 for row in rows if row["proof_bundle"] is None)
    result = {
        "schema": "cqa-v1-learning-scorecard",
        "run_a": {"name": "cold_memory", "cases": len(rows), "eligible": 0},
        "run_b": {"name": "learned_patterns", "cases": len(rows), "eligible": 0},
        "recall_delta": None,
        "false_positive_delta": None,
        "planning_efficiency": None,
        "learning_status": "NOT_ESTABLISHED",
        "reason": "No scored causal ProofBundles were available in either run.",
        "blocked_cases": blocked,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
