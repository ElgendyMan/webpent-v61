from __future__ import annotations

from webpent.shared.proof_engine import build_causal_engineering_metrics
from webpent.shared.proof_oracles import CausalDecision


def test_causal_engineering_metrics_are_operational_only():
    metrics = build_causal_engineering_metrics(
        [
            {
                "oracle_decision": CausalDecision.CONFIRMED,
                "scoring_bundle_created": True,
                "replay_success": True,
            },
            {"oracle_decision": "CLEAN", "scoring_bundle_created": False, "replay_success": True},
            {
                "oracle_decision": "INCONCLUSIVE",
                "scoring_bundle_created": False,
                "replay_success": False,
            },
            {
                "oracle_decision": "BLOCKED",
                "scoring_bundle_created": False,
                "replay_success": False,
            },
            {"oracle_decision": "BLOCKED", "scoring_bundle_created": True, "replay_success": True},
        ]
    )

    assert metrics == {
        "experiments_executed": 5,
        "oracle_decisions": {
            "CONFIRMED": 1,
            "CLEAN": 1,
            "INCONCLUSIVE": 1,
            "BLOCKED": 2,
        },
        "scoring_proof_bundles_created": 1,
        "replay_successes": 3,
    }
    assert set(metrics) == {
        "experiments_executed",
        "oracle_decisions",
        "scoring_proof_bundles_created",
        "replay_successes",
    }
