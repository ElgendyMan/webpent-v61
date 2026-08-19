from __future__ import annotations

from webpent.shared.copilot_boundary import sanitize_copilot_suggestion
from webpent.shared.coverage_ledger import CoverageIntelligence


def _state() -> dict[str, object]:
    return {
        "campaign_ledger": {
            "entries": [
                {"id": 1, "key": "idor", "status": "not_scanned", "gaps": []},
                {"id": 2, "key": "xss", "status": "not_scanned", "gaps": []},
                {"id": 3, "key": "csrf", "status": "not_scanned", "gaps": []},
            ]
        },
        "proof_outcomes": [
            {"campaign_key": "idor", "status": "tool_confirmed", "evidence_complete": True},
            {"campaign_key": "xss", "status": "clean", "evidence_complete": True},
        ],
    }


def test_coverage_metrics_are_outcome_based() -> None:
    metrics = CoverageIntelligence().metrics(_state())
    assert metrics["campaign_count"] == 3
    assert metrics["tested_count"] == 2
    assert metrics["confirmed_count"] == 1
    assert metrics["gap_count"] == 1
    assert metrics["tested_ratio"] == 0.666667


def test_copilot_can_only_emit_research_suggestions() -> None:
    suggestion = sanitize_copilot_suggestion(
        {
            "action_class": "passive_discovery",
            "target_ref": "endpoint:/api/invoices",
            "reason": "workflow gap",
            "expected_information_gain": 0.75,
            "evidence_refs": ["obs:1"],
        }
    )
    assert suggestion is not None
    assert suggestion["expected_information_gain"] == 0.75
    assert (
        sanitize_copilot_suggestion(
            {"action_class": "active", "target_ref": "x", "execute": True}
        )
        is None
    )
    assert sanitize_copilot_suggestion({"action_class": "active"}) is None
