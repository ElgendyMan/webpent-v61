from __future__ import annotations

import json
from pathlib import Path

RESULT = Path("reports/evaluation/local_causal_lab/B2-TARGET-LIVE-RESULT-v1.json")


def test_b2_result_is_present_and_global_gates_remain_closed() -> None:
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    authorization = result["authorization"]
    assert authorization["official_isolated_p10_runs_authorized"] is False
    assert authorization["p10"] == "NOT_QUALIFIED"
    assert authorization["p9"] == "NOT_QUALIFIED"
    assert authorization["vip"] == "NOT_QUALIFIED"
    assert authorization["bug_bounty"] == "BLOCKED"


def test_b2_does_not_promote_inconclusive_observations() -> None:
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    webgoat = next(item for item in result["cases"] if item["target_id"] == "owasp_webgoat")
    assert webgoat["precondition"]["status"] == "ready"
    assert webgoat["causal_oracle"]["status"] == "evaluated"
    assert webgoat["causal_oracle"]["causal_signal"] is False
    assert webgoat["final_classification"] == "INCONCLUSIVE"
    assert webgoat["proof_bundle"]["status"] == "withheld_not_scoring"
    assert webgoat["proof_bundle"]["seal"] == "not_created"


def test_b2_keeps_crapi_blocked_without_fixture_injection() -> None:
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    crapi = next(item for item in result["cases"] if item["target_id"] == "crapi")
    assert crapi["final_classification"] == "BLOCKED"
    assert crapi["precondition"]["status"] == "blocked"
    assert crapi["proof_bundle"]["status"] == "withheld"
