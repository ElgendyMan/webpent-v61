from __future__ import annotations

import json

from scripts.run_controlled_local_lab_p10 import run_lab


def test_controlled_local_lab_has_three_isolated_runs_and_redacted_proofs(tmp_path) -> None:
    output = tmp_path / "controlled-local-lab.json"
    payload = run_lab(output)

    assert payload["p10_projection"]["p10_passed"] is True
    assert payload["p10_projection"]["run_count"] == 3
    assert all(
        run["run_id"] != other["run_id"]
        for index, run in enumerate(payload["runs"])
        for other in payload["runs"][index + 1 :]
    )
    cases = [case for run in payload["runs"] for case in run["cases"]]
    assert len(cases) == 33
    assert all(case["proof_bundle_sealed"] for case in cases)
    assert all(case["replay_verified"] for case in cases)
    observations_serialized = json.dumps(
        [case["observations"] for case in cases], sort_keys=True
    ).lower()
    assert "raw_response_body" not in observations_serialized
    assert "set-cookie" not in observations_serialized
    assert all("raw_response_body" not in case["proof_bundle"] for case in cases)
    assert all("set-cookie" not in case["proof_bundle"] for case in cases)
    assert payload["qualification"]["official_juice_shop_p10"] == "NOT_QUALIFIED"
