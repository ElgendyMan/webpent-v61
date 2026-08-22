#!/usr/bin/env python3
"""Build a bounded, deterministic three-run offline qualification simulation.

This runner is intentionally offline. It does not contact a target, provider,
browser, or credential store, and its output must not be described as live VIP
qualification or as Gate 5 bbscout evidence.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from webpent.benchmark.qualification import (
    GroundTruthCase,
    QualificationFixture,
    QualificationRun,
    run_offline_qualification,
)


def _runner(fixture: QualificationFixture, repetition: int) -> QualificationRun:
    case_ids = tuple(case.case_id for case in fixture.ground_truth if case.expected)
    outcomes = tuple((case_id, "confirmed") for case_id in case_ids)
    return QualificationRun(
        run_id=f"{fixture.fixture_id}-run-{repetition}",
        target_ref=fixture.target_ref,
        evidence_artifact="artifacts/smart_hunter_review/gate3/gate3_proof_bundle.json",
        confirmed_case_ids=case_ids,
        reviewed_case_ids=case_ids,
        contacted_target=False,
        target_modified=False,
        findings_are_live=False,
        candidate_case_ids=case_ids,
        proof_case_ids=case_ids,
        replay_case_ids=case_ids,
        unauthorized_attempts=0,
        out_of_scope_attempts=0,
        budget_spent=3.0,
        budget_limit=5.0,
        stop_reason="proof_replay_complete",
        canonical_outcomes=outcomes,
    )


def build_artifact(output: Path) -> dict[str, Any]:
    fixture = QualificationFixture(
        fixture_id="offline-three-run-proof-replay",
        target_ref="offline://controlled-proof-fixture",
        ground_truth=(
            GroundTruthCase(
                case_id="offline_gate3_finding",
                category="offline_fixture",
                expected=True,
                source="controlled-offline-fixture",
            ),
        ),
        scenario={
            "transport": "disabled",
            "target_io": False,
            "proof_controls": ["baseline", "candidate", "independent_negative_control"],
        },
    )
    result = run_offline_qualification([fixture], _runner, repetitions=3)
    payload = result.as_dict()
    summary = payload["matrix"]["summary"]
    payload["qualification"] = {
        "name": "offline-three-run-qualification-simulation",
        "runs_required": 3,
        "runs_observed": summary["runs"],
        "reproducible": result.reproducible,
        "proof_replay_agreement_rate": summary["proof_replay_agreement_rate"],
        "unauthorized_attempts": summary["unauthorized_attempts"],
        "out_of_scope_attempts": summary["out_of_scope_attempts"],
        "all_runs_target_unchanged": summary["all_runs_target_unchanged"],
        "live_qualification_proven": summary["live_qualification_proven"],
        "status": "offline_pass_live_not_qualified",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = build_artifact(args.output)
    gate = payload["qualification"]
    assert gate["runs_observed"] == 3
    assert gate["reproducible"] is True
    assert gate["proof_replay_agreement_rate"] == 1.0
    assert gate["unauthorized_attempts"] == 0
    assert gate["out_of_scope_attempts"] == 0
    assert gate["all_runs_target_unchanged"] is True
    assert gate["live_qualification_proven"] is False
    print(json.dumps(gate, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["build_artifact"]
