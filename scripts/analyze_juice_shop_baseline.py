#!/usr/bin/env python3
"""Analyze one Juice Shop baseline without inventing benchmark metrics."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--evaluation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run = load(args.run)
    evaluation = load(args.evaluation)
    statuses = run.get("case_statuses", {})
    proof_states = run.get("proof_states", {})
    proof_cases = sorted(
        case_id
        for case_id, state in proof_states.items()
        if isinstance(state, dict) and state.get("promotion_ready") is True
    )
    weak_proof_cases = sorted(
        case_id
        for case_id, state in proof_states.items()
        if isinstance(state, dict)
        and state.get("status") == "confirmed_proof"
        and not (
            state.get("causal_signal") is True
            and state.get("negative_control_complete") is True
            and state.get("verify_seal") is True
            and state.get("replay_status") == "passed"
        )
    )
    observation_only = sorted(
        case_id for case_id, status in statuses.items() if status == "observation_only"
    )
    blocked = sorted(
        case_id
        for case_id, status in statuses.items()
        if status == "blocked_by_precondition"
    )
    evaluation_summary = evaluation.get("evaluation", {})
    metrics = evaluation_summary.get("metrics", {})
    target_integrity = run.get("target_integrity", {})
    result = {
        "schema_version": "juice_shop.baseline.analysis.v1",
        "run_id": run.get("run_id"),
        "target": run.get("target"),
        "detect": {
            "executed_case_count": len(run.get("executed_case_ids", [])),
            "proof_case_ids": proof_cases,
            "observation_only_case_ids": observation_only,
            "blocked_case_ids": blocked,
            "target_contacted": run.get("target_contacted") is True,
        },
        "diagnose": {
            "false_positive_case_ids": metrics.get("false_positive_case_ids", []),
            "false_negative_case_ids": metrics.get("false_negative_case_ids", []),
            "weak_confirmation_case_ids": weak_proof_cases,
            "not_scored_case_count": evaluation_summary.get("not_scored_expected_cases"),
            "root_cause": "causal_oracle_and_safe_precondition_coverage_gap",
        },
        "improve": {
            "code_change_required": bool(weak_proof_cases),
            "proposal_status": "contract_approval_required_for_unscored_cases",
            "generic_core_change": False,
            "target_scope": "juice_shop_local_only",
        },
        "retest": {
            "required": bool(weak_proof_cases),
            "performed": False,
            "reason": (
                "No FN/FP/weak confirmation was present; no improvement was "
                "applied or fabricated."
            ),
        },
        "compare": {
            "official_metrics": "withheld",
            "p10_qualified": False,
            "vip_qualified": False,
            "not_scored_is_not_fn": True,
        },
        "safety": {
            "raw_data_retained": run.get("raw_data_retained") is True,
            "raw_data_printed": run.get("raw_data_printed") is True,
            "target_unchanged_measured": target_integrity.get(
                "target_unchanged_measured"
            )
            is True,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["safety"]["raw_data_retained"] or result["safety"]["raw_data_printed"]:
        raise SystemExit("unsafe_raw_data_flag")
    if weak_proof_cases:
        raise SystemExit("weak_confirmation_requires_improvement")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
