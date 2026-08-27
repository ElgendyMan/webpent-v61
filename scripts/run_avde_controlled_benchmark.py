"""Evaluate AVDE from an existing recorded controlled artifact.

The runner is intentionally offline. It never creates observations, proof
bundles, findings, or requests. Unknown/blocked cases are excluded from
controlled scoring and remain visible in the output.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.avde_multiclass_controlled import (
    CANONICAL_CLASSES,
    build_class_inventory,
    canonical_class,
    compute_internal_metrics,
)


def load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict) or not isinstance(value.get("evaluation"), dict):
        raise ValueError("recorded_benchmark_evaluation_required")
    return value


def _strict_recorded_case(case: dict[str, Any]) -> bool:
    return (
        case.get("validation_outcome") == "confirmed"
        and case.get("ground_truth_outcome") == "confirmed"
        and case.get("proof_complete") is True
        and bool(case.get("ground_truth_source"))
    )


def evaluate(source: dict[str, Any]) -> dict[str, Any]:
    evaluation = source["evaluation"]
    cases = evaluation.get("cases", [])
    if not isinstance(cases, list):
        raise ValueError("recorded_cases_list_required")
    mapping_cases = [case for case in cases if isinstance(case, dict)]
    scorable = [case for case in mapping_cases if _strict_recorded_case(case)]
    blocked = [
        case
        for case in mapping_cases
        if case.get("validation_outcome") in {"blocked", "inconclusive", "observation_only"}
    ]
    out_of_scope = [
        case for case in mapping_cases if case.get("validation_outcome") == "out_of_scope"
    ]
    duplicate_ids = len({case.get("case_id") for case in mapping_cases}) != len(mapping_cases)
    unique_targets = sorted(
        {str(case.get("target_id")) for case in mapping_cases if case.get("target_id")}
    )
    raw_classes = sorted(
        {
            str(case.get("vulnerability_class"))
            for case in scorable
            if case.get("vulnerability_class")
        }
    )
    classes = sorted({canonical_class(item) for item in raw_classes})
    requests_used = sum(int(case.get("requests_used", 0)) for case in scorable)
    evidence_quality = (
        sum(float(case.get("evidence_quality", 0.0)) for case in scorable) / len(scorable)
        if scorable
        else 0.0
    )
    proof_completeness = (
        sum(bool(case.get("proof_complete")) for case in scorable) / len(scorable)
        if scorable
        else 0.0
    )
    average_rank = (
        sum(int(case.get("rank", 0)) for case in scorable) / len(scorable) if scorable else None
    )
    inventory = build_class_inventory(mapping_cases)
    internal_metrics = compute_internal_metrics(mapping_cases, inventory)
    return {
        "schema_version": "avde-controlled-benchmark-v2",
        "source_schema_version": source.get("schema_version"),
        "benchmark_scope": {
            "mode": "offline_replay_of_recorded_controlled_campaign",
            "requests_sent_by_this_runner": 0,
            "external_network": False,
            "credentials": False,
            "state_mutation": False,
            "network_scope": "loopback_only",
            "target_ids": unique_targets,
        },
        "registered_vulnerability_classes": list(CANONICAL_CLASSES),
        "class_inventory": list(inventory),
        "metrics": {
            "recorded_case_count": len(mapping_cases),
            "source_reported_metrics": evaluation.get("evidence_quality"),
            "raw_scorable_classes": raw_classes,
            "scorable_classes": classes,
            "scorable_case_count": len(scorable),
            "blocked_or_inconclusive_case_count": len(blocked),
            "out_of_scope_case_count": len(out_of_scope),
            "scorable_class_count": len(classes),
            "required_class_count": len(CANONICAL_CLASSES),
            "missing_required_classes": sorted(set(CANONICAL_CLASSES) - set(classes)),
            "proof_bundle_quality": evidence_quality,
            "proof_completeness": proof_completeness,
            "average_selected_rank": average_rank,
            "requests_used_for_scorable_cases": requests_used,
            "duplicate_case_ids_detected": duplicate_ids,
            **internal_metrics,
        },
        "case_disposition": {
            "scorable_case_ids": [case.get("case_id") for case in scorable],
            "blocked_case_ids": [case.get("case_id") for case in blocked],
            "out_of_scope_case_ids": [case.get("case_id") for case in out_of_scope],
            "blocked_excluded_from_tp_fp_fn": True,
            "out_of_scope_excluded_from_tp_fp_fn": True,
            "synthetic_observations_created": False,
            "synthetic_proof_bundles_created": False,
        },
        "claims": {
            "controlled_research_quality_metrics_only": True,
            "production_precision_recall_calculated": False,
            "real_world_detection_rate_measured": False,
            "qualification_claim": False,
        },
        "governance": {
            "qualification_effect": False,
            "official_isolated_p10_runs_authorized": False,
            "p10_status": "NOT_QUALIFIED",
            "p9_status": "NOT_QUALIFIED",
            "vip_status": "NOT_QUALIFIED",
            "bug_bounty_status": "BLOCKED",
            "human_signoff": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(load(args.source))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["metrics"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
