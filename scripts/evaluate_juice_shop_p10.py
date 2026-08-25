"""Build a redacted P10 evaluation artifact from local proof summaries.

This script never stores or prints raw request/response data. It deliberately
leaves isolation and target-integrity fields false when the source run did not
record them, so the P10 gate remains fail-closed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from webpent.benchmark.p10 import P10GroundTruth, P10Run, evaluate_p10


def _ids(value: Any) -> frozenset[str]:
    if value is None or isinstance(value, (str, bytes)):
        return frozenset()
    try:
        values = value
        return frozenset(
            item for item in {str(item).strip() for item in values} if item
        )
    except TypeError:
        return frozenset()


def _last_summary(path: Path) -> dict[str, Any]:
    for line in reversed(path.read_text().splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and "operation" in value:
            return value
    raise ValueError(f"no redacted proof summary found in {path}")


def _run_from_summary(path: Path) -> tuple[P10Run, dict[str, Any]]:
    summary = _last_summary(path)
    observations = summary.get("observations")
    observations = observations if isinstance(observations, dict) else {}
    all_target_backed = all(
        isinstance(item, dict) and bool(item.get("target_backed"))
        for item in observations.values()
    )
    proof_ok = bool(
        summary.get("central_store_put")
        and summary.get("central_verify_seal")
        and summary.get("central_replay")
        and summary.get("proof_bundle_sealed")
        and summary.get("replay_status") == "passed"
    )
    run_id = str(summary.get("run_id") or path.stem)
    target_integrity = summary.get("target_integrity")
    target_integrity = target_integrity if isinstance(target_integrity, dict) else {}
    target_unchanged = bool(target_integrity.get("target_unchanged_measured"))
    workspace_id = str(summary.get("workspace_id") or "")
    artifact_namespace = str(summary.get("artifact_namespace") or "")
    candidate_case_ids = _ids(summary.get("candidate_case_ids"))
    proof_case_ids = _ids(summary.get("proof_case_ids"))
    replay_case_ids = _ids(summary.get("replay_case_ids"))
    mapped_case_ids = _ids(summary.get("mapped_case_ids"))
    mapping_status = str(summary.get("mapping_status") or "not_claimed_by_source_run")
    safe_meta = {
        "run_id": run_id,
        "source_log_sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
        "operation": summary.get("operation"),
        "workflow_id": summary.get("workflow_id"),
        "target_ref": summary.get("target"),
        "target_contacted": bool(summary.get("target_contacted")),
        "proof_summary_present": proof_ok,
        "all_observations_target_backed": all_target_backed,
        "mapped_case_ids": sorted(mapped_case_ids),
        "candidate_case_ids": sorted(candidate_case_ids),
        "proof_case_ids": sorted(proof_case_ids),
        "replay_case_ids": sorted(replay_case_ids),
        "mapping_status": mapping_status,
        "workspace_id": workspace_id,
        "artifact_namespace": artifact_namespace,
        "workspace_recorded": bool(summary.get("workspace_recorded")) and bool(workspace_id),
        "artifact_namespace_recorded": bool(summary.get("artifact_namespace_recorded"))
        and bool(artifact_namespace),
        "target_unchanged_measured": target_unchanged,
    }
    run = P10Run(
        run_id=run_id,
        workspace_id=workspace_id if safe_meta["workspace_recorded"] else "",
        artifact_namespace=(
            artifact_namespace if safe_meta["artifact_namespace_recorded"] else ""
        ),
        target_ref=str(summary.get("target") or ""),
        candidate_case_ids=candidate_case_ids,
        proof_case_ids=proof_case_ids,
        replay_case_ids=replay_case_ids,
        target_unchanged=target_unchanged,
        findings_are_live=(
            bool(summary.get("target_contacted"))
            and all_target_backed
            and proof_ok
            and target_unchanged
        ),
    )
    return run, safe_meta


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("logs", nargs="+", type=Path)
    args = parser.parse_args()

    ground_truth_doc = json.loads(args.ground_truth.read_text())
    ground_truth = [
        P10GroundTruth.from_mapping(case)
        for case in ground_truth_doc.get("cases", [])
    ]
    runs = []
    run_metadata = []
    for path in args.logs:
        run, metadata = _run_from_summary(path)
        runs.append(run)
        run_metadata.append(metadata)

    evaluation = evaluate_p10(
        ground_truth,
        runs,
        minimum_approved_cases=int(
            ground_truth_doc.get("acceptance", {}).get("minimum_approved_cases", 10)
        ),
        minimum_approved_classes=int(
            ground_truth_doc.get("acceptance", {}).get("minimum_approved_classes", 6)
        ),
        minimum_runs=int(
            ground_truth_doc.get("acceptance", {}).get("minimum_runs", 3)
        ),
    )
    output = {
        "schema_version": "p10.juice_shop.evaluation.v1",
        "target": ground_truth_doc.get("target"),
        "ground_truth": {
            "path": str(args.ground_truth),
            "status": ground_truth_doc.get("status"),
            "independent_review_approved": bool(
                ground_truth_doc.get("independence", {}).get("reviewer_approval")
            ),
        },
        "run_metadata": run_metadata,
        "evaluation": evaluation,
        "raw_data_retained": False,
        "raw_data_printed": False,
    }
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "output": str(args.output),
        "p10_passed": evaluation["p10_passed"],
        "run_count": evaluation["run_count"],
        "blocking_reasons": evaluation["blocking_reasons"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
