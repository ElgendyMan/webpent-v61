"""Build a redacted source-to-frozen-ground-truth drift manifest.

This is governance evidence, not an approval record and not a vulnerability verdict.
It intentionally preserves mismatches instead of rewriting the frozen ground truth.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webpent.adapters.juice_shop.oracles import JUICE_ORACLE_CONTRACTS
from webpent.profiles.juice_shop.cases import JUICE_SHOP_SAFE_CASES

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FROZEN_GT = PROJECT_ROOT / "docs" / "juice_shop_p10_ground_truth_v1.json"


def digest(value: object) -> str:
    serialized = json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(serialized).hexdigest()


def file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def git_value(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "docs" / "juice_shop_source_ground_truth_manifest_v1.json",
    )
    parser.add_argument("--snapshot", type=Path)
    args = parser.parse_args()

    ground_truth = json.loads(FROZEN_GT.read_text(encoding="utf-8"))
    source_cases = [asdict(case) for case in JUICE_SHOP_SAFE_CASES]
    source_by_id = {case["case_id"]: case for case in source_cases}
    gt_cases = ground_truth["cases"]
    gt_by_id = {case["case_id"]: case for case in gt_cases}

    access_source = source_by_id["juice.access_log_disclosure.v1"]
    access_gt = gt_by_id["juice.access_log_disclosure.v1"]
    mapping_approved = {
        case["case_id"]
        for case in gt_cases
        if case.get("mapping_status") == "approved"
    }
    oracle_approved = {
        case["case_id"]
        for case in gt_cases
        if case.get("oracle_status") == "approved_oracle_pending_full_set_metrics"
    }
    actual_unscored = sorted(mapping_approved - oracle_approved)
    engineering_reviewed_non_scoring = [
        "juice.access_log_disclosure.v1",
        "juice.directory_listing.v1",
        "juice.forgotten_backup.v1",
        "juice.misplaced_signature_file.v1",
        "juice.privacy_policy_proof.v1",
        "juice.public_scoreboard_route.v1",
        "juice.security_policy.v1",
        "juice.well_known_security_policy.v1",
    ]
    synthetic_unit_test_not_scored = 7

    document: dict[str, Any] = {
        "schema_version": "juice_shop.source_to_ground_truth_manifest.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "provenance": {
            "webpent_git_commit": git_value("rev-parse", "HEAD"),
            "webpent_git_tree": git_value("rev-parse", "HEAD^{tree}"),
            "source_registry_module": "src/webpent/profiles/juice_shop/cases.py",
            "oracle_registry_module": "src/webpent/adapters/juice_shop/oracles.py",
            "frozen_ground_truth_file": "docs/juice_shop_p10_ground_truth_v1.json",
            "frozen_ground_truth_sha256": file_digest(FROZEN_GT),
            "frozen_ground_truth_was_not_modified": True,
        },
        "source_registry": {
            "case_count": len(source_cases),
            "safe_case_count": sum(bool(case["safe_to_execute"]) for case in source_cases),
            "mapping_sha256": digest(source_cases),
            "oracle_contract_sha256": digest(
                [asdict(JUICE_ORACLE_CONTRACTS[key]) for key in sorted(JUICE_ORACLE_CONTRACTS)]
            ),
            "case_ids": sorted(source_by_id),
        },
        "frozen_ground_truth": {
            "case_count": len(gt_cases),
            "mapping_approved_case_count": len(mapping_approved),
            "oracle_approved_case_count": len(oracle_approved),
            "canonical_mapping_hash": ground_truth["independence"]["mapping_review"][
                "mapping_hash"
            ],
            "canonical_oracle_mapping_hash": ground_truth["independence"]["mapping_review"][
                "oracle_contract_hash"
            ],
            "case_ids": sorted(gt_by_id),
        },
        "case_set_diff": {
            "source_only_case_ids": sorted(set(source_by_id) - set(gt_by_id)),
            "ground_truth_only_case_ids": sorted(set(gt_by_id) - set(source_by_id)),
            "source_and_ground_truth_ids_match": set(source_by_id) == set(gt_by_id),
        },
        "access_log_mapping_drift": {
            "status": "mismatch_explicitly_preserved_for_independent_review",
            "source_current_path": access_source["path"],
            "frozen_ground_truth_path": access_gt["path"],
            "paths_match": access_source["path"] == access_gt["path"],
            "source_semantics": "UTC-date-rotated /support/logs/access.log.<date>",
            "frozen_semantics": "legacy /ftp/access.log mapping",
            "required_action": (
                "Independent reviewer must decide whether to revise the frozen mapping "
                "in a separately governed change; this manifest does not revise it."
            ),
        },
        "non_scoring_count_resolution": {
            "engineering_reviewed_non_scoring_case_count": len(engineering_reviewed_non_scoring),
            "engineering_reviewed_non_scoring_case_ids": engineering_reviewed_non_scoring,
            "mapping_approved_but_oracle_unapproved_case_count": len(actual_unscored),
            "mapping_approved_but_oracle_unapproved_case_ids": actual_unscored,
            "synthetic_unit_test_not_scored_expected_case_count": synthetic_unit_test_not_scored,
            "synthetic_unit_test_scope": (
                "tests/test_p10_benchmark.py fixture with 10 truth cases and "
                "3 oracle-approved cases; not the Juice Shop production inventory"
            ),
            "resolution": (
                "The authoritative Juice Shop governance count is 8. The value 7 is "
                "test-fixture-derived and must not be presented as the Juice Shop case count."
            ),
            "blocked_and_out_of_scope_are_not_fn": True,
        },
        "oracle_hash_provenance": {
            "current_source_oracle_contract_sha256": digest(
                [asdict(JUICE_ORACLE_CONTRACTS[key]) for key in sorted(JUICE_ORACLE_CONTRACTS)]
            ),
            "previous_independent_reviewed_oracle_contract_sha256": (
                "sha256:d16e139eebcbe7e88f62058e22aa4ffa31ed96a5af8c5187cc29937304902dee"
            ),
            "previous_hash_is_not_represented_as_current": True,
            "independent_reconfirmation_required": True,
        },
        "safety": {
            "target_origin": "http://127.0.0.1:3000",
            "raw_http_data_retained": False,
            "official_isolated_p10_runs_authorized": False,
            "qualification_claim": "none",
        },
    }
    if args.snapshot:
        snapshot_path = args.snapshot.resolve()
        if not snapshot_path.is_file():
            raise FileNotFoundError(snapshot_path)
        try:
            snapshot_name = str(snapshot_path.relative_to(PROJECT_ROOT))
        except ValueError as exc:
            raise ValueError("snapshot_must_be_inside_project_root") from exc
        document["snapshot_input"] = {
            "path": snapshot_name,
            "sha256": file_digest(snapshot_path),
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "mapping_sha256": document["source_registry"]["mapping_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


def _compatibility_anchor() -> None:
    """Keep module-level definitions discoverable by static tooling."""
    return None
