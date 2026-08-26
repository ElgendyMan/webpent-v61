"""Fail-closed validation for the Juice Shop governance packet.

The validator checks provenance and drift evidence. It never upgrades a case,
changes frozen ground truth, or authorizes an official P10 run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from webpent.adapters.juice_shop.oracles import JUICE_ORACLE_CONTRACTS
from webpent.profiles.juice_shop.cases import JUICE_SHOP_SAFE_CASES

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_CANONICAL_MAPPING = (
    "sha256:602b2411df9b259911b1ae0757e5e26fabdc86b928fb5b43b040750182762ad5"
)
EXPECTED_CANONICAL_ORACLE = (
    "sha256:63977f8451f0709abff5671d1ac24943abe35b0bb0a4f399791e2c1f66aeb71c"
)
EXPECTED_PREVIOUS_ORACLE_REVIEW = (
    "sha256:d16e139eebcbe7e88f62058e22aa4ffa31ed96a5af8c5187cc29937304902dee"
)
EXPECTED_ORACLE_DECISION = (
    "sha256:637b1f7e10e4224d60e3bcf29abdcaadb2e87aa66ed03d776668b94f1454a97c"
)
EXPECTED_DISPOSITIONS = {
    "juice.access_log_disclosure.v1": "implemented_pending_governance_confirmation",
    "juice.directory_listing.v1": "blocked",
    "juice.forgotten_backup.v1": "blocked",
    "juice.misplaced_signature_file.v1": "blocked",
    "juice.privacy_policy_proof.v1": "out_of_scope",
    "juice.public_scoreboard_route.v1": "out_of_scope",
    "juice.security_policy.v1": "out_of_scope",
    "juice.well_known_security_policy.v1": "out_of_scope",
}
EXPECTED_APPROVED_ORACLE_CASES = {
    "juice.error_handling.v1",
    "juice.exposed_metrics.v1",
    "juice.local_xss.v1",
}


def file_hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_hash(value: object) -> str:
    data = json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"json_object_required:{path}")
    return value


def validate(packet_path: Path) -> list[str]:
    errors: list[str] = []
    packet = load(packet_path)
    gt_path = PROJECT_ROOT / "docs/juice_shop_p10_ground_truth_v1.json"
    oracle_path = PROJECT_ROOT / "docs/p10_oracle_semantics_decision_v1.json"
    source_manifest_path = PROJECT_ROOT / "docs/juice_shop_source_ground_truth_manifest_v1.json"
    runtime_manifest_path = PROJECT_ROOT / "docs/juice_shop_loopback_runtime_manifest_v1.json"
    gt = load(gt_path)
    oracle_decision = load(oracle_path)
    source_manifest = load(source_manifest_path)
    runtime_manifest = load(runtime_manifest_path)

    authority = packet.get("decision_authority", {})
    if authority.get("status") != "pending_independent_governance_signoff":
        errors.append("governance_status_must_remain_pending")
    if authority.get("independent_reviewer_id") is not None:
        errors.append("reviewer_must_not_be_fabricated")
    if authority.get("results_seen_by_reviewer") is not False:
        errors.append("results_seen_by_reviewer_must_be_false_before_signoff")
    if authority.get("self_approval_not_claimed") is not True:
        errors.append("self_approval_marker_missing")

    dispositions = packet.get("case_dispositions", {})
    if set(dispositions) != set(EXPECTED_DISPOSITIONS):
        errors.append("engineering_non_scoring_dispositions_set_mismatch")
    for case_id, expected in EXPECTED_DISPOSITIONS.items():
        if not isinstance(dispositions.get(case_id), dict):
            errors.append(f"case_disposition_missing:{case_id}")
        elif dispositions[case_id].get("disposition") != expected:
            errors.append(f"case_disposition_mismatch:{case_id}")
    if len(dispositions) != 8:
        errors.append("engineering_non_scoring_review_count_must_be_eight")

    final_set = packet.get("final_approved_scoring_case_set", {})
    final_ids = set(final_set.get("case_ids", []))
    if final_ids != EXPECTED_APPROVED_ORACLE_CASES:
        errors.append("final_approved_oracle_case_set_mismatch")
    if final_set.get("case_count") != 3 or final_set.get("class_count") != 3:
        errors.append("final_proposed_set_count_mismatch")
    if "juice.access_log_disclosure.v1" in final_ids:
        errors.append("access_log_cannot_enter_scoring_without_signoff")
    if packet.get("run_gate", {}).get("official_isolated_p10_runs_authorized") is not False:
        errors.append("official_p10_runs_must_remain_unauthorized")
    if packet.get("qualification", {}).get("p10") != "NOT_QUALIFIED":
        errors.append("p10_must_remain_not_qualified")
    if packet.get("qualification", {}).get("p9") != "NOT_QUALIFIED":
        errors.append("p9_must_remain_not_qualified")
    if packet.get("qualification", {}).get("vip") != "NOT_QUALIFIED":
        errors.append("vip_must_remain_not_qualified")

    lock = packet.get("hash_lock", {})
    if lock.get("mapping_hash") != EXPECTED_CANONICAL_MAPPING:
        errors.append("canonical_mapping_hash_changed")
    if lock.get("oracle_mapping_hash") != EXPECTED_CANONICAL_ORACLE:
        errors.append("canonical_oracle_mapping_hash_changed")
    if (
        lock.get("previous_independent_reviewed_oracle_contract_sha256")
        != EXPECTED_PREVIOUS_ORACLE_REVIEW
    ):
        errors.append("previous_oracle_review_hash_not_preserved")
    if lock.get("oracle_decision_hash") != EXPECTED_ORACLE_DECISION:
        errors.append("oracle_decision_hash_mismatch")
    if lock.get("ground_truth_document_sha256") != file_hash(gt_path):
        errors.append("ground_truth_document_hash_mismatch")
    if lock.get("source_ground_truth_manifest_sha256") != file_hash(source_manifest_path):
        errors.append("source_ground_truth_manifest_hash_mismatch")
    if lock.get("loopback_runtime_manifest_sha256") != file_hash(runtime_manifest_path):
        errors.append("loopback_runtime_manifest_hash_mismatch")

    source_cases = [asdict(case) for case in JUICE_SHOP_SAFE_CASES]
    current_mapping = canonical_hash(source_cases)
    current_oracle = canonical_hash(
        [asdict(JUICE_ORACLE_CONTRACTS[key]) for key in sorted(JUICE_ORACLE_CONTRACTS)]
    )
    if lock.get("current_source_mapping_sha256") != current_mapping:
        errors.append("current_source_mapping_hash_mismatch")
    if lock.get("current_source_oracle_contract_sha256") != current_oracle:
        errors.append("current_source_oracle_hash_mismatch")
    if source_manifest.get("source_registry", {}).get("mapping_sha256") != current_mapping:
        errors.append("source_manifest_mapping_hash_mismatch")
    if source_manifest.get("source_registry", {}).get("oracle_contract_sha256") != current_oracle:
        errors.append("source_manifest_oracle_hash_mismatch")

    gt_access = next(
        (
            c
            for c in gt.get("cases", [])
            if c.get("case_id") == "juice.access_log_disclosure.v1"
        ),
        {},
    )
    source_access = next(
        (
            c
            for c in source_cases
            if c.get("case_id") == "juice.access_log_disclosure.v1"
        ),
        {},
    )
    if source_access.get("path") == gt_access.get("path"):
        errors.append("access_log_drift_must_remain_explicit")
    drift = packet.get("drift_reconciliation", {})
    if drift.get("engineering_reviewed_non_scoring_case_count") != 8:
        errors.append("engineering_non_scoring_count_must_be_eight")
    if drift.get("synthetic_unit_test_not_scored_expected_case_count") != 7:
        errors.append("synthetic_test_count_must_be_seven")
    if drift.get("juice_shop_authoritative_non_scoring_count") != 8:
        errors.append("juice_shop_authoritative_non_scoring_count_must_be_eight")

    if (
        source_manifest.get("provenance", {}).get("frozen_ground_truth_was_not_modified")
        is not True
    ):
        errors.append("frozen_ground_truth_modification_marker_missing")
    if (
        runtime_manifest.get("binding_verification", {}).get("observed_listener")
        != "127.0.0.1:3000"
    ):
        errors.append("loopback_binding_not_verified")
    if (
        runtime_manifest.get("binding_verification", {}).get("wildcard_listener_absent")
        is not True
    ):
        errors.append("wildcard_listener_not_absent")
    if (
        runtime_manifest.get("governance", {}).get("official_isolated_p10_runs_authorized")
        is not False
    ):
        errors.append("runtime_manifest_cannot_authorize_p10")
    if (
        oracle_decision.get("reviewed_input_hashes", {}).get("oracle_contract")
        != EXPECTED_PREVIOUS_ORACLE_REVIEW
    ):
        errors.append("historical_oracle_decision_hash_provenance_changed")
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--packet",
        type=Path,
        default=PROJECT_ROOT / "docs/juice_shop_governance_decision_v1.json",
    )
    args = parser.parse_args()
    errors = validate(args.packet)
    result = {"passed": not errors, "errors": errors, "packet": str(args.packet)}
    print(json.dumps(result, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
