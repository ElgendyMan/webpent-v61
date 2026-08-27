"""Validate checked-in multi-target scoring-readiness packages without target I/O."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PACKAGE_GLOB = (
    "reports/evaluation/scoring_readiness/*-SCORING-READINESS-PACK-v1.json"
)
_SHA256 = re.compile(r"^(?:sha256:)?[0-9a-fA-F]{64}$")


def _mapping(value: Any, name: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{name}:mapping_required")
        return {}
    return value


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256.fullmatch(value.strip()))


def _loopback_origin(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlsplit(value)
    return (
        parsed.scheme in {"http", "https"}
        and parsed.hostname == "127.0.0.1"
        and not parsed.username
        and not parsed.password
    )


def _validate_scope(root: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    scope = _mapping(root.get("scope"), "scope", errors)
    if scope.get("mode") != "bounded_local_loopback":
        errors.append("scope:bounded_local_loopback_required")
    origin = scope.get("origin")
    if not _loopback_origin(origin):
        errors.append("scope:loopback_origin_required")
    if scope.get("methods") != ["GET"]:
        errors.append("scope:get_only_required")
    for field in (
        "credentials_used",
        "state_mutation",
        "external_contact",
        "oast_or_callbacks",
        "raw_bodies_headers_cookies_persistent",
    ):
        if scope.get(field) is not False:
            errors.append(f"scope:{field}_must_be_false")
    if scope.get("official_isolated_p10_runs_authorized") is not False:
        errors.append("scope:official_p10_gate_must_be_false")
    return scope


def _validate_target(
    root: dict[str, Any], scope: dict[str, Any], errors: list[str]
) -> dict[str, Any]:
    target = _mapping(root.get("target"), "target", errors)
    for field in ("target_id", "product", "source_path", "source_revision", "campaign_id"):
        if not _nonempty(target.get(field)):
            errors.append(f"target:{field}_required")
    revision = target.get("source_revision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        errors.append("target:source_revision_must_be_git_sha")
    spec = _mapping(target.get("target_spec"), "target.target_spec", errors)
    origins = spec.get("scope")
    if not isinstance(origins, list) or not origins:
        errors.append("target.target_spec:scope_required")
    elif any(not _loopback_origin(item) for item in origins):
        errors.append("target.target_spec:scope_must_be_loopback")
    if spec.get("method_policy") != ["GET"]:
        errors.append("target.target_spec:get_only_required")
    if not _nonempty(spec.get("authorization_ref")):
        errors.append("target.target_spec:authorization_ref_required")
    origin_parts = urlsplit(str(scope.get("origin") or ""))
    if origins and not any(
        urlsplit(str(item)).scheme == origin_parts.scheme
        and urlsplit(str(item)).hostname == origin_parts.hostname
        and urlsplit(str(item)).port == origin_parts.port
        for item in origins
    ):
        errors.append("target.target_spec:origin_scope_mismatch")
    return target


def _validate_case_contract(case: dict[str, Any], index: int, errors: list[str]) -> None:
    prefix = f"case_contracts[{index}]"
    for field in (
        "case_id",
        "class",
        "path",
        "method",
        "workflow_id",
        "causal_predicate",
        "safe_precondition",
        "independent_negative_control",
        "central_verifier_mapping",
        "proof_bundle_id",
        "baseline_evidence",
    ):
        if not _nonempty(case.get(field)):
            errors.append(f"{prefix}:{field}_required")
    for field in ("seal", "verify_seal", "replay"):
        if case.get(field) is not True:
            errors.append(f"{prefix}:{field}_required")
    if not case.get("causal_predicate") or any(
        forbidden in str(case["causal_predicate"]).lower()
        for forbidden in ("http 200 alone", "health response alone", "endpoint existence alone")
    ):
        errors.append(f"{prefix}:causal_predicate_must_be_semantic")
    if case.get("candidate_status") not in {"confirmed_proof", "ready_for_quality_run"}:
        errors.append(f"{prefix}:candidate_status_invalid")
    before_after = _mapping(case.get("before_after"), f"{prefix}.before_after", errors)
    for field in (
        "diagnosis",
        "improvement_proposal",
        "classification",
        "implementation",
        "regression",
        "same_condition_retest",
        "comparison",
    ):
        if not _nonempty(before_after.get(field)):
            errors.append(f"{prefix}.before_after:{field}_required")


def validate_package(package: dict[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if package.get("schema") != "webpent-target-scoring-readiness-pack-v1":
        errors.append("package:schema_invalid")
    if package.get("qualification_claim") is not None:
        errors.append("package:qualification_claim_must_be_null")
    scope = _validate_scope(package, errors)
    _validate_target(package, scope, errors)
    ground_truth = _mapping(package.get("ground_truth"), "ground_truth", errors)
    approved_ids = ground_truth.get("approved_case_ids")
    if not isinstance(approved_ids, list):
        errors.append("ground_truth:approved_case_ids_list_required")
        approved_ids = []
    if ground_truth.get("approved_case_count") != len(approved_ids):
        errors.append("ground_truth:approved_case_count_mismatch")
    if ground_truth.get("approved_class_count", 0) < 0:
        errors.append("ground_truth:approved_class_count_invalid")
    if ground_truth.get("not_scored_is_not_fn") is not True:
        errors.append("ground_truth:not_scored_is_not_fn_required")
    contracts = package.get("case_contracts")
    if not isinstance(contracts, list):
        errors.append("case_contracts:list_required")
        contracts = []
    contract_ids = [case.get("case_id") for case in contracts if isinstance(case, dict)]
    if sorted(contract_ids) != sorted(approved_ids):
        errors.append("case_contracts:ids_must_match_approved_case_ids")
    for index, case in enumerate(contracts):
        if not isinstance(case, dict):
            errors.append(f"case_contracts[{index}]:mapping_required")
            continue
        _validate_case_contract(case, index, errors)
    quality = _mapping(package.get("quality_baseline"), "quality_baseline", errors)
    if approved_ids:
        if quality.get("proof_backed_admitted_cases") != len(approved_ids):
            errors.append("quality_baseline:proof_case_count_mismatch")
        for field in (
            "official_precision",
            "official_recall",
            "official_case_coverage",
            "official_class_coverage",
        ):
            if quality.get(field) is not None:
                errors.append(f"quality_baseline:{field}_must_be_null_before_official_runs")
    else:
        if contracts:
            errors.append("quality_baseline:blocked_package_must_have_no_case_contracts")
        if quality.get("quality_metrics") is not None:
            errors.append("quality_baseline:blocked_package_metrics_must_be_null")
    procedure = _mapping(package.get("proof_procedure"), "proof_procedure", errors)
    required_sequence = procedure.get("sequence") or procedure.get("required_sequence")
    required = {
        "baseline",
        "candidate",
        "independent_negative_control",
        "central_verifier",
        "seal",
        "verify_seal",
        "replay",
    }
    if not isinstance(required_sequence, list) or not required.issubset(required_sequence):
        errors.append("proof_procedure:complete_sequence_required")
    blockers = package.get("governance_blockers")
    if not isinstance(blockers, list):
        errors.append("governance_blockers:list_required")
    elif "official_isolated_p10_runs_authorized=false" not in blockers:
        errors.append("governance_blockers:official_p10_gate_blocker_required")
    if package.get("readiness_status") == "blocked_no_admitted_scoring_cases" and approved_ids:
        errors.append("package:blocked_status_conflicts_with_approved_cases")
    return tuple(errors)


def validate_file(path: Path) -> dict[str, Any]:
    try:
        package = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"path": str(path), "passed": False, "errors": [f"read_failed:{exc}"]}
    errors = validate_package(package)
    return {"path": str(path), "passed": not errors, "errors": list(errors)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packages", nargs="*", type=Path)
    args = parser.parse_args()
    paths = args.packages or sorted(PROJECT_ROOT.glob(DEFAULT_PACKAGE_GLOB))
    results = [validate_file(path) for path in paths]
    result = {
        "passed": bool(results) and all(item["passed"] for item in results),
        "packages": results,
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
