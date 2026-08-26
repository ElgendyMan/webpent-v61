"""Fail-closed validation for target-adapter review packets.

The validator checks governance metadata only.  It never performs target I/O,
creates evidence, or promotes a finding.  Target-specific selectors and
executors remain outside this module.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

_PACKET_STATUSES = {
    "draft",
    "pending",
    "mapping_approved",
    "qualified_for_runs",
    "approved",
    "rejected",
}
_DECISIONS = {"pending", "approved", "rejected"}
_CASE_STATUSES = {"pending", "approved", "out_of_scope", "rejected"}
_OPERATIONS = {"navigate", "typed_search"}
_REQUIRED_FORBIDDEN_OPERATIONS = {
    "credential_creation",
    "credential_recovery",
    "otp_or_mfa_bypass",
    "captcha_bypass",
    "ssrf_or_oast",
    "raw_request_or_response_retention",
    "raw_cookie_or_token_retention",
}
_HEX_HASH_LENGTH = 64


def _mapping(value: Any, name: str, errors: list[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        errors.append(f"{name}:mapping_required")
        return {}
    return value


def _sequence(value: Any, name: str, errors: list[str]) -> Sequence[Any]:
    if not isinstance(value, (list, tuple)):
        errors.append(f"{name}:list_required")
        return ()
    return value


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _sha256(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip().lower()
    if normalized.startswith("sha256:"):
        normalized = normalized[7:]
    return len(normalized) == _HEX_HASH_LENGTH and all(
        character in "0123456789abcdef" for character in normalized
    )


def validate_target_adapter_review_packet(packet: Mapping[str, Any]) -> tuple[str, ...]:
    """Return deterministic validation errors for one review packet.

    ``draft`` packets may contain the empty placeholder rows from the checked-in
    template.  Every later lifecycle state must contain concrete identities,
    workflow mappings, case dispositions, and the reviewer material required by
    its state.  No lifecycle state can assert a qualification claim or carry
    live metrics through this contract.
    """
    errors: list[str] = []
    root = _mapping(packet, "packet", errors)
    if root.get("schema") != "webpent.target_adapter_review_packet.v1":
        errors.append("packet:schema_invalid")
    status = root.get("packet_status")
    if status not in _PACKET_STATUSES:
        errors.append("packet:status_invalid")
    if root.get("qualification_claim") is not False:
        errors.append("packet:qualification_claim_must_be_false")

    _mapping(root.get("target"), "target", errors)
    policy = _mapping(root.get("policy"), "policy", errors)
    workflows_raw = _sequence(root.get("workflows"), "workflows", errors)
    cases_raw = _sequence(root.get("cases"), "cases", errors)
    review = _mapping(root.get("review"), "review", errors)
    live_runs = _mapping(root.get("live_runs"), "live_runs", errors)

    if policy.get("raw_evidence_retained") is not False:
        errors.append("policy:raw_evidence_retained_must_be_false")
    forbidden = policy.get("forbidden_operations")
    if not isinstance(forbidden, (list, tuple)):
        errors.append("policy:forbidden_operations_list_required")
    elif not _REQUIRED_FORBIDDEN_OPERATIONS.issubset(set(forbidden)):
        errors.append("policy:required_forbidden_operation_missing")

    workflow_ids: list[str] = []
    workflow_operations: dict[str, str] = {}
    for index, raw_workflow in enumerate(workflows_raw):
        workflow = _mapping(raw_workflow, f"workflows[{index}]", errors)
        workflow_id = str(workflow.get("workflow_id") or "").strip()
        operation = str(workflow.get("operation") or "").strip()
        if not workflow_id:
            if status != "draft":
                errors.append(f"workflows[{index}]:workflow_id_required")
            continue
        if workflow_id in workflow_ids:
            errors.append(f"workflows[{index}]:duplicate_workflow_id")
        workflow_ids.append(workflow_id)
        if operation not in _OPERATIONS:
            errors.append(f"workflows[{index}]:operation_invalid")
        else:
            workflow_operations[workflow_id] = operation
        if status != "draft":
            if workflow.get("reviewed") is not True:
                errors.append(f"workflows[{index}]:review_required")
            if workflow.get("allowlisted") is not True:
                errors.append(f"workflows[{index}]:allowlist_required")
            if workflow.get("executor_is_target_local") is not True:
                errors.append(f"workflows[{index}]:target_local_executor_required")
            if operation == "typed_search":
                if workflow.get("executor_required") is not True:
                    errors.append(f"workflows[{index}]:typed_executor_required")
                if workflow.get("executor_callable") is not True:
                    errors.append(f"workflows[{index}]:typed_executor_callable_required")

    case_ids: list[str] = []
    for index, raw_case in enumerate(cases_raw):
        case = _mapping(raw_case, f"cases[{index}]", errors)
        case_id = str(case.get("case_id") or "").strip()
        if not case_id:
            if status != "draft":
                errors.append(f"cases[{index}]:case_id_required")
            continue
        if case_id in case_ids:
            errors.append(f"cases[{index}]:duplicate_case_id")
        case_ids.append(case_id)
        operation = str(case.get("operation") or "").strip()
        workflow_id = str(case.get("workflow_id") or "").strip()
        if operation not in _OPERATIONS:
            errors.append(f"cases[{index}]:operation_invalid")
        if workflow_id not in workflow_ids:
            errors.append(f"cases[{index}]:workflow_not_declared")
        elif workflow_operations.get(workflow_id) != operation:
            errors.append(f"cases[{index}]:workflow_operation_mismatch")
        for field in ("path", "oracle_id"):
            if not _nonempty(case.get(field)):
                errors.append(f"cases[{index}]:{field}_required")
        if operation == "typed_search" and not _nonempty(case.get("semantic_profile")):
            errors.append(f"cases[{index}]:semantic_profile_required")
        case_status = case.get("mapping_status")
        if case_status not in _CASE_STATUSES:
            errors.append(f"cases[{index}]:mapping_status_invalid")
        causal = _mapping(
            case.get("causal_signal_contract"),
            f"cases[{index}].causal_signal_contract",
            errors,
        )
        negative = _mapping(
            case.get("negative_control_contract"),
            f"cases[{index}].negative_control_contract",
            errors,
        )
        if status != "draft":
            if causal.get("defined") is not True or causal.get("target_backed") is not True:
                errors.append(f"cases[{index}]:target_backed_causal_contract_required")
            if causal.get("observation_only") is True:
                errors.append(f"cases[{index}]:causal_contract_observation_only")
            if negative.get("defined") is not True or negative.get("independent") is not True:
                errors.append(f"cases[{index}]:independent_negative_control_required")

    decision = review.get("approval_decision")
    if decision not in _DECISIONS:
        errors.append("review:approval_decision_invalid")
    if status in {"mapping_approved", "qualified_for_runs", "approved"}:
        if decision == "pending":
            errors.append("review:decision_pending_for_closed_status")
        for field in (
            "reviewer_id",
            "reviewed_at_utc",
            "reviewed_mapping_sha256",
            "reviewed_oracle_contract_sha256",
        ):
            if not _nonempty(review.get(field)):
                errors.append(f"review:{field}_required")
        for field in ("reviewed_mapping_sha256", "reviewed_oracle_contract_sha256"):
            if review.get(field) and not _sha256(review.get(field)):
                errors.append(f"review:{field}_invalid")
    if decision == "approved" and review.get("results_seen_by_reviewer") is not True:
        errors.append("review:results_must_be_seen_for_final_approval")

    disposition_sets: dict[str, set[str]] = {}
    for field in ("approved_case_ids", "out_of_scope_case_ids", "rejected_case_ids"):
        values = review.get(field)
        if not isinstance(values, (list, tuple)):
            errors.append(f"review:{field}_list_required")
            disposition_sets[field] = set()
        else:
            disposition_sets[field] = {str(value).strip() for value in values if str(value).strip()}
    if len(set().union(*disposition_sets.values())) != sum(
        len(values) for values in disposition_sets.values()
    ):
        errors.append("review:case_dispositions_overlap")
    if status in {"mapping_approved", "qualified_for_runs", "approved", "rejected"}:
        assigned = set().union(*disposition_sets.values())
        if assigned != set(case_ids):
            errors.append("review:case_dispositions_must_cover_all_cases")

    if live_runs.get("qualification_status") != "not_qualified":
        errors.append("live_runs:qualification_status_must_remain_not_qualified")
    if live_runs.get("metrics") is not None:
        errors.append("live_runs:metrics_must_remain_null")
    if (
        live_runs.get("authorized") is not False
        and status not in {"qualified_for_runs", "approved"}
    ):
        errors.append("live_runs:authorization_invalid_for_packet_status")

    return tuple(sorted(set(errors)))
