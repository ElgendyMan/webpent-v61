#!/usr/bin/env python3
"""Fail-closed validator for the target-live fixture/session injection packet."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parents[1] / (
    "reports/evaluation/owner_decision/"
    "TARGET-LIVE-FIXTURE-SESSION-INJECTION-OWNER-DECISION-PACKET-v1.json"
)

FORBIDDEN_TERMS = (
    "real credentials",
    "HTTP login",
    "token generation",
    "auth bypass",
    "application POST",
    "state-changing target request",
    "application reset",
    "external targets",
    "OAST",
    "Official P10",
)

EXPECTED_CASE_IDS = {
    "webgoat.idor.view_other_profile.v1",
    "webgoat.path_traversal.v1",
    "crapi.profile_video_object_access.v1",
    "crapi.vehicle_location_bola.v1",
    "crapi.community_post_object_access.v1",
    "crapi.mechanic_report_object_access.v1",
}


def validate(packet: dict) -> list[str]:
    errors: list[str] = []
    if packet.get("status") != "PENDING_OWNER_APPROVAL":
        errors.append("packet_must_remain_pending_owner_approval")
    decision = packet.get("decision_requested", {})
    if decision.get("no_execution_before_approval") is not True:
        errors.append("no_execution_before_approval_required")
    if decision.get("silence_is_not_approval") is not True:
        errors.append("silence_is_not_approval_required")

    governance = packet.get("current_governance_state", {})
    for key, expected in {
        "official_isolated_p10_runs_authorized": False,
        "human_independent_signoff_obtained": False,
        "scoring_promotion": False,
    }.items():
        if governance.get(key) is not expected:
            errors.append(f"governance_{key}_must_remain_{expected}")
    if governance.get("bug_bounty") != "BLOCKED":
        errors.append("bug_bounty_must_remain_blocked")
    if governance.get("option_b_status") != "LAB_NOT_READY / PRECONDITION_BLOCKED":
        errors.append("option_b_status_must_remain_lab_not_ready")

    runtime = packet.get("observed_provenance", {})
    webgoat = runtime.get("webgoat", {})
    if webgoat.get("service_alignment_status") != "not_attested":
        errors.append("webgoat_alignment_must_remain_not_attested")
    artifact_digest = webgoat.get("build_artifact_sha256")
    if not isinstance(artifact_digest, str) or len(artifact_digest) != 64:
        errors.append("webgoat_artifact_digest_invalid")
    crapi = runtime.get("crapi", {})
    images = crapi.get("runtime_images", [])
    if len(images) != 6:
        errors.append("crapi_six_runtime_images_required")
    for item in images:
        digest = item.get("repo_digest", "")
        if not digest.startswith("sha256:") or len(digest) != 71:
            errors.append("crapi_repo_digest_invalid")
    if crapi.get("service_alignment_status") != "not_attested_for_active_containers":
        errors.append("crapi_active_alignment_must_remain_not_attested")

    required = packet.get("required_readiness_flags", {})
    if required.get("target_live_preconditions_ready") is not False:
        errors.append("target_live_readiness_must_remain_false_until_approval")
    for key in (
        "preconditions_ready",
        "fixture_ready",
        "identity_model_ready",
        "reset_verified",
        "runtime_digest_verified",
        "network_scope_verified",
    ):
        if required.get(key) is not True:
            errors.append(f"offline_readiness_{key}_must_be_true")

    gate = packet.get("execution_gate", {})
    if gate.get("status") != "CLOSED":
        errors.append("execution_gate_must_be_closed")
    for key in (
        "requires_owner_approval_for_this_packet",
        "requires_fresh_runtime_attestation",
        "requires_all_readiness_flags_true",
    ):
        if gate.get(key) is not True:
            errors.append(f"execution_gate_{key}_required")
    for key in (
        "candidate_control_requests_allowed_now",
        "proof_bundle_allowed_now",
        "metrics_allowed_now",
    ):
        if gate.get(key) is not False:
            errors.append(f"execution_gate_{key}_must_be_false")

    text = json.dumps(packet, sort_keys=True).casefold()
    for term in FORBIDDEN_TERMS:
        if term.casefold() not in text:
            errors.append(f"required_boundary_term_missing:{term}")
    if "to_be_recomputed" in text or "placeholder" in text:
        errors.append("placeholder_found")

    cases = packet.get("proposed_mechanisms_for_owner_decision", {})
    if not {"webgoat_idor", "webgoat_path_traversal", "crapi_object_access"}.issubset(cases):
        errors.append("all_target_mechanism_sections_required")
    return errors


def main() -> int:
    try:
        packet = json.loads(PACKET.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL: packet_read_error:{exc}")
        return 1
    errors = validate(packet)
    if errors:
        print("FAIL")
        print("\n".join(errors))
        return 1
    print("PASS: target-live fixture/session injection packet remains pending and fail-closed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
