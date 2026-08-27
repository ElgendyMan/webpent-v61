#!/usr/bin/env python3
"""Fail-closed validation for the source-backed candidate inventory."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "reports/evaluation/source_inventory/SOURCE-BACKED-CANDIDATE-INVENTORY-v1.json"

EXPECTED_REVISIONS = {
    "owasp_juice_shop": "1618a611b173b4bf114028e6e02549950606e29d",
    "owasp_webgoat": "7517acca95d9851da706452454c223dd13545ef4",
    "crapi": "73d309cc8f28bbdeed31dbb35f05dba8354de3c9",
}
ALLOWED_DECISIONS = {
    "accepted_scoring_ready_partial",
    "blocked",
    "blocked_pending_governance_and_mapping_confirmation",
    "observation_only",
    "out_of_scope",
}
ACCEPTED_JUICE_CASES = {
    "juice.error_handling.v1",
    "juice.exposed_metrics.v1",
    "juice.local_xss.v1",
}


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def main() -> int:
    try:
        data = json.loads(INVENTORY.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"inventory is not valid JSON: {exc}")

    if data.get("schema") != "webpent-source-backed-candidate-inventory-v1":
        fail("unexpected schema")
    safety = data.get("global_safety", {})
    required_safety = {
        "scope": "authorized local loopback only",
        "methods": ["GET"],
        "credentials_used": False,
        "state_mutation": False,
        "external_contact": False,
        "oast_or_callbacks": False,
        "raw_bodies_headers_cookies_persisted": False,
        "official_isolated_p10_runs_authorized": False,
        "blocked_or_observation_only_are_not_metrics": True,
    }
    if safety != required_safety:
        fail("global safety scope is not fail-closed")

    targets = data.get("targets")
    target_ids = (
        {target.get("target_id") for target in targets}
        if isinstance(targets, list)
        else set()
    )
    if not isinstance(targets, list) or target_ids != set(EXPECTED_REVISIONS):
        fail("inventory must contain exactly the three expected targets")

    counts = {
        "accepted_scoring_ready_partial": 0,
        "blocked": 0,
        "blocked_pending_governance_and_mapping_confirmation": 0,
        "observation_only": 0,
        "out_of_scope": 0,
    }
    accepted_ids: set[str] = set()
    for target in targets:
        target_id = target.get("target_id")
        source_root = Path(target.get("source_path", ""))
        if target.get("source_revision") != EXPECTED_REVISIONS[target_id]:
            fail(f"source revision drift for {target_id}")
        gt = target.get("ground_truth_manifest", {})
        if not gt.get("not_scored_is_not_fn"):
            fail(f"not_fn invariant missing for {target_id}")
        candidates = target.get("candidates", target.get("source_candidate_surfaces", []))
        if not isinstance(candidates, list) or not candidates:
            fail(f"candidate inventory is empty for {target_id}")
        for candidate in candidates:
            decision = candidate.get("decision")
            evidence_items = candidate.get("source_evidence", [])
            if evidence_items:
                for evidence in evidence_items:
                    rel_path = evidence.get("path") or evidence.get("source_file")
                    expected_hash = evidence.get("sha256") or evidence.get("source_sha256")
                    if not rel_path or not expected_hash:
                        fail(f"source evidence lacks path/hash: {candidate.get('case_id')}")
                    source_file = source_root / rel_path
                    if not source_file.is_file():
                        fail(f"source evidence file missing: {source_file}")
                    actual_hash = hashlib.sha256(source_file.read_bytes()).hexdigest()
                    if actual_hash != expected_hash:
                        fail(f"source hash mismatch: {source_file}")
            if decision not in ALLOWED_DECISIONS:
                fail(f"invalid decision {decision!r} for {candidate.get('case_id')}")
            counts[decision] += 1
            if decision == "accepted_scoring_ready_partial":
                required = (
                    "source_evidence",
                    "causal_predicate",
                    "safe_precondition",
                    "independent_negative_control",
                    "central_verifier",
                    "proof_procedure",
                )
                if any(not candidate.get(field) for field in required):
                    case_id = candidate.get("case_id")
                    fail(f"accepted candidate lacks causal readiness fields: {case_id}")
                procedure = candidate["proof_procedure"]
                proof_steps = (
                    "baseline",
                    "candidate",
                    "negative_control",
                    "seal",
                    "verify_seal",
                    "replay",
                )
                for key in proof_steps:
                    if not procedure.get(key):
                        case_id = candidate.get("case_id")
                        fail(f"accepted candidate lacks proof step {key}: {case_id}")
                accepted_ids.add(candidate["case_id"])
            elif not candidate.get("not_fn"):
                case_id = candidate.get("case_id")
                fail(f"non-accepted candidate is not explicitly excluded from FN: {case_id}")
        if target_id in {"owasp_webgoat", "crapi"}:
            if gt.get("approved_case_ids") != []:
                fail(f"unadmitted target has approved cases: {target_id}")
            if any(c.get("decision") == "accepted_scoring_ready_partial" for c in candidates):
                fail(f"unadmitted target has accepted scoring candidate: {target_id}")

    if accepted_ids != ACCEPTED_JUICE_CASES:
        fail(f"accepted case set drift: {sorted(accepted_ids)}")
    summary = data.get("decision_summary", {})
    for key, value in counts.items():
        if summary.get(key) != value:
            fail(f"summary count mismatch for {key}: expected {value}, got {summary.get(key)}")
    if summary.get("quality_metrics_computed") is not False:
        fail("quality metrics must remain withheld")
    qualification = data.get("qualification_state", {})
    if qualification.get("official_isolated_p10_runs_authorized") is not False:
        fail("official P10 gate must remain closed")
    qualification_is_closed = (
        qualification.get("p10") == "NOT_QUALIFIED"
        and qualification.get("p9") == "NOT_QUALIFIED"
        and qualification.get("vip") == "NOT_QUALIFIED"
    )
    if not qualification_is_closed:
        fail("qualification state drift")

    print("PASS: source-backed candidate inventory is valid and fail-closed")
    blocked = counts["blocked"] + counts["blocked_pending_governance_and_mapping_confirmation"]
    print(
        f"targets={len(targets)} accepted={counts['accepted_scoring_ready_partial']} "
        f"blocked={blocked} observation_only={counts['observation_only']} "
        f"out_of_scope={counts['out_of_scope']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
