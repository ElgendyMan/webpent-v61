#!/usr/bin/env python3
"""Run the purpose-built loopback IDOR validation once and exit.

The process owns the ephemeral target lifetime.  It never contacts an external
host, never stores raw bodies, and does not update qualification or scoring
state.
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from webpent.adapters.controlled_target import (
    CONTROLLED_IDOR_CASE_ID,
    CONTROLLED_TARGET_ID,
    build_controlled_idor_registration,
    build_controlled_idor_target,
    build_controlled_target_spec,
)
from webpent.shared.generic_case_runner import GenericCaseRunner
from webpent.shared.generic_web_contracts import LifecycleAuthorization, LifecycleRunContext

OUTPUT = Path("reports/evaluation/local_causal_lab/CONTROLLED-LOCAL-IDOR-RESULT-v1.json")


def run() -> dict[str, object]:
    with build_controlled_idor_target() as target:
        spec = build_controlled_target_spec(target.target_origin)
        target.bind_target_spec(spec)
        registration = build_controlled_idor_registration(target)
        run_id = f"controlled-run-{uuid4().hex[:12]}"
        authorization = LifecycleAuthorization(
            authorized=True,
            engagement_id=spec.engagement_id,
            allowed_origin=target.target_origin,
            actor="owner-approved-local-validation",
            satisfied_requirements=(
                "controlled_local_target_authorization",
                "loopback_origin",
                "get_only_causal_validation",
            ),
        )
        context = LifecycleRunContext(
            run_id=run_id,
            target_id=CONTROLLED_TARGET_ID,
            case_id=CONTROLLED_IDOR_CASE_ID,
            engagement_id=spec.engagement_id,
        )
        reset_hash_before = target.reset()
        readiness = target.readiness()
        result = GenericCaseRunner.execute_case(
            registration, target.case_definition(), authorization, context
        )
        verification = target._last_verification
        bundle = verification.proof_bundle if verification is not None else None
        replay_context = verification.evidence.get("replay_context", {}) if verification else {}
        observed_request_count = target.request_count
        reset_hash_after = target.reset()
        artifact: dict[str, object] = {
            "artifact_version": "controlled-local-idor-result.v1",
            "classification": "controlled_local_target_backed_validation",
            "target": {
                "target_id": target.target_id,
                "target_version": "1.0",
                "origin": target.target_origin,
                "network_scope": "127.0.0.1_ephemeral_only",
                "external_scope": False,
                "raw_bodies_persisted": False,
            },
            "case": {
                "case_id": CONTROLLED_IDOR_CASE_ID,
                "vulnerability_class": "idor",
                "approved_scoring_case": False,
                "qualification_effect": False,
            },
            "readiness": readiness,
            "lifecycle": {
                "status": result.status,
                "reason": result.reason,
                "observation_refs": list(result.observation_refs),
                "request_count": observed_request_count,
            },
            "proof": {
                "created": bundle is not None,
                "passed": bool(verification and verification.passed),
                "evidence_origin": bundle.evidence_origin if bundle else None,
                "target_backed": bundle.target_backed if bundle else False,
                "oracle_decision": bundle.oracle_decision if bundle else None,
                "seal_verified": bool(bundle and bundle.verify_seal()),
                "sealed_digest": bundle.seal_digest if bundle else None,
                "replay_verified": bool(
                    verification
                    and verification.evidence.get("promotion_guard", {}).get("replay_verified")
                ),
                "replay_context_keys": sorted(replay_context.keys()),
                "evidence_count": len(verification.evidence.get("proof_evidence", []))
                if verification
                else 0,
            },
            "reset_verification": {
                "before_hash": reset_hash_before,
                "after_hash": reset_hash_after,
                "deterministic": reset_hash_before == reset_hash_after,
            },
            "governance": {
                "official_isolated_p10_runs_authorized": False,
                "human_independent_signoff_obtained": False,
                "p10": "NOT_QUALIFIED",
                "p9": "NOT_QUALIFIED",
                "vip": "NOT_QUALIFIED",
                "bug_bounty": "BLOCKED",
            },
        }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return artifact


if __name__ == "__main__":
    output = run()
    print(json.dumps(output, indent=2, sort_keys=True))
