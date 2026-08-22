"""Build a deterministic offline Gate 3 proof artifact.

This is a fixture generator, not a live qualification claim. It uses the same
ProofBundle contract as validators and deliberately keeps all observations
redacted and synthetic; no target or provider I/O is performed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from webpent.models.proof_bundle import (
    build_proof_bundle,
    proof_bundle_promotion_ready,
    validate_proof_bundle,
)


def _observation(role: str, request_digest: str, response_digest: str) -> dict[str, Any]:
    return {
        "target_backed": True,
        "observation_role": role,
        "target_fingerprint": "target-fingerprint-offline-fixture-v1",
        "request_digest": request_digest,
        "response_digest": response_digest,
        "status_code": 200,
        "body_sha256": f"{role}-body-digest",
        "body_length": len(role),
    }


def build_artifact(output_root: Path) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    baseline = _observation("baseline", "sha256:" + "1" * 64, "sha256:" + "2" * 64)
    candidate = _observation("candidate", "sha256:" + "3" * 64, "sha256:" + "4" * 64)
    negative_control = _observation(
        "negative_control", "sha256:" + "5" * 64, "sha256:" + "6" * 64
    )
    requests = [
        {"role": item["observation_role"], "digest": item["request_digest"]}
        for item in (baseline, candidate, negative_control)
    ]
    responses = [
        {"role": item["observation_role"], "digest": item["response_digest"]}
        for item in (baseline, candidate, negative_control)
    ]
    bundle = build_proof_bundle(
        engagement_id="offline-gate3-engagement",
        finding_id="offline-gate3-finding",
        hypothesis_id="offline-gate3-hypothesis",
        target_fingerprint="target-fingerprint-offline-fixture-v1",
        evidence=[baseline, candidate, negative_control],
        evidence_refs=[
            "offline://gate3/baseline",
            "offline://gate3/candidate",
            "offline://gate3/negative-control",
        ],
        negative_control=negative_control,
        baseline=baseline,
        request_evidence=requests,
        response_evidence=responses,
        scope_context={"target_origin": "offline://fixture", "scope_bound": True},
        identity_context={"mode": "offline-fixture", "role": "redacted"},
        causal_oracle={
            "causal_signal": True,
            "negative_control_complete": True,
            "requires_target_backed": True,
            "basis": "controlled_differential_offline_fixture",
        },
        target_backed=True,
        negative_control_independent=True,
        validator_id="offline-gate3-validator",
        validator_version="1.0",
        validator_config={"fixture": "gate3-v1", "network": "disabled"},
        replay_metadata={
            "replayable": True,
            "replay_script": "scripts/build_gate3_proof_artifact.py",
            "observation_count": 3,
        },
        cleanup_status="not_applicable",
        redaction_manifest=["authorization", "cookie", "token", "secret"],
    ).seal(actor="offline-gate3-validator")

    replay_ok = bundle.replay(
        [baseline, candidate, negative_control], negative_control=negative_control
    )
    promotion_ready = proof_bundle_promotion_ready(bundle)
    valid = validate_proof_bundle(bundle, require_negative_control=True)
    payload = {
        "status": "offline_fixture_passed",
        "live_target_io": False,
        "sealed_replayable_confirmations": int(valid and replay_ok and promotion_ready),
        "proof_bundle": bundle.model_dump(mode="json"),
        "verification": {
            "seal_valid": bundle.verify_seal(),
            "structurally_valid": valid,
            "promotion_ready": promotion_ready,
            "replay_result": replay_ok,
            "replay_observation_count": 3,
        },
        "limitations": [
            "offline synthetic observations; not a live target qualification",
            "must not be used as evidence of WAPTLab or Juice Shop coverage",
        ],
    }
    (output_root / "gate3_proof_bundle.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    observed = [
        {
            "key": "offline_gate3_finding",
            "category": "offline_fixture",
            "status": "confirmed",
            "confirmation_status": "tool_confirmed",
            "proof_bundle_id": bundle.bundle_id,
            "proof_bundle_sealed": bundle.sealed,
            "proof_bundle_replayable": replay_ok,
            "causal_signal": bundle.causal_oracle.get("causal_signal") is True,
            "negative_control_complete": bundle.causal_oracle.get(
                "negative_control_complete"
            ) is True,
            "target_backed": bundle.target_backed,
            "negative_control_independent": bundle.negative_control_independent,
            "evidence_refs": list(bundle.evidence_refs),
        }
    ]
    (output_root / "gate3_observed_findings.json").write_text(
        json.dumps(observed, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    benchmark = [
        {
            "key": "offline_gate3_finding",
            "category": "offline_fixture",
            "risk": "high",
        }
    ]
    (output_root / "gate3_benchmark_fixture.json").write_text(
        json.dumps(benchmark, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    result = build_artifact(args.output_root)
    print(json.dumps(result["verification"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
