"""Independently replay controlled local-lab ProofBundles from disk."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from webpent.models.proof_bundle import ProofBundle, proof_bundle_promotion_ready


def _replay_case(case: dict[str, Any]) -> None:
    observations = case["observations"]
    bundle = ProofBundle.model_validate(case["proof_bundle"])
    if not bundle.verify_seal() or not proof_bundle_promotion_ready(bundle):
        raise RuntimeError(f"bundle_not_ready:{case['case_id']}")
    if any(
        key in json.dumps(observations, sort_keys=True).lower()
        for key in ("raw_response_body", "cookie", "authorization", "set-cookie")
    ):
        raise RuntimeError(f"unsafe_artifact_key:{case['case_id']}")
    if not bundle.replay(
        [observations["baseline"], observations["candidate"], observations["control"]],
        observations["control"],
        replay_context=case["replay_context"],
    ):
        raise RuntimeError(f"replay_failed:{case['case_id']}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args()
    payload = json.loads(args.artifact.read_text(encoding="utf-8"))
    cases = [case for run in payload["runs"] for case in run["cases"]]
    for case in cases:
        _replay_case(case)
    result = {
        "schema_version": "controlled-local-lab-replay.v1",
        "artifact": str(args.artifact),
        "replayed_case_count": len(cases),
        "replayed_run_count": len(payload["runs"]),
        "all_seals_valid": True,
        "all_replays_valid": True,
        "raw_sensitive_artifacts": False,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
