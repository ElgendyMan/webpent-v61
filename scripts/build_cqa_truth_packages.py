from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OWNER_ROOT = ROOT / "target_owner" / "cqa_v1"
TARGETS = (
    ("target-alpha", "/alpha"),
    ("target-beta", "/beta"),
    ("target-gamma", "/gamma"),
    ("target-delta", "/delta"),
    ("target-epsilon", "/epsilon"),
)
CLASSES = (
    "idor",
    "tenant_isolation",
    "rbac",
    "workflow_ordering",
    "partial_authorization",
    "misleading_response",
)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def main() -> None:
    OWNER_ROOT.mkdir(parents=True, exist_ok=True)
    for target_index, (target_id, base_path) in enumerate(TARGETS):
        cases = []
        for case_index in range(10):
            case_id = f"{target_id}-case-{case_index + 1:02d}"
            vuln = case_index < 5
            vulnerability_class = CLASSES[(target_index + case_index) % len(CLASSES)]
            object_id = f"{target_id.removeprefix('target-')}-{(case_index % 4) + 1}"
            cases.append(
                {
                    "case_id": case_id,
                    "target_id": target_id,
                    "label": "vulnerable" if vuln else "clean",
                    "class": vulnerability_class if vuln else "negative_control",
                    "baseline_path": f"{base_path}/health",
                    "candidate_path": (
                        f"{base_path}/api/objects/{object_id}"
                        if vuln
                        else f"{base_path}/api/profile"
                    ),
                    "negative_control_path": f"{base_path}/api/objects/missing",
                    "causal_oracle": {
                        "requires": [
                            "baseline_observation",
                            "candidate_observation",
                            "negative_control_observation",
                            "replay_verified",
                        ],
                        "predicate": "candidate_semantics_differ_from_control_under_same_context",
                    },
                }
            )
        payload = {
            "schema": "cqa-v1-owner-truth-v1",
            "target_id": target_id,
            "cases": cases,
        }
        target_dir = OWNER_ROOT / target_id
        target_dir.mkdir(parents=True, exist_ok=True)
        truth_path = target_dir / "truth.json"
        truth_bytes = canonical(payload)
        truth_path.write_bytes(truth_bytes + b"\n")
        truth_digest = hashlib.sha256(truth_bytes + b"\n").hexdigest()
        provenance = {
            "schema": "cqa-v1-owner-provenance-v1",
            "target_id": target_id,
            "runtime_digest": f"irta-v3-{target_id}-local-v1",
            "source": "local-independent-target-factory",
            "owner_boundary": "not-imported-by-detector",
            "truth_sha256": truth_digest,
        }
        (target_dir / "provenance.json").write_bytes(canonical(provenance) + b"\n")
        (target_dir / "digest.txt").write_text(
            f"truth.json sha256:{truth_digest}\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
