from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from webpent.abhie_v6.architect import ArchitectReviewV6


def build_review() -> dict[str, object]:
    report = ArchitectReviewV6().review(
        engagement_id="abhie-v6-offline-review",
        target_id="target-neutral-recorded-scope",
        subject_id="hypothesis-v6-advisory-001",
        hypothesis={"claim": "unvalidated authorization boundary hypothesis"},
        argument_chain=None,
        scope_allowed=True,
        evidence_refs=(),
        causal_oracle_passed=False,
        negative_control_passed=False,
        proof_sealed=False,
        proof_replayable=False,
        observation_count=0,
        claim="unvalidated authorization boundary hypothesis",
    )
    payload = asdict(report)
    payload["governance"] = {
        "official_isolated_p10_runs_authorized": False,
        "p10_status": "NOT_QUALIFIED",
        "p9_status": "NOT_QUALIFIED",
        "vip_status": "NOT_QUALIFIED",
        "bug_bounty_status": "BLOCKED",
        "human_signoff": False,
        "qualification_effect": False,
    }
    payload["execution"] = {
        "offline": True,
        "requests_sent": 0,
        "mutations_performed": False,
        "credentials_used": False,
        "external_targets_contacted": False,
    }
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(build_review(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"output": str(args.output), "status": "BLOCKED"}))


if __name__ == "__main__":
    main()
