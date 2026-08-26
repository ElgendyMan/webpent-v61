"""Fail-closed independent-review gate for controlled local-lab evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _blockers(packet: dict[str, Any], manifest: dict[str, Any]) -> list[str]:
    review = packet.get("independent_review", {})
    blockers: list[str] = []
    if not review.get("reviewer_id"):
        blockers.append("independent_reviewer_missing")
    if not review.get("reviewed_at_utc"):
        blockers.append("independent_review_timestamp_missing")
    if review.get("results_seen_by_reviewer") is not True:
        blockers.append("reviewer_has_not_seen_results")
    if review.get("approval_decision") != "approved":
        blockers.append("oracle_review_not_approved")
    if review.get("full_p10_qualification_approved") is not True:
        blockers.append("full_p10_approval_missing")
    if review.get("vip_qualification_approved") is not True:
        blockers.append("vip_approval_missing")
    if manifest.get("qualification_status", {}).get("official_p10") != "QUALIFIED":
        blockers.append("official_p10_not_qualified")
    return blockers


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("packet", type=Path)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    packet = json.loads(args.packet.read_text(encoding="utf-8"))
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    blockers = _blockers(packet, manifest)
    result: dict[str, Any] = {
        "schema_version": "controlled-local-lab.independent-review-gate.v1",
        "decision": "QUALIFIED" if not blockers else "NOT_QUALIFIED",
        "blockers": blockers,
        "fail_closed": bool(blockers),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if blockers else 1


if __name__ == "__main__":
    raise SystemExit(main())
