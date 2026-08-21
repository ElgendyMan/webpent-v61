"""Offline v95 benchmark gate using deterministic fixture expectations."""

from __future__ import annotations

import json
import sys
from pathlib import Path

MIN_CONFIRMED = 1
MIN_EVIDENCE_BACKED = 1


def evaluate(report: dict) -> tuple[bool, dict[str, int]]:
    findings = report.get("findings", [])
    confirmed = sum(
        1
        for finding in findings
        if str(finding.get("confidence", "")).lower() in {"confirmed", "tool-confirmed"}
    )
    evidence_backed = sum(
        1
        for finding in findings
        if isinstance(finding.get("evidence"), dict)
        and finding["evidence"].get("evidence_bundle")
    )
    metrics = {
        "findings": len(findings),
        "confirmed": confirmed,
        "evidence_backed": evidence_backed,
    }
    return confirmed >= MIN_CONFIRMED and evidence_backed >= MIN_EVIDENCE_BACKED, metrics


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: v95_nightly_benchmark.py REPORT.json", file=sys.stderr)
        return 2
    report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    passed, metrics = evaluate(report)
    print(json.dumps({"passed": passed, **metrics}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
