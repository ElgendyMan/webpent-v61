#!/usr/bin/env python3
"""Emit the deterministic, offline VIP failure-injection matrix."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from benchmarks.failure_matrix import run_failure_matrix  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate WebPent failure boundaries without network or target execution."
    )
    parser.add_argument("--output", type=Path, help="Optional JSON output path.")
    args = parser.parse_args()
    report: dict[str, Any] = run_failure_matrix()
    payload = {
        **report,
        "live_target_executed": False,
        "waptlab_executed": False,
        "autopentestx_executed": False,
        "qualification_status": "not_evaluated",
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
