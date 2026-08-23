#!/usr/bin/env python3
"""Audit production agent wiring without importing or executing target code."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any


def _calls(path: Path) -> dict[str, int]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError) as exc:
        return {"parse_error": 1, "parse_error_text": str(exc)[:240]}
    direct_executor = 0
    harness_calls = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr == "execute":
            direct_executor += 1
        elif node.func.attr == "run_agent_proposal":
            harness_calls += 1
    return {
        "direct_executor_calls": direct_executor,
        "run_agent_proposal_calls": harness_calls,
    }


def build_report(repo: Path) -> dict[str, Any]:
    roots = [repo / "src" / "webpent" / "agents", repo / "src" / "webpent" / "graph"]
    files = sorted(
        path
        for root in roots
        if root.exists()
        for path in root.rglob("*.py")
        if "__pycache__" not in path.parts
    )
    entries = []
    for path in files:
        counts = _calls(path)
        if (
            counts.get("direct_executor_calls", 0)
            or counts.get("run_agent_proposal_calls", 0)
            or "parse_error" in counts
        ):
            entries.append({"path": str(path.relative_to(repo)), **counts})
    direct = sum(int(item.get("direct_executor_calls", 0)) for item in entries)
    harness = sum(int(item.get("run_agent_proposal_calls", 0)) for item in entries)
    parse_errors = sum(1 for item in entries if "parse_error" in item)
    return {
        "artifact_type": "superagentic_wiring_audit",
        "schema_version": "superagentic-wiring-v1",
        "static_only": True,
        "target_contacted": False,
        "direct_executor_calls": direct,
        "run_agent_proposal_calls": harness,
        "parse_errors": parse_errors,
        "harness_is_common_execution_path": direct == 0 and harness > 0 and parse_errors == 0,
        "qualification_class": "source-contract",
        "entries": entries,
        "limitations": [
            "AST counts do not prove runtime reachability or live qualification.",
            (
                "Direct executor calls remain a wiring gap until each production "
                "path is migrated safely."
            ),
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    repo = args.repo.resolve()
    report = build_report(repo)
    output = args.output or repo / "docs" / "qualification" / "superagentic_wiring_audit.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {key: report[key] for key in report if key != "entries"},
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
