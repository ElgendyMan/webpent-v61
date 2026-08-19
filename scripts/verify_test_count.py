#!/usr/bin/env python3
"""Fail if the repository loses the minimum preserved test-function count."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path


def count_test_functions(root: Path) -> tuple[int, dict[str, int]]:
    total = 0
    per_file: dict[str, int] = {}
    for path in sorted(root.rglob("test_*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except OSError as exc:
            raise SystemExit(f"cannot read test file {path}: {exc}") from exc
        count = sum(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
            for node in ast.walk(tree)
        )
        if count:
            relative = str(path.relative_to(root.parent))
            per_file[relative] = count
            total += count
    return total, per_file


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tests", type=Path, default=Path("tests"))
    parser.add_argument("--minimum", type=int, default=430)
    args = parser.parse_args()

    total, per_file = count_test_functions(args.tests)
    payload = {"total_test_functions": total, "minimum": args.minimum, "files": per_file}
    print(json.dumps(payload, indent=2, sort_keys=True))
    if total < args.minimum:
        print(
            f"ERROR: preserved test-function count {total} is below minimum {args.minimum}",
        )
        return 1
    print(f"OK: preserved test-function count {total} >= minimum {args.minimum}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
