"""Fail-closed checks for generic-core target neutrality.

The check intentionally scans only generic source packages. Target-specific route,
selector, and profile literals belong in explicit benchmark/adapter packages.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CORE_ROOTS = (
    REPO_ROOT / "src/webpent/shared",
    REPO_ROOT / "src/webpent/agents",
    REPO_ROOT / "src/webpent/contracts",
    REPO_ROOT / "src/webpent/models",
    REPO_ROOT / "src/webpent/state",
)
FORBIDDEN_PATTERNS = (
    re.compile(r"juice[_ -]?shop", re.IGNORECASE),
    re.compile(r"/ftp(?:/|$)", re.IGNORECASE),
    re.compile(r"/metrics(?:/|$)", re.IGNORECASE),
    re.compile(r"score-board", re.IGNORECASE),
    re.compile(r"security\.txt", re.IGNORECASE),
    re.compile(r"app-mat-search", re.IGNORECASE),
    re.compile(r"qwertz", re.IGNORECASE),
    re.compile(r"coupons_2013", re.IGNORECASE),
    re.compile(r"suspicious_errors", re.IGNORECASE),
)
FORBIDDEN_IMPORT_PREFIXES = (
    "webpent.benchmark.juice_shop",
    "webpent.benchmark.waptlab",
)


def _source_files() -> list[Path]:
    files: list[Path] = []
    for root in CORE_ROOTS:
        if root.exists():
            files.extend(sorted(root.rglob("*.py")))
    return files


def _import_names(tree: ast.AST) -> list[str]:
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


def main() -> int:
    findings: list[str] = []
    for path in _source_files():
        relative = path.relative_to(REPO_ROOT).as_posix()
        text = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for pattern in FORBIDDEN_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        f"forbidden_target_literal:{relative}:{line_number}:{line.strip()}"
                    )
        try:
            tree = ast.parse(text, filename=relative)
        except SyntaxError as exc:
            findings.append(f"core_parse_error:{relative}:{exc.msg}")
            continue
        for imported in _import_names(tree):
            if imported.startswith(FORBIDDEN_IMPORT_PREFIXES):
                findings.append(f"forbidden_target_import:{relative}:{imported}")
    if findings:
        print("\n".join(sorted(set(findings))))
        return 1
    print(
        "generic_target_neutrality_passed "
        f"files={len(_source_files())} roots={len(CORE_ROOTS)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
