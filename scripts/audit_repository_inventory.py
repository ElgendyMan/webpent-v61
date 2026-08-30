"""Audit-only repository inventory generator for Post-IRTA reality verification."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "reports/audit/repository_inventory.json"


def relative_files(pattern: str) -> list[str]:
    return sorted(str(path.relative_to(ROOT)) for path in ROOT.glob(pattern) if path.is_file())


def main() -> None:
    modules = relative_files("src/**/*.py")
    tests = relative_files("tests/**/*.py")
    benchmarks = sorted(
        path for path in modules if "/benchmark/" in path or path.startswith("benchmarks/")
    )
    reports = relative_files("reports/**/*")
    artifacts = sorted(
        path
        for path in relative_files("**/*")
        if path.endswith((".zip", ".json", ".log", ".txt")) and not path.startswith(".git/")
    )
    deprecated = []
    for path in modules:
        content = (ROOT / path).read_text(encoding="utf-8", errors="ignore")
        if "deprecated" in content.lower() or "DEPRECATED" in content:
            deprecated.append(path)

    # Duplicate review is intentionally conservative: list similarly named files
    # for human review, never claim equivalence from filenames alone.
    names: dict[str, list[str]] = {}
    for path in modules:
        stem = Path(path).stem.lower()
        names.setdefault(stem, []).append(path)
    duplicates = [paths for paths in names.values() if len(paths) > 1]

    payload = {
        "modules": modules,
        "tests": tests,
        "benchmarks": benchmarks,
        "reports": reports,
        "artifacts": artifacts,
        "deprecated": sorted(deprecated),
        "duplicates": duplicates,
        "counts": {
            "modules": len(modules),
            "tests": len(tests),
            "benchmarks": len(benchmarks),
            "reports": len(reports),
            "artifacts": len(artifacts),
            "deprecated": len(deprecated),
            "duplicate_name_groups": len(duplicates),
        },
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload["counts"], sort_keys=True))


if __name__ == "__main__":
    main()
