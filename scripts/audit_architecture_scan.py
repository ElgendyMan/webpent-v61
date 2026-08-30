"""Audit-only architecture and placeholder scanner."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports/audit"
GENERIC_DIRS = (
    "src/webpent/core",
    "src/webpent/engine",
    "src/webpent/planner",
    "src/webpent/reasoning",
    "src/webpent/memory",
)
TARGET_MARKERS = re.compile(
    r"juice.?shop|webgoat|crapi|waptlab|/ftp|score-board|qwertz", re.I
)
PLACEHOLDER_MARKERS = re.compile(
    r"\bTODO\b|\bFIXME\b|NotImplemented|^\s*pass\s*(#.*)?$",
    re.I | re.M,
)


def files(pattern: str) -> list[Path]:
    return sorted(p for p in ROOT.glob(pattern) if p.is_file())


def main() -> None:
    contamination = []
    for directory in GENERIC_DIRS:
        for path in files(f"{directory}/**/*.py"):
            content = path.read_text(encoding="utf-8", errors="ignore")
            matches = TARGET_MARKERS.findall(content)
            if matches:
                contamination.append(
                    {
                        "path": str(path.relative_to(ROOT)),
                        "markers": sorted(set(matches)),
                    }
                )

    names: dict[str, list[str]] = {}
    for path in files("src/**/*.py"):
        names.setdefault(path.stem.lower(), []).append(str(path.relative_to(ROOT)))
    duplicate_candidates = [paths for paths in names.values() if len(paths) > 1]

    placeholders = []
    for path in files("src/**/*.py") + files("tests/**/*.py"):
        content = path.read_text(encoding="utf-8", errors="ignore")
        matches = PLACEHOLDER_MARKERS.findall(content)
        if matches:
            placeholders.append(
                {"path": str(path.relative_to(ROOT)), "marker_count": len(matches)}
            )

    payload = {
        "generic_core_directories_scanned": list(GENERIC_DIRS),
        "target_specific_markers_in_generic_dirs": contamination,
        "duplicate_name_candidates": duplicate_candidates,
        "placeholders": placeholders,
        "interpretation": {
            "contamination": (
                "candidate markers require manual ownership review; filenames are not proof"
            ),
            "duplicates": "same basename is not semantic duplication",
            "placeholders": (
                "TODO/FIXME/pass require classification; intentional guards may be valid"
            ),
        },
    }
    OUT.mkdir(parents=True, exist_ok=True)
    output = OUT / "architecture_scan.json"
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    summary = {
        "contamination": len(contamination),
        "duplicate_candidates": len(duplicate_candidates),
        "placeholder_files": len(placeholders),
    }
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
