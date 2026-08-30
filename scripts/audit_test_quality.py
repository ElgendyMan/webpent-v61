"""Conservative test-quality classifier for audit reporting."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports/audit/test_quality_matrix.json"


def classify(path: Path) -> tuple[str, str, str]:
    text = path.read_text(encoding="utf-8", errors="ignore").lower()
    rel = str(path.relative_to(ROOT))
    if "benchmark" in rel or any(word in text for word in ("precision", "recall", "f1")):
        return (
            "Benchmark Test",
            "quality measurement or scoring contract",
            "strong if independent ground truth is present",
        )
    if "http" in text or "integration" in rel or "rta" in rel or "harness" in text:
        return (
            "Integration Test",
            "component/HTTP integration behavior",
            "medium; inspect causal oracle separately",
        )
    markers = ("permission", "authorization", "vulnerability", "causal", "negative_control")
    if any(marker in text for marker in markers):
        return (
            "Capability Test",
            "security capability or safety invariant",
            "medium to strong depending on independent evidence",
        )
    return (
        "Contract Test",
        "API/dataclass/invariant behavior",
        "contract strength; not a live capability claim",
    )


def main() -> None:
    entries = []
    counts = {
        "Contract Test": 0,
        "Integration Test": 0,
        "Capability Test": 0,
        "Benchmark Test": 0,
    }
    for path in sorted((ROOT / "tests").rglob("test_*.py")):
        category, capability, strength = classify(path)
        counts[category] += 1
        entries.append(
            {
                "test": str(path.relative_to(ROOT)),
                "category": category,
                "capability_proven": capability,
                "strength": strength,
            }
        )
    payload = {"summary": {"total_tests": len(entries), "counts": counts}, "tests": entries}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
