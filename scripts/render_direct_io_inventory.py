#!/usr/bin/env python3
"""Render the checked-in G-02 inventory as an auditable Markdown table."""

from __future__ import annotations

import json
from pathlib import Path

from webpent.shared.direct_io_inventory import LOGICAL_TRANSPORTS

ROOT = Path(__file__).resolve().parents[1]
JSON_PATH = ROOT / "docs" / "direct_io_inventory.json"
MD_PATH = ROOT / "docs" / "DIRECT_IO_INVENTORY.md"


def main() -> None:
    data = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    lines = [
        "# G-02 Direct-I/O Transport Inventory",
        "",
        "> This artifact is generated from the current `src/**/*.py` AST and is",
        "> enforced by `tests/test_g02_direct_io_inventory.py`. A new direct",
        "> transport or an unclassified site fails the contract test until it is",
        "> reviewed and catalogued.",
        "",
        "## Logical transport contract",
        "",
        "| Transport | Boundary | Authority | Promotion/evidence contract |",
        "|---|---|---|---|",
    ]
    for name, contract in LOGICAL_TRANSPORTS.items():
        lines.append(
            f"| `{name}` | {contract['boundary']} | {contract['authority']} | "
            f"{contract['proof']} |"
        )
    lines.extend(
        [
            "",
            "## Source-level records",
            "",
            f"Total records: **{len(data['records'])}**.",
            "",
            "| File | Line | Kind | Symbol | Transport |",
            "|---|---:|---|---|---|",
        ]
    )
    for record in data["records"]:
        lines.append(
            f"| `{record['file']}` | {record['line']} | `{record['kind']}` | "
            f"`{record['symbol']}` | `{record['transport']}` |"
        )
    lines.extend(
        [
            "",
            "## Enforcement rules",
            "",
            "Raw imports and raw transport calls are permitted only in reviewed",
            "boundary files listed in `APPROVED_DIRECT_FILES`. Application code",
            "uses hardened HTTP helpers, the bounded subprocess wrapper, or an",
            "explicitly catalogued validator exception.",
            "",
            "The logical `api`, `graphql`, `file_upload`, and `oob` families do not",
            "create independent socket implementations: they are HTTP protocols",
            "and inherit the hardened HTTP boundary. Browser traffic is separately",
            "catalogued under Playwright. DNS and raw TCP validators remain explicit",
            "exceptions with bounded scope and no implicit confirmation.",
            "",
            "The JSON artifact is the machine-readable source for release review.",
            "This Markdown file is its human-readable rendering and must be",
            "regenerated whenever source transport sites change.",
            "",
        ]
    )
    MD_PATH.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {MD_PATH} ({len(data['records'])} records)")


if __name__ == "__main__":
    main()
