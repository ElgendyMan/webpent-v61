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
        "# G-02 Direct-I/O Inventory",
        "",
        "> This artifact is generated from the current `src/**/*.py` AST and is",
        "> enforced by the G-02 static/runtime gate. New direct transports,",
        "> unclassified sites, or artifact drift fail closed until reviewed.",
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
            "| File | Line | Kind | Symbol | Transport | Approval |",
            "|---|---:|---|---|---|---|",
        ]
    )
    for record in data["records"]:
        lines.append(
            f"| `{record['file']}` | {record['line']} | `{record['kind']}` | "
            f"`{record['symbol']}` | `{record['transport']}` | "
            f"`{record['approval_status']}` |"
        )
    lines.extend(
        [
            "",
            "## Enforcement rules",
            "",
            "Raw imports and raw transport calls are permitted only in reviewed "
            "boundary files and symbol-scoped approvals. Application code uses "
            "hardened HTTP helpers, the bounded subprocess wrapper, or an "
            "explicitly catalogued validator exception.",
            "",
            "Unknown and indirect transport resolution remain missing-validator "
            "states; they are never promoted to confirmation by this artifact.",
            "",
        ]
    )
    MD_PATH.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {MD_PATH} ({len(data['records'])} records)")


if __name__ == "__main__":
    main()
