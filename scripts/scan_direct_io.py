#!/usr/bin/env python3
"""Generate the checked-in G-02 direct-I/O inventory artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from webpent.shared.direct_io_inventory import (
    APPROVED_DIRECT_FILES,
    APPROVED_TRANSPORT_RECORDS,
    DYNAMIC_IMPORT_ALLOWLIST,
    LOGICAL_TRANSPORTS,
    scan_direct_io,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
JSON_OUTPUT_PATH = PROJECT_ROOT / "docs" / "direct_io_inventory.json"
MARKDOWN_OUTPUT_PATH = PROJECT_ROOT / "docs" / "DIRECT_IO_INVENTORY.md"


def build_payload(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "webpent.direct_io_inventory.v1",
        "generated_from": "src/**/*.py",
        "transport_families": sorted(LOGICAL_TRANSPORTS),
        "logical_transports": LOGICAL_TRANSPORTS,
        "approved_direct_files": APPROVED_DIRECT_FILES,
        "approved_transport_records": list(APPROVED_TRANSPORT_RECORDS),
        "dynamic_import_allowlist": list(DYNAMIC_IMPORT_ALLOWLIST),
        "coverage": {
            "record_count": len(records),
            "raw_or_boundary_records": sum(
                record["kind"] in {"import", "call", "safe_boundary_call"}
                for record in records
            ),
            "dynamic_records": sum(
                record["kind"] in {"dynamic_import", "dynamic_resolution"}
                for record in records
            ),
            "unapproved_records": sum(
                record["approval_status"] == "not_approved" for record in records
            ),
            "unknown_family_records": sum(
                record["transport_family"] == "unknown" for record in records
            ),
        },
        "records": records,
    }


def render_markdown(payload: dict[str, Any]) -> str:
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
    for name, contract in payload["logical_transports"].items():
        lines.append(
            f"| `{name}` | {contract['boundary']} | {contract['authority']} | "
            f"{contract['proof']} |"
        )
    lines.extend(
        [
            "",
            "## Source-level records",
            "",
            f"Total records: **{len(payload['records'])}**.",
            "",
            "| File | Line | Kind | Symbol | Transport | Approval |",
            "|---|---:|---|---|---|---|",
        ]
    )
    for record in payload["records"]:
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
    return "\n".join(lines)


def main() -> None:
    records = scan_direct_io(SOURCE_ROOT)
    payload = build_payload(records)
    JSON_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    JSON_OUTPUT_PATH.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    MARKDOWN_OUTPUT_PATH.write_text(render_markdown(payload), encoding="utf-8")
    print(
        f"wrote {JSON_OUTPUT_PATH} and {MARKDOWN_OUTPUT_PATH} "
        f"({len(records)} records)"
    )


if __name__ == "__main__":
    main()

__all__ = ["build_payload", "main", "render_markdown"]
