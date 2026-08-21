#!/usr/bin/env python3
"""Generate the checked-in G-02 direct-I/O inventory artifact."""

from __future__ import annotations

import json
from pathlib import Path

from webpent.shared.direct_io_inventory import (
    APPROVED_DIRECT_FILES,
    APPROVED_TRANSPORT_RECORDS,
    DYNAMIC_IMPORT_ALLOWLIST,
    LOGICAL_TRANSPORTS,
    scan_direct_io,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
OUTPUT_PATH = PROJECT_ROOT / "docs" / "direct_io_inventory.json"


def main() -> None:
    records = scan_direct_io(SOURCE_ROOT)
    payload = {
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
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {OUTPUT_PATH} ({len(records)} records)")


if __name__ == "__main__":
    main()
