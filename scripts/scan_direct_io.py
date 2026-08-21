#!/usr/bin/env python3
"""Generate the checked-in G-02 direct-I/O inventory artifact."""

from __future__ import annotations

import json
from pathlib import Path

from webpent.shared.direct_io_inventory import (
    APPROVED_DIRECT_FILES,
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
        "transport_families": [
            "http",
            "browser",
            "api",
            "graphql",
            "file_upload",
            "oob",
            "subprocess",
            "raw_tcp_dns",
        ],
        "logical_transports": LOGICAL_TRANSPORTS,
        "approved_direct_files": APPROVED_DIRECT_FILES,
        "records": records,
    }
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {OUTPUT_PATH} ({len(records)} records)")


if __name__ == "__main__":
    main()
