"""G-02 acceptance tests for complete direct-I/O transport inventory."""

from __future__ import annotations

import json
from pathlib import Path

from webpent.shared.direct_io_inventory import (
    APPROVED_DIRECT_FILES,
    LOGICAL_TRANSPORTS,
    scan_direct_io,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = PROJECT_ROOT / "docs" / "direct_io_inventory.json"


def _inventory() -> dict:
    return json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))


def test_g02_inventory_is_generated_from_current_source_without_drift():
    inventory = _inventory()
    assert inventory["schema"] == "webpent.direct_io_inventory.v1"
    assert inventory["generated_from"] == "src/**/*.py"
    assert inventory["records"] == scan_direct_io(PROJECT_ROOT / "src")


def test_g02_artifact_contracts_match_source_contracts():
    inventory = _inventory()
    assert inventory["logical_transports"] == LOGICAL_TRANSPORTS
    assert inventory["approved_direct_files"] == APPROVED_DIRECT_FILES
    assert set(inventory["transport_families"]) == set(LOGICAL_TRANSPORTS)


def test_g02_all_raw_transport_sites_are_allowlisted():
    records = _inventory()["records"]
    raw_sites = [record for record in records if record["kind"] in {"import", "call"}]
    assert raw_sites
    assert all(record["file"] in APPROVED_DIRECT_FILES for record in raw_sites)

    observed_transports = {record["transport"] for record in records}
    assert "http_implementation" in observed_transports
    assert "browser_implementation" in observed_transports
    assert "raw_tcp_dns_implementation" in observed_transports
    assert "subprocess_implementation" in observed_transports


def test_g02_required_logical_transports_have_explicit_boundary_authority_and_proof():
    required = {
        "http",
        "browser",
        "api",
        "graphql",
        "file_upload",
        "oob",
        "subprocess",
        "raw_tcp_dns",
    }
    assert required <= LOGICAL_TRANSPORTS.keys()
    for name in required:
        contract = LOGICAL_TRANSPORTS[name]
        assert contract["boundary"]
        assert contract["authority"]
        assert contract["proof"]


def test_g02_inventory_does_not_allow_unclassified_transport_sites():
    records = _inventory()["records"]
    assert all(record["transport"] != "unclassified" for record in records)
    record_keys = {
        (record["file"], record["line"], record["kind"], record["symbol"])
        for record in records
    }
    assert len(record_keys) == len(records)
