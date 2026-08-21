"""G-02 expanded static and independent-scanner contracts."""

from __future__ import annotations

from pathlib import Path

from webpent.shared.direct_io_inventory import (
    APPROVED_TRANSPORT_RECORDS,
    DYNAMIC_IMPORT_ALLOWLIST,
    inventory_contract_errors,
    scan_direct_io,
)
from webpent.shared.secondary_io_scanner import cross_check_primary

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"


def test_g02_primary_inventory_has_no_unapproved_or_unclassified_records():
    records = scan_direct_io(SOURCE_ROOT)
    assert records
    assert all(record["approval_status"] != "not_approved" for record in records)
    assert all(record["transport"] != "unclassified" for record in records)
    assert all(
        record["transport_family"] != "unknown"
        or record["approval_status"] in {"approved", "approved_with_expiry"}
        for record in records
    )


def test_g02_secondary_scanner_has_zero_disagreements():
    records = scan_direct_io(SOURCE_ROOT)
    assert cross_check_primary(records, SOURCE_ROOT) == []


def test_g02_structured_approval_policy_is_present_and_bounded():
    assert APPROVED_TRANSPORT_RECORDS
    assert DYNAMIC_IMPORT_ALLOWLIST
    for entry in APPROVED_TRANSPORT_RECORDS:
        assert entry["file"].startswith("src/")
        assert entry["owner"]
        assert entry["approved_by"]
        assert entry["expires_at"]
        assert entry["canonical_wrapper"]
    for entry in DYNAMIC_IMPORT_ALLOWLIST:
        assert entry["file"].startswith("src/")
        assert entry["owner"]
        assert entry["approved_by"]
        assert entry["expires_at"]
        assert entry["required_wrapper_contract"]


def test_g02_inventory_contract_helper_is_clean():
    from json import loads

    artifact = loads(
        (PROJECT_ROOT / "docs" / "direct_io_inventory.json").read_text(encoding="utf-8")
    )
    assert inventory_contract_errors(artifact, SOURCE_ROOT) == []


def test_g02_new_transport_names_are_classifiable_without_wildcard_approval():
    records = scan_direct_io(SOURCE_ROOT)
    observed = {record["transport"] for record in records}
    assert observed <= {
        "http_implementation",
        "http_sync",
        "http_async",
        "http_transport",
        "browser_implementation",
        "browser_playwright",
        "browser_selenium",
        "raw_tcp_dns_implementation",
        "raw_tcp_dns",
        "subprocess_implementation",
        "subprocess",
        "subprocess_boundary",
        "websocket",
        "cloud_provider",
        "ssh",
        "dynamic_import",
        "dynamic_resolution",
    }


def test_g02_synthetic_transport_families_and_dynamic_resolution_are_covered(tmp_path):
    fixture = tmp_path / "transport_fixture.py"
    fixture.write_text(
        "\n".join(
            [
                "import importlib",
                "import os",
                "import subprocess as sp",
                "import requests",
                "import httpx",
                "from requests import Session as ReqSession",
                "from aiohttp import ClientSession as AioSession",
                "from urllib.request import urlopen",
                "from websockets import connect as ws_connect",
                "from boto3 import client as cloud_client",
                "from paramiko import SSHClient",
                "from http.client import HTTPSConnection",
                "from urllib3 import PoolManager",
                "httpx.Client()",
                "httpx.AsyncClient()",
                "requests.Session()",
                "ReqSession().get(url)",
                "AioSession().get(url)",
                "urlopen(url)",
                "ws_connect(url)",
                "cloud_client(\"s3\")",
                "SSHClient()",
                "HTTPSConnection(host)",
                "PoolManager().request(\"GET\", url)",
                "sp.run([\"echo\", \"ok\"], shell=False)",
                "os.system(\"echo ok\")",
                "os.spawnv(os.P_WAIT, \"echo\", [\"echo\", \"ok\"])",
                "os.execv(\"echo\", [\"echo\", \"ok\"])",
                "importlib.import_module(\"requests\")",
                "__import__(\"requests\")",
                "getattr(sys.modules, \"requests\")",
            ]
        ),
        encoding="utf-8",
    )
    records = scan_direct_io(tmp_path)
    assert records
    observed = {record["transport"] for record in records}
    assert {
        "http_transport",
        "http_sync",
        "http_async",
        "websocket",
        "cloud_provider",
        "ssh",
        "subprocess",
        "shell_execution",
        "dynamic_import",
        "dynamic_resolution",
    } <= observed
    assert all(record["transport"] != "unclassified" for record in records)
    dynamic = [record for record in records if record["kind"].startswith("dynamic_")]
    assert dynamic
    assert all(record["approval_status"] == "not_approved" for record in dynamic)
    assert all(record["transport_family"] == "unknown" for record in dynamic)


def test_g02_inventory_has_no_duplicate_observations():
    records = scan_direct_io(SOURCE_ROOT)
    keys = [
        (record["file"], record["line"], record["column"], record["kind"], record["symbol"])
        for record in records
    ]
    assert len(keys) == len(set(keys))


def test_g02_mutating_a_record_fails_closed():
    from copy import deepcopy
    from json import loads

    artifact = loads(
        (PROJECT_ROOT / "docs" / "direct_io_inventory.json").read_text(encoding="utf-8")
    )
    mutated = deepcopy(artifact)
    mutated["records"][0]["symbol"] = "untrusted.dynamic.transport"
    errors = inventory_contract_errors(mutated, SOURCE_ROOT)
    assert errors
    assert any("drift" in error for error in errors)


def test_g02_mutating_dynamic_allowlist_fails_closed():
    from copy import deepcopy
    from json import loads

    artifact = loads(
        (PROJECT_ROOT / "docs" / "direct_io_inventory.json").read_text(encoding="utf-8")
    )
    mutated = deepcopy(artifact)
    mutated["dynamic_import_allowlist"] = []
    errors = inventory_contract_errors(mutated, SOURCE_ROOT)
    assert errors
    assert any("allowlist" in error for error in errors)
