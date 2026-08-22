from __future__ import annotations

from pathlib import Path

from webpent.shared.direct_io_inventory import scan_direct_io


def _records(tmp_path: Path, source: str) -> list[dict]:
    target = tmp_path / "synthetic.py"
    target.write_text(source, encoding="utf-8")
    return scan_direct_io(tmp_path)


def _dynamic_records(records: list[dict]) -> list[dict]:
    return [record for record in records if record["kind"] == "dynamic_resolution"]


def test_getattr_sys_modules_subprocess_is_fail_closed(tmp_path: Path):
    records = _records(
        tmp_path,
        "import sys\nrunner = getattr(sys.modules[\"subprocess\"], \"run\")\n",
    )
    dynamic = _dynamic_records(records)
    assert dynamic
    assert any(record["approval_status"] == "not_approved" for record in dynamic)
    assert any("sys.modules" in record["normalized_symbol"] for record in dynamic)


def test_getattr_sys_modules_socket_single_quote_is_fail_closed(tmp_path: Path):
    records = _records(
        tmp_path,
        "import sys\nfactory = getattr(sys.modules['socket'], 'socket')\n",
    )
    dynamic = _dynamic_records(records)
    assert dynamic
    assert any(record["approval_status"] == "not_approved" for record in dynamic)
    assert any("sys.modules" in record["normalized_symbol"] for record in dynamic)


def test_local_alias_from_sys_modules_subscript_is_fail_closed(tmp_path: Path):
    records = _records(
        tmp_path,
        "import sys\nmod = sys.modules[\"subprocess\"]\nmod.run(cmd)\n",
    )
    assert any(
        record["kind"] in {"call", "dynamic_resolution"}
        and record["approval_status"] == "not_approved"
        for record in records
    )


def test_non_literal_importlib_module_name_is_not_allowlisted(tmp_path: Path):
    records = _records(
        tmp_path,
        "import importlib\nname = \"htt\" + \"px\"\nmodule = importlib.import_module(name)\n",
    )
    dynamic_imports = [record for record in records if record["kind"] == "dynamic_import"]
    assert dynamic_imports
    assert all(record["approval_status"] == "not_approved" for record in dynamic_imports)


def test_httpx_client_alias_resolves_and_is_not_approved(tmp_path: Path):
    records = _records(
        tmp_path,
        "from httpx import Client as X\nclient = X()\n",
    )
    assert any(
        record["kind"] == "call"
        and record["normalized_symbol"] == "httpx.Client"
        and record["approval_status"] == "not_approved"
        for record in records
    )


def test_aliased_os_system_is_not_approved(tmp_path: Path):
    records = _records(
        tmp_path,
        "import os as _o\n_o.system(cmd)\n",
    )
    assert any(
        record["kind"] == "call"
        and record["normalized_symbol"] == "os.system"
        and record["approval_status"] == "not_approved"
        for record in records
    )
