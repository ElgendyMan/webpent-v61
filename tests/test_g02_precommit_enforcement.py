from __future__ import annotations

import json
import shutil
from pathlib import Path

from scripts.check_g02_precommit import check_repository, render_markdown
from webpent.shared.direct_io_inventory import scan_direct_io

ROOT = Path(__file__).resolve().parents[1]


def _minimal_project(
    tmp_path: Path, *, unsafe_source: bool = False, extra_source: str = ""
) -> Path:
    project = tmp_path / "project"
    (project / "src/webpent/tools/utils").mkdir(parents=True)
    (project / "src/webpent/shared").mkdir(parents=True)
    (project / "docs").mkdir()
    for relative in (
        "src/webpent/tools/utils/subprocess.py",
        "src/webpent/shared/http.py",
    ):
        destination = project / relative
        destination.write_text(
            (ROOT / relative).read_text(encoding="utf-8"), encoding="utf-8"
        )
    if unsafe_source:
        path = project / "src/webpent/tools/utils/subprocess.py"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "                shell=False,", "                shell=True,", 1
            ),
            encoding="utf-8",
        )
    if extra_source:
        path = project / "src/webpent/agents/unsafe_transport.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(extra_source, encoding="utf-8")

    records = scan_direct_io(project / "src")
    payload = {
        "schema": "webpent.direct_io_inventory.v1",
        "generated_from": "src/**/*.py",
        "transport_families": sorted(
            {
                "http",
                "browser",
                "api",
                "graphql",
                "file_upload",
                "oob",
                "subprocess",
                "raw_tcp_dns",
                "websocket",
                "cloud",
                "ssh",
            }
        ),
        "logical_transports": {
            "http": {"boundary": "h", "authority": "a", "proof": "p"}
        },
        "approved_direct_files": {},
        "approved_transport_records": [],
        "dynamic_import_allowlist": [],
        "coverage": {},
        "records": records,
    }
    # The checker uses the canonical policy fields; this fixture only needs
    # artifact parity, while its negative assertions target runtime/approval.
    from scripts.check_g02_precommit import _payload

    payload = _payload(records)
    (project / "docs/direct_io_inventory.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (project / "docs/DIRECT_IO_INVENTORY.md").write_text(
        render_markdown(payload), encoding="utf-8"
    )
    return project


def test_precommit_checker_accepts_current_deterministic_artifacts() -> None:
    assert check_repository(project_root=ROOT) == []


def test_precommit_checker_rejects_synthetic_unsafe_patch(tmp_path: Path) -> None:
    project = _minimal_project(tmp_path, unsafe_source=True)
    errors = check_repository(project_root=project)
    assert any(
        "shell=False" in error or "artifact records drift" in error for error in errors
    )


def test_precommit_checker_rejects_unapproved_new_transport(tmp_path: Path) -> None:
    project = _minimal_project(
        tmp_path,
        extra_source="import requests\n\nrequests.get('https://example.test')\n",
    )
    errors = check_repository(project_root=project)
    assert any("unapproved" in error for error in errors)


def test_regenerated_markdown_is_stable(tmp_path: Path) -> None:
    project = _minimal_project(tmp_path)
    first = (project / "docs/DIRECT_IO_INVENTORY.md").read_text(encoding="utf-8")
    records = scan_direct_io(project / "src")
    from scripts.check_g02_precommit import _payload

    assert first == render_markdown(_payload(records))
    shutil.rmtree(project / "docs")
