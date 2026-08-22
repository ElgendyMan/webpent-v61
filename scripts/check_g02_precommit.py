"""Fail-closed pre-commit/CI checker for the G-02 direct-I/O contract."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from webpent.shared.direct_io_inventory import (
    APPROVED_DIRECT_FILES,
    APPROVED_TRANSPORT_RECORDS,
    DYNAMIC_IMPORT_ALLOWLIST,
    LOGICAL_TRANSPORTS,
    expired_approval_errors,
    inventory_contract_errors,
    scan_direct_io,
)
from webpent.shared.secondary_io_scanner import cross_check_primary

try:
    from scripts.check_g02_runtime import runtime_source_invariant_errors
except ModuleNotFoundError:  # direct execution from the scripts directory
    from check_g02_runtime import runtime_source_invariant_errors

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
JSON_PATH = PROJECT_ROOT / "docs" / "direct_io_inventory.json"
MARKDOWN_PATH = PROJECT_ROOT / "docs" / "DIRECT_IO_INVENTORY.md"


def _payload(records: list[dict[str, Any]]) -> dict[str, Any]:
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


def _git_text(project_root: Path, path: str) -> str | None:
    result = subprocess.run(
        ["git", "show", f"HEAD:{path}"],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout if result.returncode == 0 else None


def _staged_paths(project_root: Path) -> set[str]:
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
    )
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def check_repository(
    *, require_staged_artifacts: bool = False, project_root: Path = PROJECT_ROOT
) -> list[str]:
    errors: list[str] = []
    source_root = project_root / "src"
    json_path = project_root / "docs" / "direct_io_inventory.json"
    markdown_path = project_root / "docs" / "DIRECT_IO_INVENTORY.md"
    records = scan_direct_io(source_root)
    expected_payload = _payload(records)
    expected_json = json.dumps(expected_payload, indent=2, sort_keys=True) + "\n"
    expected_markdown = render_markdown(expected_payload)

    try:
        observed = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        observed = None
        errors.append(f"JSON artifact unreadable: {exc}")
    if observed is not None:
        errors.extend(inventory_contract_errors(observed, source_root))
        if json.dumps(observed, indent=2, sort_keys=True) + "\n" != expected_json:
            errors.append("JSON artifact is not the deterministic scanner output")

    try:
        observed_markdown = markdown_path.read_text(encoding="utf-8")
    except OSError as exc:
        observed_markdown = ""
        errors.append(f"Markdown artifact unreadable: {exc}")
    if observed_markdown != expected_markdown:
        errors.append("Markdown artifact is not the deterministic scanner output")

    errors.extend(expired_approval_errors())
    errors.extend(cross_check_primary(records, source_root))
    errors.extend(runtime_source_invariant_errors(source_root))
    errors.extend(
        f"unapproved direct/indirect transport: {record['file']}:{record['line']}"
        for record in records
        if record["kind"] in {"import", "call", "dynamic_import", "dynamic_resolution"}
        and record["approval_status"] not in {
            "approved",
            "approved_with_expiry",
            "not_applicable",
        }
    )
    if require_staged_artifacts:
        staged = _staged_paths(project_root)
        source_staged = any(path.startswith("src/") and path.endswith(".py") for path in staged)
        if source_staged:
            for artifact_path, expected in (
                ("docs/direct_io_inventory.json", expected_json),
                ("docs/DIRECT_IO_INVENTORY.md", expected_markdown),
            ):
                head_value = _git_text(project_root, artifact_path)
                if head_value != expected and artifact_path not in staged:
                    errors.append(f"{artifact_path} must be staged with the source change")
    return sorted(set(errors))


def main() -> int:
    errors = check_repository(require_staged_artifacts=True)
    result = {
        "passed": not errors,
        "errors": errors,
        "external_target_contacted": False,
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())

__all__ = ["check_repository", "main", "render_markdown"]
