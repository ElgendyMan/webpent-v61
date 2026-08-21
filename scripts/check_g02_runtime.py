"""Run deterministic G-02 static/runtime-boundary invariants locally."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from webpent.shared.direct_io_inventory import (
    inventory_contract_errors,
    scan_direct_io,
)
from webpent.shared.secondary_io_scanner import cross_check_primary

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
ARTIFACT_PATH = PROJECT_ROOT / "docs" / "direct_io_inventory.json"


def runtime_source_invariant_errors(source_root: Path) -> list[str]:
    """Check immutable safety markers for the approved execution wrappers."""
    errors: list[str] = []
    subprocess_source = (source_root / "webpent/tools/utils/subprocess.py").read_text(
        encoding="utf-8"
    )
    try:
        subprocess_tree = ast.parse(subprocess_source)
    except SyntaxError:
        subprocess_tree = None
    popen_calls = (
        [
            node
            for node in ast.walk(subprocess_tree)
            if isinstance(node, ast.Call) and ast.unparse(node.func) == "subprocess.Popen"
        ]
        if subprocess_tree is not None
        else []
    )
    if len(popen_calls) < 2:
        errors.append("subprocess wrapper must enforce shell=False in both paths")
    for call in popen_calls:
        shell_keyword = next((keyword for keyword in call.keywords if keyword.arg == "shell"), None)
        if (
            shell_keyword is None
            or not isinstance(shell_keyword.value, ast.Constant)
            or shell_keyword.value.value is not False
        ):
            errors.append("subprocess wrapper must enforce shell=False in both paths")
    if "start_new_session=True" not in subprocess_source:
        errors.append("subprocess wrapper must isolate the process group")
    if "timeout=effective_timeout" not in subprocess_source:
        errors.append("subprocess wrapper must enforce an explicit timeout")
    if "_validate_cmd(cmd)" not in subprocess_source:
        errors.append("subprocess wrapper must validate argv before execution")

    http_source = (source_root / "webpent/shared/http.py").read_text(encoding="utf-8")
    if "verify=False" in http_source or "verify = False" in http_source:
        errors.append("HTTP wrapper contains a TLS verification downgrade")
    for marker, message in (
        ("kwargs[\"verify\"] = True", "HTTP wrapper must force TLS verification"),
        ("_redirect_guard", "HTTP wrapper must install redirect guard"),
        ("SSRFPinningTransport", "HTTP wrapper must pin validated destination IPs"),
        ("is_engagement_origin_allowed", "HTTP wrapper must enforce origin scope"),
        ("sanitize_cookie_pair", "HTTP wrapper must provide cookie redaction/sanitization"),
    ):
        if marker not in http_source:
            errors.append(message)
    return errors


def main() -> int:
    try:
        artifact = json.loads(ARTIFACT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"passed": False, "errors": [f"artifact: {exc}"]}))
        return 1

    primary = scan_direct_io(SOURCE_ROOT)
    errors = inventory_contract_errors(artifact, SOURCE_ROOT)
    errors.extend(cross_check_primary(primary, SOURCE_ROOT))
    errors.extend(runtime_source_invariant_errors(SOURCE_ROOT))
    errors.extend(
        f"unapproved runtime record: {record['file']}:{record['line']}"
        for record in primary
        if record["approval_status"] not in {"approved", "approved_with_expiry", "not_applicable"}
    )
    result = {
        "passed": not errors,
        "primary_records": len(primary),
        "errors": sorted(set(errors)),
        "external_target_contacted": False,
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
