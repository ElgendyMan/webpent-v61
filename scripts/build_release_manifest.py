"""Build a reproducible release manifest without treating a checksum as a signature."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT = PROJECT_ROOT / "docs" / "release_manifest.json"
EXCLUDED_PARTS = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
}
EXCLUDED_ROOT_DIRS = {"audit", "memory", "output"}
EXCLUDED_NAMES = {
    ".env",
    ".coverage",
    "webpent.db",
    "webpent.db.migration.lock",
    "action_ledger.db",
    "action_ledger.db.migration.lock",
    "decision_log.db",
    "decision_log.db.migration.lock",
    "lessons.db",
    "lessons.db.migration.lock",
    "audit_summary_current.txt",
    "plan_verification_summary.txt",
    "release_manifest_provenance_v1.json",
}
EXCLUDED_SUFFIXES = {
    ".pyc",
    ".db",
    ".db-shm",
    ".db-wal",
    ".db-journal",
    ".sqlite",
    ".sqlite3",
    ".log",
}
EXCLUDED_NAME_SUFFIXES = (".db.migration.lock",)
EXCLUDED_RELATIVE_PREFIXES = ("docs/live_waptlab_output_",)


def _is_excluded_relative(relative: Path) -> bool:
    """Return whether a path is runtime, cache, secret, or raw-output data.

    The release manifest is intentionally redacted. It inventories source,
    tests, configuration templates, and selected evidence artifacts, but it
    must never hash local credentials, mutable databases, caches, or historical
    live-output directories that can contain target-specific data.
    """
    if relative.parts and relative.parts[0] in EXCLUDED_ROOT_DIRS:
        return True
    if any(part.endswith(".egg-info") for part in relative.parts):
        return True
    relative_text = relative.as_posix()
    return any(
        relative_text == prefix.rstrip("/") or relative_text.startswith(prefix)
        for prefix in EXCLUDED_RELATIVE_PREFIXES
    )


def _git_revision(argument: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", argument],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _tracked_commit() -> str | None:
    return _git_revision("HEAD")


def _tracked_tree() -> str | None:
    return _git_revision("HEAD^{tree}")


def _included(path: Path) -> bool:
    relative = path.relative_to(PROJECT_ROOT)
    if any(part in EXCLUDED_PARTS for part in relative.parts):
        return False
    if _is_excluded_relative(relative):
        return False
    if (
        path.name in EXCLUDED_NAMES
        or path.suffix in EXCLUDED_SUFFIXES
        or path.name.endswith(EXCLUDED_NAME_SUFFIXES)
    ):
        return False
    if path.name.endswith(".zip"):
        return False
    return path.is_file()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_hashes() -> dict[str, str]:
    artifacts = [
        "docs/vip_quality_gate.json",
        "docs/waptlab_regression.json",
        "docs/waptlab_live_smoke_2cb9024.json",
        "docs/waptlab_coverage_ledger.json",
        "docs/waptlab_mock_reproducibility.json",
        "docs/bandit_release.json",
        "docs/pip_audit_release.json",
        "docs/sbom.cdx.json",
    ]
    return {
        relative: _sha256(PROJECT_ROOT / relative)
        for relative in artifacts
        if (PROJECT_ROOT / relative).is_file()
    }


def _qualification() -> dict[str, Any]:
    live_path = PROJECT_ROOT / "docs" / "waptlab_live_smoke_2cb9024.json"
    using_historical_live_artifact = live_path.is_file()
    path = (
        live_path
        if using_historical_live_artifact
        else PROJECT_ROOT / "docs" / "waptlab_regression.json"
    )
    if not path.is_file():
        return {
            "live_qualification": False,
            "target_contacted": None,
            "waptlab_modified": None,
            "status": "missing_artifact",
            "artifact_scope": "missing_artifact",
        }
    payload = json.loads(path.read_text(encoding="utf-8"))
    result: dict[str, Any] = {
        "live_qualification": bool(payload.get("live_qualification", False)),
        "target_contacted": payload.get("target_contacted"),
        "waptlab_modified": payload.get("waptlab_modified"),
        "campaign_count": payload.get("campaign_count", payload.get("catalog_count")),
        "summary": payload.get("summary", payload.get("campaign_summary", {})),
        "status": payload.get(
            "qualification_status",
            "live" if payload.get("live_qualification") else "contract_only",
        ),
        "artifact": path.name,
        "artifact_scope": (
            "historical_live_artifact"
            if using_historical_live_artifact
            else "offline_regression_artifact"
        ),
    }
    for key in (
        "run_id",
        "scan_completed",
        "scan_status",
        "exit_code",
        "findings_total",
        "reported_confirmed",
        "strict_confirmed",
        "evidence_bundle_count",
        "proof_bundle_count",
        "threshold",
    ):
        if key in payload:
            result[key] = payload[key]
    return result


def _security_status() -> dict[str, Any]:
    path = PROJECT_ROOT / "docs" / "vip_quality_gate.json"
    if not path.is_file():
        return {"gate_present": False, "gate_passed": False}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {
        "gate_present": True,
        "gate_passed": bool(payload.get("passed", False)),
        "schema_version": payload.get("schema_version"),
        "known_blockers": payload.get("known_blockers", []),
        "checks": {
            item.get("name", "unknown"): bool(item.get("passed", False))
            for item in payload.get("checks", [])
        },
    }


def _signature_status() -> dict[str, Any]:
    """Sign only when an explicit private key is supplied by the release operator."""
    key_path = os.environ.get("WEBPENT_SIGNING_KEY")
    if not key_path:
        return {
            "status": "not_configured",
            "algorithm": None,
            "signature_path": None,
            "note": "A SHA-256 manifest is integrity evidence, not a cryptographic signature.",
        }
    return {
        "status": "operator_required",
        "algorithm": "external-signing-key",
        "signature_path": None,
        "key_path_present": bool(Path(key_path).is_file()),
        "note": "The release must be signed by the operator outside this sandbox.",
    }


def main() -> int:
    files = sorted(
        {
            str(path.relative_to(PROJECT_ROOT)): _sha256(path)
            for path in PROJECT_ROOT.rglob("*")
            if _included(path) and path != OUTPUT
        }.items()
    )
    payload = {
        "schema_version": "webpent-release-manifest-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": "WebPent",
        "git_commit": _tracked_commit(),
        "git_tree": _tracked_tree(),
        "provenance": {
            "commit_and_tree_are_source_revision_evidence": True,
            "manifest_path_excluded_from_file_hashes": True,
            "archive_verification_method": (
                "compare extracted archive tree/files to git archive of git_commit"
            ),
            "inventory_revision_relationship": (
                "git_commit and git_tree identify the pre-manifest source revision; "
                "the release_manifest commit is recorded by the separate provenance sidecar"
            ),
            "provenance_sidecar": "docs/release_manifest_provenance_v1.json",
        },
        "file_count": len(files),
        "files": dict(files),
        "artifact_hashes": _artifact_hashes(),
        "qualification": _qualification(),
        "security": _security_status(),
        "signature": _signature_status(),
        "redaction": {
            "status": "applied",
            "excluded_parts": sorted(EXCLUDED_PARTS | EXCLUDED_ROOT_DIRS),
            "excluded_names": sorted(EXCLUDED_NAMES),
            "excluded_suffixes": sorted(EXCLUDED_SUFFIXES),
            "excluded_name_suffixes": list(EXCLUDED_NAME_SUFFIXES),
            "excluded_relative_prefixes": list(EXCLUDED_RELATIVE_PREFIXES),
        },
        "release_decision": "blocked" if not _security_status()["gate_passed"] else "candidate",
    }
    OUTPUT.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"output": str(OUTPUT), "file_count": len(files)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
