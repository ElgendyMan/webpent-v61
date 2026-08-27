from __future__ import annotations

import hashlib
import json
import subprocess
import tarfile
from io import BytesIO
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_RELATIVE = "docs/release_manifest.json"
SIDECAR_RELATIVE = "docs/release_manifest_provenance_v1.json"


def _git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fail(checks: dict[str, bool], name: str) -> None:
    checks[name] = False


def validate() -> dict[str, Any]:
    checks: dict[str, bool] = {}
    manifest_path = PROJECT_ROOT / MANIFEST_RELATIVE
    sidecar_path = PROJECT_ROOT / SIDECAR_RELATIVE
    if not manifest_path.is_file() or not sidecar_path.is_file():
        return {
            "passed": False,
            "checks": {"artifacts_present": False},
            "blockers": ["missing_provenance_artifact"],
        }
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    checks["artifacts_present"] = True
    checks["manifest_declares_sidecar"] = (
        manifest.get("provenance", {}).get("provenance_sidecar") == SIDECAR_RELATIVE
    )
    artifact = sidecar.get("artifact", {})
    source = sidecar.get("inventory_source_revision", {})
    manifest_commit = artifact.get("manifest_commit")
    source_commit = manifest.get("git_commit")
    source_tree = manifest.get("git_tree")
    checks["sidecar_manifest_path"] = artifact.get("path") == MANIFEST_RELATIVE
    checks["sidecar_sha_matches_current_manifest"] = (
        artifact.get("sha256") == f"sha256:{_sha256_bytes(manifest_path.read_bytes())}"
    )
    observed_manifest_commit = _git("log", "-1", "--format=%H", "--", MANIFEST_RELATIVE)
    checks["manifest_commit_matches_history"] = manifest_commit == observed_manifest_commit
    checks["source_commit_matches_manifest"] = source.get("git_commit") == source_commit
    checks["source_tree_matches_manifest"] = source.get("git_tree") == source_tree
    observed_parent = _git("rev-parse", f"{manifest_commit}^")
    observed_parent_tree = _git("rev-parse", f"{observed_parent}^{{tree}}")
    checks["manifest_parent_is_inventory_source"] = observed_parent == source_commit
    checks["manifest_parent_tree_is_inventory_source"] = observed_parent_tree == source_tree
    checks["sidecar_records_observed_parent"] = (
        source.get("parent_commit_observed") == observed_parent
        and source.get("parent_tree_observed") == observed_parent_tree
    )
    changed_paths = [
        p
        for p in _git(
            "diff-tree", "--no-commit-id", "--name-only", "-r", manifest_commit
        ).splitlines()
        if p
    ]
    checks["manifest_commit_changes_only_manifest"] = changed_paths == [MANIFEST_RELATIVE]
    checks["manifest_is_self_excluded"] = bool(
        sidecar.get("archive_scope", {}).get("manifest_self_hash_excluded")
    )
    checks["sidecar_is_self_excluded"] = bool(
        sidecar.get("archive_scope", {}).get("sidecar_self_hash_excluded")
    )
    try:
        archive = subprocess.run(
            ["git", "archive", source_commit], cwd=PROJECT_ROOT, capture_output=True, check=True
        ).stdout
        members = {}
        with tarfile.open(fileobj=BytesIO(archive), mode="r:") as tar:
            for member in tar.getmembers():
                if member.isfile():
                    handle = tar.extractfile(member)
                    if handle is not None:
                        members[member.name] = _sha256_bytes(handle.read())
        listed = manifest.get("files", {})
        checks["archive_contains_all_listed_files"] = all(path in members for path in listed)
        checks["archive_hashes_match_manifest"] = checks[
            "archive_contains_all_listed_files"
        ] and all(members[path] == digest for path, digest in listed.items())
    except (OSError, subprocess.CalledProcessError, tarfile.TarError):
        checks["archive_contains_all_listed_files"] = False
        checks["archive_hashes_match_manifest"] = False
    blockers = [name for name, passed in checks.items() if not passed]
    return {
        "passed": not blockers,
        "checks": checks,
        "blockers": blockers,
        "manifest_commit": manifest_commit,
        "source_commit": source_commit,
        "source_tree": source_tree,
    }


def main() -> int:
    result = validate()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
