from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = PROJECT_ROOT / "docs" / "release_manifest.json"
OUTPUT = PROJECT_ROOT / "docs" / "release_manifest_provenance_v1.json"


def _git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_payload() -> dict[str, Any]:
    if not MANIFEST.is_file():
        raise FileNotFoundError(MANIFEST)
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    manifest_relative = MANIFEST.relative_to(PROJECT_ROOT).as_posix()
    manifest_commit = _git("log", "-1", "--format=%H", "--", manifest_relative)
    source_commit = manifest.get("git_commit")
    source_tree = manifest.get("git_tree")
    if not source_commit or not source_tree:
        raise ValueError("release manifest must record git_commit and git_tree")
    parent_commit = _git("rev-parse", f"{manifest_commit}^")
    parent_tree = _git("rev-parse", f"{parent_commit}^{{tree}}")
    changed_paths = [
        path
        for path in _git(
            "diff-tree", "--no-commit-id", "--name-only", "-r", manifest_commit
        ).splitlines()
        if path
    ]
    return {
        "schema_version": "webpent-release-manifest-provenance-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "artifact": {
            "path": manifest_relative,
            "sha256": f"sha256:{_sha256(MANIFEST)}",
            "manifest_commit": manifest_commit,
            "manifest_commit_tree": _git("rev-parse", f"{manifest_commit}^{{tree}}"),
        },
        "inventory_source_revision": {
            "git_commit": source_commit,
            "git_tree": source_tree,
            "relationship": "manifest_commit_parent",
            "parent_commit_observed": parent_commit,
            "parent_tree_observed": parent_tree,
        },
        "archive_scope": {
            "archive_commit": manifest_commit,
            "archive_verification": (
                "git archive archive_commit; verify manifest sha256 and all listed file hashes"
            ),
            "manifest_self_hash_excluded": True,
            "sidecar_self_hash_excluded": True,
            "changed_paths_in_manifest_commit": changed_paths,
        },
        "fail_closed_conditions": [
            "manifest_commit parent must equal release_manifest.git_commit",
            "manifest_commit parent tree must equal release_manifest.git_tree",
            "manifest commit must change only release_manifest.json",
            "current manifest bytes must match the committed manifest bytes",
            "all manifest-listed files must hash identically from the archive source revision",
        ],
    }


def main() -> int:
    payload = build_payload()
    OUTPUT.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {"output": str(OUTPUT), "manifest_commit": payload["artifact"]["manifest_commit"]},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
