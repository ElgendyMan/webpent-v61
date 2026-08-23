"""Build a deterministic provenance manifest for an installed Nuclei template set."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

SCHEMA_VERSION = "nuclei-template-manifest-v1"


def build_manifest(root: Path, version: str, output: Path) -> dict[str, object]:
    if not root.is_dir():
        raise SystemExit(f"template root does not exist: {root}")
    files = sorted(
        path for path in root.rglob("*")
        if path.is_file() and path.resolve() != output.resolve()
    )
    digest = hashlib.sha256()
    total_bytes = 0
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
        total_bytes += len(content)
    return {
        "schema_version": SCHEMA_VERSION,
        "version": version,
        "digest": digest.hexdigest(),
        "file_count": len(files),
        "total_bytes": total_bytes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = build_manifest(args.root, args.version, args.output)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["SCHEMA_VERSION", "build_manifest", "main"]

